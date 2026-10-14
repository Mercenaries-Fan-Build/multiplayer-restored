//! Windows-only layer: DllMain, deferred initialisation, and the ProtoSSL detours.
//!
//! Start-up order (on a thread started from `DllMain`, never inside the loader lock):
//! 1. read `<asi stem>.ini` beside the ASI, open the log file it names;
//! 2. wait — bounded by `[startup] signature_wait_ms` — until every ProtoSSL signature matches exactly
//!    once in the main module's `.text` (SecuROM decrypts `.text` at run time, so early scans find
//!    nothing); pages that are not committed+readable count as "not yet";
//! 3. hash `.text` (the build identity, [`crate::build_id`]) before anything is patched;
//! 4. add the `Mp` Lua namespace through m2-sdk.dll's Lua host at once ([`crate::lua::win::install`]): the
//!    game creates its Lua state early in start-up, and `Mp` must be registered on it;
//! 5. build the TLS connector, worker thread and runtime, then detour ProtoSSL (the game reaches
//!    ProtoSSLConnect only from the front end, long after start-up) and GameSpy Voice ([`crate::voice`]:
//!    `GVInitialize` and `GVStartup` do nothing, so in-game voice never starts).
//!
//! Each step is logged as it finishes, so the log's timestamps show where start-up spends its time.
//!
//! Any failure in 1–5 is fatal: it is logged (when the log is open), shown in a message box, and the
//! process exits — the game never runs with its network stack unhooked.
//!
//! Hook library: `m2-sdk.dll` (`mercs2_formats::mod_runtime`), the runtime every mod shares: it holds the
//! process's one MinHook instance and the Lua host. Its version is checked against the one this ASI was built
//! against before anything is hooked.

use std::ffi::{CStr, c_char, c_void};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery};
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows_sys::Win32::System::Threading::ExitProcess;
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

use crate::config::Config;
use crate::fesl::{FeslAdapter, FeslSettings};
use crate::http::HttpsClient;
use crate::lobby::LobbyProvider;
use crate::log::Logger;
use crate::relay::{AliasPlan, RelayFactory, ShimFactory, ShimSettings};
use crate::theater::{TheaterAdapter, TheaterSettings};
use crate::ws::{WsLobbyProvider, WsSettings};
use crate::protossl::{REF_SIZE, RefView};
use crate::session::SessionSlot;
use crate::signature::{CODE_SECTION, ProtoSslFn, Resolved, resolve};
use crate::vconn::{ConnectArgs, ConnectEnv, Service, ServiceFactory, Table};
use crate::voice::{VoiceFn, VoiceSites};
use mercs2_formats::exe_image::{self, Image};
use mercs2_formats::mod_runtime as rt;
use crate::worker::{RestApi, Worker};

const TITLE: &str = "multiplayer_restored";
/// The m2-sdk.dll release this ASI is built against (manifest.yaml requires `^0.4`).
const SDK_BUILT: &str = "0.4.0";
/// How often the start-up thread re-scans `.text` while waiting for SecuROM to decrypt it.
const SCAN_INTERVAL: Duration = Duration::from_millis(250);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Log (if possible), show the reason, end the process.
fn fatal(log: Option<&Logger>, msg: &str) -> ! {
    if let Some(l) = log {
        l.error(format!("FATAL: {msg}"));
    }
    let text = wide(&format!("{msg}\n\nThe game will now exit."));
    let title = wide(TITLE);
    unsafe {
        OutputDebugStringW(text.as_ptr());
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
        ExitProcess(1)
    }
}

struct RuntimeFactory {
    settings: Arc<FeslSettings>,
    theater: Arc<TheaterSettings>,
    worker: Worker,
    session: SessionSlot,
    account: Arc<dyn crate::account::StoredAccount>,
    lobby: Arc<dyn LobbyProvider>,
    relays: Arc<dyn RelayFactory>,
    log: Logger,
}

impl ServiceFactory for RuntimeFactory {
    fn fesl(&self) -> Box<dyn Service> {
        // init() installs the store before the hooks exist, so this cannot fail once a connect arrives.
        let keys = crate::room_key::global().unwrap_or_else(|e| fatal(Some(&self.log), &e)).clone();
        Box::new(FeslAdapter::new(
            self.settings.clone(),
            self.worker.handle(),
            self.session.clone(),
            self.account.clone(),
            self.lobby.clone(),
            keys,
            self.log.clone(),
        ))
    }
    fn theater(&self) -> Result<Box<dyn Service>, String> {
        let session = self
            .session
            .lock()
            .map_err(|_| "session lock poisoned".to_string())?
            .clone()
            .ok_or("Theater connect before FESL Login: no session to serve it")?;
        let keys = crate::room_key::global()?.clone();
        let lobby = self.lobby.handle(true)?;
        Ok(Box::new(TheaterAdapter::new(self.theater.clone(), lobby, session, keys, self.relays.clone(), self.log.clone())))
    }
}

struct Runtime {
    cfg: Config,
    log: Logger,
    factory: RuntimeFactory,
    table: Mutex<Table>,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static ORIG_DISCONNECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_DESTROY: AtomicUsize = AtomicUsize::new(0);

fn rt() -> &'static Runtime {
    RUNTIME.get().expect("ProtoSSL detours run only after the runtime is installed")
}

/// # Safety
/// `r` is a ProtoSSL ref: the game allocated `REF_SIZE` bytes for it (Create, `push 0x128`).
unsafe fn ref_view<'a>(r: *mut u8) -> RefView<'a> {
    RefView(unsafe { &mut *(r as *mut [u8; REF_SIZE]) })
}

fn table() -> std::sync::MutexGuard<'static, Table> {
    rt().table.lock().unwrap_or_else(|p| p.into_inner())
}

unsafe extern "C" fn hook_connect(r: *mut u8, secure: i32, name: *const c_char, ip: u32, port: i32) -> i32 {
    let rt = rt();
    let name: &[u8] = if name.is_null() { b"" } else { unsafe { CStr::from_ptr(name) }.to_bytes() };
    let env = ConnectEnv { cfg: &rt.cfg, factory: &rt.factory, log: &rt.log };
    let args = ConnectArgs { secure: secure != 0, name, ip, port };
    table().connect(r as usize, &mut unsafe { ref_view(r) }, &env, args)
}

unsafe extern "C" fn hook_update(r: *mut u8) {
    table().update(r as usize, &mut unsafe { ref_view(r) }, Instant::now(), &rt().log)
}

unsafe extern "C" fn hook_send(r: *mut u8, buf: *const u8, len: i32) -> i32 {
    if buf.is_null() {
        rt().log.error(format!("ProtoSSLSend(ref {:#x}) with a NULL buffer", r as usize));
        return -1;
    }
    // len < 0 means strlen(buf) (0x9da8ce).
    let n = if len < 0 { unsafe { CStr::from_ptr(buf as *const c_char) }.to_bytes().len() } else { len as usize };
    let data = unsafe { std::slice::from_raw_parts(buf, n) };
    table().send(r as usize, &mut unsafe { ref_view(r) }, data, Instant::now(), &rt().log)
}

unsafe extern "C" fn hook_recv(r: *mut u8, buf: *mut u8, len: i32) -> i32 {
    if buf.is_null() || len < 0 {
        rt().log.error(format!("ProtoSSLRecv(ref {:#x}) with buffer {buf:p} length {len}", r as usize));
        return -1;
    }
    let data = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
    table().recv(r as usize, &mut unsafe { ref_view(r) }, data, Instant::now(), &rt().log)
}

unsafe extern "C" fn hook_stat(r: *mut u8, sel: u32, _buf: *mut c_void, _len: i32) -> i32 {
    table().stat(r as usize, &mut unsafe { ref_view(r) }, sel, &rt().log)
}

unsafe extern "C" fn hook_disconnect(r: *mut u8) -> i32 {
    let ours = table().disconnect(r as usize, &mut unsafe { ref_view(r) }, &rt().log);
    match ours {
        Some(v) => v,
        None => {
            let orig: unsafe extern "C" fn(*mut u8) -> i32 =
                unsafe { std::mem::transmute(ORIG_DISCONNECT.load(Ordering::Acquire)) };
            unsafe { orig(r) }
        }
    }
}

unsafe extern "C" fn hook_destroy(r: *mut u8) {
    table().destroy(r as usize);
    let orig: unsafe extern "C" fn(*mut u8) = unsafe { std::mem::transmute(ORIG_DESTROY.load(Ordering::Acquire)) };
    unsafe { orig(r) }
}

/// `GVInitialize` replacement: no Winsock start-up, no socket, no bind; reports failure (its callers ignore
/// the result). It takes the peer address string in EDI, which this never reads.
unsafe extern "C" fn hook_gv_initialize() -> u32 {
    0
}

/// `GVStartup` replacement: no device enumeration and no DirectSound devices, so the caller takes the
/// game's own no-voice branch.
unsafe extern "C" fn hook_gv_startup() {}

/// True when `[ptr, ptr+len)` is committed and readable.
fn readable(ptr: *const u8, len: usize) -> bool {
    let end = ptr as usize + len;
    let mut at = ptr as usize;
    while at < end {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let got = unsafe { VirtualQuery(at as *const c_void, &mut mbi, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };
        if got == 0 || mbi.State != MEM_COMMIT || mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD) != 0 || mbi.Protect == 0 {
            return false;
        }
        at = mbi.BaseAddress as usize + mbi.RegionSize;
    }
    true
}

struct Game {
    image: Image<'static>,
    code: &'static [u8],
    resolved: Resolved,
}

fn wait_for_image(cfg: &Config, log: &Logger) -> Game {
    let base = unsafe { GetModuleHandleW(std::ptr::null()) } as *const u8;
    if base.is_null() || !readable(base, 0x1000) {
        fatal(Some(log), "cannot read the game module's PE headers");
    }
    let headers = unsafe { std::slice::from_raw_parts(base, 0x1000) };
    let (image_base, sections) =
        exe_image::parse_headers(headers).unwrap_or_else(|e| fatal(Some(log), &format!("game module headers: {e}")));
    let sec = sections
        .iter()
        .find(|s| s.name == CODE_SECTION)
        .unwrap_or_else(|| fatal(Some(log), &format!("game module: no {CODE_SECTION} section")))
        .clone();
    let code_ptr = unsafe { base.add(sec.virtual_address as usize) };
    let code_va = base as u32 + sec.virtual_address;
    let deadline = Instant::now() + Duration::from_millis(cfg.signature_wait_ms.into());
    loop {
        let last = if readable(code_ptr, sec.common_len()) {
            let code: &'static [u8] = unsafe { std::slice::from_raw_parts(code_ptr, sec.common_len()) };
            match resolve(code, |o| code_va + o as u32) {
                Ok(resolved) => {
                    // Every section's common span is part of the mapped image for the life of the process.
                    let image = unsafe { Image::from_mapped(base, image_base, sections) };
                    return Game { image, code, resolved };
                }
                Err(e) => Some((e, crate::build_id::sha256_hex(code))),
            }
        } else {
            None
        };
        if Instant::now() >= deadline {
            let detail = match last {
                Some((e, hash)) => format!("{e}\n.text sha256 = {hash}"),
                None => format!("{CODE_SECTION} never became readable"),
            };
            fatal(
                Some(log),
                &format!(
                    "unsupported game build: the ProtoSSL signatures did not resolve within {} ms.\n{detail}",
                    cfg.signature_wait_ms
                ),
            );
        }
        std::thread::sleep(SCAN_INTERVAL);
    }
}

fn install_hooks(img: &Game, voice: &VoiceSites, log: &Logger) {
    let target = |f: ProtoSslFn| img.resolved.va(f) as usize as *mut c_void;
    // Disconnect and Destroy call the original; the SDK writes their trampolines before enabling each hook.
    let hooks: [(ProtoSslFn, *mut c_void, Option<&AtomicUsize>); 7] = [
        (ProtoSslFn::Connect, hook_connect as *mut c_void, None),
        (ProtoSslFn::Disconnect, hook_disconnect as *mut c_void, Some(&ORIG_DISCONNECT)),
        (ProtoSslFn::Destroy, hook_destroy as *mut c_void, Some(&ORIG_DESTROY)),
        (ProtoSslFn::Update, hook_update as *mut c_void, None),
        (ProtoSslFn::Send, hook_send as *mut c_void, None),
        (ProtoSslFn::Recv, hook_recv as *mut c_void, None),
        (ProtoSslFn::Stat, hook_stat as *mut c_void, None),
    ];
    for (f, detour, orig) in hooks {
        unsafe { rt::hook_attach(target(f), detour, orig, f.name()) }.unwrap_or_else(|e| fatal(Some(log), &e));
    }
    let voice_hooks: [(VoiceFn, *mut c_void); 2] = [
        (VoiceFn::Initialize, hook_gv_initialize as *mut c_void),
        (VoiceFn::Startup, hook_gv_startup as *mut c_void),
    ];
    for (f, detour) in voice_hooks {
        unsafe { rt::hook_attach(voice.va(f) as usize as *mut c_void, detour, None, f.name()) }
            .unwrap_or_else(|e| fatal(Some(log), &e));
    }
}

fn module_path(hinst: HMODULE) -> PathBuf {
    let mut buf = vec![0u16; 32768];
    let n = unsafe { GetModuleFileNameW(hinst, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n >= buf.len() {
        fatal(None, "cannot determine the ASI's own path (GetModuleFileNameW failed)");
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..n]))
}

fn init(hinst: usize) {
    let asi = module_path(hinst as HMODULE);
    let dir = asi
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| fatal(None, &format!("ASI path {} has no parent directory", asi.display())));
    let ini = asi.with_extension("ini");
    let text = std::fs::read_to_string(&ini)
        .unwrap_or_else(|e| fatal(None, &format!("cannot read {}: {e}", ini.display())));
    let cfg = Config::parse(&text).unwrap_or_else(|e| fatal(None, &format!("{}: {e}", ini.display())));
    let log_path = dir.join(&cfg.log_file);
    let log = Logger::open(&log_path, Arc::new(|reason: &str| fatal(None, reason)))
        .unwrap_or_else(|e| fatal(None, &format!("cannot open log file {}: {e}", log_path.display())));
    crate::room_key::install(crate::room_key::RoomKeyStore::new(cfg.room_key.clone()))
        .unwrap_or_else(|e| fatal(Some(&log), &e));
    {
        let log = log.clone();
        std::panic::set_hook(Box::new(move |info| {
            log.error(format!("PANIC: {info}"));
            let text = wide(&format!("internal error: {info}"));
            let title = wide(TITLE);
            unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR) };
        }));
    }
    log.info(format!(
        "multiplayer_restored {} starting: ini {}, server https://{}:{}{}, OpenSSL {}, CA bundle {} ({})",
        crate::ASI_VERSION,
        ini.display(),
        cfg.server.host,
        cfg.server.port,
        cfg.server.prefix,
        openssl::version::version(),
        crate::tls::CA_BUNDLE_SHA256,
        crate::tls::CA_BUNDLE_MOZILLA_DATE
    ));

    let sdk = rt::loaded_version();
    rt::compatible(sdk, SDK_BUILT).unwrap_or_else(|e| fatal(Some(&log), &e));
    log.info(format!("m2-sdk.dll {}.{}.{} (built against {SDK_BUILT})", sdk / 10000, sdk / 100 % 100, sdk % 100));

    let img = wait_for_image(&cfg, &log);
    let build = crate::build_id::sha256_hex(img.code);
    for f in ProtoSslFn::ALL {
        log.info(format!("signature {} -> {:#x}", f.name(), img.resolved.va(f)));
    }
    log.info(format!("build .text sha256 {build}"));
    let voice = crate::voice::resolve(&img.image).unwrap_or_else(|e| fatal(Some(&log), &format!("unsupported game build: {e}")));
    for f in VoiceFn::ALL {
        log.info(format!("signature {} -> {:#x}", f.name(), voice.va(f)));
    }
    crate::lua::win::install(&img.image, &log, fatal);

    let connector = crate::tls::mozilla_connector().unwrap_or_else(|e| fatal(Some(&log), &format!("TLS setup: {e}")));
    log.info("TLS connector ready (CA bundle loaded)");
    let lobby = WsLobbyProvider::new(
        WsSettings {
            base: cfg.server.clone(),
            connector: connector.clone(),
            connect_timeout: Duration::from_millis(cfg.connect_timeout_ms.into()),
            io_timeout: Duration::from_millis(cfg.io_timeout_ms.into()),
            poll_interval: Duration::from_millis(cfg.ws_poll_interval_ms.into()),
            idle_timeout: Duration::from_secs(cfg.ws_idle_timeout_secs.into()),
        },
        log.clone(),
    );
    let relays = ShimFactory {
        settings: ShimSettings {
            plan: AliasPlan::Loopback { base: cfg.relay.alias_base, tunnel_port: cfg.relay.alias_tunnel_port },
            game_ip: std::net::Ipv4Addr::LOCALHOST,
            mtu: cfg.relay.dtls_mtu,
            handshake_timeout: Duration::from_millis(cfg.relay.handshake_timeout_ms.into()),
            poll: Duration::from_millis(cfg.relay.poll_interval_ms.into()),
        },
        log: log.clone(),
    };
    let http = HttpsClient::new(
        connector,
        cfg.server.clone(),
        Duration::from_millis(cfg.connect_timeout_ms.into()),
        Duration::from_millis(cfg.io_timeout_ms.into()),
    );
    let api = RestApi::new(http);
    let worker = Worker::spawn(move |req| api.execute(req))
        .unwrap_or_else(|e| fatal(Some(&log), &format!("cannot start the worker thread: {e}")));
    let account: Arc<dyn crate::account::StoredAccount> =
        Arc::new(crate::account::GameIni::of_main_module().unwrap_or_else(|e| fatal(Some(&log), &format!("stored account: {e}"))));
    log.info(format!("stored account: {}", account.describe()));
    let session = crate::session::new_slot();
    let lobby: Arc<dyn LobbyProvider> = Arc::new(lobby);
    crate::account::install(crate::account::Logout::new(account.clone(), session.clone(), lobby.clone()))
        .unwrap_or_else(|e| fatal(Some(&log), &e));
    let factory = RuntimeFactory {
        settings: Arc::new(FeslSettings::from_config(&cfg, &build)),
        theater: Arc::new(TheaterSettings {
            activity_timeout_secs: cfg.theater_activity_timeout_secs,
            keepalive: Duration::from_secs(cfg.theater_keepalive_interval_secs.into()),
            lobby_name: cfg.lobby_name.clone(),
            relay_close_grace: Duration::from_millis(cfg.relay.close_grace_ms.into()),
        }),
        worker,
        session,
        account,
        lobby,
        relays: Arc::new(relays),
        log: log.clone(),
    };
    if RUNTIME.set(Runtime { cfg, log: log.clone(), factory, table: Mutex::new(Table::new()) }).is_err() {
        fatal(Some(&log), "runtime initialised twice");
    }
    log.info("runtime ready (worker thread, connection table)");
    install_hooks(&img, &voice, &log);
    log.info("ProtoSSL detours installed: Connect Disconnect Destroy Update Send Recv Stat");
    log.info("GameSpy Voice disabled (GVInitialize, GVStartup detoured); use external voice chat");
}

/// # Safety
/// Called by the Windows loader.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(hinst: HMODULE, reason: u32, _reserved: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        unsafe { DisableThreadLibraryCalls(hinst) };
        let h = hinst as usize;
        // The thread starts running after the loader lock is released.
        if std::thread::Builder::new().name("mp-restored-init".into()).spawn(move || init(h)).is_err() {
            return 0;
        }
    }
    1
}
