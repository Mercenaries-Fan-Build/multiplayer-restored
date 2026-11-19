//! Windows-only: the `lua_CFunction` entry points of the `Mp` namespace and of the `Net` and `Pg` functions
//! the game's leaderboards use, and their registration through m2-sdk.dll.
//!
//! [`install`] runs on the ASI's start-up thread. It finds the game's account buffers
//! ([`super::signature::resolve`]) and the save-record singleton's pointer ([`crate::cheats`]), installs the
//! SDK's Lua host (`m2_lua_install`, idempotent: whichever mod calls it first installs it), and adds `Mp`, and
//! the leaderboard functions to the engine's own `Net` and `Pg` tables, with `m2_lua_add_namespace`: the SDK
//! registers them on every state the script host creates, right after the engine's own namespaces and before
//! any script of that state runs, and Lua 5.1's `luaL_register` adds to a global table that already exists
//! rather than replacing it. A state callback checks, on every state scripts run on, that the engine's own
//! functions are still there beside the added ones (and on a new load cycle drops the leaderboard callbacks
//! held in the old state's registry); a tick callback hands finished leaderboard requests to their Lua
//! callbacks on the game thread. [`start_leaderboards`] connects the leaderboards to the worker thread once it
//! runs. Every failure is fatal through the caller's `fatal` (log, message box, exit).
//!
//! Raising a Lua error `longjmp`s over the Rust frames of the binding (`m2_lua_raise`); the bindings drop
//! every owned value before they raise ([`game::call`] leaks only the message).

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use mercs2_formats::exe_image::Image;
use mercs2_formats::lua_stack::OFF_GLOBAL;
use mercs2_formats::mod_runtime::lua::{Lua, Ret, game};
use mercs2_formats::mod_runtime::{self as rt, LuaReg, ffi};
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery};

use super::bindings::{self, NAMESPACE};
use super::signature::{AccountSites, resolve};
use crate::cheats::{self, CheatsFlag};
use crate::leaderboard::{self, Env, Job, Leaderboards, LuaRefs};
use crate::log::Logger;
use crate::session::{Lookup, SessionSlot};
use crate::worker::{Backend, JobId, WorkerHandle};

/// The caller's fatal-error path: log (to the logger given), show, exit.
pub type Fatal = fn(Option<&Logger>, &str) -> !;

struct Ctx {
    account: AccountSites,
    /// The global that points at the save-record singleton ([`cheats::resolve_profile_pointer`]).
    profile_pointer: u32,
    session: SessionSlot,
    log: Logger,
}

static CTX: OnceLock<Ctx> = OnceLock::new();

/// What the state check runs: each engine function beside each added one.
const STATE_CHECK: &[u8] = b"return type(Net.IsServer), type(Net.GetUserName), type(Net.LeaderboardGetScore), \
    type(Net.LeaderboardPushScore), type(Pg.SaveGame), type(Pg.SetCheatsUsed), type(Pg.WereCheatsUsed)";
const STATE_CHECK_EXPECT: &[u8] =
    b"[ok]\t\"function\"\t\"function\"\t\"function\"\t\"function\"\t\"function\"\t\"function\"\t\"function\"";

/// The leaderboards' callback slots.
static LEADERBOARDS: Mutex<Leaderboards> = Mutex::new(Leaderboards::new());
/// The worker handle the leaderboard requests go through, and each queued request by its job id.
static BOARD_WORKER: OnceLock<Mutex<BoardWorker>> = OnceLock::new();
/// How many leaderboard requests are queued and not yet delivered: the tick's lock-free fast path.
static OUTSTANDING: AtomicUsize = AtomicUsize::new(0);

struct BoardWorker {
    handle: WorkerHandle,
    next: JobId,
    jobs: HashMap<JobId, Job>,
}

/// True when `[addr, addr+len)` is committed and readable.
fn readable(addr: u32, len: u32) -> bool {
    let end = addr as usize + len as usize;
    let mut at = addr as usize;
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

fn ctx() -> &'static Ctx {
    CTX.get().expect("the Lua bindings run only after install() stored their context")
}

/// A leaderboard line (`[*] …` or `[!] …`) at its level.
fn board_log(line: &str) {
    let log = &ctx().log;
    match line.strip_prefix("[!] ") {
        Some(rest) => log.error(rest),
        None => log.info(line.strip_prefix("[*] ").unwrap_or(line)),
    }
}

/// Log a binding's outcome and hand it to the game.
fn logged(what: &str, ret: Ret) -> Ret {
    match &ret {
        Ret::Values(n) => board_log(&format!("[*] Lua {what} -> {n} value(s)")),
        Ret::Raise(m) => board_log(&format!("[!] Lua {what} raised: {m}")),
    }
    ret
}

unsafe extern "C" fn mp_get_room_key(l: *mut c_void) -> i32 {
    let c = ctx();
    unsafe { game::call(l, |g| bindings::get_room_key(g, crate::room_key::global(), &c.log)) }
}

unsafe extern "C" fn mp_set_room_key(l: *mut c_void) -> i32 {
    let c = ctx();
    unsafe { game::call(l, |g| bindings::set_room_key(g, crate::room_key::global(), &c.log)) }
}

/// `Mp.Logout` in the game: forget the stored name and end the session ([`crate::account::Logout`]) first, so
/// a name that cannot be removed leaves everything as it was; then empty the game's in-memory account name and
/// password the way its login-failure handler does (`mov byte [buffer], 0`, [`super::signature::ACCOUNT_CLEAR`]).
struct GameLogout<'a>(&'a Ctx);

impl bindings::LogoutAction for GameLogout<'_> {
    fn logout(&self) -> Result<Option<String>, String> {
        let c = self.0;
        let was = crate::account::global()?.run(&c.log)?;
        for addr in [c.account.name, c.account.password] {
            if !readable(addr, 1) {
                return Err(format!("the game's account buffer at {addr:#x} is not mapped"));
            }
            unsafe { std::ptr::write_volatile(addr as usize as *mut u8, 0) };
        }
        c.log.info(format!(
            "logout: emptied the game's account name ({:#x}) and password ({:#x})",
            c.account.name, c.account.password
        ));
        Ok(was)
    }
}

unsafe extern "C" fn mp_logout(l: *mut c_void) -> i32 {
    let c = ctx();
    unsafe { game::call(l, |g| bindings::logout(g, Ok(&GameLogout(c)), &c.log)) }
}

/// The cheats-used byte of the save-record singleton, through the pointer global.
struct ProfileFlag;

impl ProfileFlag {
    fn byte(&self) -> Result<*mut u8, String> {
        let ptr = ctx().profile_pointer;
        let singleton = unsafe { (ptr as usize as *const u32).read_volatile() };
        if singleton == 0 {
            return Err(format!("the save-record singleton's pointer {ptr:#x} holds NULL"));
        }
        Ok(singleton.wrapping_add(cheats::CHEATS_USED) as usize as *mut u8)
    }
}

impl CheatsFlag for ProfileFlag {
    fn read(&self) -> Result<bool, String> {
        Ok(unsafe { self.byte()?.read_volatile() } != 0)
    }
    fn write(&mut self, used: bool) -> Result<(), String> {
        unsafe { self.byte()?.write_volatile(u8::from(used)) };
        Ok(())
    }
}

/// The game's stack with the registry references m2-sdk.dll gives.
struct Refs<'a>(&'a mut game::GameLua);

impl Lua for Refs<'_> {
    fn arg_type(&self, i: i32) -> i32 {
        self.0.arg_type(i)
    }
    fn arg_number(&self, i: i32) -> Option<f64> {
        self.0.arg_number(i)
    }
    fn arg_bool(&self, i: i32) -> Option<bool> {
        self.0.arg_bool(i)
    }
    fn arg_string(&self, i: i32) -> Option<Vec<u8>> {
        self.0.arg_string(i)
    }
    fn arg_object(&self, i: i32) -> Option<u32> {
        self.0.arg_object(i)
    }
    fn push_nil(&mut self) {
        self.0.push_nil()
    }
    fn push_bool(&mut self, b: bool) {
        self.0.push_bool(b)
    }
    fn push_number(&mut self, n: f64) {
        self.0.push_number(n)
    }
    fn push_string(&mut self, s: &[u8]) {
        self.0.push_string(s)
    }
}

/// `L->l_G`, the global state whose registry holds the references (shared by the main thread and every
/// coroutine of it).
///
/// # Safety
/// `l` is a usable `lua_State` (`rt::lua_state_ok`, or the `L` of a running Lua C function).
unsafe fn global_of(l: *mut c_void) -> usize {
    unsafe { (l.cast::<u8>().add(OFF_GLOBAL as usize).cast::<u32>()).read_volatile() as usize }
}

impl LuaRefs for Refs<'_> {
    fn global(&self) -> usize {
        unsafe { global_of(self.0.0) }
    }
    /// `m2_lua_ref` takes a Lua stack index: argument `i` (0-based) is index `i + 1`. 0 is no reference.
    fn ref_arg(&mut self, i: i32) -> Option<i32> {
        let r = unsafe { ffi::m2_lua_ref(self.0.0, i + 1) };
        (r > 0).then_some(r)
    }
    fn unref(&mut self, r: i32) -> bool {
        unsafe { ffi::m2_lua_unref(self.0.0, r) == 1 }
    }
    fn push_ref(&mut self, r: i32) -> bool {
        unsafe { ffi::m2_lua_push_ref(self.0.0, r) == 1 }
    }
    /// No results: m2-sdk.dll has no export to read or pop them.
    fn pcall(&mut self, nargs: i32) -> i32 {
        unsafe { ffi::m2_lua_pcall(self.0.0, nargs, 0) }
    }
}

fn leaderboards() -> MutexGuard<'static, Leaderboards> {
    LEADERBOARDS.lock().expect("panic = abort: the lock is never poisoned")
}

fn board_worker() -> Result<MutexGuard<'static, BoardWorker>, String> {
    let w = BOARD_WORKER.get().ok_or("the worker thread has not started yet (the ASI is still starting up)")?;
    Ok(w.lock().expect("panic = abort: the lock is never poisoned"))
}

/// What the leaderboard bindings reach in the process.
struct WinEnv;

impl Env for WinEnv {
    fn session(&mut self) -> Lookup {
        crate::session::lookup(&ctx().session)
    }
    fn send(&mut self, job: Job) -> Result<(), String> {
        let mut w = board_worker()?;
        let id = w.next;
        w.next += 1;
        let req = job.request();
        w.jobs.insert(id, job);
        OUTSTANDING.fetch_add(1, Ordering::AcqRel);
        w.handle.submit(id, req);
        Ok(())
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn log(&mut self, line: String) {
        board_log(&line);
    }
}

unsafe extern "C" fn net_get_user_name(l: *mut c_void) -> i32 {
    unsafe {
        game::call(l, |g| {
            let session = crate::session::lookup(&ctx().session);
            if let Err(e) = &session {
                board_log(&format!("[!] Net.GetUserName: the session cannot be read ({e}); treated as not signed in"));
            }
            logged("Net.GetUserName()", crate::net::get_user_name(g, &session))
        })
    }
}

unsafe extern "C" fn net_leaderboard_get_score(l: *mut c_void) -> i32 {
    unsafe { game::call(l, |g| logged("Net.LeaderboardGetScore", leaderboards().get_score(&mut Refs(g), &mut WinEnv))) }
}

unsafe extern "C" fn net_leaderboard_push_score(l: *mut c_void) -> i32 {
    unsafe { game::call(l, |g| logged("Net.LeaderboardPushScore", leaderboards().push_score(&mut Refs(g), &mut WinEnv, &ProfileFlag))) }
}

unsafe extern "C" fn pg_set_cheats_used(l: *mut c_void) -> i32 {
    unsafe {
        game::call(l, |g| {
            let what = match g.arg_type(0) {
                rt::lua::TBOOLEAN => format!("Pg.SetCheatsUsed({})", g.arg_bool(0) == Some(true)),
                t => format!("Pg.SetCheatsUsed(<{}>)", rt::lua::type_name(t)),
            };
            logged(&what, cheats::set_cheats_used(g, &mut ProfileFlag))
        })
    }
}

unsafe extern "C" fn pg_were_cheats_used(l: *mut c_void) -> i32 {
    unsafe { game::call(l, |g| logged("Pg.WereCheatsUsed()", cheats::were_cheats_used(g, &ProfileFlag))) }
}

/// Hand finished leaderboard requests to their callbacks, on the state this tick runs on. Every call on a
/// captured state runs this; no outstanding request is the fast path. A reply asked on another global state (an
/// earlier load cycle) is dropped with a line, its references never touched. No lock is held while a callback
/// runs: it may call the leaderboard bindings again.
unsafe extern "C" fn tick(l: *mut c_void, _ud: *mut c_void) {
    if OUTSTANDING.load(Ordering::Acquire) == 0 || !rt::lua_state_ok(l) {
        return;
    }
    let finished: Vec<leaderboard::Done> = {
        let Ok(mut w) = board_worker() else { return };
        let mut out = Vec::new();
        for (id, outcome) in w.handle.poll() {
            match w.jobs.remove(&id) {
                Some(job) => out.push(leaderboard::finish(&job, outcome)),
                None => board_log(&format!("[!] the worker answered leaderboard job {id}, which was never queued")),
            }
            OUTSTANDING.fetch_sub(1, Ordering::AcqRel);
        }
        out
    };
    let g = unsafe { global_of(l) };
    for d in finished {
        let taken = leaderboards().take(g, d, Instant::now(), &mut |x| board_log(&x));
        if let Some(x) = taken {
            let mut lua = game::GameLua(l);
            leaderboard::call(&mut Refs(&mut lua), x, &mut |x| board_log(&x));
        }
    }
}

unsafe extern "C" fn check_state(l: *mut c_void, is_new_cycle: i32, _ud: *mut c_void) {
    // A state m2-sdk.dll announces may be a coroutine of the current global state (is_new_cycle is per
    // lua_State pointer), so the global state decides whether this is a new load cycle.
    let dropped = leaderboards().observe(unsafe { global_of(l) });
    if dropped > 0 {
        board_log(&format!(
            "[*] lua_State {l:p} (new cycle {is_new_cycle}) runs on a new global state: {dropped} leaderboard callback(s) of the old one dropped unreleased"
        ));
    }
    let out = unsafe { rt::lua_exec(l, STATE_CHECK, 512) };
    let text = String::from_utf8_lossy(&out.text).into_owned();
    board_log(&format!("[*] state {l:p} (new cycle {is_new_cycle}): {text}"));
    if out.status != rt::EXEC_OK || !out.text.starts_with(STATE_CHECK_EXPECT) {
        let c = ctx();
        FATAL.get().expect("install() stores the fatal path before it registers the state callback")(
            Some(&c.log),
            &format!(
                "on lua_State {l:p} the engine's Net and Pg functions and this ASI's are not both there ({text}); \
                 registering into the engine's tables did not merge"
            ),
        );
    }
}

static FATAL: OnceLock<Fatal> = OnceLock::new();

const fn reg(name: &'static std::ffi::CStr, f: rt::LuaCFunction) -> LuaReg {
    LuaReg { name: name.as_ptr(), func: Some(f) }
}

const END: LuaReg = LuaReg { name: std::ptr::null(), func: None };
static MP_LIB: [LuaReg; 4] = [reg(c"GetRoomKey", mp_get_room_key), reg(c"SetRoomKey", mp_set_room_key), reg(c"Logout", mp_logout), END];
static NET_LIB: [LuaReg; 4] = [
    reg(c"GetUserName", net_get_user_name),
    reg(c"LeaderboardGetScore", net_leaderboard_get_score),
    reg(c"LeaderboardPushScore", net_leaderboard_push_score),
    END,
];
static PG_LIB: [LuaReg; 3] = [reg(c"SetCheatsUsed", pg_set_cheats_used), reg(c"WereCheatsUsed", pg_were_cheats_used), END];

/// The `(table, field)` names of `(table, rows)`, without the NULL-name row that ends each.
fn registered(tables: &[(&std::ffi::CStr, &[LuaReg])]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (table, rows) in tables {
        for row in rows.iter().take_while(|r| !r.name.is_null()) {
            let field = unsafe { std::ffi::CStr::from_ptr(row.name) };
            out.push((table.to_string_lossy().into_owned(), field.to_string_lossy().into_owned()));
        }
    }
    out.sort();
    out
}

/// Find the account buffers and the save-record singleton's pointer in `img` (the mapped game image), then add
/// `Mp` and the `Net` / `Pg` leaderboard functions to every Lua state. `session` is the one the FESL adapter
/// fills at login.
pub fn install(img: &Image, session: SessionSlot, log: &Logger, fatal: Fatal) {
    let account = resolve(img).unwrap_or_else(|e| fatal(Some(log), &format!("unsupported game build: {e}")));
    log.info(format!(
        "signature {} -> {:#x} (account name {:#x}, password {:#x})",
        super::signature::ACCOUNT_CLEAR_NAME,
        account.clear,
        account.name,
        account.password
    ));
    let profile_pointer =
        cheats::resolve_profile_pointer(img).unwrap_or_else(|e| fatal(Some(log), &format!("unsupported game build: {e}")));
    log.info(format!("save-record singleton pointer {profile_pointer:#x} (cheats flag at +{:#x})", cheats::CHEATS_USED));
    let tables: [(&'static std::ffi::CStr, &'static [LuaReg]); 3] = [(c"Mp", &MP_LIB), (c"Net", &NET_LIB), (c"Pg", &PG_LIB)];
    let mut declared: Vec<(String, String)> = crate::registry::ADDED.iter().map(|(t, f)| (t.to_string(), f.to_string())).collect();
    declared.sort();
    if registered(&tables) != declared {
        fatal(Some(log), &format!("the registered names {:?} are not registry::ADDED {declared:?}", registered(&tables)));
    }
    if CTX.set(Ctx { account, profile_pointer, session, log: log.clone() }).is_err() || FATAL.set(fatal).is_err() {
        fatal(Some(log), "the Lua bindings were installed twice");
    }
    rt::lua_install().unwrap_or_else(|e| fatal(Some(log), &format!("m2-sdk.dll's Lua host: {e}")));
    for (table, rows) in tables {
        rt::lua_add_namespace(table, rows).unwrap_or_else(|e| fatal(Some(log), &format!("adding to {}: {e}", table.to_string_lossy())));
    }
    unsafe { rt::lua_on_state(check_state, std::ptr::null_mut()) }.unwrap_or_else(|e| fatal(Some(log), &e));
    unsafe { rt::lua_on_tick(tick, std::ptr::null_mut()) }.unwrap_or_else(|e| fatal(Some(log), &e));
    log.info(format!(
        "Lua namespace {NAMESPACE} (GetRoomKey, SetRoomKey, Logout) and {} added through m2-sdk.dll",
        ["Net.GetUserName", "Net.LeaderboardGetScore", "Net.LeaderboardPushScore", "Pg.SetCheatsUsed", "Pg.WereCheatsUsed"].join(", ")
    ));
}

/// Send the leaderboards' requests through `handle` of the worker thread from now on.
pub fn start_leaderboards(handle: WorkerHandle, log: &Logger, fatal: Fatal) {
    if BOARD_WORKER.set(Mutex::new(BoardWorker { handle, next: 1, jobs: HashMap::new() })).is_err() {
        fatal(Some(log), "the leaderboards' worker handle was set twice");
    }
    log.info("leaderboards ready (worker thread)");
}
