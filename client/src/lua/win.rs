//! Windows-only: the namespace-walker detour, `Mp` registration, and the `lua_CFunction` entry points.
//!
//! [`install`] runs on the ASI's start-up thread after the ProtoSSL detours are in place. It resolves
//! the six sites ([`super::signature::resolve`]), detours the walker, and then checks that the script
//! host has not already created its `lua_State` without us: if the host's `initialised` byte is set and
//! the detour has not registered `Mp` within [`LATE_INIT_GRACE`] (the case of an init already past the
//! walker), the state that exists will never have `Mp`, and start-up fails. Every failure is fatal
//! through the caller's `fatal` (log, message box, exit).
//!
//! Calling conventions (from the disassembly, see [`super::signature`]): the walker is
//! `__stdcall (host)`; `luaL_register` takes `ECX = L`, `EAX = libname` and the `luaL_Reg*` pushed,
//! caller pops; `luaS_newlstr` is cdecl `(L, str, len)`; `luaG_errormsg` takes `EAX = L` and does not
//! return (`longjmp` to the enclosing `lua_pcall`).
//!
//! Raising a Lua error `longjmp`s over the Rust frames of the binding. MSVC's `longjmp` unwinds only
//! the SEH frames registered on the way, and Rust frames register none, so the jump restores the
//! registers and leaves them; the bindings therefore drop every owned value before they raise
//! ([`raise`] takes nothing that needs dropping).

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use minhook::MinHook;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery};

use super::bindings::{self, NAMESPACE, Ret};
use super::signature::{HOST_INITIALISED, HOST_LUA_STATE, LuaFn, LuaSites, resolve};
use super::state::{L_TOP, LUA_TTABLE, Stack, TVALUE_SIZE, TVALUE_TT, Vm};
use crate::log::Logger;

/// The caller's fatal-error path: log (to the logger given), show, exit.
pub type Fatal = fn(Option<&Logger>, &str) -> !;

/// How long an init that is already running when the detour goes in may take to reach the walker.
const LATE_INIT_GRACE: Duration = Duration::from_secs(2);

struct Ctx {
    sites: LuaSites,
    log: Logger,
    fatal: Fatal,
}

static CTX: OnceLock<Ctx> = OnceLock::new();
static ORIG_WALKER: AtomicUsize = AtomicUsize::new(0);
/// How many `lua_State`s `Mp` has been registered on.
static REGISTERED: AtomicU32 = AtomicU32::new(0);

fn ctx() -> &'static Ctx {
    CTX.get().expect("the Lua detour runs only after install() stored its context")
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

/// The game process as a [`Vm`]: addresses are this process's (i686: 32-bit).
struct Process {
    newlstr: u32,
}

impl Vm for Process {
    fn read_u32(&self, addr: u32) -> u32 {
        unsafe { std::ptr::read_unaligned(addr as usize as *const u32) }
    }
    fn write_u32(&mut self, addr: u32, value: u32) {
        unsafe { std::ptr::write_unaligned(addr as usize as *mut u32, value) }
    }
    fn read_bytes(&self, addr: u32, len: u32) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(addr as usize as *const u8, len as usize) }.to_vec()
    }
    fn new_string(&mut self, l: u32, bytes: &[u8]) -> u32 {
        let f: unsafe extern "C" fn(u32, *const u8, u32) -> u32 = unsafe { std::mem::transmute(self.newlstr as usize) };
        unsafe { f(l, bytes.as_ptr(), bytes.len() as u32) }
    }
}

/// `luaL_Reg`: `{ const char *name; lua_CFunction func; }`, NULL-terminated.
#[repr(C)]
struct Reg {
    name: *const std::ffi::c_char,
    func: Option<unsafe extern "C" fn(u32) -> i32>,
}

struct RegTable([Reg; 3]);
// SAFETY: the table is immutable and its pointers are to 'static data and functions.
unsafe impl Sync for RegTable {}

static MP_LIB: RegTable = RegTable([
    Reg { name: c"GetRoomKey".as_ptr(), func: Some(mp_get_room_key) },
    Reg { name: c"SetRoomKey".as_ptr(), func: Some(mp_set_room_key) },
    Reg { name: std::ptr::null(), func: None },
]);

static MP_NAME: &std::ffi::CStr = c"Mp";

/// Push the message, then `luaG_errormsg(L)`; never returns.
///
/// # Safety
/// `l` is the running `lua_State` of a binding call, and the caller holds no value that needs dropping.
unsafe fn raise(l: u32, message: String) -> ! {
    let c = ctx();
    {
        let mut vm = Process { newlstr: c.sites.va(LuaFn::LuaSNewLStr) };
        Stack::new(&mut vm, l).push_string(message.as_bytes());
    }
    drop(message);
    let errormsg = c.sites.va(LuaFn::LuaGErrorMsg);
    unsafe {
        std::arch::asm!(
            "call {f}",
            f = in(reg) errormsg,
            in("eax") l,
            options(noreturn)
        )
    }
}

fn dispatch(
    l: u32,
    f: fn(&mut Stack<'_, Process>, Result<&crate::room_key::RoomKeyStore, String>, &Logger) -> Ret,
) -> i32 {
    let c = ctx();
    let ret = {
        let mut vm = Process { newlstr: c.sites.va(LuaFn::LuaSNewLStr) };
        let mut stack = Stack::new(&mut vm, l);
        f(&mut stack, crate::room_key::global(), &c.log)
    };
    match ret {
        Ret::Values(n) => n,
        Ret::Raise(message) => unsafe { raise(l, message) },
    }
}

unsafe extern "C" fn mp_get_room_key(l: u32) -> i32 {
    dispatch(l, bindings::get_room_key)
}

unsafe extern "C" fn mp_set_room_key(l: u32) -> i32 {
    dispatch(l, bindings::set_room_key)
}

/// Register `Mp` on `l` with the game's `luaL_register`, then pop the table it leaves on the stack.
fn register(c: &Ctx, l: u32) {
    let mut vm = Process { newlstr: c.sites.va(LuaFn::LuaSNewLStr) };
    let top_before = vm.read_u32(l + L_TOP);
    let func = c.sites.va(LuaFn::LuaLRegister);
    let table = MP_LIB.0.as_ptr() as u32;
    let name = MP_NAME.as_ptr() as u32;
    unsafe {
        std::arch::asm!(
            "push {table}",
            "call {func}",
            "add esp, 4",
            table = in(reg) table,
            func = in(reg) func,
            inout("ecx") l => _,
            inout("eax") name => _,
            out("edx") _,
            clobber_abi("C"),
        )
    }
    let top = vm.read_u32(l + L_TOP);
    let tag = if top == top_before + TVALUE_SIZE { vm.read_u32(top_before + TVALUE_TT) } else { u32::MAX };
    if tag != LUA_TTABLE {
        (c.fatal)(Some(&c.log), &format!(
            "luaL_register({NAMESPACE}) on lua_State {l:#x} left the stack top at {top:#x} (was {top_before:#x}) \
             with tag {tag:#x}; expected exactly one table"
        ));
    }
    vm.write_u32(l + L_TOP, top_before);
    let n = REGISTERED.fetch_add(1, Ordering::AcqRel) + 1;
    c.log.info(format!(
        "registered Lua namespace {NAMESPACE} (GetRoomKey, SetRoomKey) on lua_State {l:#x} (script-host state #{n})"
    ));
}

unsafe extern "stdcall" fn hook_register_namespaces(host: u32) {
    let orig: unsafe extern "stdcall" fn(u32) = unsafe { std::mem::transmute(ORIG_WALKER.load(Ordering::Acquire)) };
    unsafe { orig(host) };
    let c = ctx();
    let l = Process { newlstr: 0 }.read_u32(host + HOST_LUA_STATE);
    if l == 0 {
        (c.fatal)(Some(&c.log), &format!("the script host {host:#x} has no lua_State at +{HOST_LUA_STATE:#x} after its namespaces were registered"));
    }
    register(c, l);
}

/// Resolve the sites in `code` (the mapped `.text`), detour the walker, and verify the host had no
/// `lua_State` we missed.
pub fn install(code: &'static [u8], log: &Logger, fatal_path: Fatal) {
    let fatal = |m: &str| -> ! { fatal_path(Some(log), m) };
    let text_va = code.as_ptr() as u32;
    let read = |va: u32| readable(va, 4).then(|| Process { newlstr: 0 }.read_u32(va));
    let sites = resolve(code, |o| text_va + o as u32, read).unwrap_or_else(|e| fatal(&format!("unsupported game build: {e}")));
    for f in LuaFn::ALL {
        log.info(format!("lua signature {} -> {:#x}", f.name(), sites.va(f)));
    }
    log.info(format!("lua script host at {:#x}", sites.host()));
    if CTX.set(Ctx { sites, log: log.clone(), fatal: fatal_path }).is_err() {
        fatal("Lua bindings installed twice");
    }
    let walker = sites.va(LuaFn::RegisterNamespaces) as usize as *mut c_void;
    let tramp = unsafe { MinHook::create_hook(walker, hook_register_namespaces as *mut c_void) }
        .unwrap_or_else(|e| fatal(&format!("MinHook create_hook ScriptHostRegisterNamespaces at {walker:p}: {e:?}")));
    ORIG_WALKER.store(tramp as usize, Ordering::Release);
    unsafe { MinHook::enable_hook(walker) }
        .unwrap_or_else(|e| fatal(&format!("MinHook enable_hook ScriptHostRegisterNamespaces at {walker:p}: {e:?}")));
    log.info(format!("Lua detour installed: ScriptHostRegisterNamespaces at {walker:p}"));

    let flag = sites.host() + HOST_INITIALISED;
    if !readable(flag, 1) {
        fatal(&format!("the script host's initialised byte at {flag:#x} is not readable"));
    }
    let initialised = unsafe { std::ptr::read_volatile(flag as usize as *const u8) } != 0;
    if initialised {
        let deadline = Instant::now() + LATE_INIT_GRACE;
        while REGISTERED.load(Ordering::Acquire) == 0 {
            if Instant::now() >= deadline {
                fatal(&format!(
                    "the game created its Lua state before the multiplayer ASI could hook it (script host {:#x} \
                     was already initialised), so the Lua namespace {NAMESPACE} would be missing. Load the ASI \
                     earlier (it must be loaded before the front end starts).",
                    sites.host()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    log.info(format!(
        "script host {} a Lua state at hook time; {NAMESPACE} is registered on every state it creates",
        if initialised { "already had" } else { "had not yet created" }
    ));
}
