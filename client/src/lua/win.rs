//! Windows-only: the `Mp` namespace's `lua_CFunction` entry points and its registration through
//! m2-sdk.dll.
//!
//! [`install`] runs on the ASI's start-up thread. It finds the game's account buffers
//! ([`super::signature::resolve`]), installs the SDK's Lua host (`m2_lua_install`, idempotent: whichever mod
//! calls it first installs it), and adds `Mp` with `m2_lua_add_namespace`: the SDK registers it on every
//! state the script host creates, before any script of that state runs, and on any state it captures that
//! already existed. Every failure is fatal through the caller's `fatal` (log, message box, exit).
//!
//! Raising a Lua error `longjmp`s over the Rust frames of the binding (`m2_lua_raise`); the bindings drop
//! every owned value before they raise ([`game::call`] leaks only the message).

use std::ffi::c_void;
use std::sync::OnceLock;

use mercs2_formats::exe_image::Image;
use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery};
use mercs2_formats::mod_runtime::lua::game;
use mercs2_formats::mod_runtime::{self as rt, LuaReg};

use super::bindings::{self, NAMESPACE};
use super::signature::{AccountSites, resolve};
use crate::log::Logger;

/// The caller's fatal-error path: log (to the logger given), show, exit.
pub type Fatal = fn(Option<&Logger>, &str) -> !;

struct Ctx {
    account: AccountSites,
    log: Logger,
}

static CTX: OnceLock<Ctx> = OnceLock::new();

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
    CTX.get().expect("the Mp bindings run only after install() stored their context")
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

const fn reg(name: &'static std::ffi::CStr, f: rt::LuaCFunction) -> LuaReg {
    LuaReg { name: name.as_ptr(), func: Some(f) }
}

static MP_LIB: [LuaReg; 4] = [
    reg(c"GetRoomKey", mp_get_room_key),
    reg(c"SetRoomKey", mp_set_room_key),
    reg(c"Logout", mp_logout),
    LuaReg { name: std::ptr::null(), func: None },
];

/// Find the account buffers in `img` (the mapped game image), then add `Mp` to every Lua state.
pub fn install(img: &Image, log: &Logger, fatal: Fatal) {
    let account = resolve(img).unwrap_or_else(|e| fatal(Some(log), &format!("unsupported game build: {e}")));
    log.info(format!(
        "signature {} -> {:#x} (account name {:#x}, password {:#x})",
        super::signature::ACCOUNT_CLEAR_NAME,
        account.clear,
        account.name,
        account.password
    ));
    if CTX.set(Ctx { account, log: log.clone() }).is_err() {
        fatal(Some(log), "the Mp bindings were installed twice");
    }
    rt::lua_install().unwrap_or_else(|e| fatal(Some(log), &format!("m2-sdk.dll's Lua host: {e}")));
    rt::lua_add_namespace(c"Mp", &MP_LIB).unwrap_or_else(|e| fatal(Some(log), &format!("adding {NAMESPACE}: {e}")));
    log.info(format!("Lua namespace {NAMESPACE} (GetRoomKey, SetRoomKey, Logout) added through m2-sdk.dll"));
}
