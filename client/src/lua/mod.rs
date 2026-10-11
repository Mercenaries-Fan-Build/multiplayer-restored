//! The `Mp` Lua namespace: native functions the game's own Lua (the front end's shell scripts and
//! gameplay alike) can call to read and change client state the original game never had.
//!
//! How it gets into the game (evidence: `docs/reverse_engineer/multiplayer_menu_re.md` §6):
//!
//! * The engine has **one script host**, a static singleton whose constructor stores its vtable and
//!   publishes it in a global ([`signature::LuaFn::ScriptHostCtor`]). Its init method
//!   ([`signature::LuaFn::ScriptHostInit`]) runs only while the host's `initialised` byte (`+0xC42`) is
//!   clear: it creates a fresh `lua_State`, stores it at `+0x10`, and calls the namespace walker
//!   ([`signature::LuaFn::RegisterNamespaces`]) — the function that registers every engine namespace
//!   (`Sys`, `Net`, `Gui`, … from the `.data` registry) on that state. Its shutdown method closes the
//!   state and clears the byte. No script runs on a state before the walker has returned.
//! * The ASI detours the walker. After the game's own namespaces are registered, the detour registers
//!   `Mp` on the same state with the game's `luaL_register` ([`signature::LuaFn::LuaLRegister`]), so
//!   `Mp` exists in every Lua state the host ever creates — the front end's and gameplay's — before any
//!   script of that state can run.
//! * The bindings are plain `lua_CFunction`s (cdecl, `L` on the stack — the calling convention of every
//!   engine binding, e.g. `Net.IsOnlineConnected` at `0x005CAD10`). Arguments are read and results
//!   pushed through the 32-bit Lua 5.1 stack layout ([`state`]); strings are created with the game's
//!   `luaS_newlstr` and errors are raised with its `luaG_errormsg`.
//!
//! Module map: [`signature`] (locating the six code sites), [`state`] (the stack layout and value
//! marshalling over a [`state::Vm`]), [`bindings`] (what each `Mp` function does), and the Windows-only
//! hook layer in `win`.

pub mod bindings;
pub mod signature;
pub mod state;

#[cfg(windows)]
pub mod win;
