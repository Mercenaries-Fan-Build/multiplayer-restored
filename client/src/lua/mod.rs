//! The `Mp` Lua namespace: native functions the game's own Lua (the front end's shell scripts and
//! gameplay alike) can call to read and change client state the original game never had.
//!
//! How it gets into the game: m2-sdk.dll's Lua host detours the script host's namespace walker and
//! registers every namespace mods add (`m2_lua_add_namespace`) on each `lua_State` the host creates,
//! after the game's own namespaces and before any script of that state runs
//! (`docs/reverse_engineer/multiplayer_menu_re.md` §6 has the walker's role). The bindings are plain
//! `lua_CFunction`s that read arguments and push results through the SDK's `m2_lua_*` exports.
//!
//! Module map: [`signature`] (the account buffers `Mp.Logout` empties), [`bindings`] (what each `Mp`
//! function does, over [`mercs2_formats::mod_runtime::lua::Lua`]), and the Windows-only entry points and
//! registration in `win`.

pub mod bindings;
pub mod signature;

#[cfg(windows)]
pub mod win;
