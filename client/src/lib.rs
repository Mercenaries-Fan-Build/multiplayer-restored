//! `multiplayer_restored.asi` — Mercenaries 2 multiplayer client.
//!
//! The ASI replaces the game's ProtoSSL entry points (the only TCP path the game has,
//! `docs/reverse_engineer/multiplayer_rewrite_re.md` §4) with virtual connections served locally: the
//! game's FESL protocol is answered in-process by [`fesl::FeslAdapter`], which talks to the multiplayer
//! server over HTTPS (the shared `mercs2_https` crate) on a worker thread ([`worker`]). Module map:
//!
//! * game image: [`signature`], [`build_id`], and [`voice`], the GameSpy Voice functions detoured so
//!   in-game voice never starts (PE parsing and pattern scanning are `mercs2_formats`');
//! * ProtoSSL contract: [`protossl`] (ref layout, state values, Send/Recv/Stat return codes) and
//!   [`vconn`] (connection classification + per-ref virtual connection table);
//! * services: [`fesl`] (+ [`errors`] for ApiError → FESL error codes, [`curtime`]) and [`theater`];
//! * backend: `mercs2_https` (REST client and TLS policy), [`worker`], [`session`]; after login the lobby
//!   WebSocket ([`lobby`], [`ws`]) and, per game, the DTLS relay shim ([`relay`]) that carries gameplay UDP;
//! * for other ASIs: [`session_export`], who is signed in, behind the `mr_session_v1` C export (never the token);
//! * the game's leaderboards and the functions PC never registered that go with them: [`leaderboard`]
//!   (`Net.LeaderboardGetScore`, `Net.LeaderboardPushScore`), [`net`] (`Net.GetUserName`) and [`cheats`]
//!   (`Pg.SetCheatsUsed`, `Pg.WereCheatsUsed`); [`registry`] lists every Lua name the ASI adds;
//! * runtime: [`config`], [`log`], the Lua namespaces ([`lua`]), and the Windows-only hook layer in
//!   `win`. Every detour and the Lua host go through m2-sdk.dll, the runtime every mod shares
//!   (`mercs2_formats::mod_runtime`).

pub mod account;
pub mod build_id;
pub mod cheats;
pub mod config;
pub mod curtime;
pub mod errors;
pub mod fesl;
pub mod leaderboard;
pub mod lobby;
pub mod log;
pub mod lua;
pub mod net;
pub mod protossl;
pub mod registry;
pub mod relay;
pub mod room_key;
pub mod session;
pub mod session_export;
pub mod signature;
pub mod theater;
pub mod vconn;
pub mod voice;
pub mod worker;
pub mod ws;

#[cfg(windows)]
mod win;

#[cfg(test)]
mod testdata;
#[cfg(test)]
mod testserver;

/// The ASI's version string (`ClientInfo::asi_version`).
pub const ASI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The `User-Agent` of every REST request.
pub fn user_agent() -> String {
    format!("multiplayer_restored/{ASI_VERSION}")
}
