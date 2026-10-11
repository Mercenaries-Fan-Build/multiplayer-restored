//! `multiplayer_restored.asi` — Mercenaries 2 multiplayer client.
//!
//! The ASI replaces the game's ProtoSSL entry points (the only TCP path the game has,
//! `docs/reverse_engineer/multiplayer_rewrite_re.md` §4) with virtual connections served locally: the
//! game's FESL protocol is answered in-process by [`fesl::FeslAdapter`], which talks to the multiplayer
//! server over HTTPS ([`http`]) on a worker thread ([`worker`]). Module map:
//!
//! * game image: [`pe`], [`signature`], [`build_id`];
//! * ProtoSSL contract: [`protossl`] (ref layout, state values, Send/Recv/Stat return codes) and
//!   [`vconn`] (connection classification + per-ref virtual connection table);
//! * services: [`fesl`] (+ [`errors`] for ApiError → FESL error codes, [`curtime`]) and [`theater`];
//! * backend: [`http`], [`tls`], [`worker`], [`session`]; after login the lobby WebSocket ([`lobby`],
//!   [`ws`]) and, per game, the DTLS relay shim ([`relay`]) that carries gameplay and voice UDP;
//! * runtime: [`config`], [`log`], [`m2sdk`] (the shared m2-sdk layer every detour goes through), and the
//!   Windows-only hook layer in `win`.

pub mod build_id;
pub mod config;
pub mod curtime;
pub mod errors;
pub mod fesl;
pub mod http;
pub mod lobby;
pub mod log;
pub mod lua;
pub mod m2sdk;
pub mod pe;
pub mod protossl;
pub mod relay;
pub mod room_key;
pub mod session;
pub mod signature;
pub mod theater;
pub mod tls;
pub mod vconn;
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
