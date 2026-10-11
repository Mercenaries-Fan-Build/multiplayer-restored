//! The lobby: everything after login that goes through the server's WebSocket (`mercs2_mp_api::ws`).
//!
//! Adapters (FESL `pnow`, the Theater adapter) run on the game thread and must never block, so they talk to
//! the lobby through a [`Lobby`] handle: [`Lobby::request`] queues a request and returns its id, and
//! [`Lobby::poll`] returns the replies (and, for the one handle that subscribed, the pushes) that arrived
//! since the last poll. The WebSocket itself runs on its own thread ([`crate::ws`]).
//!
//! Lifecycle: FESL Login success calls [`LobbyProvider::start`] with the new session, which opens the
//! WebSocket with that session's bearer token (replacing any earlier one). If the WebSocket ends for any
//! reason, every handle's `poll`/`request` returns `Err(reason)` from then on — the adapters turn that into
//! a failed virtual connection, which the game shows as a disconnect. The lobby is never reopened
//! silently: only a new FESL Login starts a new one.

use mercs2_mp_api::ApiError;
use mercs2_mp_api::ws::{Push, Request, Response};

use crate::session::LoggedIn;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LobbyEvent {
    /// The answer to the request with this id.
    Reply { id: u64, result: Result<Response, ApiError> },
    /// An unsolicited server push (only delivered to the handle that subscribed to pushes).
    Push(Push),
}

/// One adapter's view of the lobby.
pub trait Lobby: Send {
    /// Queue a request; `Err` names why the lobby cannot take it (it ended).
    fn request(&mut self, req: Request) -> Result<u64, String>;
    /// Everything that arrived for this handle; `Err` once the lobby has ended.
    fn poll(&mut self) -> Result<Vec<LobbyEvent>, String>;
}

/// Owns the process's lobby connection.
pub trait LobbyProvider: Send + Sync {
    /// Called when FESL Login succeeds: opens the lobby for this session, replacing any earlier one.
    fn start(&self, session: &LoggedIn) -> Result<(), String>;
    /// A new handle on the current lobby. With `pushes`, this handle receives every server push from now
    /// on (taking over from any earlier subscriber). `Err` when there is no lobby (no login yet) or it ended.
    fn handle(&self, pushes: bool) -> Result<Box<dyn Lobby>, String>;
    /// Close the current lobby (`Mp.Logout`). No lobby open is not an error.
    fn end(&self, why: &str) -> Result<(), String>;
}

/// Short description of a request for logs (never includes room keys).
pub fn describe(req: &Request) -> String {
    match req {
        Request::Ping => "ping".into(),
        Request::GamesList { joinable_only, room_key } => {
            format!("games.list (joinable_only {joinable_only}, room key {})", if room_key.is_some() { "set" } else { "none" })
        }
        Request::GamesGet { game_id, .. } => format!("games.get {}", game_id.0),
        Request::GamesCreate(c) => format!("games.create {:?} (max {})", c.name, c.max_players),
        Request::GamesUpdate(u) => format!("games.update {}", u.game_id.0),
        Request::GamesClose { game_id } => format!("games.close {}", game_id.0),
        Request::GamesJoin { game_id, .. } => format!("games.join {}", game_id.0),
        Request::JoinRespond { join_id, allowed, .. } => format!("join.respond {join_id} allowed={allowed}"),
        Request::PlayerEntered { game_id, user_id } => format!("players.enter {} user {}", game_id.0, user_id.0),
        Request::PlayerLeft { game_id, user_id } => format!("players.leave {} user {}", game_id.0, user_id.0),
        Request::FriendsList => "friends.list".into(),
        Request::FriendsAdd { username } => format!("friends.add {username:?}"),
        Request::FriendsRemove { user_id } => format!("friends.remove {}", user_id.0),
        Request::StatsGet { owner, .. } => format!("stats.get {}", owner.0),
        Request::StatsUpdate { entries } => format!("stats.update ({} entries)", entries.len()),
        Request::UsersLookup { .. } => "users.lookup".into(),
    }
}

#[cfg(test)]
pub mod fake {
    //! A scripted lobby for adapter tests: the test sees every request and decides every reply and push.

    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Default)]
    pub struct Script {
        pub sent: Vec<(u64, Request)>,
        pub events: Vec<LobbyEvent>,
        pub dead: Option<String>,
        next: u64,
    }

    #[derive(Clone, Default)]
    pub struct FakeLobby(pub Arc<Mutex<Script>>);

    impl FakeLobby {
        /// The last request sent and its id.
        pub fn last(&self) -> (u64, Request) {
            self.0.lock().unwrap().sent.last().cloned().expect("no request was sent")
        }
        pub fn take_sent(&self) -> Vec<(u64, Request)> {
            std::mem::take(&mut self.0.lock().unwrap().sent)
        }
        pub fn reply(&self, id: u64, result: Result<Response, ApiError>) {
            self.0.lock().unwrap().events.push(LobbyEvent::Reply { id, result });
        }
        pub fn push(&self, p: Push) {
            self.0.lock().unwrap().events.push(LobbyEvent::Push(p));
        }
        pub fn kill(&self, why: &str) {
            self.0.lock().unwrap().dead = Some(why.into());
        }
    }

    impl Lobby for FakeLobby {
        fn request(&mut self, req: Request) -> Result<u64, String> {
            let mut s = self.0.lock().unwrap();
            if let Some(d) = &s.dead {
                return Err(d.clone());
            }
            s.next += 1;
            let id = s.next;
            s.sent.push((id, req));
            Ok(id)
        }
        fn poll(&mut self) -> Result<Vec<LobbyEvent>, String> {
            let mut s = self.0.lock().unwrap();
            if let Some(d) = &s.dead {
                return Err(d.clone());
            }
            Ok(std::mem::take(&mut s.events))
        }
    }

    /// Provider handing out one shared [`FakeLobby`]; records `start` calls.
    #[derive(Default)]
    pub struct FakeProvider {
        pub lobby: FakeLobby,
        pub started: Mutex<Vec<String>>,
    }

    impl LobbyProvider for FakeProvider {
        fn start(&self, session: &LoggedIn) -> Result<(), String> {
            self.started.lock().unwrap().push(session.token.clone());
            Ok(())
        }
        fn handle(&self, _pushes: bool) -> Result<Box<dyn Lobby>, String> {
            if self.started.lock().unwrap().is_empty() {
                return Err("no lobby: not logged in".into());
            }
            Ok(Box::new(self.lobby.clone()))
        }
        fn end(&self, why: &str) -> Result<(), String> {
            self.lobby.kill(why);
            Ok(())
        }
    }
}
