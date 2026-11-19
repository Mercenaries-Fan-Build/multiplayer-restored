//! The logged-in account, shared between the FESL adapter (which creates it) and later services (Theater,
//! the WebSocket) that need the bearer token and identity.

use std::sync::{Arc, Mutex};

use mercs2_mp_api::UserId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoggedIn {
    /// Bearer token for the server; never handed to the game.
    pub token: String,
    pub user_id: UserId,
    pub display_name: String,
    pub expires_at: i64,
    /// The `lkey` given to the game in the Login reply: a local random id, not the server token.
    pub lkey: String,
}

pub type SessionSlot = Arc<Mutex<Option<LoggedIn>>>;

pub fn new_slot() -> SessionSlot {
    Arc::new(Mutex::new(None))
}

/// Who is signed in, for the Lua bindings that act as the player ([`crate::leaderboard`], [`crate::net`]).
#[derive(Clone, PartialEq, Eq)]
pub struct SignedIn {
    pub token: String,
    pub username: String,
}

impl std::fmt::Debug for SignedIn {
    /// The token never reaches a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedIn").field("token", &"<redacted>").field("username", &self.username).finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Session {
    SignedIn(SignedIn),
    SignedOut,
}

/// The session, or why it could not be read (a poisoned lock), which the bindings log on every call.
pub type Lookup = Result<Session, String>;

/// The session in `slot` now.
pub fn lookup(slot: &SessionSlot) -> Lookup {
    let guard = slot.lock().map_err(|_| "the session lock is poisoned (a thread panicked while holding it)".to_string())?;
    Ok(match guard.as_ref() {
        Some(s) => Session::SignedIn(SignedIn { token: s.token.clone(), username: s.display_name.clone() }),
        None => Session::SignedOut,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_reads_the_slot_and_never_formats_the_token() {
        let slot = new_slot();
        assert_eq!(lookup(&slot), Ok(Session::SignedOut));
        *slot.lock().unwrap() = Some(LoggedIn {
            token: "s3cret".into(),
            user_id: UserId(7),
            display_name: "Mattias".into(),
            expires_at: 1,
            lkey: "lk".into(),
        });
        let got = lookup(&slot);
        assert_eq!(got, Ok(Session::SignedIn(SignedIn { token: "s3cret".into(), username: "Mattias".into() })));
        assert!(!format!("{got:?}").contains("s3cret"));
    }
}
