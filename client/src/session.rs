//! The logged-in account, shared between the FESL adapter (which creates it) and later services (Theater,
//! the WebSocket) that need the bearer token and identity.

use std::sync::{Arc, Mutex};

use mp_api::UserId;

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
