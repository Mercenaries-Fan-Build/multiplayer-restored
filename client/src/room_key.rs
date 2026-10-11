//! The player's current room key, shared by the Theater adapter (game listing / hosting / joining) and the
//! in-game multiplayer menu (which can change it at runtime). Initialised from `[privacy] room_key`.
//!
//! Semantics (`mp_api::rules::check_room_key`): `None` = public games only; `Some(key)` = only games hosted
//! with exactly that key (case-sensitive, not unique).

use std::sync::{Arc, Mutex, OnceLock};

use mp_api::ApiError;

static GLOBAL: OnceLock<RoomKeyStore> = OnceLock::new();

/// Install the process-wide store (once, at ASI start-up, from the ini). A second call is an error.
pub fn install(store: RoomKeyStore) -> Result<(), String> {
    GLOBAL.set(store).map_err(|_| "room key store installed twice".to_string())
}

/// The process-wide store; an error if start-up has not installed it yet.
pub fn global() -> Result<&'static RoomKeyStore, String> {
    GLOBAL.get().ok_or_else(|| "room key store used before start-up installed it".to_string())
}

#[derive(Clone, Debug)]
pub struct RoomKeyStore {
    inner: Arc<Mutex<Option<String>>>,
}

impl RoomKeyStore {
    /// `initial` must already be validated (the config parser does this).
    pub fn new(initial: Option<String>) -> Self {
        RoomKeyStore { inner: Arc::new(Mutex::new(initial)) }
    }

    pub fn get(&self) -> Result<Option<String>, String> {
        self.inner.lock().map(|k| k.clone()).map_err(|_| "room key lock poisoned".to_string())
    }

    /// Replace the key; a malformed key is refused and the old one kept.
    pub fn set(&self, key: Option<String>) -> Result<(), ApiError> {
        if let Some(k) = &key {
            mp_api::rules::check_room_key(k)?;
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| ApiError::new(mp_api::ErrorCode::Internal, "room key lock poisoned"))?;
        *guard = key;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_validates_and_shares() {
        let a = RoomKeyStore::new(None);
        let b = a.clone();
        a.set(Some("venezuela-42".into())).unwrap();
        assert_eq!(b.get().unwrap().as_deref(), Some("venezuela-42"));
        assert!(a.set(Some("bad key".into())).is_err());
        assert_eq!(b.get().unwrap().as_deref(), Some("venezuela-42"));
        a.set(None).unwrap();
        assert_eq!(b.get().unwrap(), None);
    }
}
