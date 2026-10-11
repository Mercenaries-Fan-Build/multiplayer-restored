//! What each `Mp` function does, independent of how it is called.
//!
//! * `Mp.GetRoomKey()` → the current room key (a string), or `nil` when the player sees public games
//!   only.
//! * `Mp.SetRoomKey(key)` → `true`, or `false, message` when `key` is not a valid room key
//!   (`mp_api::rules::check_room_key`; the old key is kept). `key == nil` (or no argument) clears it.
//!
//! Misuse and internal failures raise a Lua error with a message naming the function: an argument of
//! the wrong type, too many arguments, a room-key store that start-up never installed, a poisoned lock.
//! Every call is logged.

use mp_api::ErrorCode;

use super::state::{Arg, Stack, Vm, type_name};
use crate::log::Logger;
use crate::room_key::RoomKeyStore;

/// The global table the functions are registered under.
pub const NAMESPACE: &str = "Mp";

/// What a binding wants returned to Lua.
#[derive(Debug, PartialEq, Eq)]
pub enum Ret {
    /// This many values were pushed.
    Values(i32),
    /// Raise a Lua error with this message (nothing was pushed).
    Raise(String),
}

fn too_many(name: &str, max: u32, got: u32) -> Ret {
    Ret::Raise(format!("{NAMESPACE}.{name} takes at most {max} argument(s), got {got}"))
}

/// `Mp.GetRoomKey()`.
pub fn get_room_key<V: Vm>(s: &mut Stack<'_, V>, store: Result<&RoomKeyStore, String>, log: &Logger) -> Ret {
    let n = s.arg_count();
    if n > 0 {
        let r = too_many("GetRoomKey", 0, n);
        log_raise(log, "GetRoomKey", &r);
        return r;
    }
    let key = match store.and_then(|st| st.get()) {
        Ok(k) => k,
        Err(e) => {
            let r = Ret::Raise(format!("{NAMESPACE}.GetRoomKey: {e}"));
            log_raise(log, "GetRoomKey", &r);
            return r;
        }
    };
    match &key {
        Some(k) => s.push_string(k.as_bytes()),
        None => s.push_nil(),
    }
    log.info(format!("Lua {NAMESPACE}.GetRoomKey() -> {}", describe(&key)));
    Ret::Values(1)
}

/// `Mp.SetRoomKey(key | nil)`.
pub fn set_room_key<V: Vm>(s: &mut Stack<'_, V>, store: Result<&RoomKeyStore, String>, log: &Logger) -> Ret {
    let n = s.arg_count();
    if n > 1 {
        let r = too_many("SetRoomKey", 1, n);
        log_raise(log, "SetRoomKey", &r);
        return r;
    }
    let key = match s.arg(1) {
        Arg::Nil => None,
        Arg::Str(bytes) => match String::from_utf8(bytes) {
            Ok(k) => Some(k),
            Err(e) => {
                // Not UTF-8 is not ASCII either, so it can never be a key: refuse it like any other.
                let msg = format!("room_key: not valid text ({e})");
                s.push_bool(false);
                s.push_string(msg.as_bytes());
                log.warn(format!("Lua {NAMESPACE}.SetRoomKey(<{} bytes>) refused: {msg}", e.as_bytes().len()));
                return Ret::Values(2);
            }
        },
        Arg::Other(tag) => {
            let r = Ret::Raise(format!(
                "{NAMESPACE}.SetRoomKey expects a string or nil, got {}",
                type_name(tag)
            ));
            log_raise(log, "SetRoomKey", &r);
            return r;
        }
    };
    let store = match store {
        Ok(st) => st,
        Err(e) => {
            let r = Ret::Raise(format!("{NAMESPACE}.SetRoomKey: {e}"));
            log_raise(log, "SetRoomKey", &r);
            return r;
        }
    };
    match store.set(key.clone()) {
        Ok(()) => {
            s.push_bool(true);
            log.info(format!("Lua {NAMESPACE}.SetRoomKey({}) -> true", describe(&key)));
            Ret::Values(1)
        }
        Err(e) if e.code == ErrorCode::Internal => {
            let r = Ret::Raise(format!("{NAMESPACE}.SetRoomKey: {}", e.message));
            log_raise(log, "SetRoomKey", &r);
            r
        }
        Err(e) => {
            s.push_bool(false);
            s.push_string(e.message.as_bytes());
            log.warn(format!("Lua {NAMESPACE}.SetRoomKey({}) -> false, {:?}", describe(&key), e.message));
            Ret::Values(2)
        }
    }
}

fn describe(key: &Option<String>) -> String {
    match key {
        Some(k) => format!("{k:?}"),
        None => "nil".into(),
    }
}

fn log_raise(log: &Logger, name: &str, r: &Ret) {
    if let Ret::Raise(m) = r {
        log.error(format!("Lua {NAMESPACE}.{name} raises: {m}"));
    }
}

#[cfg(test)]
mod tests {
    use super::super::state::arena::*;
    use super::super::state::{LUA_TBOOLEAN, LUA_TNIL, LUA_TSTRING};
    use super::*;
    use crate::log::capture::logger;

    fn store(k: Option<&str>) -> RoomKeyStore {
        RoomKeyStore::new(k.map(str::to_owned))
    }

    #[test]
    fn get_returns_the_key_or_nil() {
        let (log, cap) = logger();
        let st = store(Some("venezuela-42"));
        let mut a = Arena::with_args(&[]);
        assert_eq!(get_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Values(1));
        assert_eq!(a.results(0)[0].1.as_deref(), Some("venezuela-42"));
        assert_eq!(a.results(0)[0].0, LUA_TSTRING);

        st.set(None).unwrap();
        let mut a = Arena::with_args(&[]);
        assert_eq!(get_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Values(1));
        assert_eq!(a.results(0)[0].0, LUA_TNIL);
        let t = cap.text();
        assert!(t.contains("Mp.GetRoomKey() -> \"venezuela-42\"") && t.contains("Mp.GetRoomKey() -> nil"), "{t}");
    }

    #[test]
    fn set_validates_with_the_store() {
        let (log, cap) = logger();
        let st = store(None);

        let mut a = Arena::with_args(&[ArenaArg::Str("1234567")]);
        assert_eq!(set_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Values(1));
        assert_eq!((a.results(1)[0].0, a.results(1)[0].2), (LUA_TBOOLEAN, 1));
        assert_eq!(st.get().unwrap().as_deref(), Some("1234567"));

        // Invalid: false + the rule's message, old key kept.
        let mut a = Arena::with_args(&[ArenaArg::Str("bad key")]);
        assert_eq!(set_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Values(2));
        let r = a.results(1);
        assert_eq!((r[0].0, r[0].2), (LUA_TBOOLEAN, 0));
        assert!(r[1].1.as_deref().unwrap().contains("room_key"), "{r:?}");
        assert_eq!(st.get().unwrap().as_deref(), Some("1234567"));

        // nil and no argument both clear.
        let mut a = Arena::with_args(&[ArenaArg::Nil]);
        assert_eq!(set_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Values(1));
        assert_eq!(st.get().unwrap(), None);
        st.set(Some("abcdef".into())).unwrap();
        let mut a = Arena::with_args(&[]);
        assert_eq!(set_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Values(1));
        assert_eq!(st.get().unwrap(), None);

        let t = cap.text();
        assert!(t.contains("Mp.SetRoomKey(\"1234567\") -> true"), "{t}");
        assert!(t.contains("WARN  Lua Mp.SetRoomKey(\"bad key\") -> false"), "{t}");
        assert!(t.contains("Mp.SetRoomKey(nil) -> true"), "{t}");
    }

    #[test]
    fn misuse_and_missing_store_raise() {
        let (log, cap) = logger();
        let st = store(None);
        let mut a = Arena::with_args(&[ArenaArg::Num]);
        let r = set_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log);
        assert_eq!(r, Ret::Raise("Mp.SetRoomKey expects a string or nil, got number".into()));
        assert!(a.results(1).is_empty(), "nothing pushed before a raise");

        let mut a = Arena::with_args(&[ArenaArg::Str("abcdef"), ArenaArg::Str("x")]);
        assert!(matches!(set_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Raise(m) if m.contains("at most 1")));

        let mut a = Arena::with_args(&[ArenaArg::Table]);
        assert!(matches!(get_room_key(&mut Stack::new(&mut a, L), Ok(&st), &log), Ret::Raise(m) if m.contains("at most 0")));

        let missing = || Err("room key store used before start-up installed it".to_string());
        let mut a = Arena::with_args(&[]);
        assert!(matches!(get_room_key(&mut Stack::new(&mut a, L), missing(), &log), Ret::Raise(m) if m.contains("before start-up")));
        let mut a = Arena::with_args(&[ArenaArg::Str("abcdef")]);
        assert!(matches!(set_room_key(&mut Stack::new(&mut a, L), missing(), &log), Ret::Raise(m) if m.contains("before start-up")));
        assert!(cap.text().contains("ERROR Lua Mp.SetRoomKey raises:"), "{}", cap.text());
    }
}
