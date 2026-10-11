//! What each `Mp` function does, independent of how it is called.
//!
//! * `Mp.GetRoomKey()` → the current room key (a string), or `nil` when the player sees public games
//!   only.
//! * `Mp.SetRoomKey(key)` → `true`, or `false, message` when `key` is not a valid room key
//!   (`mercs2_mp_api::rules::check_room_key`; the old key is kept). `key == nil` (or no argument) clears it.
//!
//! * `Mp.Logout()` → `true`: forgets the account name the game stores (`Mercs2.ini [Network] Username`), empties
//!   the game's in-memory account name and password, and ends this ASI's server session if one is open
//!   ([`crate::account`]). The game's next online start then offers Create Account. Raises when the stored
//!   name cannot be removed.
//!
//! Misuse and internal failures raise a Lua error with a message naming the function: an argument of
//! the wrong type, too many arguments, a room-key store that start-up never installed, a poisoned lock.
//! Every call is logged.

use mercs2_mp_api::ErrorCode;

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

/// What `Mp.Logout` does, behind the Lua calling convention.
pub trait LogoutAction {
    /// Log out. `Ok(Some(name))` when a server session was ended, `Ok(None)` when none was open.
    fn logout(&self) -> Result<Option<String>, String>;
}

/// `Mp.Logout()`.
pub fn logout<V: Vm>(s: &mut Stack<'_, V>, action: Result<&dyn LogoutAction, String>, log: &Logger) -> Ret {
    let n = s.arg_count();
    if n > 0 {
        let r = too_many("Logout", 0, n);
        log_raise(log, "Logout", &r);
        return r;
    }
    match action.and_then(|a| a.logout()) {
        Ok(was) => {
            s.push_bool(true);
            log.info(format!(
                "Lua {NAMESPACE}.Logout() -> true ({})",
                match was {
                    Some(name) => format!("ended the session of {name:?}"),
                    None => "no session was open".into(),
                }
            ));
            Ret::Values(1)
        }
        Err(e) => {
            let r = Ret::Raise(format!("{NAMESPACE}.Logout: {e}"));
            log_raise(log, "Logout", &r);
            r
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

    struct Action(Result<Option<String>, String>);
    impl LogoutAction for Action {
        fn logout(&self) -> Result<Option<String>, String> {
            self.0.clone()
        }
    }

    #[test]
    fn logout_returns_true_and_raises_on_failure() {
        let (log, cap) = logger();
        let mut a = Arena::with_args(&[]);
        let ok = Action(Ok(Some("Addicted_24_7".into())));
        assert_eq!(logout(&mut Stack::new(&mut a, L), Ok(&ok), &log), Ret::Values(1));
        assert_eq!((a.results(0)[0].0, a.results(0)[0].2), (LUA_TBOOLEAN, 1));
        let mut a = Arena::with_args(&[]);
        assert_eq!(logout(&mut Stack::new(&mut a, L), Ok(&Action(Ok(None))), &log), Ret::Values(1));
        let t = cap.text();
        assert!(t.contains("Mp.Logout() -> true (ended the session of \"Addicted_24_7\")"), "{t}");
        assert!(t.contains("Mp.Logout() -> true (no session was open)"), "{t}");

        let mut a = Arena::with_args(&[]);
        let failed = Action(Err("could not remove [Network] Username: access denied".into()));
        let r = logout(&mut Stack::new(&mut a, L), Ok(&failed), &log);
        assert_eq!(r, Ret::Raise("Mp.Logout: could not remove [Network] Username: access denied".into()));
        assert!(a.results(0).is_empty(), "nothing pushed before a raise");

        let mut a = Arena::with_args(&[ArenaArg::Nil]);
        assert!(matches!(logout(&mut Stack::new(&mut a, L), Ok(&ok), &log), Ret::Raise(m) if m.contains("at most 0")));
        let mut a = Arena::with_args(&[]);
        let missing: Result<&dyn LogoutAction, String> = Err("logout used before start-up installed it".into());
        assert!(matches!(logout(&mut Stack::new(&mut a, L), missing, &log), Ret::Raise(m) if m.contains("before start-up")));
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
