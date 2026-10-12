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

use mercs2_formats::mod_runtime::lua::{Lua, TNIL, TSTRING, type_name};

pub use mercs2_formats::mod_runtime::lua::Ret;

use crate::log::Logger;
use crate::room_key::RoomKeyStore;

/// The global table the functions are registered under.
pub const NAMESPACE: &str = "Mp";

fn too_many(name: &str, max: i32, got: i32) -> Ret {
    Ret::Raise(format!("{NAMESPACE}.{name} takes at most {max} argument(s), got {got}"))
}

/// `Mp.GetRoomKey()`.
pub fn get_room_key<L: Lua>(s: &mut L, store: Result<&RoomKeyStore, String>, log: &Logger) -> Ret {
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
pub fn set_room_key<L: Lua>(s: &mut L, store: Result<&RoomKeyStore, String>, log: &Logger) -> Ret {
    let n = s.arg_count();
    if n > 1 {
        let r = too_many("SetRoomKey", 1, n);
        log_raise(log, "SetRoomKey", &r);
        return r;
    }
    let tag = s.arg_type(0);
    let key = match tag {
        -1 | TNIL => None,
        TSTRING => match String::from_utf8(s.arg_string(0).expect("a string argument reads")) {
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
        _ => {
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
pub fn logout<L: Lua>(s: &mut L, action: Result<&dyn LogoutAction, String>, log: &Logger) -> Ret {
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
    use super::*;
    use crate::log::capture::logger;
    use mercs2_formats::mod_runtime::lua::fake::{FakeLua, Val, s};

    fn store(k: Option<&str>) -> RoomKeyStore {
        RoomKeyStore::new(k.map(str::to_owned))
    }

    fn call(args: Vec<Val>, f: impl FnOnce(&mut FakeLua) -> Ret) -> (Ret, Vec<Val>) {
        let mut l = FakeLua::with(args);
        let r = f(&mut l);
        (r, l.pushed)
    }

    #[test]
    fn get_returns_the_key_or_nil() {
        let (log, cap) = logger();
        let st = store(Some("venezuela-42"));
        assert_eq!(call(vec![], |l| get_room_key(l, Ok(&st), &log)), (Ret::Values(1), vec![s("venezuela-42")]));
        st.set(None).unwrap();
        assert_eq!(call(vec![], |l| get_room_key(l, Ok(&st), &log)), (Ret::Values(1), vec![Val::Nil]));
        let t = cap.text();
        assert!(t.contains("Mp.GetRoomKey() -> \"venezuela-42\"") && t.contains("Mp.GetRoomKey() -> nil"), "{t}");
    }

    #[test]
    fn set_validates_with_the_store() {
        let (log, cap) = logger();
        let st = store(None);
        assert_eq!(call(vec![s("1234567")], |l| set_room_key(l, Ok(&st), &log)), (Ret::Values(1), vec![Val::Bool(true)]));
        assert_eq!(st.get().unwrap().as_deref(), Some("1234567"));

        // Invalid: false + the rule's message, old key kept.
        let (r, pushed) = call(vec![s("bad key")], |l| set_room_key(l, Ok(&st), &log));
        assert_eq!(r, Ret::Values(2));
        assert_eq!(pushed[0], Val::Bool(false));
        assert!(matches!(&pushed[1], Val::Str(m) if String::from_utf8_lossy(m).contains("room_key")), "{pushed:?}");
        assert_eq!(st.get().unwrap().as_deref(), Some("1234567"));

        // nil and no argument both clear.
        assert_eq!(call(vec![Val::Nil], |l| set_room_key(l, Ok(&st), &log)).0, Ret::Values(1));
        assert_eq!(st.get().unwrap(), None);
        st.set(Some("abcdef".into())).unwrap();
        assert_eq!(call(vec![], |l| set_room_key(l, Ok(&st), &log)).0, Ret::Values(1));
        assert_eq!(st.get().unwrap(), None);

        let t = cap.text();
        assert!(t.contains("Mp.SetRoomKey(\"1234567\") -> true"), "{t}");
        assert!(t.contains("WARN  Lua Mp.SetRoomKey(\"bad key\") -> false"), "{t}");
        assert!(t.contains("Mp.SetRoomKey(nil) -> true"), "{t}");
    }

    #[test]
    fn a_key_that_is_not_text_is_refused_not_raised() {
        let (log, _) = logger();
        let st = store(Some("abcdef"));
        let (r, pushed) = call(vec![Val::Str(vec![0xff, 0xfe])], |l| set_room_key(l, Ok(&st), &log));
        assert_eq!(r, Ret::Values(2));
        assert_eq!(pushed[0], Val::Bool(false));
        assert_eq!(st.get().unwrap().as_deref(), Some("abcdef"));
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
        let ok = Action(Ok(Some("Addicted_24_7".into())));
        assert_eq!(call(vec![], |l| logout(l, Ok(&ok), &log)), (Ret::Values(1), vec![Val::Bool(true)]));
        assert_eq!(call(vec![], |l| logout(l, Ok(&Action(Ok(None))), &log)).0, Ret::Values(1));
        let t = cap.text();
        assert!(t.contains("Mp.Logout() -> true (ended the session of \"Addicted_24_7\")"), "{t}");
        assert!(t.contains("Mp.Logout() -> true (no session was open)"), "{t}");

        let failed = Action(Err("could not remove [Network] Username: access denied".into()));
        let (r, pushed) = call(vec![], |l| logout(l, Ok(&failed), &log));
        assert_eq!(r, Ret::Raise("Mp.Logout: could not remove [Network] Username: access denied".into()));
        assert!(pushed.is_empty(), "nothing pushed before a raise");

        assert!(matches!(call(vec![Val::Nil], |l| logout(l, Ok(&ok), &log)).0, Ret::Raise(m) if m.contains("at most 0")));
        let missing: Result<&dyn LogoutAction, String> = Err("logout used before start-up installed it".into());
        assert!(matches!(call(vec![], |l| logout(l, missing, &log)).0, Ret::Raise(m) if m.contains("before start-up")));
    }

    #[test]
    fn misuse_and_missing_store_raise() {
        let (log, cap) = logger();
        let st = store(None);
        let (r, pushed) = call(vec![Val::Num(1.0)], |l| set_room_key(l, Ok(&st), &log));
        assert_eq!(r, Ret::Raise("Mp.SetRoomKey expects a string or nil, got number".into()));
        assert!(pushed.is_empty(), "nothing pushed before a raise");

        let two = call(vec![s("abcdef"), s("x")], |l| set_room_key(l, Ok(&st), &log)).0;
        assert!(matches!(two, Ret::Raise(m) if m.contains("at most 1")));
        let table = call(vec![Val::Table], |l| get_room_key(l, Ok(&st), &log)).0;
        assert!(matches!(table, Ret::Raise(m) if m.contains("at most 0")));

        let missing = || Err("room key store used before start-up installed it".to_string());
        assert!(matches!(call(vec![], |l| get_room_key(l, missing(), &log)).0, Ret::Raise(m) if m.contains("before start-up")));
        assert!(matches!(call(vec![s("abcdef")], |l| set_room_key(l, missing(), &log)).0, Ret::Raise(m) if m.contains("before start-up")));
        assert!(cap.text().contains("ERROR Lua Mp.SetRoomKey raises:"), "{}", cap.text());
    }
}
