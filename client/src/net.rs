//! `Net.GetUserName`, independent of how it is called. Ported from the Blow It Up Again ASI.
//!
//! * `Net.GetUserName()` → the signed-in player's name. PS3 v1.03 (`0x00537030`) reads no argument and pushes
//!   the online user's name buffer (`*(user + 0x3C) + 0x1C7`, never NULL), with no online check. On PC the name
//!   is this ASI's session's username; with no session it pushes `""` (what PS3's buffer holds then is unread:
//!   INFERRED). Its one caller, the briefing's friends-leaderboard block, never runs on retail.
//! * `Net.LeaderboardGetScore` / `Net.LeaderboardPushScore`: [`crate::leaderboard`].

use crate::session::{Lookup, Session};
use mercs2_formats::mod_runtime::lua::{Lua, Ret};

/// `Net.GetUserName()`, given the session.
pub fn get_user_name<L: Lua>(s: &mut L, session: &Lookup) -> Ret {
    match session {
        Ok(Session::SignedIn(who)) => s.push_string(who.username.as_bytes()),
        Ok(Session::SignedOut) | Err(_) => s.push_string(b""),
    }
    Ret::Values(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercs2_formats::mod_runtime::lua::fake::{FakeLua, Val, s};

    #[test]
    fn the_user_name_is_the_sessions_and_empty_without_one() {
        use crate::session::SignedIn;
        let mut l = FakeLua::with(vec![Val::Num(1.0)]);
        let who = Ok(Session::SignedIn(SignedIn { token: "t".into(), username: "Mattias".into() }));
        assert_eq!(get_user_name(&mut l, &who), Ret::Values(1));
        assert_eq!(l.pushed, [s("Mattias")]);
        for session in [Ok(Session::SignedOut), Err("the session lock is poisoned".to_string())] {
            let mut l = FakeLua::default();
            assert_eq!(get_user_name(&mut l, &session), Ret::Values(1));
            assert_eq!(l.pushed, [s("")]);
        }
    }
}
