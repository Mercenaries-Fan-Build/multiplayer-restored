//! The online account the game remembers, and logging out of it.
//!
//! The game keeps one thing between runs: the account name, as `[Network] Username` in `Mercs2.ini` next to
//! the exe (`FUN_0074b760` builds the path from `GetModuleFileNameA(NULL)` and `"%s.ini"` of `"Mercs2"`;
//! the settings loader `FUN_00753280` and the online start `FUN_00847550` read it). No password is stored.
//! While a name is stored, `FUN_00848ca0` reports "has an account" to the front end, which then offers only
//! the login, never Create Account; nothing in the exe removes the key. [`StoredAccount::forget`] removes it.
//!
//! The FESL adapter forgets the stored name when a Login is refused, and `Mp.Logout()` forgets it, clears the
//! game's in-memory name and password, and ends this ASI's server session ([`Logout`]).

use std::sync::{Arc, OnceLock};

use crate::lobby::LobbyProvider;
use crate::log::Logger;
use crate::session::SessionSlot;

/// The section and key the game stores the account name under (`FUN_00753280`).
pub const SECTION: &str = "Network";
pub const KEY: &str = "Username";

pub trait StoredAccount: Send + Sync {
    /// Remove the stored account name, so the next online start finds none.
    fn forget(&self) -> Result<(), String>;
    /// Where it is stored, for logs.
    fn describe(&self) -> String;
}

/// What logging out does besides the game's own buffers: forget the stored name and end the server session.
pub struct Logout {
    store: Arc<dyn StoredAccount>,
    session: SessionSlot,
    lobby: Arc<dyn LobbyProvider>,
}

impl Logout {
    pub fn new(store: Arc<dyn StoredAccount>, session: SessionSlot, lobby: Arc<dyn LobbyProvider>) -> Self {
        Logout { store, session, lobby }
    }

    /// Forget the stored name, drop the session and close its lobby. Returns the logged-out user's display
    /// name, or `None` when no one was logged in.
    pub fn run(&self, log: &Logger) -> Result<Option<String>, String> {
        self.store.forget()?;
        log.info(format!("logout: removed the stored account name ({})", self.store.describe()));
        let was = self.session.lock().map_err(|_| "session lock poisoned".to_string())?.take();
        match &was {
            Some(s) => {
                self.lobby.end("logged out (Mp.Logout)")?;
                log.info(format!("logout: ended the server session of {:?} (user {})", s.display_name, s.user_id.0));
            }
            None => log.info("logout: no server session was open"),
        }
        Ok(was.map(|s| s.display_name))
    }
}

static GLOBAL: OnceLock<Logout> = OnceLock::new();

pub fn install(logout: Logout) -> Result<(), String> {
    GLOBAL.set(logout).map_err(|_| "logout installed twice".to_string())
}

pub fn global() -> Result<&'static Logout, String> {
    GLOBAL.get().ok_or_else(|| "logout used before start-up installed it".to_string())
}

/// `Mercs2.ini` beside the game's exe, written with the profile API the game reads it with.
#[cfg(windows)]
pub struct GameIni {
    path: std::path::PathBuf,
}

#[cfg(windows)]
impl GameIni {
    /// The game's own path: the main module's folder plus `Mercs2.ini` (`FUN_0074b760`).
    pub fn of_main_module() -> Result<Self, String> {
        use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
        let mut buf = vec![0u16; 32768];
        let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            return Err(format!("GetModuleFileNameW(NULL) failed (returned {n})"));
        }
        let exe = std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n]));
        let dir = exe.parent().ok_or_else(|| format!("game exe path {} has no folder", exe.display()))?;
        Ok(GameIni { path: dir.join("Mercs2.ini") })
    }
}

#[cfg(windows)]
impl StoredAccount for GameIni {
    fn forget(&self) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::System::WindowsProgramming::WritePrivateProfileStringW;
        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain([0]).collect::<Vec<u16>>();
        let (section, key, path) = (wide(SECTION.as_ref()), wide(KEY.as_ref()), wide(self.path.as_os_str()));
        // A NULL value deletes the key.
        let ok = unsafe { WritePrivateProfileStringW(section.as_ptr(), key.as_ptr(), std::ptr::null(), path.as_ptr()) };
        if ok == 0 {
            return Err(format!(
                "could not remove [{SECTION}] {KEY} from {}: {}",
                self.path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("[{SECTION}] {KEY} in {}", self.path.display())
    }
}

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::sync::Mutex;

    /// Counts forgets; fails them when `fail` is set.
    #[derive(Default)]
    pub struct FakeStore {
        pub forgets: Mutex<u32>,
        pub fail: Mutex<Option<String>>,
    }

    impl StoredAccount for FakeStore {
        fn forget(&self) -> Result<(), String> {
            if let Some(e) = self.fail.lock().unwrap().clone() {
                return Err(e);
            }
            *self.forgets.lock().unwrap() += 1;
            Ok(())
        }
        fn describe(&self) -> String {
            "[Network] Username in the fake store".into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeStore;
    use super::*;
    use crate::lobby::{Lobby, LobbyProvider};
    use crate::log::capture::logger;
    use crate::session::{LoggedIn, new_slot};
    use mercs2_mp_api::UserId;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Provider {
        ended: Mutex<Vec<String>>,
    }

    impl LobbyProvider for Provider {
        fn start(&self, _: &LoggedIn) -> Result<(), String> {
            Ok(())
        }
        fn handle(&self, _: bool) -> Result<Box<dyn Lobby>, String> {
            Err("no lobby in this test".into())
        }
        fn end(&self, why: &str) -> Result<(), String> {
            self.ended.lock().unwrap().push(why.to_owned());
            Ok(())
        }
    }

    #[test]
    fn logout_forgets_the_name_and_ends_the_session() {
        let (log, cap) = logger();
        let store = Arc::new(FakeStore::default());
        let session = new_slot();
        let lobby = Arc::new(Provider::default());
        *session.lock().unwrap() = Some(LoggedIn {
            token: "t".into(),
            user_id: UserId(1),
            display_name: "Addicted_24_7".into(),
            expires_at: 0,
            lkey: "k".into(),
        });
        let l = Logout::new(store.clone(), session.clone(), lobby.clone());
        assert_eq!(l.run(&log), Ok(Some("Addicted_24_7".into())));
        assert_eq!(*store.forgets.lock().unwrap(), 1);
        assert!(session.lock().unwrap().is_none());
        assert_eq!(*lobby.ended.lock().unwrap(), vec!["logged out (Mp.Logout)".to_string()]);
        assert!(cap.text().contains("ended the server session of \"Addicted_24_7\" (user 1)"), "{}", cap.text());

        // Logged out already: still forgets (the stored name may have come back), no lobby to end.
        assert_eq!(l.run(&log), Ok(None));
        assert_eq!(*store.forgets.lock().unwrap(), 2);
        assert_eq!(lobby.ended.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_failed_forget_stops_the_logout() {
        let (log, _) = logger();
        let store = Arc::new(FakeStore::default());
        *store.fail.lock().unwrap() = Some("Mercs2.ini is read-only".into());
        let session = new_slot();
        *session.lock().unwrap() = Some(LoggedIn {
            token: "t".into(),
            user_id: UserId(1),
            display_name: "a".into(),
            expires_at: 0,
            lkey: "k".into(),
        });
        let l = Logout::new(store, session.clone(), Arc::new(Provider::default()));
        assert_eq!(l.run(&log), Err("Mercs2.ini is read-only".into()));
        assert!(session.lock().unwrap().is_some(), "nothing else is undone when the name could not be removed");
    }
}
