//! The logged-in session, handed to other ASIs through the C export `mr_session_v1`
//! (`include/multiplayer_restored.h`), so a mod can call the multiplayer server as the player.
//!
//! The session is the one the game's online `acct Login` created ([`crate::fesl`] stores it in the
//! [`SessionSlot`] when `POST /v1/sessions` succeeds); it lasts until `Mp.Logout` ([`crate::account`]) or the
//! next Login replaces it. The token is the server's: it expires at the server's `expires_at`, and the server
//! answers an expired one with 401.
//!
//! This module holds the platform-independent part, [`export`], so its rules are tested on the host; the
//! Windows layer wraps it in the `extern "C"` function.

use std::mem::{align_of, offset_of, size_of};

use mercs2_https::BaseUrl;
use thiserror::Error;

use crate::session::SessionSlot;

pub const SERVER_BASE_URL_CAP: usize = 256;
pub const TOKEN_CAP: usize = 512;
pub const USERNAME_CAP: usize = 64;

/// `MrSessionV1` of `include/multiplayer_restored.h`. Each string is NUL-terminated UTF-8.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MrSessionV1 {
    pub struct_size: u32,
    pub server_base_url: [u8; SERVER_BASE_URL_CAP],
    pub token: [u8; TOKEN_CAP],
    pub username: [u8; USERNAME_CAP],
}

/// `sizeof(MrSessionV1)`: the only `struct_size` [`export`] accepts.
pub const MR_SESSION_V1_SIZE: u32 = 836;

// The C header asserts the same numbers; these hold on every target this crate is compiled for, i686 included.
const _: () = {
    assert!(size_of::<MrSessionV1>() == MR_SESSION_V1_SIZE as usize);
    assert!(align_of::<MrSessionV1>() == 4);
    assert!(offset_of!(MrSessionV1, struct_size) == 0);
    assert!(offset_of!(MrSessionV1, server_base_url) == 4);
    assert!(offset_of!(MrSessionV1, token) == 260);
    assert!(offset_of!(MrSessionV1, username) == 772);
};

impl MrSessionV1 {
    /// Every byte zero except `struct_size`.
    pub const fn empty() -> Self {
        MrSessionV1 {
            struct_size: MR_SESSION_V1_SIZE,
            server_base_url: [0; SERVER_BASE_URL_CAP],
            token: [0; TOKEN_CAP],
            username: [0; USERNAME_CAP],
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExportError {
    #[error("out is NULL")]
    NullOut,
    #[error("out->struct_size is {got}, not sizeof(MrSessionV1) = {MR_SESSION_V1_SIZE}")]
    StructSize { got: u32 },
    #[error("{field} is {len} bytes and does not fit with its NUL in {capacity}")]
    TooLong { field: &'static str, len: usize, capacity: usize },
    #[error("{field} contains a NUL byte")]
    InteriorNul { field: &'static str },
    #[error("the session lock is poisoned (a thread panicked while holding it)")]
    Poisoned,
}

/// What the export reads once start-up has finished.
pub struct Source<'a> {
    pub server: &'a BaseUrl,
    pub session: &'a SessionSlot,
}

/// Fill `*out` from `source` (`None` before start-up has finished, which counts as not signed in).
///
/// * `Ok(true)`: signed in; `*out` holds the server's base URL (canonical `https://host[:port]prefix`, which
///   `BaseUrl::parse` reads back), the bearer token and the username.
/// * `Ok(false)`: not signed in; `*out` is all zero except `struct_size`.
/// * `Err(NullOut | StructSize)`: nothing is written.
/// * `Err(_)` otherwise (a value that does not fit, which is never truncated): `*out` is all zero except
///   `struct_size`.
///
/// # Safety
/// `out` is NULL or points to at least 4 readable bytes, and to `sizeof(MrSessionV1)` writable bytes when
/// those 4 bytes hold that size. It need not be aligned.
pub unsafe fn export(out: *mut MrSessionV1, source: Option<Source<'_>>) -> Result<bool, ExportError> {
    if out.is_null() {
        return Err(ExportError::NullOut);
    }
    let got = unsafe { std::ptr::addr_of!((*out).struct_size).read_unaligned() };
    if got != MR_SESSION_V1_SIZE {
        return Err(ExportError::StructSize { got });
    }
    let mut local = MrSessionV1::empty();
    let result = fill(&mut local, source);
    if result != Ok(true) {
        local = MrSessionV1::empty();
    }
    unsafe { out.write_unaligned(local) };
    result
}

fn fill(local: &mut MrSessionV1, source: Option<Source<'_>>) -> Result<bool, ExportError> {
    let Some(source) = source else { return Ok(false) };
    let slot = source.session.lock().map_err(|_| ExportError::Poisoned)?;
    let Some(session) = slot.as_ref() else { return Ok(false) };
    put("server_base_url", &source.server.to_string(), &mut local.server_base_url)?;
    put("token", &session.token, &mut local.token)?;
    put("username", &session.display_name, &mut local.username)?;
    Ok(true)
}

fn put(field: &'static str, value: &str, dst: &mut [u8]) -> Result<(), ExportError> {
    let bytes = value.as_bytes();
    if bytes.contains(&0) {
        return Err(ExportError::InteriorNul { field });
    }
    if bytes.len() >= dst.len() {
        return Err(ExportError::TooLong { field, len: bytes.len(), capacity: dst.len() });
    }
    dst[..bytes.len()].copy_from_slice(bytes);
    dst[bytes.len()..].fill(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{LoggedIn, new_slot};
    use mercs2_mp_api::UserId;

    fn base() -> BaseUrl {
        BaseUrl::parse("https://mp.example.org:8443/api/").unwrap()
    }

    fn signed_in(token: &str, name: &str) -> SessionSlot {
        let slot = new_slot();
        *slot.lock().unwrap() = Some(LoggedIn {
            token: token.into(),
            user_id: UserId(42),
            display_name: name.into(),
            expires_at: 1_800_000_000,
            lkey: "lk".into(),
        });
        slot
    }

    fn c_str(field: &[u8]) -> &str {
        let n = field.iter().position(|&b| b == 0).expect("NUL-terminated");
        assert!(field[n..].iter().all(|&b| b == 0), "bytes after the NUL are zero");
        std::str::from_utf8(&field[..n]).unwrap()
    }

    /// A buffer with every byte 0xAA and `struct_size` set.
    fn dirty(size: u32) -> MrSessionV1 {
        MrSessionV1 { struct_size: size, server_base_url: [0xAA; 256], token: [0xAA; 512], username: [0xAA; 64] }
    }

    #[test]
    fn layout_is_the_c_header_layout() {
        assert_eq!(size_of::<MrSessionV1>(), 836);
        assert_eq!(align_of::<MrSessionV1>(), 4);
        assert_eq!(offset_of!(MrSessionV1, struct_size), 0);
        assert_eq!(offset_of!(MrSessionV1, server_base_url), 4);
        assert_eq!(offset_of!(MrSessionV1, token), 260);
        assert_eq!(offset_of!(MrSessionV1, username), 772);
        let header = include_str!("../include/multiplayer_restored.h");
        for line in [
            "MR_STATIC_ASSERT(sizeof(MrSessionV1) == 836,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, server_base_url) == 4,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, token) == 260,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, username) == 772,",
        ] {
            assert!(header.contains(line), "header lacks {line:?}");
        }
    }

    #[test]
    fn signed_in_fills_every_field() {
        let token = "ab".repeat(32);
        let slot = signed_in(&token, "Mattias");
        let server = base();
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) };
        assert_eq!(r, Ok(true));
        assert_eq!(out.struct_size, MR_SESSION_V1_SIZE);
        assert_eq!(c_str(&out.server_base_url), "https://mp.example.org:8443/api");
        assert_eq!(BaseUrl::parse(c_str(&out.server_base_url)).unwrap(), server);
        assert_eq!(c_str(&out.token), token);
        assert_eq!(c_str(&out.username), "Mattias");
    }

    #[test]
    fn not_signed_in_zeroes_all_but_struct_size() {
        let server = base();
        let slot = new_slot();
        for source in [None, Some(Source { server: &server, session: &slot })] {
            let mut out = dirty(MR_SESSION_V1_SIZE);
            assert_eq!(unsafe { export(&mut out, source) }, Ok(false));
            assert_eq!(out, MrSessionV1::empty());
        }
    }

    #[test]
    fn null_and_wrong_size_write_nothing() {
        let slot = signed_in("t", "n");
        let server = base();
        let src = || Some(Source { server: &server, session: &slot });
        assert_eq!(unsafe { export(std::ptr::null_mut(), src()) }, Err(ExportError::NullOut));
        for size in [0, 4, 835, 837, 0xFFFF_FFFF] {
            let mut out = dirty(size);
            let before = out;
            assert_eq!(unsafe { export(&mut out, src()) }, Err(ExportError::StructSize { got: size }));
            assert_eq!(out, before);
        }
    }

    #[test]
    fn only_struct_size_is_read_when_it_is_wrong() {
        // A caller built against a smaller struct: four bytes, nothing after them belongs to us.
        let mut small = [0u8; 4];
        small.copy_from_slice(&100u32.to_ne_bytes());
        let slot = signed_in("t", "n");
        let server = base();
        let r = unsafe { export(small.as_mut_ptr() as *mut MrSessionV1, Some(Source { server: &server, session: &slot })) };
        assert_eq!(r, Err(ExportError::StructSize { got: 100 }));
        assert_eq!(small, 100u32.to_ne_bytes());
    }

    #[test]
    fn a_value_that_does_not_fit_is_an_error_and_never_truncated() {
        let server = base();
        // Capacity includes the NUL: 63 bytes fit in 64, 64 do not.
        let ok = signed_in("t", &"u".repeat(63));
        let mut out = dirty(MR_SESSION_V1_SIZE);
        assert_eq!(unsafe { export(&mut out, Some(Source { server: &server, session: &ok })) }, Ok(true));
        assert_eq!(c_str(&out.username).len(), 63);

        for (slot, field, len, capacity) in [
            (signed_in("t", &"u".repeat(64)), "username", 64, 64),
            (signed_in(&"t".repeat(512), "n"), "token", 512, 512),
        ] {
            let mut out = dirty(MR_SESSION_V1_SIZE);
            let r = unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) };
            assert_eq!(r, Err(ExportError::TooLong { field, len, capacity }));
            assert_eq!(out, MrSessionV1::empty(), "{field}: nothing partial is left behind");
        }

        let long = BaseUrl { host: "h".repeat(240), port: 8443, prefix: "/api".into() };
        let slot = signed_in("t", "n");
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(Source { server: &long, session: &slot })) };
        assert!(matches!(r, Err(ExportError::TooLong { field: "server_base_url", capacity: 256, .. })), "{r:?}");
        assert_eq!(out, MrSessionV1::empty());
    }

    #[test]
    fn multibyte_utf8_counts_bytes() {
        let server = base();
        // "é" is two bytes: 31 of them are 62 bytes and fit; 32 are 64 and do not.
        let slot = signed_in("t", &"é".repeat(31));
        let mut out = dirty(MR_SESSION_V1_SIZE);
        assert_eq!(unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) }, Ok(true));
        assert_eq!(c_str(&out.username), "é".repeat(31));
        let slot = signed_in("t", &"é".repeat(32));
        let r = unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) };
        assert_eq!(r, Err(ExportError::TooLong { field: "username", len: 64, capacity: 64 }));
    }

    #[test]
    fn interior_nul_is_an_error() {
        let server = base();
        let slot = signed_in("to\0ken", "n");
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) };
        assert_eq!(r, Err(ExportError::InteriorNul { field: "token" }));
        assert_eq!(out, MrSessionV1::empty());
    }

    #[test]
    fn a_poisoned_session_lock_is_an_error() {
        let server = base();
        let slot = signed_in("t", "n");
        let s2 = slot.clone();
        let _ = std::thread::spawn(move || {
            let _guard = s2.lock().unwrap();
            panic!("poison the session lock");
        })
        .join();
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) };
        assert_eq!(r, Err(ExportError::Poisoned));
        assert_eq!(out, MrSessionV1::empty());
    }

    #[test]
    fn concurrent_readers_and_a_writer_see_whole_sessions() {
        let server = std::sync::Arc::new(base());
        let slot = signed_in(&"a".repeat(64), "first");
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let (server, slot) = (server.clone(), slot.clone());
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        let mut out = MrSessionV1::empty();
                        let r = unsafe { export(&mut out, Some(Source { server: &server, session: &slot })) };
                        match r {
                            Ok(true) => {
                                let pair = (c_str(&out.token).to_owned(), c_str(&out.username).to_owned());
                                assert!(
                                    pair == ("a".repeat(64), "first".into()) || pair == ("b".repeat(64), "second".into()),
                                    "{pair:?}"
                                );
                            }
                            Ok(false) => assert_eq!(out, MrSessionV1::empty()),
                            Err(e) => panic!("{e}"),
                        }
                    }
                })
            })
            .collect();
        for i in 0..2000 {
            let mut g = slot.lock().unwrap();
            *g = match i % 3 {
                0 => None,
                1 => signed_in(&"b".repeat(64), "second").lock().unwrap().take(),
                _ => signed_in(&"a".repeat(64), "first").lock().unwrap().take(),
            };
        }
        for r in readers {
            r.join().unwrap();
        }
    }
}
