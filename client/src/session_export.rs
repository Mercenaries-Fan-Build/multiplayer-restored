//! Who is signed in, handed to other ASIs through the C export `mr_session_v1`
//! (`include/multiplayer_restored.h`): whether the player holds a session, the account id, the username and
//! when the session expires. The session token never leaves this ASI; what needs it (the leaderboards,
//! [`crate::leaderboard`]) runs here.
//!
//! The session is the one the game's online `acct Login` created ([`crate::fesl`] stores it in the
//! [`SessionSlot`] when `POST /v1/sessions` succeeds); it lasts until `Mp.Logout` ([`crate::account`]) or the
//! next Login replaces it. `expires_at` is the server's.
//!
//! This module holds the platform-independent part, [`export`], so its rules are tested on the host; the
//! Windows layer wraps it in the `extern "C"` function.

use std::mem::{offset_of, size_of};

use thiserror::Error;

use crate::session::SessionSlot;

pub const USERNAME_CAP: usize = 64;

/// `MrSessionV1` of `include/multiplayer_restored.h`. The username is NUL-terminated UTF-8.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MrSessionV1 {
    pub struct_size: u32,
    /// 1 signed in, 0 not.
    pub signed_in: u32,
    /// The server's user id of the account.
    pub account_id: i64,
    /// When the server ends the session, in Unix seconds.
    pub expires_at: i64,
    pub username: [u8; USERNAME_CAP],
}

/// `sizeof(MrSessionV1)`: the only `struct_size` [`export`] accepts.
pub const MR_SESSION_V1_SIZE: u32 = 88;

// The C header asserts the same numbers. Every field sits at a multiple of its own size, so the layout has no
// padding whether a target aligns 64-bit integers to 4 or to 8 bytes; i686 is among the targets this compiles for.
const _: () = {
    assert!(size_of::<MrSessionV1>() == MR_SESSION_V1_SIZE as usize);
    assert!(offset_of!(MrSessionV1, struct_size) == 0);
    assert!(offset_of!(MrSessionV1, signed_in) == 4);
    assert!(offset_of!(MrSessionV1, account_id) == 8);
    assert!(offset_of!(MrSessionV1, expires_at) == 16);
    assert!(offset_of!(MrSessionV1, username) == 24);
};

impl MrSessionV1 {
    /// Every byte zero except `struct_size`.
    pub const fn empty() -> Self {
        MrSessionV1 { struct_size: MR_SESSION_V1_SIZE, signed_in: 0, account_id: 0, expires_at: 0, username: [0; USERNAME_CAP] }
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

/// Fill `*out` from `session` (`None` before start-up has finished, which counts as not signed in).
///
/// * `Ok(true)`: signed in; `*out` holds `signed_in = 1`, the account id, the session's expiry and the
///   username.
/// * `Ok(false)`: not signed in; `*out` is all zero except `struct_size`.
/// * `Err(NullOut | StructSize)`: nothing is written.
/// * `Err(_)` otherwise (a username that does not fit, which is never truncated): `*out` is all zero except
///   `struct_size`.
///
/// # Safety
/// `out` is NULL or points to at least 4 readable bytes, and to `sizeof(MrSessionV1)` writable bytes when
/// those 4 bytes hold that size. It need not be aligned.
pub unsafe fn export(out: *mut MrSessionV1, session: Option<&SessionSlot>) -> Result<bool, ExportError> {
    if out.is_null() {
        return Err(ExportError::NullOut);
    }
    let got = unsafe { std::ptr::addr_of!((*out).struct_size).read_unaligned() };
    if got != MR_SESSION_V1_SIZE {
        return Err(ExportError::StructSize { got });
    }
    let mut local = MrSessionV1::empty();
    let result = fill(&mut local, session);
    if result != Ok(true) {
        local = MrSessionV1::empty();
    }
    unsafe { out.write_unaligned(local) };
    result
}

fn fill(local: &mut MrSessionV1, session: Option<&SessionSlot>) -> Result<bool, ExportError> {
    let Some(session) = session else { return Ok(false) };
    let slot = session.lock().map_err(|_| ExportError::Poisoned)?;
    let Some(s) = slot.as_ref() else { return Ok(false) };
    put("username", &s.display_name, &mut local.username)?;
    local.signed_in = 1;
    local.account_id = s.user_id.0;
    local.expires_at = s.expires_at;
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
        MrSessionV1 { struct_size: size, signed_in: 0xAAAA_AAAA, account_id: -1, expires_at: -1, username: [0xAA; 64] }
    }

    /// The bytes of `s` as the C side sees them.
    fn bytes(s: &MrSessionV1) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts((s as *const MrSessionV1).cast::<u8>(), size_of::<MrSessionV1>()) }.to_vec()
    }

    #[test]
    fn layout_is_the_c_header_layout() {
        assert_eq!(size_of::<MrSessionV1>(), 88);
        assert_eq!(
            [
                offset_of!(MrSessionV1, struct_size),
                offset_of!(MrSessionV1, signed_in),
                offset_of!(MrSessionV1, account_id),
                offset_of!(MrSessionV1, expires_at),
                offset_of!(MrSessionV1, username),
            ],
            [0, 4, 8, 16, 24]
        );
        let header = include_str!("../include/multiplayer_restored.h");
        for line in [
            "MR_STATIC_ASSERT(sizeof(MrSessionV1) == 88,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, signed_in) == 4,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, account_id) == 8,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, expires_at) == 16,",
            "MR_STATIC_ASSERT(offsetof(MrSessionV1, username) == 24,",
        ] {
            assert!(header.contains(line), "header lacks {line:?}");
        }
        assert!(!header.contains("char token"), "the struct has no token field");
    }

    #[test]
    fn signed_in_fills_every_field_and_never_the_token() {
        let slot = signed_in("s3cret-token", "Mattias");
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(&slot)) };
        assert_eq!(r, Ok(true));
        assert_eq!((out.struct_size, out.signed_in, out.account_id, out.expires_at), (MR_SESSION_V1_SIZE, 1, 42, 1_800_000_000));
        assert_eq!(c_str(&out.username), "Mattias");
        let raw = bytes(&out);
        assert!(!raw.windows(b"s3cret".len()).any(|w| w == b"s3cret"), "no byte of the export holds the token");
    }

    #[test]
    fn not_signed_in_zeroes_all_but_struct_size() {
        let slot = new_slot();
        for session in [None, Some(&slot)] {
            let mut out = dirty(MR_SESSION_V1_SIZE);
            assert_eq!(unsafe { export(&mut out, session) }, Ok(false));
            assert_eq!(out, MrSessionV1::empty());
        }
    }

    #[test]
    fn null_and_wrong_size_write_nothing() {
        let slot = signed_in("t", "n");
        assert_eq!(unsafe { export(std::ptr::null_mut(), Some(&slot)) }, Err(ExportError::NullOut));
        for size in [0, 4, 836, 87, 89, 0xFFFF_FFFF] {
            let mut out = dirty(size);
            let before = out;
            assert_eq!(unsafe { export(&mut out, Some(&slot)) }, Err(ExportError::StructSize { got: size }));
            assert_eq!(out, before);
        }
    }

    #[test]
    fn only_struct_size_is_read_when_it_is_wrong() {
        // A caller built against a smaller struct: four bytes, nothing after them belongs to us.
        let mut small = [0u8; 4];
        small.copy_from_slice(&100u32.to_ne_bytes());
        let slot = signed_in("t", "n");
        let r = unsafe { export(small.as_mut_ptr() as *mut MrSessionV1, Some(&slot)) };
        assert_eq!(r, Err(ExportError::StructSize { got: 100 }));
        assert_eq!(small, 100u32.to_ne_bytes());
    }

    #[test]
    fn an_unaligned_buffer_is_written() {
        let slot = signed_in("t", "Mattias");
        let mut buf = vec![0u8; MR_SESSION_V1_SIZE as usize + 1];
        buf[1..5].copy_from_slice(&MR_SESSION_V1_SIZE.to_ne_bytes());
        let out = unsafe { buf.as_mut_ptr().add(1) } as *mut MrSessionV1;
        assert_eq!(unsafe { export(out, Some(&slot)) }, Ok(true));
        let got = unsafe { out.read_unaligned() };
        assert_eq!((got.signed_in, got.account_id), (1, 42));
    }

    #[test]
    fn a_username_that_does_not_fit_is_an_error_and_never_truncated() {
        // Capacity includes the NUL: 63 bytes fit in 64, 64 do not.
        let ok = signed_in("t", &"u".repeat(63));
        let mut out = dirty(MR_SESSION_V1_SIZE);
        assert_eq!(unsafe { export(&mut out, Some(&ok)) }, Ok(true));
        assert_eq!(c_str(&out.username).len(), 63);

        let slot = signed_in("t", &"u".repeat(64));
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(&slot)) };
        assert_eq!(r, Err(ExportError::TooLong { field: "username", len: 64, capacity: 64 }));
        assert_eq!(out, MrSessionV1::empty(), "nothing partial is left behind");
    }

    #[test]
    fn multibyte_utf8_counts_bytes() {
        // "é" is two bytes: 31 of them are 62 bytes and fit; 32 are 64 and do not.
        let slot = signed_in("t", &"é".repeat(31));
        let mut out = dirty(MR_SESSION_V1_SIZE);
        assert_eq!(unsafe { export(&mut out, Some(&slot)) }, Ok(true));
        assert_eq!(c_str(&out.username), "é".repeat(31));
        let slot = signed_in("t", &"é".repeat(32));
        let r = unsafe { export(&mut out, Some(&slot)) };
        assert_eq!(r, Err(ExportError::TooLong { field: "username", len: 64, capacity: 64 }));
    }

    #[test]
    fn interior_nul_is_an_error() {
        let slot = signed_in("t", "na\0me");
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(&slot)) };
        assert_eq!(r, Err(ExportError::InteriorNul { field: "username" }));
        assert_eq!(out, MrSessionV1::empty());
    }

    #[test]
    fn a_poisoned_session_lock_is_an_error() {
        let slot = signed_in("t", "n");
        let s2 = slot.clone();
        let _ = std::thread::spawn(move || {
            let _guard = s2.lock().unwrap();
            panic!("poison the session lock");
        })
        .join();
        let mut out = dirty(MR_SESSION_V1_SIZE);
        let r = unsafe { export(&mut out, Some(&slot)) };
        assert_eq!(r, Err(ExportError::Poisoned));
        assert_eq!(out, MrSessionV1::empty());
    }

    #[test]
    fn concurrent_readers_and_a_writer_see_whole_sessions() {
        let slot = signed_in("a", "first");
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let slot = slot.clone();
                std::thread::spawn(move || {
                    for _ in 0..2000 {
                        let mut out = MrSessionV1::empty();
                        let r = unsafe { export(&mut out, Some(&slot)) };
                        match r {
                            Ok(true) => {
                                let pair = (out.account_id, c_str(&out.username).to_owned());
                                assert!(pair == (42, "first".into()) || pair == (43, "second".into()), "{pair:?}");
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
                1 => {
                    let mut s = signed_in("b", "second").lock().unwrap().take().unwrap();
                    s.user_id = UserId(43);
                    Some(s)
                }
                _ => signed_in("a", "first").lock().unwrap().take(),
            };
        }
        for r in readers {
            r.join().unwrap();
        }
    }
}
