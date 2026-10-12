//! The one code site `Mp.Logout` needs from the game image: the front end's login-failure handler, which
//! empties the game's in-memory account name and password. Every other Lua site (the script host, its
//! namespace walker, `luaL_register`, `luaS_newlstr`, `luaG_errormsg`) is m2-sdk.dll's.
//!
//! Same rules as the ProtoSSL table ([`crate::signature`]): the pattern is scanned over the main module's
//! `.text` and must match **exactly once**; `call rel32` targets and absolute addresses are `??`. Copied
//! from `mercs2_nodrm_v3.exe` / `mercs2_unpacked.exe` (identical here); it also resolves in the retail v1.1
//! dump (`genuine_patched_unpacked.exe`), where the code sits elsewhere (tests below).
//!
//! | site | VA (unpacked) | what it is |
//! |---|---|---|
//! | `OnlineAccountClear` | `0x00848900` | the login-failure handler: empties the account name (`0x01176460`) and the password (`0x01176480`) with `mov byte [moffs32], al`, then posts the failure to the UI. `Mp.Logout` reads the two buffer addresses from it and empties them the same way; it is never called or patched |

use mercs2_formats::exe_image::Image;
use mercs2_formats::lua_sites::Pattern;
use thiserror::Error;

use crate::signature::CODE_SECTION;

pub const ACCOUNT_CLEAR_NAME: &str = "OnlineAccountClear";

/// sub esp,0x10; mov eax,[esp+0x14]; mov edx,[<game>]; push esi; mov [ecx+0x10],eax; xor eax,eax;
/// push edi; mov byte [<name>],al; mov byte [<password>],al; push eax; mov [ecx+0xd],al; ...
/// mov esi,[edx+0xa884]; ...; call <post>; pop edi; pop esi; add esp,0x10; ret 4
pub const ACCOUNT_CLEAR: &str = "83 ec 10 8b 44 24 14 8b 15 ?? ?? ?? ?? 56 89 41 10 33 c0 57 a2 ?? ?? ?? ?? a2 ?? ?? ?? ?? \
     50 88 41 0d 8b b2 84 a8 00 00 50 8d 4c 24 10 51 bf ?? ?? ?? ?? 89 44 24 14 e8 ?? ?? ?? ?? \
     5f 5e 83 c4 10 c2 04 00";

/// Offsets of the `mov byte [moffs32], al` (`a2`) instructions in [`ACCOUNT_CLEAR`] that empty the account
/// name and the password.
const CLEAR_NAME_AT: usize = 20;
const CLEAR_PASSWORD_AT: usize = 25;
/// The account-name buffer's size: the password buffer follows it (`FUN_00847760` fills both; `FUN_00848520`
/// copies the login screen's two strings into them).
pub const ACCOUNT_NAME_SIZE: u32 = 0x20;

/// Where the account-clear function was found, and the two buffers it empties.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountSites {
    pub clear: u32,
    /// The game's in-memory account name (`[Network] Username` copied in at online start).
    pub name: u32,
    /// The game's in-memory password, typed on the login screen.
    pub password: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccountSitesError {
    #[error("the image has no {CODE_SECTION} section")]
    NoCode,
    #[error("{ACCOUNT_CLEAR_NAME}: {0} matches of its signature, not exactly one")]
    Matches(usize),
    #[error(
        "{ACCOUNT_CLEAR_NAME} at {clear:#x} empties {name:#x} and {password:#x}; the password buffer must follow the \
         {ACCOUNT_NAME_SIZE:#x}-byte name buffer"
    )]
    NotAdjacent { clear: u32, name: u32, password: u32 },
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Find the account-clear function in `img`'s code and read the two buffer addresses from it.
pub fn resolve(img: &Image) -> Result<AccountSites, AccountSitesError> {
    let code = img.section(CODE_SECTION).ok_or(AccountSitesError::NoCode)?;
    let hits = Pattern::parse(ACCOUNT_CLEAR).expect("built-in pattern parses").find_all(code.bytes);
    let [at] = hits[..] else { return Err(AccountSitesError::Matches(hits.len())) };
    let clear = code.va + at as u32;
    let name = u32_at(code.bytes, at + CLEAR_NAME_AT + 1);
    let password = u32_at(code.bytes, at + CLEAR_PASSWORD_AT + 1);
    if password != name.wrapping_add(ACCOUNT_NAME_SIZE) {
        return Err(AccountSitesError::NotAdjacent { clear, name, password });
    }
    Ok(AccountSites { clear, name, password })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;

    const IMAGES: [&str; 3] = [testdata::EXES[0], testdata::EXES[1], testdata::V11_DUMP];

    /// Expected addresses per reference image (test oracle only), read with objdump: `mercs2_nodrm_v3.exe`
    /// and `mercs2_unpacked.exe` share one layout; the v1.1 dump has its own.
    fn expected(image: &str) -> AccountSites {
        if image == testdata::V11_DUMP {
            AccountSites { clear: 0x848b60, name: 0x1175460, password: 0x1175480 }
        } else {
            AccountSites { clear: 0x848900, name: 0x1176460, password: 0x1176480 }
        }
    }

    #[test]
    fn the_site_resolves_at_the_expected_va_in_all_three_images() {
        for image in IMAGES {
            let bytes = testdata::read_exe(image);
            let img = Image::from_file(&bytes).unwrap();
            assert_eq!(resolve(&img), Ok(expected(image)), "{image}");
        }
    }

    #[test]
    fn signature_bytes_are_the_exe_bytes_at_the_va() {
        // Independent of the scanner: every fixed byte equals the file byte at VA - 0x400000.
        for image in IMAGES {
            let bytes = testdata::read_exe(image);
            let p = Pattern::parse(ACCOUNT_CLEAR).unwrap();
            assert!(p.matches_at(&bytes, (expected(image).clear - 0x400000) as usize), "{image}");
        }
    }

    #[test]
    fn the_buffer_offsets_are_moves_with_wildcarded_addresses() {
        let clear: Vec<&str> = ACCOUNT_CLEAR.split_whitespace().collect();
        for at in [CLEAR_NAME_AT, CLEAR_PASSWORD_AT] {
            assert_eq!(clear[at], "a2", "offset {at}");
            assert_eq!(clear[at + 1..at + 5], ["??"; 4], "offset {at}");
        }
    }

    #[test]
    fn the_buffers_must_be_adjacent_and_the_site_unique() {
        let mut bytes = testdata::read_exe(testdata::EXES[0]).to_vec();
        let at = (expected(testdata::EXES[0]).clear - 0x400000) as usize;
        bytes[at + CLEAR_PASSWORD_AT + 1] ^= 0x40;
        let img = Image::from_file(&bytes).unwrap();
        assert!(matches!(resolve(&img), Err(AccountSitesError::NotAdjacent { name: 0x1176460, .. })));
        bytes[at] = 0xcc;
        let img = Image::from_file(&bytes).unwrap();
        assert_eq!(resolve(&img), Err(AccountSitesError::Matches(0)));
    }
}
