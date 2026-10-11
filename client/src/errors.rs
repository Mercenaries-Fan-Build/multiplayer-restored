//! `mercs2_mp_api::ApiError` → FESL `errorCode` / `localizedMessage`.
//!
//! The only error-code → UI mapping found in the exe is the login-result handler `FUN_006caf20`, which
//! turns `errorCode` into a stringdb key. The keys were resolved against the shipped English stringdb
//! (`shell.wad`, `blocks\Shell\english_P000_Q3.block#2`, dumped with `mercs2_probe stringdb_dump`):
//!
//! | code | stringdb key | text |
//! |---|---|---|
//! | 101 | `0xDB23598B` | Connection failed. Your account was not found. |
//! | 102 | `0x2C18D3CE` | Connection failed. Your account has been disabled. |
//! | 103 | `0x2994CA42` | Connection failed. Your account has been banned. |
//! | 120 | `0x2E0C603A` | Connection failed. Your account is not entitled to play the game online. |
//! | 250 | `0x0D1B343C` | Connection failed. Your account has been deactivated. |
//! | −165 | `0xD6F8D178` | (Xbox LIVE date-of-birth message) |
//! | −221 | `0x0AD7E491` | (Xbox LIVE gamer-profile message) |
//! | other | `0xDE375957` | Cannot connect to the EA Servers. |
//!
//! Mapping policy: `bad_credentials` → 101 (the nearest evidenced meaning — the server deliberately does
//! not distinguish unknown user from wrong password). Every other `ErrorCode` has no evidenced FESL code,
//! so it uses [`GENERIC_ERROR_CODE`], which is outside the table and therefore shows the generic
//! "Cannot connect" text; `localizedMessage` carries the server's message. The AddAccount reply parser was
//! not located in the exe (catalogue §1 acct), so which of these the create-account screen displays is
//! only verifiable in game.

use mercs2_mp_api::{ApiError, ErrorCode};

/// Login result "account was not found" (`FUN_006caf20`, stringdb `0xDB23598B`).
pub const ACCOUNT_NOT_FOUND: i64 = 101;

/// A code outside `FUN_006caf20`'s table: the game shows its default "Cannot connect to the EA Servers."
/// The specific value has no meaning in the exe beyond being non-zero and unlisted.
pub const GENERIC_ERROR_CODE: i64 = 99;

/// The codes `FUN_006caf20` maps to specific strings (test oracle for [`GENERIC_ERROR_CODE`]).
pub const LOGIN_TABLE_CODES: [i64; 7] = [101, 102, 103, 120, 250, -165, -221];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeslError {
    pub code: i64,
    pub message: String,
}

pub fn map_api_error(e: &ApiError) -> FeslError {
    let code = match e.code {
        ErrorCode::BadCredentials => ACCOUNT_NOT_FOUND,
        ErrorCode::InvalidField
        | ErrorCode::NameTaken
        | ErrorCode::Unauthorized
        | ErrorCode::RateLimited
        | ErrorCode::NotFound
        | ErrorCode::Forbidden
        | ErrorCode::GameFull
        | ErrorCode::GameClosed
        | ErrorCode::JoinDenied
        | ErrorCode::Unsupported
        | ErrorCode::Internal => GENERIC_ERROR_CODE,
    };
    FeslError { code, message: e.message.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_code_is_outside_the_login_table() {
        assert!(!LOGIN_TABLE_CODES.contains(&GENERIC_ERROR_CODE));
        assert_ne!(GENERIC_ERROR_CODE, 0);
    }

    #[test]
    fn login_table_matches_the_exe() {
        // FUN_006caf20 compares against 0x66 (102), -0xdd (-221), -0xa5 (-165), 0x65 (101), 0x67 (103),
        // 0x78 (120), 0xfa (250); the stringdb hashes it loads are the immediates below.
        let exe = crate::testdata::read_exe("mercs2_unpacked.exe");
        let text = &exe[0x1000..0x1000 + 0x704000];
        for (hash, code) in [
            (0xdb23598bu32, 101),
            (0x2c18d3ce, 102),
            (0x2994ca42, 103),
            (0x2e0c603a, 120),
            (0x0d1b343c, 250),
            (0xd6f8d178, -165),
            (0x0ad7e491, -221),
        ] {
            assert!(LOGIN_TABLE_CODES.contains(&code));
            // `mov reg, imm32` / `push imm32` both embed the little-endian immediate.
            let imm = hash.to_le_bytes();
            let vas: Vec<usize> =
                text.windows(4).enumerate().filter(|(_, w)| *w == imm).map(|(p, _)| p + 0x401000).collect();
            assert!(vas.iter().any(|va| (0x6caf20..0x6cb1a2).contains(va)), "{hash:#x} found at {vas:#x?}");
        }
    }

    #[test]
    fn mapping() {
        let e = ApiError::new(ErrorCode::BadCredentials, "wrong username or password");
        assert_eq!(map_api_error(&e), FeslError { code: 101, message: "wrong username or password".into() });
        let e = ApiError::new(ErrorCode::NameTaken, "taken");
        assert_eq!(map_api_error(&e).code, GENERIC_ERROR_CODE);
        let e = ApiError::new(ErrorCode::RateLimited, "slow down");
        assert_eq!(map_api_error(&e).code, GENERIC_ERROR_CODE);
    }
}
