//! The game's GameSpy Voice entry points, which the ASI detours so in-game voice never starts.
//!
//! The game starts voice when a peer enters a game: its session callbacks call `GVInitialize` and then
//! `GVStartup` back to back and ignore `GVInitialize`'s result (`FUN_00845110` at `0x845256`/`0x84525b`,
//! `FUN_00845cc0` at `0x845e21`/`0x845e26`). `GVInitialize` binds UDP `0.0.0.0:55123`; when that bind fails
//! it returns before setting the codec's frame size, and `GVStartup`'s capture-buffer setup then divides by
//! it (`0x849EEB`). With both detoured to do nothing, neither device pointer is set, both callers take the
//! game's own no-voice branch, and the per-frame voice think (`FUN_00846d80`, gated on the voice-active flag)
//! never runs. Players use external voice chat.
//!
//! Same rules as the ProtoSSL table ([`crate::signature`]): each pattern is scanned over the main module's
//! `.text` and must match **exactly once**; `call rel32` targets and absolute addresses are `??`. Copied from
//! `mercs2_nodrm_v3.exe` / `mercs2_unpacked.exe` (identical here); both also resolve in the retail v1.1 dump
//! (`genuine_patched_unpacked.exe`), where the code sits 0x260 higher (tests below).
//!
//! | site | VA (unpacked) | what it is |
//! |---|---|---|
//! | `GVInitialize` | `0x00846f40` | `WSAStartup(0x101)`, UDP socket, non-blocking, bind `0.0.0.0:55123`, peer address from EDI, sample rate, codec frame sizes; returns 0 on failure |
//! | `GVStartup` | `0x00847170` | enumerates audio devices (loops until at least one exists), creates the DirectSound playback and capture devices, sets the capture threshold, starts both |

use mercs2_formats::exe_image::Image;
use mercs2_formats::lua_sites::Pattern;
use thiserror::Error;

use crate::signature::CODE_SECTION;

/// The detoured GameSpy Voice functions, in table order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VoiceFn {
    Initialize,
    Startup,
}

impl VoiceFn {
    pub const ALL: [VoiceFn; 2] = [VoiceFn::Initialize, VoiceFn::Startup];

    pub fn name(self) -> &'static str {
        match self {
            VoiceFn::Initialize => "GVInitialize",
            VoiceFn::Startup => "GVStartup",
        }
    }

    /// Signature, as space-separated hex bytes with `??` wildcards.
    pub fn pattern(self) -> &'static str {
        match self {
            // push ebp; mov ebp,esp; and esp,-16; sub esp,0x41c; push esi; WSAStartup(0x101, &wsa);
            // [socket] = socket(2, 2, 0x11); == -1 → sprintf("GVInitialize: Failed to create socket")
            VoiceFn::Initialize => {
                "55 8b ec 83 e4 f0 81 ec 1c 04 00 00 56 8d 44 24 20 50 68 01 01 00 00 e8 ?? ?? ?? ?? 6a 11 be 02 \
                 00 00 00 56 56 e8 ?? ?? ?? ?? 83 f8 ff a3 ?? ?? ?? ?? 75 24 8d 4c 24 20 68 ?? ?? ?? ?? 51 e8 ?? \
                 ?? ?? ?? 83 c4 08"
            }
            // sub esp,0x5a4; sprintf("GVStartup: Checking for devices"); OutputDebugStringA;
            // do { n = enumerate(); Sleep(10); } while (n == 0)
            VoiceFn::Startup => {
                "81 ec a4 05 00 00 53 55 56 57 8d 44 24 18 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? 83 \
                 c4 08 8d 4c 24 18 51 ff d5 8b 3d ?? ?? ?? ?? 90 8d 84 24 18 02 00 00 e8 ?? ?? ?? ?? 6a 0a 8b f0 \
                 ff d7 85 f6 74 ea"
            }
        }
    }
}

/// Where each GameSpy Voice function was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoiceSites {
    pub initialize: u32,
    pub startup: u32,
}

impl VoiceSites {
    pub fn va(&self, f: VoiceFn) -> u32 {
        match f {
            VoiceFn::Initialize => self.initialize,
            VoiceFn::Startup => self.startup,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VoiceSitesError {
    #[error("the image has no {CODE_SECTION} section")]
    NoCode,
    #[error("GameSpy Voice signatures did not resolve to exactly one match each: {0}")]
    Matches(String),
}

/// Find both GameSpy Voice functions in `img`'s code.
pub fn resolve(img: &Image) -> Result<VoiceSites, VoiceSitesError> {
    let code = img.section(CODE_SECTION).ok_or(VoiceSitesError::NoCode)?;
    let hits: Vec<(VoiceFn, Vec<usize>)> = VoiceFn::ALL
        .iter()
        .map(|&f| (f, Pattern::parse(f.pattern()).expect("built-in pattern parses").find_all(code.bytes)))
        .collect();
    if hits.iter().any(|(_, h)| h.len() != 1) {
        let detail = hits.iter().map(|(f, h)| format!("{}={} match(es)", f.name(), h.len())).collect::<Vec<_>>().join(", ");
        return Err(VoiceSitesError::Matches(detail));
    }
    let va = |f: VoiceFn| code.va + hits.iter().find(|(g, _)| *g == f).expect("every function scanned").1[0] as u32;
    Ok(VoiceSites { initialize: va(VoiceFn::Initialize), startup: va(VoiceFn::Startup) })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testdata;

    const IMAGES: [&str; 3] = [testdata::EXES[0], testdata::EXES[1], testdata::V11_DUMP];

    /// Expected addresses per reference image (test oracle only), read with objdump: `mercs2_nodrm_v3.exe`
    /// and `mercs2_unpacked.exe` share one layout; the v1.1 dump has the same code 0x260 higher.
    pub(crate) fn expected(image: &str) -> VoiceSites {
        if image == testdata::V11_DUMP {
            VoiceSites { initialize: 0x8471a0, startup: 0x8473d0 }
        } else {
            VoiceSites { initialize: 0x846f40, startup: 0x847170 }
        }
    }

    #[test]
    fn both_sites_resolve_at_the_expected_va_in_all_three_images() {
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
            for f in VoiceFn::ALL {
                let p = Pattern::parse(f.pattern()).unwrap();
                assert!(p.matches_at(&bytes, (expected(image).va(f) - 0x400000) as usize), "{image} {}", f.name());
            }
        }
    }

    #[test]
    fn a_missing_site_fails_resolution_naming_each_count() {
        let mut bytes = testdata::read_exe(testdata::EXES[0]).to_vec();
        bytes[(expected(testdata::EXES[0]).startup - 0x400000) as usize] = 0xcc;
        let img = Image::from_file(&bytes).unwrap();
        assert_eq!(
            resolve(&img),
            Err(VoiceSitesError::Matches("GVInitialize=1 match(es), GVStartup=0 match(es)".into()))
        );
    }
}
