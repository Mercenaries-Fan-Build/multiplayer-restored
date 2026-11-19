//! `Pg.SetCheatsUsed` / `Pg.WereCheatsUsed`, and where PC keeps the flag.
//!
//! * `Pg.SetCheatsUsed(used)` (PS3 v1.03 `0x00554B30`): a boolean or nil argument (`0x00503D38` accepts Lua
//!   types 1 and 0 and stores `toboolean`, so nil clears it); any other argument, or none, pushes nil. The PS3
//!   setter `0x001C15A8` writes the byte at save-record offset `0x4E`.
//! * `Pg.WereCheatsUsed()` (PS3 `0x00550B50`): pushes the byte as a boolean.
//!
//! PC has the same save record and the same byte, which no PC code sets: the record is
//! `R = singleton + 0x18` (header `{4, 0x3458}` there in every v1.0 memory dump), so the flag is
//! [`CHEATS_USED`] = singleton `+0x66`, file offset `0x52` of the `.profile`. The record resets zero it (`0x634860`
//! `mov [edi+0x4e], bl` with `EDI = R`, and the new-game reset `0x6355F0`), and the save writes and the load
//! reads the whole record, so the byte goes out and comes back with the save (`docs/reverse_engineer/dlc_cheats_gate.md`).
//!
//! The singleton is the object behind a global pointer, found by [`PROFILE_POINTER`]: `Player.GetCash`, which
//! reads the cash at singleton `+0x2C`. v1.1 `0x005DF430` reads `[0x01175054]`, v1.0 `0x005DF440` `[0x01176054]`.
//!
//! Not ported (both INFERRED, left out by decision): the PS3 setter also marks the record dirty (PS3 `G+8`;
//! PC `+0x11` by matching write patterns) and queues net message `0x32 {G+0xAD}` (PC `0x3B {+0xB5}`). Without
//! them the flag reaches the `.profile` with the next save of the record. The other PS3 consumers of the flag
//! (achievements, autosave, money milestones) are not gated here; only `Net.LeaderboardPushScore` reads it.

use mercs2_formats::exe_image::Image;
use mercs2_formats::lua_sites::Pattern;
use mercs2_formats::mod_runtime::lua::{Lua, Ret, TBOOLEAN, TNIL};

/// The one match of `pattern` in `.text`, or an error naming how many there were.
fn find_once(img: &Image, what: &str, pattern: &str) -> Result<u32, String> {
    let text = img.section(".text").ok_or("the image has no .text section")?;
    let p = Pattern::parse(pattern).map_err(|e| format!("{what}: the pattern does not parse: {e:?}"))?;
    match p.find_all(text.bytes)[..] {
        [one] => Ok(text.va + one as u32),
        ref all => Err(format!("{what} matched {} time(s) in .text, not once", all.len())),
    }
}

/// The cheats-used byte, from the singleton.
pub const CHEATS_USED: u32 = 0x66;

/// `Player.GetCash`: `mov eax, [singleton pointer]; push esi; mov esi, [esp+8]; push edi; mov edi, [eax+0x2c];
/// mov eax, 1; mov ecx, esi; call <checkstack>; test eax, eax; je; mov eax, [esi+8]; cvtsi2ss xmm0, edi;
/// movss [eax], xmm0; mov dword [eax+4], 3; add dword [esi+8], 8; pop edi; mov eax, 1; pop esi; ret`.
pub const PROFILE_POINTER: &str = "a1 ?? ?? ?? ?? 56 8b 74 24 08 57 8b 78 2c b8 01 00 00 00 8b ce e8 ?? ?? ?? ?? 85 c0 74 16 \
     8b 46 08 f3 0f 2a c7 f3 0f 11 00 c7 40 04 03 00 00 00 83 46 08 08 5f b8 01 00 00 00 5e c3";
/// Where the pointer's address sits in the match.
const POINTER_AT: usize = 1;

/// The address of the global that points at the save-record singleton.
pub fn resolve_profile_pointer(img: &Image) -> Result<u32, String> {
    let at = find_once(img, "Player.GetCash (the save-record singleton's pointer)", PROFILE_POINTER)?;
    let b = img.bytes_at(at + POINTER_AT as u32).ok_or_else(|| format!("{at:#x} is not in the image"))?;
    let ptr = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    if img.u32_at(ptr).is_none() {
        return Err(format!("Player.GetCash at {at:#x} reads the singleton through {ptr:#x}, which is not in the image"));
    }
    Ok(ptr)
}

/// The flag's storage.
pub trait CheatsFlag {
    fn read(&self) -> Result<bool, String>;
    fn write(&mut self, used: bool) -> Result<(), String>;
}

/// `Pg.SetCheatsUsed(used)`.
pub fn set_cheats_used<L: Lua, F: CheatsFlag>(s: &mut L, f: &mut F) -> Ret {
    let t = s.arg_type(0);
    if t != TBOOLEAN && t != TNIL {
        s.push_nil();
        return Ret::Values(1);
    }
    let used = s.arg_bool(0).unwrap_or(false);
    match f.write(used) {
        Ok(()) => Ret::Values(0),
        Err(e) => Ret::Raise(format!("Pg.SetCheatsUsed: {e}")),
    }
}

/// `Pg.WereCheatsUsed()`.
pub fn were_cheats_used<L: Lua, F: CheatsFlag>(s: &mut L, f: &F) -> Ret {
    match f.read() {
        Ok(used) => {
            s.push_bool(used);
            Ret::Values(1)
        }
        Err(e) => Ret::Raise(format!("Pg.WereCheatsUsed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mercs2_formats::mod_runtime::lua::fake::{FakeLua, Val, s};

    struct Byte(Option<bool>);

    impl CheatsFlag for Byte {
        fn read(&self) -> Result<bool, String> {
            self.0.ok_or_else(|| "the singleton pointer is NULL".to_string())
        }
        fn write(&mut self, used: bool) -> Result<(), String> {
            match self.0 {
                Some(_) => {
                    self.0 = Some(used);
                    Ok(())
                }
                None => Err("the singleton pointer is NULL".into()),
            }
        }
    }

    #[test]
    fn set_takes_a_boolean_or_nil_like_the_ps3_reader() {
        let mut f = Byte(Some(false));
        assert_eq!(set_cheats_used(&mut FakeLua::with(vec![Val::Bool(true)]), &mut f), Ret::Values(0));
        assert_eq!(f.0, Some(true));
        assert_eq!(set_cheats_used(&mut FakeLua::with(vec![Val::Nil]), &mut f), Ret::Values(0));
        assert_eq!(f.0, Some(false), "nil is toboolean(nil) = false");
        assert_eq!(set_cheats_used(&mut FakeLua::with(vec![Val::Bool(true)]), &mut f), Ret::Values(0));
        assert_eq!(set_cheats_used(&mut FakeLua::with(vec![Val::Bool(false)]), &mut f), Ret::Values(0));
        assert_eq!(f.0, Some(false));
    }

    #[test]
    fn set_with_no_argument_or_another_type_pushes_nil_and_writes_nothing() {
        for args in [vec![], vec![Val::Num(1.0)], vec![s("true")], vec![Val::Table], vec![Val::Light(1)]] {
            let mut f = Byte(Some(true));
            let mut l = FakeLua::with(args.clone());
            assert_eq!(set_cheats_used(&mut l, &mut f), Ret::Values(1), "{args:?}");
            assert_eq!(l.pushed, [Val::Nil], "{args:?}");
            assert_eq!(f.0, Some(true), "{args:?}");
        }
    }

    #[test]
    fn were_pushes_the_flag_and_ignores_arguments() {
        for used in [false, true] {
            let mut l = FakeLua::with(vec![Val::Num(3.0)]);
            assert_eq!(were_cheats_used(&mut l, &Byte(Some(used))), Ret::Values(1));
            assert_eq!(l.pushed, [Val::Bool(used)]);
        }
    }

    #[test]
    fn an_unreadable_flag_raises() {
        let mut l = FakeLua::default();
        assert!(matches!(were_cheats_used(&mut l, &Byte(None)), Ret::Raise(m) if m.contains("NULL")));
        assert!(matches!(set_cheats_used(&mut FakeLua::with(vec![Val::Bool(true)]), &mut Byte(None)), Ret::Raise(m) if m.contains("NULL")));
    }

    /// The three PC executables: the pattern matches once in each, and reads the pointer the decomp shows.
    #[test]
    fn the_singleton_pointer_resolves_once_in_every_pc_build() {
        use crate::testdata;
        for (file, want) in [
            (testdata::V11_DUMP, 0x0117_5054u32),
            ("mercs2_unpacked.exe", 0x0117_6054),
            ("mercs2_nodrm_v3.exe", 0x0117_6054),
        ] {
            let bytes = testdata::read_exe(file);
            let img = Image::from_file(&bytes).unwrap_or_else(|e| panic!("{file}: {e}"));
            assert_eq!(resolve_profile_pointer(&img), Ok(want), "{file}");
        }
    }
}
