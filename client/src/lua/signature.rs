//! Byte signatures for the seven code sites the `Mp` namespace needs, and the structural checks that tie
//! them together.
//!
//! Same rules as the ProtoSSL table ([`crate::signature`]): every pattern is scanned over the main
//! module's `.text` and must match **exactly once**; `call rel32` targets and absolute addresses are
//! `??`. Patterns were copied from `mercs2_nodrm_v3.exe` / `mercs2_unpacked.exe` (identical for these
//! functions) and also resolve in the retail v1.1 dump (`genuine_patched_unpacked.exe`), where the code
//! sits at other addresses (tests below). Roles, from the disassembly of `mercs2_unpacked.exe`:
//!
//! | site | VA (unpacked) | what it is |
//! |---|---|---|
//! | [`LuaFn::RegisterNamespaces`] | `0x005A2C40` | `__stdcall (host)`, `ret 4`: pushes the `_SYS` hooks, then walks the 31-row namespace registry at `0x00DFD478` registering each table on `host+0x10` (the `lua_State`) and running its boot chunk. The ASI detours this. |
//! | [`LuaFn::ScriptHostInit`] | `0x005A1760` | `__thiscall (host)`: if `host+0xC42 == 0`, sets it, creates the `lua_State` (stored at `+0x10` and `+0x14`) and calls `RegisterNamespaces` (the `call` at pattern offset 71) |
//! | [`LuaFn::ScriptHostCtor`] | `0x005A1677` | the static constructor's stores: vtable → host, host → global; `mov eax, host; ret` |
//! | [`LuaFn::LuaLRegister`] | `0x0085F500` | Lua 5.1 `luaL_register` with the engine's register ABI: `ECX = L`, `EAX = libname`, table pushed, caller pops (the `"name conflict for module"` string is referenced inside it) |
//! | [`LuaFn::LuaSNewLStr`] | `0x0086A2B0` | `luaS_newlstr(L, str, len)`, cdecl, returns the `TString*` (`luaI_openlib`'s `lua_setfield` calls it with `push len; push str; push L`) |
//! | [`LuaFn::LuaGErrorMsg`] | `0x0085EEA0` | `luaG_errormsg(L)` with `L` in `EAX`: runs `L->errfunc` (`+0x60`) if set, then `luaD_throw(L, LUA_ERRRUN)` (`longjmp`); `error()` (`0x00860480`) ends in it |
//! | [`LuaFn::AccountClear`] | `0x00848900` | the front end's login-failure handler: empties the account name (`0x01176460`) and the password (`0x01176480`) with `mov byte [moffs32], al`, then posts the failure to the UI. `Mp.Logout` reads the two buffer addresses from it and empties them the same way; it is never called or patched |

use thiserror::Error;

use crate::signature::Pattern;

/// The code sites, in table order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LuaFn {
    RegisterNamespaces,
    ScriptHostInit,
    ScriptHostCtor,
    LuaLRegister,
    LuaSNewLStr,
    LuaGErrorMsg,
    AccountClear,
}

/// Offset of the `lua_State*` in the script host (`mov [esi+0x10], eax` in [`LuaFn::ScriptHostInit`],
/// `mov esi, [ebp+0x10]` in [`LuaFn::RegisterNamespaces`]; both are fixed bytes of the patterns).
pub const HOST_LUA_STATE: u32 = 0x10;
/// Offset of the host's "a `lua_State` exists" byte (`cmp byte [esi+0xC42], 0` / `mov byte [esi+0xC42], 1`
/// in [`LuaFn::ScriptHostInit`]; fixed bytes of the pattern).
pub const HOST_INITIALISED: u32 = 0xC42;
/// The vtable slot holding [`LuaFn::ScriptHostInit`] (the system loop `FUN_004C0730` calls slot `+0x14`
/// to start a system and `+0x18` to stop it).
pub const HOST_VTABLE_INIT_SLOT: u32 = 0x14;

/// Offset of the `call RegisterNamespaces` instruction inside the [`LuaFn::ScriptHostInit`] pattern.
const INIT_CALL_AT: usize = 71;

/// Offsets of the `mov byte [moffs32], al` (`a2`) instructions in [`LuaFn::AccountClear`] that empty the
/// account name and the password.
const CLEAR_NAME_AT: usize = 20;
const CLEAR_PASSWORD_AT: usize = 25;
/// The account-name buffer's size: the password buffer follows it (`FUN_00847760` fills both; `FUN_00848520`
/// copies the login screen's two strings into them).
pub const ACCOUNT_NAME_SIZE: u32 = 0x20;

impl LuaFn {
    pub const ALL: [LuaFn; 7] = [
        LuaFn::RegisterNamespaces,
        LuaFn::ScriptHostInit,
        LuaFn::ScriptHostCtor,
        LuaFn::LuaLRegister,
        LuaFn::LuaSNewLStr,
        LuaFn::LuaGErrorMsg,
        LuaFn::AccountClear,
    ];

    /// The sites the ASI detours (the others are called or read, never patched).
    pub const HOOKED: [LuaFn; 1] = [LuaFn::RegisterNamespaces];

    pub fn name(self) -> &'static str {
        match self {
            LuaFn::RegisterNamespaces => "ScriptHostRegisterNamespaces",
            LuaFn::ScriptHostInit => "ScriptHostInit",
            LuaFn::ScriptHostCtor => "ScriptHostCtor",
            LuaFn::LuaLRegister => "luaL_register",
            LuaFn::LuaSNewLStr => "luaS_newlstr",
            LuaFn::LuaGErrorMsg => "luaG_errormsg",
            LuaFn::AccountClear => "OnlineAccountClear",
        }
    }

    /// Signature, as space-separated hex bytes with `??` wildcards.
    pub fn pattern(self) -> &'static str {
        match self {
            // push ebx; push ebp; mov ebp,[esp+0xc] (host); push esi; mov esi,[ebp+0x10] (L); push edi;
            // three times: push <cfunc>; xor eax,eax; call lua_pushcclosure; luaD_call(L, top-8, 0) ...
            // then four nil pushes via [L+8], and `mov edi, <name>; mov ecx, LUA_GLOBALSINDEX; call`
            LuaFn::RegisterNamespaces => {
                "53 55 8b 6c 24 0c 56 8b 75 10 57 68 ?? ?? ?? ?? 33 c0 e8 ?? ?? ?? ?? 8b 46 08 33 db 53 83 \
                 e8 08 50 56 e8 ?? ?? ?? ?? 8b 75 10 68 ?? ?? ?? ?? 33 c0 e8 ?? ?? ?? ?? 8b 4e 08 53 83 e9 \
                 08 51 56 e8 ?? ?? ?? ?? 8b 75 10 68 ?? ?? ?? ?? 33 c0 e8 ?? ?? ?? ?? 8b 56 08 53 83 ea 08 \
                 52 56 e8 ?? ?? ?? ?? 8b 75 10 8b 46 08 89 58 04 83 46 08 08 83 c4 30 bf ?? ?? ?? ?? b9 ee \
                 d8 ff ff e8"
            }
            // push esi; mov esi,ecx; cmp byte [esi+0xc42],0; jne <out>; push edi; mov byte [esi+0xc42],1;
            // call lua_open; push 0xc00; mov [esi+0x10],eax; mov [esi+0x14],eax; lea eax,[esi+0x28]; push 0;
            // push eax; call memset; add esp,0xc; push 0x10; mov edi,esi; call ...; push esi;
            // mov dword [esi+0x20],0; call RegisterNamespaces
            LuaFn::ScriptHostInit => {
                "56 8b f1 80 be 42 0c 00 00 00 0f 85 ?? ?? ?? ?? 57 c6 86 42 0c 00 00 01 e8 ?? ?? ?? ?? 68 \
                 00 0c 00 00 89 46 10 89 46 14 8d 46 28 6a 00 50 e8 ?? ?? ?? ?? 83 c4 0c 6a 10 8b fe e8 ?? \
                 ?? ?? ?? 56 c7 46 20 00 00 00 00 e8 ?? ?? ?? ??"
            }
            // mov [host], vtable; mov [global], host; movss [..], xmm0; movss [..], xmm0; mov eax, host; ret
            LuaFn::ScriptHostCtor => {
                "c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? f3 0f 11 05 ?? ?? ?? ?? f3 0f 11 \
                 05 ?? ?? ?? ?? b8 ?? ?? ?? ?? c3"
            }
            // push ebp; mov ebp,esp; and esp,-8; sub esp,0xc; push ebx; mov ebx,[ebp+8] (l); push esi;
            // push edi; mov edi,eax (libname); test edi,edi; mov esi,ecx (L); jz <no libname>;
            // count the luaL_Reg rows (8 bytes each) up to a NULL name; push ecx
            LuaFn::LuaLRegister => {
                "55 8b ec 83 e4 f8 83 ec 0c 53 8b 5d 08 56 57 8b f8 85 ff 8b f1 0f 84 b9 00 00 00 33 c9 39 \
                 0b 8b c3 89 4c 24 0c 74 0f 83 c0 08 83 c1 01 83 38 00 75 f5 89 4c 24 0c 51"
            }
            // h = len; step = (len>>5)+1; hash loop; G(L)->strt.hash[h & (size-1)]; compare ts->len (+0xc)
            LuaFn::LuaSNewLStr => {
                "55 8b ec 83 e4 f8 83 ec 0c 53 56 57 8b 7d 10 8b c7 c1 e8 05 83 c0 01 3b f8 8b d7 89 7c 24 \
                 14 8b cf 72 22 8b 75 0c 0f b6 74 0e ff 8b da c1 e3 05 03 f3 8b da c1 eb 02 03 f3 2b c8 33 \
                 d6 3b c8 73 e2 89 54 24 14 8b 45 08 8b 40 10 8b 48 08 8b 00 83 e9 01 23 ca 8b 04 88 85 c0 \
                 89 44 24 10 0f 84 ?? ?? ?? ?? 39 78 0c"
            }
            // push esi; mov esi,eax (L); mov eax,[esi+0x60] (errfunc); test; push edi; jz <throw>;
            // errfunc must be a function (tt 6) else luaD_throw(L, LUA_ERRERR=5); move the message up
            LuaFn::LuaGErrorMsg => {
                "56 8b f0 8b 46 60 85 c0 57 74 6f 8b 7e 20 03 f8 83 7f 04 06 74 0b 6a 05 56 e8 ?? ?? ?? ?? \
                 83 c4 08 8b 46 08 8b 48 f8 89 08 8b 50 fc 89 50 04 8b 46 08 8b 0f 83 e8 08 89 08 8b 57 04 \
                 89 50 04"
            }
            // sub esp,0x10; mov eax,[esp+0x14]; mov edx,[<game>]; push esi; mov [ecx+0x10],eax; xor eax,eax;
            // push edi; mov byte [<name>],al; mov byte [<password>],al; push eax; mov [ecx+0xd],al; ...
            // mov esi,[edx+0xa884]; ...; call <post>; pop edi; pop esi; add esp,0x10; ret 4
            LuaFn::AccountClear => {
                "83 ec 10 8b 44 24 14 8b 15 ?? ?? ?? ?? 56 89 41 10 33 c0 57 a2 ?? ?? ?? ?? a2 ?? ?? ?? ?? \
                 50 88 41 0d 8b b2 84 a8 00 00 50 8d 4c 24 10 51 bf ?? ?? ?? ?? 89 44 24 14 e8 ?? ?? ?? ?? \
                 5f 5e 83 c4 10 c2 04 00"
            }
        }
    }
}

/// Where every site was found, and the script host's address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LuaSites {
    va: [u32; 7],
    host: u32,
    account_name: u32,
    account_password: u32,
}

impl LuaSites {
    pub fn va(&self, f: LuaFn) -> u32 {
        self.va[f as usize]
    }
    /// The script host singleton (`this` of [`LuaFn::ScriptHostInit`]).
    pub fn host(&self) -> u32 {
        self.host
    }
    /// The game's in-memory account name (`[Network] Username` copied in at online start).
    pub fn account_name(&self) -> u32 {
        self.account_name
    }
    /// The game's in-memory password, typed on the login screen.
    pub fn account_password(&self) -> u32 {
        self.account_password
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LuaResolveError {
    #[error("Lua signatures did not resolve to exactly one match each: {0}")]
    Matches(String),
    #[error(
        "ScriptHostInit at {init:#x} calls {called:#x}, not ScriptHostRegisterNamespaces at {walker:#x}"
    )]
    InitCallsElsewhere { init: u32, called: u32, walker: u32 },
    #[error("ScriptHostCtor at {ctor:#x} is inconsistent: {why}")]
    Ctor { ctor: u32, why: String },
    #[error(
        "OnlineAccountClear at {clear:#x} empties {name:#x} and {password:#x}; the password buffer must follow the \
         {ACCOUNT_NAME_SIZE:#x}-byte name buffer"
    )]
    AccountBuffers { clear: u32, name: u32, password: u32 },
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Scan `code` (the code section's bytes) for every site and check that they belong together.
/// `va_of(offset)` turns a section offset into a VA; `read_u32(va)` reads the image at any VA (`None`
/// when unreadable) — used for the host's vtable in `.rdata`.
pub fn resolve(
    code: &[u8],
    va_of: impl Fn(usize) -> u32,
    read_u32: impl Fn(u32) -> Option<u32>,
) -> Result<LuaSites, LuaResolveError> {
    let hits: Vec<(LuaFn, Vec<usize>)> = LuaFn::ALL
        .iter()
        .map(|&f| (f, Pattern::parse(f.pattern()).expect("built-in pattern parses").find_all(code)))
        .collect();
    if !hits.iter().all(|(_, h)| h.len() == 1) {
        return Err(LuaResolveError::Matches(
            hits.iter().map(|(f, h)| format!("{}={} match(es)", f.name(), h.len())).collect::<Vec<_>>().join(", "),
        ));
    }
    let off = |f: LuaFn| hits[f as usize].1[0];
    let mut va = [0u32; 7];
    for f in LuaFn::ALL {
        va[f as usize] = va_of(off(f));
    }

    // ScriptHostInit's call must land on the walker we are about to detour.
    let init_off = off(LuaFn::ScriptHostInit);
    let rel = u32_at(code, init_off + INIT_CALL_AT + 1);
    let called = va[LuaFn::ScriptHostInit as usize].wrapping_add(INIT_CALL_AT as u32 + 5).wrapping_add(rel);
    if called != va[LuaFn::RegisterNamespaces as usize] {
        return Err(LuaResolveError::InitCallsElsewhere {
            init: va[LuaFn::ScriptHostInit as usize],
            called,
            walker: va[LuaFn::RegisterNamespaces as usize],
        });
    }

    // The constructor: [host] = vtable; [global] = host; eax = host; and vtable[+0x14] == ScriptHostInit.
    let c = off(LuaFn::ScriptHostCtor);
    let ctor = va[LuaFn::ScriptHostCtor as usize];
    let host = u32_at(code, c + 2);
    let vtable = u32_at(code, c + 6);
    let published = u32_at(code, c + 16);
    let returned = u32_at(code, c + 37);
    if published != host || returned != host {
        return Err(LuaResolveError::Ctor {
            ctor,
            why: format!("stores vtable at {host:#x} but publishes {published:#x} and returns {returned:#x}"),
        });
    }
    let slot = vtable.wrapping_add(HOST_VTABLE_INIT_SLOT);
    match read_u32(slot) {
        Some(f) if f == va[LuaFn::ScriptHostInit as usize] => {}
        Some(f) => {
            return Err(LuaResolveError::Ctor {
                ctor,
                why: format!(
                    "vtable {vtable:#x} slot +{HOST_VTABLE_INIT_SLOT:#x} is {f:#x}, not ScriptHostInit {:#x}",
                    va[LuaFn::ScriptHostInit as usize]
                ),
            });
        }
        None => {
            return Err(LuaResolveError::Ctor { ctor, why: format!("vtable slot {slot:#x} is not readable") });
        }
    }

    // The account-clear function empties the name buffer and the password buffer right after it.
    let a = off(LuaFn::AccountClear);
    let account_name = u32_at(code, a + CLEAR_NAME_AT + 1);
    let account_password = u32_at(code, a + CLEAR_PASSWORD_AT + 1);
    if account_password != account_name.wrapping_add(ACCOUNT_NAME_SIZE) {
        return Err(LuaResolveError::AccountBuffers {
            clear: va[LuaFn::AccountClear as usize],
            name: account_name,
            password: account_password,
        });
    }
    Ok(LuaSites { va, host, account_name, account_password })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::pe::{PeHeaders, Section};
    use crate::testdata;

    /// Expected VAs per reference image (test oracle only): `mercs2_nodrm_v3.exe` and
    /// `mercs2_unpacked.exe` share one layout; the v1.1 dump has its own. Read with objdump.
    pub(crate) fn expected(image: &str, f: LuaFn) -> u32 {
        let v11 = image == testdata::V11_DUMP;
        match (f, v11) {
            (LuaFn::RegisterNamespaces, false) => 0x5a2c40,
            (LuaFn::RegisterNamespaces, true) => 0x5a2c30,
            (LuaFn::ScriptHostInit, false) => 0x5a1760,
            (LuaFn::ScriptHostInit, true) => 0x5a1750,
            (LuaFn::ScriptHostCtor, false) => 0x5a1677,
            (LuaFn::ScriptHostCtor, true) => 0x5a1667,
            (LuaFn::LuaLRegister, false) => 0x85f500,
            (LuaFn::LuaLRegister, true) => 0x85f720,
            (LuaFn::LuaSNewLStr, false) => 0x86a2b0,
            (LuaFn::LuaSNewLStr, true) => 0x86a4d0,
            (LuaFn::LuaGErrorMsg, false) => 0x85eea0,
            (LuaFn::LuaGErrorMsg, true) => 0x85f0c0,
            (LuaFn::AccountClear, false) => 0x848900,
            (LuaFn::AccountClear, true) => 0x848b60,
        }
    }

    pub(crate) const IMAGES: [&str; 3] = [testdata::EXES[0], testdata::EXES[1], testdata::V11_DUMP];

    /// Read a u32 at `va` from an exe FILE through its section table.
    fn file_reader<'a>(bytes: &'a [u8], h: &'a PeHeaders) -> impl Fn(u32) -> Option<u32> + 'a {
        move |va| {
            let rva = va.checked_sub(h.image_base)?;
            let s: &Section =
                h.sections.iter().find(|s| rva >= s.virtual_address && rva + 4 <= s.virtual_address + s.common_len() as u32)?;
            let at = (s.raw_pointer + rva - s.virtual_address) as usize;
            bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
    }

    #[test]
    fn every_site_resolves_at_the_expected_va_in_all_three_images() {
        for image in IMAGES {
            let bytes = testdata::read_exe(image);
            let h = PeHeaders::parse(&bytes).unwrap();
            let (sec, code) = h.file_section(&bytes, crate::signature::CODE_SECTION).unwrap();
            for f in LuaFn::ALL {
                let hits = Pattern::parse(f.pattern()).unwrap().find_all(code);
                let vas: Vec<String> = hits.iter().map(|&o| format!("{:#x}", h.va_of(sec, o))).collect();
                println!("{image} {:<28} matches={} at {:?}", f.name(), hits.len(), vas);
                assert_eq!(hits.len(), 1, "{image} {}: {vas:?}", f.name());
                assert_eq!(h.va_of(sec, hits[0]), expected(image, f), "{image} {}", f.name());
            }
            let sites = resolve(code, |o| h.va_of(sec, o), file_reader(&bytes, &h)).unwrap();
            for f in LuaFn::ALL {
                assert_eq!(sites.va(f), expected(image, f), "{image} {}", f.name());
            }
            let host = if image == testdata::V11_DUMP { 0x14a4da0 } else { 0x14a5da0 };
            assert_eq!(sites.host(), host, "{image}");
            let name = if image == testdata::V11_DUMP { 0x1175460 } else { 0x1176460 };
            assert_eq!((sites.account_name(), sites.account_password()), (name, name + 0x20), "{image}");
        }
    }

    #[test]
    fn signature_bytes_are_the_exe_bytes_at_the_va() {
        // Independent of the scanner: every fixed byte equals the file byte at VA - 0x400000.
        for image in IMAGES {
            let bytes = testdata::read_exe(image);
            for f in LuaFn::ALL {
                let p = Pattern::parse(f.pattern()).unwrap();
                assert!(p.matches_at(&bytes, (expected(image, f) - 0x400000) as usize), "{image} {}", f.name());
            }
        }
    }

    #[test]
    fn host_offsets_are_fixed_bytes_of_the_patterns() {
        // `cmp byte [esi+0xc42], 0` and `mov [esi+0x10], eax` in ScriptHostInit; `mov esi, [ebp+0x10]` in
        // the walker. If a pattern stops pinning an offset, the constant is unproven.
        let init = LuaFn::ScriptHostInit.pattern().split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(init.contains("80 be 42 0c 00 00 00"));
        assert!(init.contains("c6 86 42 0c 00 00 01"));
        assert!(init.contains("89 46 10"));
        assert_eq!(HOST_INITIALISED, 0xc42);
        assert_eq!(HOST_LUA_STATE, 0x10);
        assert!(LuaFn::RegisterNamespaces.pattern().starts_with("53 55 8b 6c 24 0c 56 8b 75 10"));
        // The call the structural check follows is at offset 71.
        let p: Vec<&str> = init.split_whitespace().collect();
        assert_eq!(p[INIT_CALL_AT], "e8");
        assert_eq!(p.len(), INIT_CALL_AT + 5);
        // The two `mov byte [moffs32], al` the account buffers are read from, each followed by a wildcarded address.
        let clear: Vec<&str> = LuaFn::AccountClear.pattern().split_whitespace().collect();
        for at in [CLEAR_NAME_AT, CLEAR_PASSWORD_AT] {
            assert_eq!(clear[at], "a2", "offset {at}");
            assert_eq!(clear[at + 1..at + 5], ["??"; 4], "offset {at}");
        }
    }

    #[test]
    fn account_buffers_must_be_adjacent() {
        let bytes = testdata::read_exe(testdata::EXES[0]);
        let h = PeHeaders::parse(&bytes).unwrap();
        let (sec, code) = h.file_section(&bytes, crate::signature::CODE_SECTION).unwrap();
        let mut patched = code.to_vec();
        let clear = (expected(testdata::EXES[0], LuaFn::AccountClear) - 0x401000) as usize;
        patched[clear + CLEAR_PASSWORD_AT + 1] ^= 0x40;
        let err = resolve(&patched, |o| h.va_of(sec, o), file_reader(&bytes, &h)).unwrap_err();
        assert!(matches!(err, LuaResolveError::AccountBuffers { name: 0x1176460, .. }), "{err}");
    }

    #[test]
    fn the_structural_checks_refuse_a_wrong_wiring() {
        let bytes = testdata::read_exe(testdata::EXES[0]);
        let h = PeHeaders::parse(&bytes).unwrap();
        let (sec, code) = h.file_section(&bytes, crate::signature::CODE_SECTION).unwrap();

        // A vtable whose init slot is not ScriptHostInit.
        let err = resolve(code, |o| h.va_of(sec, o), |_| Some(0x1234)).unwrap_err();
        assert!(matches!(err, LuaResolveError::Ctor { .. }), "{err}");
        assert!(err.to_string().contains("not ScriptHostInit"), "{err}");
        let err = resolve(code, |o| h.va_of(sec, o), |_| None).unwrap_err();
        assert!(err.to_string().contains("not readable"), "{err}");

        // ScriptHostInit calling somewhere else.
        let mut patched = code.to_vec();
        let init = (expected(testdata::EXES[0], LuaFn::ScriptHostInit) - 0x401000) as usize;
        patched[init + INIT_CALL_AT + 1] ^= 0x10;
        let err = resolve(&patched, |o| h.va_of(sec, o), file_reader(&bytes, &h)).unwrap_err();
        assert!(matches!(err, LuaResolveError::InitCallsElsewhere { .. }), "{err}");

        // Nothing to find.
        let err = resolve(&[0xcc; 4096], |o| o as u32, |_| None).unwrap_err();
        assert!(err.to_string().contains("ScriptHostRegisterNamespaces=0 match(es)"), "{err}");
    }
}
