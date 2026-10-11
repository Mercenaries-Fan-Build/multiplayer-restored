//! Byte signatures that locate the ProtoSSL entry points in the game image.
//!
//! The table is data, not per-build addresses: every pattern is scanned over the main module's `.text`
//! section and must match **exactly once**; zero or several matches is a hard failure. Patterns were
//! copied from the bytes of `mercs2_nodrm_v3.exe` / `mercs2_unpacked.exe` (identical for these functions)
//! with every `call rel32` target and absolute data address replaced by `??`, so a build that relinks the
//! same code at another address still matches. Intra-function branch displacements are kept: they only
//! change if the function body itself changes. Function roles and argument lists:
//! `docs/reverse_engineer/multiplayer_rewrite_re.md` §4.

use thiserror::Error;

/// The ProtoSSL entries, in table order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtoSslFn {
    Create,
    Destroy,
    Connect,
    Disconnect,
    Update,
    Send,
    Recv,
    Stat,
}

impl ProtoSslFn {
    pub const ALL: [ProtoSslFn; 8] = [
        ProtoSslFn::Create,
        ProtoSslFn::Destroy,
        ProtoSslFn::Connect,
        ProtoSslFn::Disconnect,
        ProtoSslFn::Update,
        ProtoSslFn::Send,
        ProtoSslFn::Recv,
        ProtoSslFn::Stat,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ProtoSslFn::Create => "ProtoSSLCreate",
            ProtoSslFn::Destroy => "ProtoSSLDestroy",
            ProtoSslFn::Connect => "ProtoSSLConnect",
            ProtoSslFn::Disconnect => "ProtoSSLDisconnect",
            ProtoSslFn::Update => "ProtoSSLUpdate",
            ProtoSslFn::Send => "ProtoSSLSend",
            ProtoSslFn::Recv => "ProtoSSLRecv",
            ProtoSslFn::Stat => "ProtoSSLStat",
        }
    }

    /// Signature, as space-separated hex bytes with `??` wildcards.
    pub fn pattern(self) -> &'static str {
        match self {
            // push esi; push edi; call <memgroup>; ...; push 'pssl'; push 0x128; call <alloc>; ...
            // memset(ref, 0, 0x128); ref->memgroup(+8) = edi; return ref
            ProtoSslFn::Create => {
                "56 57 e8 ?? ?? ?? ?? 8b f8 57 68 6c 73 73 70 68 28 01 00 00 e8 ?? ?? ?? ?? 8b f0 83 c4 0c \
                 85 f6 75 03 5f 5e c3 68 28 01 00 00 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c 89 7e 08 5f 8b c6 5e c3"
            }
            // ebx = 0 (secure); Reset(ref in eax); free(ref, 'pssl', ref->memgroup)
            ProtoSslFn::Destroy => {
                "53 56 8b 74 24 0c 33 db 8b c6 e8 ?? ?? ?? ?? 8b 46 08 50 68 6c 73 73 70 56 e8 ?? ?? ?? ?? \
                 83 c4 0c 5e 5b c3"
            }
            // Reset(ref, secure); sock = SocketOpen(2,1,0) or return -9; sockaddr at +0x10c: family 2,
            // port +0x10e, addr +0x110..+0x11b zeroed
            ProtoSslFn::Connect => {
                "53 8b 5c 24 0c 56 8b 74 24 0c 8b c6 e8 ?? ?? ?? ?? 33 db 3b c3 0f 85 5f 01 00 00 53 6a 01 \
                 6a 02 e8 ?? ?? ?? ?? 83 c4 0c 3b c3 89 06 75 08 5e b8 f7 ff ff ff 5b c3 55 8b 6c 24 18 3b \
                 eb 8d 8e 0c 01 00 00 57 66 c7 01 02 00 66 89 9e 0e 01 00 00"
            }
            // ebx = (ref->secure(+0x124) != 0); Reset(ref); return 0
            ProtoSslFn::Disconnect => "8b 44 24 04 53 33 db 39 98 24 01 00 00 0f 95 c3 e8 ?? ?? ?? ?? 33 c0 5b c3",
            // state(+0x11c) == 1 → poll DNS job (+4); not found → state 0x1001
            ProtoSslFn::Update => {
                "53 55 56 8b 74 24 10 8b ae 24 01 00 00 57 bf 01 00 00 00 33 db 39 be 1c 01 00 00 75 5e 8b \
                 46 04 50 8b 40 08 ff d0 83 c4 04 85 c0 74 4e 8b 4e 04 39 59 04 75 0c c7 86 1c 01 00 00 01 \
                 10 00 00 eb 2e"
            }
            // len < 0 → strlen(buf); state == 0x1e and no record in flight → cap at 16000 (0x3e80)
            ProtoSslFn::Send => {
                "53 55 8b 6c 24 10 56 8b 74 24 18 83 cb ff 85 f6 57 8b 7c 24 14 7d 16 8b c5 8d 50 01 8d 64 \
                 24 00 8a 08 83 c0 01 84 c9 75 f7 2b c2 8b f0 83 bf 1c 01 00 00 1e 75 33 8b 87 24 01 00 00 \
                 33 db 39 58 0c 75 26 81 fe 80 3e 00 00"
            }
            // result = -1; state == 0x1e → pump Update while records pend, copy decrypted bytes
            ProtoSslFn::Recv => {
                "53 8b 5c 24 10 55 8b 6c 24 0c 56 8b b5 24 01 00 00 57 83 cf ff 83 bd 1c 01 00 00 1e 75 78 \
                 8b 46 14 33 ff 3b 46 18 74 09 55 e8 ?? ?? ?? ?? 83 c4 04 8b 46 18 83 f8 05 7c 05 39 46 14 \
                 7d 10"
            }
            // sel == 'sock' → *(int*)buf = ref->socket when len == 4
            ProtoSslFn::Stat => {
                "56 8b 74 24 0c 83 c8 ff 81 fe 6b 63 6f 73 75 20 8b 44 24 10 85 c0 74 13 83 7c 24 14 04 75 \
                 0c 8b 4c 24 08 8b 11 89 10 33 c0 5e c3 83 c8 ff 5e c3"
            }
        }
    }
}

/// The section every ProtoSSL signature is searched in.
pub const CODE_SECTION: &str = ".text";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PatternError {
    #[error("pattern token {0:?} is neither two hex digits nor ??")]
    BadToken(String),
    #[error("empty pattern")]
    Empty,
    #[error("pattern starts with a wildcard (a scan needs a fixed first byte)")]
    LeadingWildcard,
}

/// A parsed byte pattern; `None` is a wildcard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern(Vec<Option<u8>>);

impl Pattern {
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let mut out = Vec::new();
        for tok in text.split_ascii_whitespace() {
            if tok == "??" {
                out.push(None);
            } else if tok.len() == 2 {
                out.push(Some(u8::from_str_radix(tok, 16).map_err(|_| PatternError::BadToken(tok.to_owned()))?));
            } else {
                return Err(PatternError::BadToken(tok.to_owned()));
            }
        }
        match out.first() {
            None => Err(PatternError::Empty),
            Some(None) => Err(PatternError::LeadingWildcard),
            Some(Some(_)) => Ok(Pattern(out)),
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn matches_at(&self, hay: &[u8], at: usize) -> bool {
        hay.get(at..at + self.0.len())
            .is_some_and(|w| w.iter().zip(&self.0).all(|(b, p)| p.is_none_or(|p| p == *b)))
    }

    /// Every offset in `hay` where the pattern matches.
    pub fn find_all(&self, hay: &[u8]) -> Vec<usize> {
        let first = self.0[0].expect("parse() rejects a leading wildcard");
        let mut hits = Vec::new();
        if hay.len() < self.0.len() {
            return hits;
        }
        let last_start = hay.len() - self.0.len();
        let mut i = 0;
        while i <= last_start {
            match hay[i..=last_start].iter().position(|&b| b == first) {
                None => break,
                Some(p) => {
                    let at = i + p;
                    if self.matches_at(hay, at) {
                        hits.push(at);
                    }
                    i = at + 1;
                }
            }
        }
        hits
    }
}

/// Where each ProtoSSL function was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resolved {
    va: [u32; 8],
}

impl Resolved {
    pub fn va(&self, f: ProtoSslFn) -> u32 {
        self.va[f as usize]
    }
}

/// Outcome of scanning one function's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanReport {
    pub function: ProtoSslFn,
    /// Section offsets of every match.
    pub offsets: Vec<usize>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("ProtoSSL signatures did not resolve to exactly one match each: {}", describe(.0))]
pub struct ResolveError(pub Vec<ScanReport>);

fn describe(reports: &[ScanReport]) -> String {
    reports
        .iter()
        .map(|r| format!("{}={} match(es)", r.function.name(), r.offsets.len()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Scan `code` (the bytes of the code section) for every ProtoSSL signature.
/// `va_of(offset)` turns a section offset into a virtual address.
pub fn resolve(code: &[u8], va_of: impl Fn(usize) -> u32) -> Result<Resolved, ResolveError> {
    let reports: Vec<ScanReport> = ProtoSslFn::ALL
        .iter()
        .map(|&f| ScanReport {
            function: f,
            offsets: Pattern::parse(f.pattern()).expect("built-in pattern parses").find_all(code),
        })
        .collect();
    if reports.iter().all(|r| r.offsets.len() == 1) {
        let mut va = [0u32; 8];
        for r in &reports {
            va[r.function as usize] = va_of(r.offsets[0]);
        }
        Ok(Resolved { va })
    } else {
        Err(ResolveError(reports))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeHeaders;
    use crate::testdata;

    /// Expected VAs (multiplayer_rewrite_re.md §4) — test oracle only, never used at runtime.
    fn expected(f: ProtoSslFn) -> u32 {
        match f {
            ProtoSslFn::Create => 0x9d9910,
            ProtoSslFn::Destroy => 0x9d9950,
            ProtoSslFn::Connect => 0x9d9a00,
            ProtoSslFn::Disconnect => 0x9d9b80,
            ProtoSslFn::Update => 0x9da500,
            ProtoSslFn::Send => 0x9da8c0,
            ProtoSslFn::Recv => 0x9da960,
            ProtoSslFn::Stat => 0x9daa30,
        }
    }

    #[test]
    fn every_signature_matches_exactly_once_at_the_expected_va_in_both_exes() {
        for exe in testdata::EXES {
            let bytes = testdata::read_exe(exe);
            let h = PeHeaders::parse(&bytes).unwrap();
            let (sec, code) = h.file_section(&bytes, CODE_SECTION).unwrap();
            for f in ProtoSslFn::ALL {
                let hits = Pattern::parse(f.pattern()).unwrap().find_all(code);
                let vas: Vec<String> = hits.iter().map(|&o| format!("{:#x}", h.va_of(sec, o))).collect();
                println!("{exe} {:<20} matches={} at {:?}", f.name(), hits.len(), vas);
                assert_eq!(hits.len(), 1, "{exe} {}: {vas:?}", f.name());
                assert_eq!(h.va_of(sec, hits[0]), expected(f), "{exe} {}", f.name());
            }
            let r = resolve(code, |o| h.va_of(sec, o)).unwrap();
            for f in ProtoSslFn::ALL {
                assert_eq!(r.va(f), expected(f));
            }
        }
    }

    #[test]
    fn the_v11_retail_dump_resolves_too() {
        // genuine_patched_unpacked.exe: the retail v1.1 image dumped after SecuROM decrypted it. Its
        // ProtoSSL block is the same code 0xF0 bytes higher (objdump: Create at 0x9d9a00, Connect at
        // 0x9d9af0), which the wildcarded table must find without a per-build address list.
        let bytes = testdata::read_exe(testdata::V11_DUMP);
        let h = PeHeaders::parse(&bytes).unwrap();
        let (sec, code) = h.file_section(&bytes, CODE_SECTION).unwrap();
        let r = resolve(code, |o| h.va_of(sec, o)).unwrap();
        for f in ProtoSslFn::ALL {
            println!("{} {:<20} at {:#x}", testdata::V11_DUMP, f.name(), r.va(f));
            assert_eq!(r.va(f), expected(f) + 0xf0, "{}", f.name());
        }
    }

    #[test]
    fn manifest_signature_guards_match_the_exes_and_the_table() {
        // Every `"0xVA": "bytes"` line under signature_guard in ../manifest.yaml guards one detoured
        // function at one of its expected VAs: the bytes must be the leading fixed bytes of THAT
        // function's pattern and appear at that VA in every reference image where the function sits
        // there (.text file offset == VA - 0x400000 in all three). Detoured: every ProtoSSL entry but
        // Create (resolved, not detoured), and `crate::lua::signature::LuaFn::HOOKED`.
        use crate::lua::signature::{LuaFn, tests::expected as lua_expected};
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../manifest.yaml");
        let text = std::fs::read_to_string(&path).unwrap();
        let prefix = |p: &str| -> Vec<u8> { Pattern::parse(p).unwrap().0.into_iter().map_while(|b| b).collect() };
        let names: Vec<&str> = testdata::EXES.iter().copied().chain([testdata::V11_DUMP]).collect();
        let images: Vec<_> = names.iter().map(|n| testdata::read_exe(n)).collect();
        // (function, VA, guard prefix, indices of the images where the function sits at VA)
        let mut sites: Vec<(&str, usize, Vec<u8>, Vec<usize>)> = Vec::new();
        let mut add = |name: &'static str, pattern: &str, image: usize, va: u32| {
            match sites.iter_mut().find(|s| s.0 == name && s.1 == va as usize) {
                Some(s) => s.3.push(image),
                None => sites.push((name, va as usize, prefix(pattern), vec![image])),
            }
        };
        for (i, image) in names.iter().enumerate() {
            for f in ProtoSslFn::ALL.into_iter().filter(|&f| f != ProtoSslFn::Create) {
                let va = if *image == testdata::V11_DUMP { expected(f) + 0xf0 } else { expected(f) };
                add(f.name(), f.pattern(), i, va);
            }
            for f in LuaFn::HOOKED {
                add(f.name(), f.pattern(), i, lua_expected(image, f));
            }
        }
        let mut guards = 0;
        for line in text.lines().map(str::trim).filter(|l| l.starts_with("\"0x")) {
            let (k, v) = line.split_once(": ").unwrap();
            let va = u32::from_str_radix(k.trim_matches('"').trim_start_matches("0x"), 16).unwrap() as usize;
            let bytes: Vec<u8> =
                v.trim_matches('"').split_whitespace().map(|t| u8::from_str_radix(t, 16).unwrap()).collect();
            let site = sites.iter().find(|s| s.1 == va).unwrap_or_else(|| panic!("{line}: no detoured function at this VA"));
            assert!(site.2.starts_with(&bytes), "{line}: not a prefix of {}'s pattern", site.0);
            let off = va - 0x400000;
            for &i in &site.3 {
                assert_eq!(images[i][off..off + bytes.len()], bytes[..], "{line}: not at this VA in {}", names[i]);
            }
            guards += 1;
        }
        assert_eq!(guards, sites.len(), "one guard per detoured function per VA: {:?}", sites.iter().map(|s| (s.0, s.1)).collect::<Vec<_>>());
    }

    #[test]
    fn signature_bytes_are_the_exe_bytes_at_the_va() {
        // Independent check of the pattern text: compare each non-wildcard byte with the file bytes at
        // VA - 0x400000 (.text file offset == RVA for these images).
        for exe in testdata::EXES {
            let bytes = testdata::read_exe(exe);
            for f in ProtoSslFn::ALL {
                let p = Pattern::parse(f.pattern()).unwrap();
                let off = (expected(f) - 0x400000) as usize;
                assert!(p.matches_at(&bytes, off), "{exe} {}", f.name());
            }
        }
    }

    #[test]
    fn missing_and_ambiguous_signatures_fail_resolution() {
        let empty = vec![0xccu8; 4096];
        let err = resolve(&empty, |o| o as u32).unwrap_err();
        assert!(err.0.iter().all(|r| r.offsets.is_empty()));
        assert!(err.to_string().contains("ProtoSSLConnect=0 match(es)"));

        // Two copies of the Disconnect body → ambiguous.
        let disc = Pattern::parse(ProtoSslFn::Disconnect.pattern()).unwrap();
        let body: Vec<u8> = disc.0.iter().map(|b| b.unwrap_or(0x11)).collect();
        let mut hay = body.clone();
        hay.extend_from_slice(&body);
        assert_eq!(disc.find_all(&hay), vec![0, body.len()]);
    }

    #[test]
    fn pattern_parser_is_strict() {
        assert_eq!(Pattern::parse(""), Err(PatternError::Empty));
        assert_eq!(Pattern::parse("?? 90"), Err(PatternError::LeadingWildcard));
        assert_eq!(Pattern::parse("9g"), Err(PatternError::BadToken("9g".into())));
        assert_eq!(Pattern::parse("909"), Err(PatternError::BadToken("909".into())));
        assert!(Pattern::parse("90 ?? c3").unwrap().matches_at(&[0x90, 0x12, 0xc3], 0));
    }
}
