//! `m2-sdk.dll`, the shared mod layer (<https://github.com/Mercenaries-Fan-Build/mercs2-sdk>), which the
//! m2-sdk Shipment places in the game root. Every detour this ASI installs goes through its `m2_hook_attach`,
//! so the process has one MinHook instance however many mods hook.
//!
//! The ASI imports the DLL, so Windows resolves it before any of this code runs; a missing DLL means the ASI
//! is not loaded at all. What the code can check is the version: the loader binds imports by name only, so a
//! DLL older than the import library this ASI was linked against would be called with signatures it may not
//! have. [`compatible`] is that check: the caret rule the manifest's `load.requires` uses for m2-sdk.

/// `M2_VERSION_NUM` of a version: `major * 10000 + minor * 100 + patch` (`m2_version.h`).
fn version_num(major: i32, minor: i32, patch: i32) -> i32 {
    major * 10000 + minor * 100 + patch
}

/// Parse `X.Y.Z` into `M2_VERSION_NUM`.
pub fn parse(version: &str) -> Result<i32, String> {
    let parts: Vec<&str> = version.split('.').collect();
    let [major, minor, patch] = parts[..] else {
        return Err(format!("m2-sdk version {version:?} is not X.Y.Z"));
    };
    let n = |s: &str| s.parse::<i32>().ok().filter(|v| (0..100).contains(v)).ok_or_else(|| format!("m2-sdk version {version:?} has a part outside 0-99"));
    Ok(version_num(n(major)?, n(minor)?, n(patch)?))
}

/// Does the loaded DLL (`m2_version_num()`) satisfy the version this ASI was built against? The caret rule:
/// the same major, and for major 0 the same minor; and no older than the build's version.
pub fn compatible(loaded: i32, built: &str) -> Result<(), String> {
    let want = parse(built)?;
    let (lmaj, lmin) = (loaded / 10000, loaded / 100 % 100);
    let (wmaj, wmin) = (want / 10000, want / 100 % 100);
    let show = |v: i32| format!("{}.{}.{}", v / 10000, v / 100 % 100, v % 100);
    let same_line = lmaj == wmaj && (wmaj != 0 || lmin == wmin);
    if !same_line || loaded < want {
        return Err(format!(
            "m2-sdk.dll in the game folder is version {}, but this ASI needs ^{} (built against {}); install the \
             m2-sdk Shipment version this release requires",
            show(loaded),
            if wmaj == 0 { format!("0.{wmin}") } else { wmaj.to_string() },
            show(want)
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub mod ffi {
    use std::ffi::c_void;
    use std::sync::atomic::AtomicUsize;

    #[link(name = "m2-sdk")]
    unsafe extern "C" {
        pub fn m2_version_num() -> i32;
        fn m2_hook_attach(target: *mut c_void, detour: *mut c_void, orig: *mut *mut c_void) -> i32;
    }

    /// Create and enable a detour at `target` through the SDK's MinHook. `orig` receives the trampoline that
    /// calls the original: `m2_hook_attach` creates and enables in one call, and MinHook writes the trampoline
    /// during the create, so it is in place before the detour can first run. `m2_hook_attach` reports only
    /// success or failure, so the error names the call.
    pub fn attach(target: *mut c_void, detour: *mut c_void, orig: Option<&AtomicUsize>, what: &str) -> Result<(), String> {
        let slot = orig.map_or(std::ptr::null_mut(), |o| o.as_ptr() as *mut *mut c_void);
        if unsafe { m2_hook_attach(target, detour, slot) } != 1 {
            return Err(format!("m2_hook_attach failed for {what} at {target:p}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_matches_m2_version_num() {
        assert_eq!(parse("0.3.1"), Ok(301));
        assert_eq!(parse("1.2.3"), Ok(10203));
        assert!(parse("0.3").is_err());
        assert!(parse("0.3.x").is_err());
        assert!(parse("0.100.0").is_err());
    }

    #[test]
    fn caret_rule_like_the_manifest() {
        // Built against 0.3.1: any 0.3.x from 0.3.1.
        assert_eq!(compatible(301, "0.3.1"), Ok(()));
        assert_eq!(compatible(309, "0.3.1"), Ok(()));
        let older = compatible(300, "0.3.1").unwrap_err();
        assert!(older.contains("version 0.3.0") && older.contains("needs ^0.3 (built against 0.3.1)"), "{older}");
        assert!(compatible(400, "0.3.1").is_err(), "0.4 is a breaking line under 0.x");
        assert!(compatible(201, "0.3.1").is_err());
        assert!(compatible(10000, "0.3.1").is_err());
        // From 1.0: any 1.x from the build's version.
        assert_eq!(compatible(10500, "1.2.0"), Ok(()));
        assert!(compatible(20000, "1.2.0").is_err());
        assert!(compatible(10100, "1.2.0").is_err());
    }
}
