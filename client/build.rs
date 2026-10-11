//! For `i686-pc-windows-gnu`, link against the DWARF-2 `libgcc`/`libgcc_eh` that the official Rust
//! `rust-mingw` component ships for this target (the prebuilt i686 std references `_Unwind_Resume`; a
//! SJLJ MinGW such as Homebrew's provides only `_Unwind_SjLj_Resume`). `scripts/fetch_dw2_libgcc.sh`
//! downloads and sha256-verifies them into `toolchain/i686-dw2/` for the exact rustc in use; this script
//! refuses to build if they are missing or were fetched for another rustc. Likewise the `m2-sdk.dll` import
//! library (`scripts/fetch_m2_sdk.sh`, into `toolchain/m2-sdk/`) for the SDK release `m2-sdk.version` names.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=toolchain/i686-dw2");
    let target = std::env::var("TARGET").expect("cargo sets TARGET");
    if target != "i686-pc-windows-gnu" {
        return;
    }
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"))
        .join("toolchain/i686-dw2");
    let rustc = std::env::var("RUSTC").expect("cargo sets RUSTC");
    let out = Command::new(&rustc).arg("-V").output().expect("run rustc -V");
    assert!(out.status.success(), "rustc -V failed");
    let rustc_version = String::from_utf8(out.stdout).expect("rustc -V is UTF-8").trim().to_owned();
    let recorded = std::fs::read_to_string(dir.join("VERSION")).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nRun scripts/fetch_dw2_libgcc.sh to fetch the DWARF-2 libgcc for {rustc_version}",
            dir.join("VERSION").display()
        )
    });
    if recorded.trim() != rustc_version {
        panic!(
            "toolchain/i686-dw2 was fetched for {:?} but the build uses {rustc_version:?}; \
             re-run scripts/fetch_dw2_libgcc.sh",
            recorded.trim()
        );
    }
    for lib in ["libgcc.a", "libgcc_eh.a"] {
        assert!(dir.join(lib).is_file(), "{} missing; re-run scripts/fetch_dw2_libgcc.sh", dir.join(lib).display());
    }
    println!("cargo:rustc-link-search=native={}", dir.display());

    // m2-sdk.dll's import library, fetched by scripts/fetch_m2_sdk.sh for the release m2-sdk.version names.
    // The version is also handed to the code, whose load-time ABI check compares the loaded DLL against it.
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));
    println!("cargo:rerun-if-changed=m2-sdk.version");
    println!("cargo:rerun-if-changed=toolchain/m2-sdk");
    let wanted = std::fs::read_to_string(manifest_dir.join("m2-sdk.version")).expect("read m2-sdk.version");
    let wanted = wanted.trim();
    let sdk = manifest_dir.join("toolchain/m2-sdk");
    let fetched = std::fs::read_to_string(sdk.join("VERSION"))
        .unwrap_or_else(|e| panic!("{}: {e}\nRun scripts/fetch_m2_sdk.sh to fetch the m2-sdk {wanted} import library", sdk.join("VERSION").display()));
    if fetched.trim() != wanted {
        panic!("toolchain/m2-sdk holds m2-sdk {:?} but m2-sdk.version names {wanted:?}; re-run scripts/fetch_m2_sdk.sh", fetched.trim());
    }
    assert!(sdk.join("libm2-sdk.dll.a").is_file(), "{} missing; re-run scripts/fetch_m2_sdk.sh", sdk.join("libm2-sdk.dll.a").display());
    println!("cargo:rustc-link-search=native={}", sdk.display());
    println!("cargo:rustc-env=M2_SDK_VERSION={}", wanted.trim_start_matches('v'));
}
