//! Test-only access to the reference executables in the repository
//! (`output/_ghidra/securom_dump/`). A missing file fails the test that needs it — it is never skipped.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// The two exe images the signature table is verified against.
pub const EXES: [&str; 2] = ["mercs2_nodrm_v3.exe", "mercs2_unpacked.exe"];

/// The retail v1.1 image dumped after SecuROM decrypted it (different layout: code shifted).
pub const V11_DUMP: &str = "genuine_patched_unpacked.exe";

fn dump_dir() -> PathBuf {
    // client/ -> multiplayer-restored/ -> shipments/ -> repository root
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../output/_ghidra/securom_dump")
}

pub fn read_exe(name: &str) -> std::sync::Arc<Vec<u8>> {
    static CACHE: OnceLock<Mutex<HashMap<String, std::sync::Arc<Vec<u8>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("testdata cache poisoned");
    map.entry(name.to_owned())
        .or_insert_with(|| {
            let path = dump_dir().join(name);
            std::sync::Arc::new(
                std::fs::read(&path).unwrap_or_else(|e| panic!("reference exe {} unreadable: {e}", path.display())),
            )
        })
        .clone()
}
