//! Build identity reported to the server as `mercs2_mp_api::rest::ClientInfo::build_sha256`.
//!
//! **Definition:** lowercase hex SHA-256 over the main module's `.text` section bytes as mapped in memory,
//! covering `min(VirtualSize, SizeOfRawData)` bytes from `ImageBase + VirtualAddress` (see
//! [`crate::pe::Section::common_len`]). It is computed after the ProtoSSL signatures have resolved — i.e.
//! after SecuROM has decrypted the code — and **before** any hook is written, so it identifies the
//! game's own code, not our patches. For an unpacked/no-DRM exe the same value is obtained from the file
//! on disk (`.text` at `PointerToRawData`), which is how the tests pin the two reference builds.

use sha2::{Digest, Sha256};

pub fn sha256_hex(text: &[u8]) -> String {
    let digest = Sha256::digest(text);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeHeaders;
    use crate::testdata;

    #[test]
    fn reference_builds_have_stable_identities() {
        // Cross-checked out of band: dd if=<exe> bs=4096 skip=1 count=1796 | shasum -a 256
        // (.text = file offset 0x1000, 0x704000 bytes).
        let expected = [
            ("mercs2_nodrm_v3.exe", NODRM_V3_TEXT_SHA256),
            ("mercs2_unpacked.exe", UNPACKED_TEXT_SHA256),
        ];
        for (exe, want) in expected {
            let bytes = testdata::read_exe(exe);
            let h = PeHeaders::parse(&bytes).unwrap();
            let (_, text) = h.file_section(&bytes, ".text").unwrap();
            assert_eq!(sha256_hex(text), want, "{exe}");
        }
    }

    const NODRM_V3_TEXT_SHA256: &str = "7e8a9de90f63d6465012d36fb93cdf5990b97685f87cc938eb882b5e3dfacc89";
    const UNPACKED_TEXT_SHA256: &str = "526bc6dd9c6f5390ba1b58528eb775ffb81b1f8cfdba594115e114a790fb1b70";
}
