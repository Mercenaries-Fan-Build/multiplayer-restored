//! Minimal PE32 header reader: just enough to find a section in a file on disk or in a mapped image.
//!
//! Field offsets are the PE/COFF specification's: `e_lfanew` at DOS header `0x3c`; COFF file header after
//! the `PE\0\0` signature (`NumberOfSections` +2, `SizeOfOptionalHeader` +16); PE32 optional header magic
//! `0x10b`, `ImageBase` +28, `SizeOfHeaders` +60; 40-byte section headers (`VirtualSize` +8,
//! `VirtualAddress` +12, `SizeOfRawData` +16, `PointerToRawData` +20).
//!
//! The same parse serves both layouts, so a VA computed from an exe file on disk is the VA the code has
//! once Windows maps the image:
//!
//! * file layout — section bytes start at `PointerToRawData`;
//! * mapped layout — section bytes start at `VirtualAddress` from the module base.
//!
//! Only `min(VirtualSize, SizeOfRawData)` bytes of a section are "the section's bytes" here: that span is
//! present in both layouts with identical content when nothing has patched the image.

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PeError {
    #[error("image is {0} bytes, too small for the header field at {1:#x}")]
    Truncated(usize, usize),
    #[error("no MZ signature")]
    NoMz,
    #[error("no PE\\0\\0 signature at {0:#x}")]
    NoPe(usize),
    #[error("optional header magic {0:#06x} is not PE32 (0x010b)")]
    NotPe32(u16),
    #[error("section {0:?} not found")]
    NoSection(String),
    #[error("section {name:?} spans {start:#x}..{end:#x}, outside the {len}-byte buffer")]
    SectionOutOfBounds { name: String, start: usize, end: usize, len: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
}

impl Section {
    /// Length of the span that exists identically in the file and in the mapped image.
    pub fn common_len(&self) -> usize {
        self.virtual_size.min(self.raw_size) as usize
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeHeaders {
    pub image_base: u32,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, PeError> {
    b.get(off..off + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(PeError::Truncated(b.len(), off))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, PeError> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(PeError::Truncated(b.len(), off))
}

impl PeHeaders {
    /// Parse from the start of a file or a mapped image (headers are laid out identically in both).
    pub fn parse(b: &[u8]) -> Result<Self, PeError> {
        if b.get(0..2) != Some(b"MZ") {
            return Err(PeError::NoMz);
        }
        let pe = u32_at(b, 0x3c)? as usize;
        if b.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err(PeError::NoPe(pe));
        }
        let coff = pe + 4;
        let nsec = u16_at(b, coff + 2)? as usize;
        let opt_size = u16_at(b, coff + 16)? as usize;
        let opt = coff + 20;
        let magic = u16_at(b, opt)?;
        if magic != 0x10b {
            return Err(PeError::NotPe32(magic));
        }
        let image_base = u32_at(b, opt + 28)?;
        let size_of_headers = u32_at(b, opt + 60)?;
        let table = opt + opt_size;
        let mut sections = Vec::with_capacity(nsec);
        for i in 0..nsec {
            let h = table + i * 40;
            let raw_name = b.get(h..h + 8).ok_or(PeError::Truncated(b.len(), h))?;
            let end = raw_name.iter().position(|&c| c == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
                virtual_size: u32_at(b, h + 8)?,
                virtual_address: u32_at(b, h + 12)?,
                raw_size: u32_at(b, h + 16)?,
                raw_pointer: u32_at(b, h + 20)?,
            });
        }
        Ok(PeHeaders { image_base, size_of_headers, sections })
    }

    pub fn section(&self, name: &str) -> Result<&Section, PeError> {
        self.sections.iter().find(|s| s.name == name).ok_or_else(|| PeError::NoSection(name.to_owned()))
    }

    /// The bytes of `name` in an exe **file** buffer.
    pub fn file_section<'a>(&self, file: &'a [u8], name: &str) -> Result<(&Section, &'a [u8]), PeError> {
        let s = self.section(name)?;
        let start = s.raw_pointer as usize;
        let end = start + s.common_len();
        let bytes = file.get(start..end).ok_or_else(|| PeError::SectionOutOfBounds {
            name: name.to_owned(),
            start,
            end,
            len: file.len(),
        })?;
        Ok((s, bytes))
    }

    /// Virtual address of byte `offset` within section `s`.
    pub fn va_of(&self, s: &Section, offset: usize) -> u32 {
        self.image_base + s.virtual_address + offset as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testdata;

    #[test]
    fn parses_both_reference_exes() {
        for exe in testdata::EXES {
            let bytes = testdata::read_exe(exe);
            let h = PeHeaders::parse(&bytes).unwrap();
            assert_eq!(h.image_base, 0x400000, "{exe}");
            let text = h.section(".text").unwrap();
            // objdump -h: .text VMA 0x00401000, file offset 0x1000, size 0x704000.
            assert_eq!(text.virtual_address, 0x1000, "{exe}");
            assert_eq!(text.raw_pointer, 0x1000, "{exe}");
            assert_eq!(text.common_len(), 0x704000, "{exe}");
            let (_, b) = h.file_section(&bytes, ".text").unwrap();
            assert_eq!(b.len(), 0x704000);
        }
    }

    #[test]
    fn rejects_non_pe() {
        assert_eq!(PeHeaders::parse(b"ZZ"), Err(PeError::NoMz));
        let mut b = vec![0u8; 0x80];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3c] = 0x40;
        assert_eq!(PeHeaders::parse(&b), Err(PeError::NoPe(0x40)));
    }
}
