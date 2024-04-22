#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod elf_aux_structures;
pub mod elf_structures;
pub mod errors;
pub mod range;

mod macros;

use core::{
    ffi::CStr,
    num::{NonZeroU16, NonZeroU64},
    ops::Range,
};

use elf_aux_structures::*;
use elf_structures::*;
use errors::ElfError;
use zerocopy::FromBytes;

/// An Elf header type, representing either 64 or 32 bit little-endian ELFs.
#[derive(Debug, Clone, Copy)]
pub enum ElfHeader<'buf> {
    Elf32(&'buf Elf32Header),
    Elf64(&'buf Elf64Header),
}

impl<'buf> ElfHeader<'buf> {
    pub fn parse(bytes: &'buf [u8]) -> Result<Self, ElfError> {
        let e_ident: &ElfIdent = ElfIdent::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?;

        if e_ident.ei_magic != ElfIdent::ELF_MAGIC {
            return Err(ElfError::InvalidMagic(e_ident.ei_magic));
        } else if e_ident.ei_data != ElfIdentData::DATA_2_LSB {
            return Err(ElfError::InvalidDataEncoding(e_ident.ei_data));
        } else if e_ident.ei_version != ElfIdentVersion::EV_CURRENT {
            return Err(ElfError::InvalidVersion(e_ident.ei_version));
        }

        let header = match e_ident.ei_class {
            ElfIdentClass::CLASS_32 => {
                Self::Elf32(Elf32Header::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?)
            }
            ElfIdentClass::CLASS_64 => {
                Self::Elf64(Elf64Header::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?)
            }
            ElfIdentClass(_) => {
                return Err(ElfError::InvalidClass(e_ident.ei_class));
            }
        };

        Ok(header)
    }

    pub fn section_header_location(&self, header_number: u16) -> Option<Range<u64>> {
        if header_number >= self.e_shnum()?.get() {
            return None;
        }

        let size = u64::from(self.e_shentsize());
        let start = self
            .e_shoff()?
            .get()
            .saturating_add(u64::from(header_number).saturating_mul(size));

        Some(Range {
            start,
            end: start.saturating_add(size),
        })
    }

    pub fn string_table_header_location(&self) -> Option<Range<u64>> {
        self.section_header_location(self.e_shstrndx()?.get())
    }

    pub fn program_header_location(&self, header_number: u16) -> Option<Range<u64>> {
        if header_number >= self.e_phnum()?.get() {
            return None;
        }

        let size = u64::from(self.e_phentsize());
        let start = self
            .e_phoff()?
            .get()
            .saturating_add(u64::from(header_number).saturating_mul(size));
        Some(Range {
            start,
            end: start.saturating_add(size),
        })
    }
}

/// An Elf header type, representing either 64 or 32 bit section headers.
#[derive(Debug, Clone, Copy)]
pub enum ElfSectionHeader<'buf> {
    Elf32(&'buf Elf32SectionHeader),
    Elf64(&'buf Elf64SectionHeader),
}

impl<'buf> ElfSectionHeader<'buf> {
    pub fn parse(header: ElfHeader, bytes: &'buf [u8]) -> Result<Self, ElfError> {
        let sh_header = match header {
            ElfHeader::Elf32(_) => Self::Elf32(
                Elf32SectionHeader::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?,
            ),
            ElfHeader::Elf64(_) => Self::Elf64(
                Elf64SectionHeader::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?,
            ),
        };

        Ok(sh_header)
    }

    pub fn location(&self) -> Range<u64> {
        let (start, size) = match self {
            Self::Elf32(header) => (u64::from(header.sh_offset), u64::from(header.sh_size)),
            Self::Elf64(header) => (header.sh_offset, header.sh_size),
        };

        Range {
            start,
            end: start.saturating_add(size),
        }
    }
}

/// An Elf header type, representing either 64 or 32 bit program headers.
#[derive(Debug, Clone, Copy)]
pub enum ElfProgramHeader<'buf> {
    Elf32(&'buf Elf32ProgramHeader),
    Elf64(&'buf Elf64ProgramHeader),
}

impl<'buf> ElfProgramHeader<'buf> {
    pub fn parse(header: ElfHeader, bytes: &'buf [u8]) -> Result<Self, ElfError> {
        let p_header = match header {
            ElfHeader::Elf32(_) => Self::Elf32(
                Elf32ProgramHeader::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?,
            ),
            ElfHeader::Elf64(_) => Self::Elf64(
                Elf64ProgramHeader::ref_from_prefix(bytes).ok_or(ElfError::ZeroCopyError)?,
            ),
        };

        Ok(p_header)
    }

    pub fn file_location(&self) -> Option<Range<u64>> {
        let start = self.p_offset();
        let size: u64 = self.p_filesz()?.into();

        Some(Range {
            start,
            end: start.saturating_add(size),
        })
    }

    pub fn memory_location(&self) -> Result<Option<Range<u64>>, ElfError> {
        let start = self.p_vaddr();
        let Some(size): Option<u64> = self.p_memsz().map(Into::into) else {
            // the memory image of the segment may be zero.
            return Ok(None);
        };

        if self.p_filesz() > self.p_memsz() {
            return Err(ElfError::FileSzLargerThanMemSz);
        }
        if self.p_type() == ElfSegmentType::PT_LOAD
            && self.p_align() > 1
            && self.p_vaddr() % self.p_align() != self.p_offset() % self.p_align()
        {
            // Loadable process segments must have congruent values for p_vaddr and
            // p_offset, modulo the page size.This member gives the value to which the
            // segments are aligned in memory and in the file. Values 0 and 1 mean that no
            // alignment is required. Otherwise, p_align should be a positive, integral power of
            // 2, and p_addr should equal p_offset, modulo p_align.
            // — Section 2-2 of https://refspecs.linuxfoundation.org/elf/elf.pdf
            return Err(ElfError::IncongurentSegmentAlignment);
        }

        Ok(Some(Range {
            start,
            end: start.saturating_add(size),
        }))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ElfSectionHeaders<'buf> {
    Elf32(&'buf [Elf32SectionHeader]),
    Elf64(&'buf [Elf64SectionHeader]),
}

impl<'buf> ElfSectionHeaders<'buf> {
    // bytes must be a multiple of the length?
    // todo: better to use slice_from_prefix?
    // todo: should require the length?
    pub fn parse(header: ElfHeader, bytes: &'buf [u8]) -> Result<Self, ElfError> {
        let section_headers = match header {
            ElfHeader::Elf32(_) => {
                Self::Elf32(Elf32SectionHeader::slice_from(bytes).ok_or(ElfError::ZeroCopyError)?)
            }
            ElfHeader::Elf64(_) => {
                Self::Elf64(Elf64SectionHeader::slice_from(bytes).ok_or(ElfError::ZeroCopyError)?)
            }
        };

        // Note: We don't need to do any further checks, as ElfSectionHeader::parse and ElfProgramHeader::parse
        //       are just wrappers around ref_from_prefix(), and so this is fine..

        Ok(section_headers)
    }

    pub fn find_by_name(
        &self,
        string_table: ElfStringTable,
        name: &str,
    ) -> Option<ElfSectionHeader> {
        self.into_iter().find(|header| {
            string_table
                .section_name(*header)
                .is_ok_and(|header_name| header_name == name)
        })
    }
}

impl<'buf> IntoIterator for ElfSectionHeaders<'buf> {
    type Item = ElfSectionHeader<'buf>;
    type IntoIter = ElfSectionHeadersIter<'buf>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            ElfSectionHeaders::Elf32(headers) => Self::IntoIter::Elf32(headers.iter()),
            ElfSectionHeaders::Elf64(headers) => Self::IntoIter::Elf64(headers.iter()),
        }
    }
}

pub enum ElfSectionHeadersIter<'buf> {
    Elf32(core::slice::Iter<'buf, Elf32SectionHeader>),
    Elf64(core::slice::Iter<'buf, Elf64SectionHeader>),
}

impl<'buf> Iterator for ElfSectionHeadersIter<'buf> {
    type Item = ElfSectionHeader<'buf>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Elf32(iter) => iter.next().map(Self::Item::Elf32),
            Self::Elf64(iter) => iter.next().map(Self::Item::Elf64),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ElfStringTable<'buf> {
    buffer: &'buf [u8],
}

impl<'buf> ElfStringTable<'buf> {
    pub fn parse(buffer: &'buf [u8]) -> Result<ElfStringTable<'buf>, ElfError> {
        // The first byte, which is index zero, is defined to hold a null
        // character. Likewise, a string table's last byte is defined to hold a
        // null character, ensuring null termination for all strings.
        // — Section 1-18 of https://refspecs.linuxfoundation.org/elf/elf.pdf

        match (buffer.first(), buffer.last()) {
            (Some(0), Some(0)) => Ok(Self { buffer }),
            _ => Err(ElfError::StringTableNotZeroTerminated),
        }
    }

    pub fn section_name(&self, header: ElfSectionHeader) -> Result<&str, ElfError> {
        // This should be fine on almost any platform, unless the string
        // table is absolutely huge.
        let sh_name_index = header.sh_name().try_into()?;

        let null_terminated = self
            .buffer
            .get(sh_name_index..)
            .ok_or(ElfError::StringTableOutOfBounds(sh_name_index))?;

        Ok(CStr::from_bytes_until_nul(null_terminated)?.to_str()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_valid_ident_64() {
        let buffer = {
            // 64 is the length of ELF64 header.
            let mut buffer = [0; 64];
            buffer[..4].copy_from_slice(b"\x7fELF");
            buffer[4] = ElfIdentClass::CLASS_64.0;
            buffer[5] = ElfIdentData::DATA_2_LSB.0;
            buffer[6] = ElfIdentVersion::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_ok());
    }

    #[test]
    fn allows_valid_ident_32() {
        let buffer = {
            // 52 is the length of ELF32 header.
            let mut buffer = [0; 52];
            buffer[..4].copy_from_slice(b"\x7fELF");
            buffer[4] = ElfIdentClass::CLASS_32.0;
            buffer[5] = ElfIdentData::DATA_2_LSB.0;
            buffer[6] = ElfIdentVersion::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_ok());
    }

    #[test]
    fn disallows_invalid_magic() {
        let buffer = {
            // 64 is the length of ELF64 header.
            let mut buffer = [0; 64];
            buffer[..4].copy_from_slice(b"0000");
            buffer[4] = ElfIdentClass::CLASS_64.0;
            buffer[5] = ElfIdentData::DATA_2_LSB.0;
            buffer[6] = ElfIdentVersion::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_err_and(|e| matches!(e, ElfError::InvalidMagic(_))));
    }

    #[test]
    fn disallows_big_endian() {
        let buffer = {
            // 64 is the length of ELF64 header.
            let mut buffer = [0; 64];
            buffer[..4].copy_from_slice(b"\x7fELF");
            buffer[4] = ElfIdentClass::CLASS_64.0;
            buffer[5] = ElfIdentData::DATA_2_MSB.0;
            buffer[6] = ElfIdentVersion::EV_CURRENT.0;

            buffer
        };

        assert!(
            ElfHeader::parse(&buffer).is_err_and(|e| matches!(e, ElfError::InvalidDataEncoding(_)))
        );
    }
}
