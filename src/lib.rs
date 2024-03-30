pub mod elf_aux_structures;
pub mod elf_structures;
pub mod range;

use std::{
    borrow::Cow,
    ffi::CStr,
    num::{NonZeroU16, NonZeroU64},
    ops::Range,
};

use elf_aux_structures::*;
use elf_structures::*;
use zerocopy::FromBytes;

/// An Elf header type, representing either 64 or 32 bit little-endian ELFs.
#[derive(Debug)]
pub enum ElfHeader<'buf> {
    Elf32(&'buf Elf32Header),
    Elf64(&'buf Elf64Header),
}

pub fn valid_ident(e_ident: &ElfIdent) -> bool {
    e_ident.ei_magic == *b"\x7fELF"
        && e_ident.ei_data == ElfIdent::DATA_2_LSB
        && e_ident.ei_version == ElfIdent::EV_CURRENT
}

impl<'buf> ElfHeader<'buf> {
    pub fn parse(bytes: &'buf [u8]) -> Option<Self> {
        let e_ident: &ElfIdent = ElfIdent::ref_from_prefix(bytes)?;
        if !valid_ident(e_ident) {
            return None;
        }

        match e_ident.ei_class {
            ElfIdent::CLASS_32 => Some(Self::Elf32(Elf32Header::ref_from_prefix(bytes)?)),
            ElfIdent::CLASS_64 => Some(Self::Elf64(Elf64Header::ref_from_prefix(bytes)?)),
            ElfIdentClass(_) => None,
        }
    }

    #[inline]
    fn get_string_table_index(&self) -> Option<NonZeroU16> {
        match self {
            Self::Elf32(header) => header.e_shstrndx,
            Self::Elf64(header) => header.e_shstrndx,
        }
    }

    #[inline]
    pub fn e_shnum(&self) -> Option<NonZeroU16> {
        match self {
            Self::Elf32(header) => header.e_shnum,
            Self::Elf64(header) => header.e_shnum,
        }
    }

    #[inline]
    pub fn e_shoff(&self) -> Option<NonZeroU64> {
        match self {
            Self::Elf32(header) => header.e_shoff.map(|v| v.into()),
            Self::Elf64(header) => header.e_shoff,
        }
    }

    #[inline]
    pub fn e_shentsize(&self) -> u16 {
        match self {
            Self::Elf32(header) => header.e_shentsize,
            Self::Elf64(header) => header.e_shentsize,
        }
    }

    pub fn get_section_header_offset(&self, header_number: u16) -> Option<Range<u64>> {
        if header_number >= self.e_shnum()?.get() {
            return None;
        }

        let size = u64::from(self.e_shentsize());
        let start = self.e_shoff()?.get() + u64::from(header_number) * size;
        Some(Range {
            start,
            end: start + size,
        })
    }

    pub fn get_string_table_header_offset(&self) -> Option<Range<u64>> {
        self.get_section_header_offset(self.get_string_table_index()?.get())
    }
}

/// An Elf header type, representing either 64 or 32 bit section headers.
#[derive(Debug)]
pub enum ElfSectionHeader<'buf> {
    Elf32(&'buf Elf32SectionHeader),
    Elf64(&'buf Elf64SectionHeader),
}

impl<'buf> ElfSectionHeader<'buf> {
    pub fn parse(header: &ElfHeader, bytes: &'buf [u8]) -> Option<Self> {
        let sh_header = match header {
            ElfHeader::Elf32(_) => Self::Elf32(Elf32SectionHeader::ref_from_prefix(bytes)?),
            ElfHeader::Elf64(_) => Self::Elf64(Elf64SectionHeader::ref_from_prefix(bytes)?),
        };

        Some(sh_header)
    }

    pub fn get_location_within_file(&self) -> Range<u64> {
        let (start, size) = match self {
            Self::Elf32(header) => (u64::from(header.sh_offset), u64::from(header.sh_size)),
            Self::Elf64(header) => (header.sh_offset, header.sh_size),
        };

        Range {
            start,
            end: start + size,
        }
    }

    pub fn get_name<'a>(
        &self,
        string_table: &'a [u8],
    ) -> Result<&'a str, Box<dyn std::error::Error>> {
        let sh_name_index = match self {
            Self::Elf32(header) => header.sh_name,
            Self::Elf64(header) => header.sh_name,
        }
        .try_into()?;

        if sh_name_index >= string_table.len() {
            // bad data.
            todo!()
        }

        let null_terminated = &string_table[sh_name_index..];

        Ok(CStr::from_bytes_until_nul(null_terminated)?.to_str()?)
    }

    pub fn get_type_name(&self) -> Cow<'static, str> {
        let sh_type = match self {
            Self::Elf32(header) => header.sh_type,
            Self::Elf64(header) => header.sh_type,
        };

        match sh_type {
            0 => "NULL".into(),
            1 => "PROGBITS".into(),
            2 => "SYMTAB".into(),
            3 => "STRTAB".into(),
            4 => "RELA".into(),
            5 => "HASH".into(),
            6 => "DYNAMIC".into(),
            7 => "NOTE".into(),
            8 => "NOBITS".into(),
            9 => "REL".into(),
            10 => "SHLIB".into(),
            11 => "DYNSYM".into(),
            14 => "INIT_ARRAY".into(),
            15 => "FINI_ARRAY".into(),
            0x6ffffff6 => "GNU_HASH".into(),
            0x6ffffffe => "VERNEED".into(),
            0x6fffffff => "VERSYM".into(),
            // unknonwn
            _ => sh_type.to_string().into(),
        }
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
            buffer[4] = ElfIdent::CLASS_64.0;
            buffer[5] = ElfIdent::DATA_2_LSB.0;
            buffer[6] = ElfIdent::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_some());
    }

    #[test]
    fn allows_valid_ident_32() {
        let buffer = {
            // 52 is the length of ELF32 header.
            let mut buffer = [0; 52];
            buffer[..4].copy_from_slice(b"\x7fELF");
            buffer[4] = ElfIdent::CLASS_32.0;
            buffer[5] = ElfIdent::DATA_2_LSB.0;
            buffer[6] = ElfIdent::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_some());
    }

    #[test]
    fn disallows_invalid_magic() {
        let buffer = {
            // 64 is the length of ELF64 header.
            let mut buffer = [0; 64];
            buffer[..4].copy_from_slice(b"0000");
            buffer[4] = ElfIdent::CLASS_64.0;
            buffer[5] = ElfIdent::DATA_2_LSB.0;
            buffer[6] = ElfIdent::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_none());
    }

    #[test]
    fn disallows_big_endian() {
        let buffer = {
            // 64 is the length of ELF64 header.
            let mut buffer = [0; 64];
            buffer[..4].copy_from_slice(b"\x7fELF");
            buffer[4] = ElfIdent::CLASS_64.0;
            buffer[5] = ElfIdent::DATA_2_MSB.0;
            buffer[6] = ElfIdent::EV_CURRENT.0;

            buffer
        };

        assert!(ElfHeader::parse(&buffer).is_none());
    }
}
