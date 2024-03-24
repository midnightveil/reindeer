pub mod elf_aux_structures;
pub mod elf_structures;

use std::{borrow::Cow, ffi::CStr};

use elf_aux_structures::*;
use elf_structures::*;
use zerocopy::{FromBytes, Ref};

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
    pub fn parse(bytes: &'buf [u8]) -> Option<(Self, &'buf [u8])> {
        let e_ident: &ElfIdent = ElfIdent::ref_from_prefix(bytes)?;
        if !valid_ident(e_ident) {
            return None;
        }

        // TODO: add more checks.

        match e_ident.ei_class {
            ElfIdent::CLASS_32 => {
                let (e_header, rest) = Ref::<_, Elf32Header>::new_from_prefix(bytes)?;
                Some((Self::Elf32(e_header.into_ref()), rest))
            }
            ElfIdent::CLASS_64 => {
                let (e_header, rest) = Ref::<_, Elf64Header>::new_from_prefix(bytes)?;
                Some((Self::Elf64(e_header.into_ref()), rest))
            }
            ElfIdent::CLASS_NONE | ElfIdentClass(_) => None,
        }
    }
}

/// An Elf header type, representing either 64 or 32 bit section headers.
#[derive(Debug)]
pub enum ElfSectionHeader<'buf> {
    Elf32(&'buf Elf32SectionHeader),
    Elf64(&'buf Elf64SectionHeader),
}

impl<'buf> ElfSectionHeader<'buf> {
    pub fn parse() {}

    pub fn get_name<'a>(
        &self,
        string_table: &'a [u8],
    ) -> Result<&'a str, Box<dyn std::error::Error>> {
        let null_terminated = match self {
            Self::Elf32(header) => &string_table[header.sh_name as usize..],
            Self::Elf64(header) => &string_table[header.sh_name as usize..],
        };

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
