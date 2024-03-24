//! Structures for parsing of ELF file headers.
//!
//! The standard is [TIS Portable Formats Specification v1.2][elf standard].
//! The man page [elf(5)][man-elf] also contains details.
//!
//! Here we assume that all data is little-endian, to make my life easier.
//!
//! [elf standard]: https://refspecs.linuxfoundation.org/elf/elf.pdf
//! [man-elf]: https://man7.org/linux/man-pages/man5/elf.5.html

pub mod elf_aux_structures;
pub mod elf_structures;

use elf_aux_structures::ElfIdentClass;
use elf_structures::*;
use zerocopy::{FromBytes, Ref};

/// An Elf header type, representing either 64 or 32 bit little-endian ELFs.
#[derive(Debug)]
pub enum ElfHeader<'buf> {
    Elf32(&'buf Elf32Header),
    Elf64(&'buf Elf64Header),
}

pub fn valid_ident(e_ident: &ElfIdent) -> bool {
    return e_ident.ei_magic == *b"\x7fELF"
        && e_ident.ei_data == ElfIdent::DATA_2_LSB
        && e_ident.ei_version == ElfIdent::EV_CURRENT;
}

impl<'buf> ElfHeader<'buf> {
    pub fn parse(bytes: &'buf [u8]) -> Option<(Self, &'buf [u8])> {
        let e_ident: &ElfIdent = ElfIdent::ref_from_prefix(bytes)?;
        if !valid_ident(e_ident) {
            return None;
        }

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
