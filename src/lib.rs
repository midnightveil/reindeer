//! Structures for parsing of ELF file headers.
//!
//! The standard is [TIS Portable Formats Specification v1.2][elf standard].
//! The man page [elf(5)][man-elf] also contains details.
//!
//! Here we assume that all data is little-endian, to make my life easier.
//!
//! [elf standard]: https://refspecs.linuxfoundation.org/elf/elf.pdf
//! [man-elf]: https://man7.org/linux/man-pages/man5/elf.5.html

use std::mem::size_of;

use zerocopy::{FromBytes, FromZeroes, Ref};
