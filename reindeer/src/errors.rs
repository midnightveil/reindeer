use std::{ffi::FromBytesUntilNulError, num::TryFromIntError, str::Utf8Error};

use crate::{elf_aux_structures::*, elf_structures::ElfIdent};

#[derive(thiserror::Error, Debug)]
pub enum ElfError {
    #[error("buffer is smaller than expected, or is not aligned")]
    ZeroCopyError,
    #[error("invalid magic number, expected {:?}, found {:?}", ElfIdent::ELF_MAGIC, .0)]
    InvalidMagic([u8; 4]),
    #[error("invalid data encoding, expected {:?}, found {:?}", ElfIdentData::DATA_2_LSB, .0)]
    InvalidDataEncoding(ElfIdentData),
    #[error("invalid elf ident version, expected {:?}, found {:?}", ElfIdentVersion::EV_CURRENT, .0)]
    InvalidVersion(ElfIdentVersion),
    #[error("invalid elf ident class, found {:?}", .0)]
    InvalidClass(ElfIdentClass),

    #[error("too big for usize: {}", .0)]
    TooBigForUsize(#[from] TryFromIntError),
    #[error("string table index {} is outside the string table", .0)]
    StringTableOutOfBounds(usize),
    #[error("{}", .0)]
    FromBytesUntilNull(#[from] FromBytesUntilNulError),
    #[error("{}", .0)]
    Utf8Error(#[from] Utf8Error),

    #[error("The file size can not be larger than the memory size.")]
    FileSzLargerThanMemSz,
    #[error("")]
    IncongurentSegmentAlignment,
}
