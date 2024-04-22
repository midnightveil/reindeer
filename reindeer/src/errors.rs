use core::{
    ffi::FromBytesUntilNulError,
    num::{NonZeroU16, TryFromIntError},
    str::Utf8Error,
};

use crate::{elf_aux_structures::*, elf_structures::ElfIdent};

#[derive(err_derive::Error, Debug)]
pub enum ElfError {
    #[error(display = "buffer is smaller than expected, or is not aligned")]
    ZeroCopyError,
    #[error(
        display = "invalid magic number, expected {:?}, found {:?}",
        ElfIdent::ELF_MAGIC,
        _0
    )]
    InvalidMagic([u8; 4]),
    #[error(
        display = "invalid data encoding, expected {:?}, found {:?}",
        ElfIdentData::DATA_2_LSB,
        _0
    )]
    InvalidDataEncoding(ElfIdentData),
    #[error(
        display = "invalid elf ident version, expected {:?}, found {:?}",
        ElfIdentVersion::EV_CURRENT,
        _0
    )]
    InvalidVersion(ElfIdentVersion),
    #[error(display = "invalid elf ident class, found {:?}", _0)]
    InvalidClass(ElfIdentClass),

    #[error(display = "too big for usize: {}", _0)]
    TooBigForUsize(#[source] TryFromIntError),
    #[error(
        display = "string table section header index {} is outside the section table",
        _0
    )]
    StringTableHeaderOutOfBounds(NonZeroU16),
    #[error(display = "string table index {} is outside the string table", _0)]
    StringTableOutOfBounds(usize),
    #[error(display = "string table first/last bytes were not zero")]
    StringTableNotZeroTerminated,
    #[error(display = "{}", _0)]
    FromBytesUntilNull(#[source] FromBytesUntilNulError),
    #[error(display = "{}", _0)]
    Utf8Error(#[source] Utf8Error),

    #[error(display = "The file size can not be larger than the memory size.")]
    FileSzLargerThanMemSz,
    #[error(display = "segment alignment is congruent with address")]
    IncongurentSegmentAlignment,

    #[error(display = "the elf file has no section header table")]
    NoSectionHeaders,
}
