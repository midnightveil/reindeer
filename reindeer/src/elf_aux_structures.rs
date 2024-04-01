use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::{macros::*, *};

impl ElfIdent {
    pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ElfIdentClass(pub u8);

declare_constants!(ElfIdentClass, {
    CLASS_NONE = 0,
    CLASS_32 = 1,
    CLASS_64 = 2,
});

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ElfIdentData(pub u8);

declare_constants!(ElfIdentData, {
    DATA_NONE = 0,
    DATA_2_LSB = 1,
    DATA_2_MSB = 2,
});

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ElfIdentVersion(pub u8);

declare_constants!(ElfIdentVersion, {
    EV_NONE = 0,
    EV_CURRENT = 1,
});

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ElfHeaderType(pub u16);

declare_constants!(ElfHeaderType, {
    ET_NONE = 0, // No file type
    ET_REL = 1, // Relocatable file
    ET_EXEC = 2, // Executable file
    ET_DYN = 3, // Shared object file
    ET_CORE = 4, // Core file

    // TODO: This is really a range....
    ET_LOPROC = 0xff00, // Processor-specific
    ET_HIPROC = 0xffff, // Processor-specific
});

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ElfHeaderMachine(pub u16);

declare_constants!(ElfHeaderMachine, {
    EM_NONE = 0,
});

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(transparent)]
pub struct ElfHeaderVersion(pub u32);

declare_constants!(ElfHeaderVersion, {
    EV_NONE = 0,
    EV_CURRENT = 1,
});

impl ElfHeader<'_> {
    enum_getter!(&e_ident, &ElfIdent);
    enum_getter!(e_type, ElfHeaderType);
    enum_getter!(e_version, ElfHeaderVersion);
    enum_getter!(e_entry, Option<NonZeroU64>);
    enum_getter!(e_phoff, Option<NonZeroU64>);
    enum_getter!(e_shoff, Option<NonZeroU64>);
    enum_getter!(e_flags, u32);
    enum_getter!(e_ehsize, u16);
    enum_getter!(e_phentsize, u16);
    enum_getter!(e_phnum, Option<NonZeroU16>);
    enum_getter!(e_shentsize, u16);
    enum_getter!(e_shnum, Option<NonZeroU16>);
    enum_getter!(e_shstrndx, Option<NonZeroU16>);
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfSectionType(pub u32);

declare_constants!(ElfSectionType, {
    SHT_NULL = 0,
    SHT_PROGBITS = 1,
    SHT_SYMTAB = 2,
    SHT_STRTAB = 3,
    SHT_RELA = 4,
    SHT_HASH = 5,
    SHT_DYNAMIC = 6,
    SHT_NOTE = 7,
    SHT_NOBITS = 8,
    SHT_REL = 9,
    SHT_SHLIB = 10,
    SHT_DYNSYM = 11,
    SHT_INIT_ARRAY = 14,
    SHT_FINI_ARRAY = 15,
    SHT_GNU_HASH = 0x6ffffff6,
    SHT_VERNEED = 0x6ffffffe,
    SHT_VERSYM = 0x6fffffff,
});

impl ElfSectionHeader<'_> {
    enum_getter!(sh_name, u32);
    enum_getter!(sh_type, ElfSectionType);
    enum_getter!(sh_flags, u64);
    enum_getter!(sh_addr, Option<NonZeroU64>);
    enum_getter!(sh_offset, u64);
    enum_getter!(sh_size, u64);
    enum_getter!(sh_link, u32);
    enum_getter!(sh_info, u32);
    enum_getter!(sh_addralign, u64);
    enum_getter!(sh_entsize, Option<NonZeroU64>);
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfSegmentType(pub u32);

declare_constants!(ElfSegmentType, {
    PT_NULL = 0,
    PT_LOAD = 1,
    PT_DYNAMIC = 2,
    PT_INTERP = 3,
    PT_NOTE = 4,
    PT_SHLIB = 5,
    PT_PHDR = 6,
    PT_TLS = 7,
    // https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/progheader.html
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_GNU_STACK = 0x6474e551,
    PT_GNU_RELRO = 0x6474e552,
    PT_GNU_PROPERTY = 0x6474e553,

    // TODO: This is really a range...
    PT_LOPROC = 0x70000000,
    PT_HIPROC = 0x7fffffff,
});

impl ElfProgramHeader<'_> {
    enum_getter!(p_type, ElfSegmentType);
    enum_getter!(p_offset, u64);
    enum_getter!(p_vaddr, u64);
    enum_getter!(p_paddr, u64);
    enum_getter!(p_filesz, Option<NonZeroU64>);
    enum_getter!(p_memsz, Option<NonZeroU64>);
    enum_getter!(p_flags, u32);
    enum_getter!(p_align, u64);
}
