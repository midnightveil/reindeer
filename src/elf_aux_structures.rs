use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::*;

macro_rules! enum_getter {
    ($property:ident, Option<$typ:ty>) => {
        #[inline]
        pub fn $property(&self) -> Option<$typ> {
            match self {
                Self::Elf32(header) => header.$property.map(Into::into),
                Self::Elf64(header) => header.$property,
            }
        }
    };
    (&$property:ident, $type:ty) => {
        #[inline]
        pub fn $property(&self) -> $type {
            match self {
                Self::Elf32(header) => &header.$property,
                Self::Elf64(header) => &header.$property,
            }
        }
    };
    ($property:ident, $type:ty) => {
        #[inline]
        pub fn $property(&self) -> $type {
            match self {
                Self::Elf32(header) => header.$property.into(),
                Self::Elf64(header) => header.$property,
            }
        }
    };
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfIdentClass(pub u8);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfIdentData(pub u8);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfIdentVersion(pub u8);

impl ElfIdent {
    pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

    pub const CLASS_NONE: ElfIdentClass = ElfIdentClass(0);
    pub const CLASS_32: ElfIdentClass = ElfIdentClass(1);
    pub const CLASS_64: ElfIdentClass = ElfIdentClass(2);

    pub const DATA_NONE: ElfIdentData = ElfIdentData(0);
    pub const DATA_2_LSB: ElfIdentData = ElfIdentData(1);
    pub const DATA_2_MSB: ElfIdentData = ElfIdentData(2);

    pub const EV_NONE: ElfIdentVersion = ElfIdentVersion(0);
    pub const EV_CURRENT: ElfIdentVersion = ElfIdentVersion(1);
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfHeaderType(pub u16);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfHeaderMachine(pub u16);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C)]
pub struct ElfHeaderVersion(pub u32);

impl ElfHeader<'_> {
    pub const ET_NONE: ElfHeaderType = ElfHeaderType(0); // No file type
    pub const ET_REL: ElfHeaderType = ElfHeaderType(1); // Relocatable file
    pub const ET_EXEC: ElfHeaderType = ElfHeaderType(2); // Executable file
    pub const ET_DYN: ElfHeaderType = ElfHeaderType(3); // Shared object file
    pub const ET_CORE: ElfHeaderType = ElfHeaderType(4); // Core file
    pub const ET_LOPROC: ElfHeaderType = ElfHeaderType(0xff00); // Processor-specific
    pub const ET_HIPROC: ElfHeaderType = ElfHeaderType(0xffff); // Processor-specific

    pub const EM_NONE: ElfHeaderMachine = ElfHeaderMachine(0); // No machine

    pub const EV_NONE: ElfHeaderVersion = ElfHeaderVersion(0);
    pub const EV_CURRENT: ElfHeaderVersion = ElfHeaderVersion(1);

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

impl ElfSectionHeader<'_> {
    pub const SHT_NULL: ElfSectionType = ElfSectionType(0);
    pub const SHT_PROGBITS: ElfSectionType = ElfSectionType(1);
    pub const SHT_SYMTAB: ElfSectionType = ElfSectionType(2);
    pub const SHT_STRTAB: ElfSectionType = ElfSectionType(3);
    pub const SHT_RELA: ElfSectionType = ElfSectionType(4);
    pub const SHT_HASH: ElfSectionType = ElfSectionType(5);
    pub const SHT_DYNAMIC: ElfSectionType = ElfSectionType(6);
    pub const SHT_NOTE: ElfSectionType = ElfSectionType(7);
    pub const SHT_NOBITS: ElfSectionType = ElfSectionType(8);
    pub const SHT_REL: ElfSectionType = ElfSectionType(9);
    pub const SHT_SHLIB: ElfSectionType = ElfSectionType(10);
    pub const SHT_DYNSYM: ElfSectionType = ElfSectionType(11);
    pub const SHT_INIT_ARRAY: ElfSectionType = ElfSectionType(14);
    pub const SHT_FINI_ARRAY: ElfSectionType = ElfSectionType(15);
    pub const SHT_GNU_HASH: ElfSectionType = ElfSectionType(0x6ffffff6);
    pub const SHT_VERNEED: ElfSectionType = ElfSectionType(0x6ffffffe);
    pub const SHT_VERSYM: ElfSectionType = ElfSectionType(0x6fffffff);

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

impl ElfProgramHeader<'_> {
    pub const PT_NULL: ElfSegmentType = ElfSegmentType(0);
    pub const PT_LOAD: ElfSegmentType = ElfSegmentType(1);
    pub const PT_DYNAMIC: ElfSegmentType = ElfSegmentType(2);
    pub const PT_INTERP: ElfSegmentType = ElfSegmentType(3);
    pub const PT_NOTE: ElfSegmentType = ElfSegmentType(4);
    pub const PT_SHLIB: ElfSegmentType = ElfSegmentType(5);
    pub const PT_PHDR: ElfSegmentType = ElfSegmentType(6);
    pub const PT_TLS: ElfSegmentType = ElfSegmentType(7);
    // https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/progheader.html
    pub const PT_GNU_EH_FRAME: ElfSegmentType = ElfSegmentType(0x6474e550);
    pub const PT_GNU_STACK: ElfSegmentType = ElfSegmentType(0x6474e551);
    pub const PT_GNU_RELRO: ElfSegmentType = ElfSegmentType(0x6474e552);
    pub const PT_GNU_PROPERTY: ElfSegmentType = ElfSegmentType(0x6474e553);

    pub const PT_LOPROC: ElfSegmentType = ElfSegmentType(0x70000000);
    pub const PT_HIPROC: ElfSegmentType = ElfSegmentType(0x7fffffff);

    enum_getter!(p_type, ElfSegmentType);
    enum_getter!(p_offset, u64);
    enum_getter!(p_vaddr, u64);
    enum_getter!(p_paddr, u64);
    enum_getter!(p_filesz, Option<NonZeroU64>);
    enum_getter!(p_memsz, Option<NonZeroU64>);
    enum_getter!(p_flags, u32);
    enum_getter!(p_align, u64);
}
