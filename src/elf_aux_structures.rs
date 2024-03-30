use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::*;

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfIdentClass(pub u8);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfIdentData(pub u8);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfIdentVersion(pub u8);

impl ElfIdent {
    pub const CLASS_NONE: ElfIdentClass = ElfIdentClass(0);
    pub const CLASS_32: ElfIdentClass = ElfIdentClass(1);
    pub const CLASS_64: ElfIdentClass = ElfIdentClass(2);

    pub const DATA_NONE: ElfIdentData = ElfIdentData(0);
    pub const DATA_2_LSB: ElfIdentData = ElfIdentData(1);
    pub const DATA_2_MSB: ElfIdentData = ElfIdentData(2);

    pub const EV_NONE: ElfIdentVersion = ElfIdentVersion(0);
    pub const EV_CURRENT: ElfIdentVersion = ElfIdentVersion(1);
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfHeaderType(pub u16);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ElfHeaderMachine(pub u16);
#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
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
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug, Eq, PartialEq)]
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
    pub const PT_LOPROC: ElfSegmentType = ElfSegmentType(0x70000000);
    pub const PT_HIPROC: ElfSegmentType = ElfSegmentType(0x7fffffff);
}
