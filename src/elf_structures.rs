use std::mem::size_of;

use zerocopy::{FromBytes, FromZeroes, AsBytes};

use crate::elf_aux_structures::*;

macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

const_assert!(size_of::<ElfIdent>() == 16);
const_assert!(size_of::<Elf32Header>() == 52);
const_assert!(size_of::<Elf64Header>() == 64);

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct ElfIdent {
    /// ELF Magic, should be `b"\x7fELF"`.
    pub ei_magic: [u8; 4],
    /// EI_CLASS identifies the file's class, or capacity.
    pub ei_class: ElfIdentClass,
    /// EI_DATA specifies the data encoding of the processor-specific data in the object file.
    pub ei_data: ElfIdentData,
    /// EI_VERSION specifies the ELF header version number.
    pub ei_version: ElfIdentVersion,
    /// Padding bytes.
    pub ei_pad: [u8; 9],
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct Elf32Header {
    /// ELF Ident
    pub e_ident: ElfIdent,
    /// Identifies the object file type (executable, shared object, etc)
    pub e_type: ElfHeaderType,
    /// The required architecture for a file.
    pub e_machine: ElfHeaderMachine,
    /// The ELF object file version. (1 = current)
    pub e_version: ElfHeaderVersion,
    /// This member gives the virtual address to which the system first
    /// transfers control, thus starting the process. If the file has no
    /// associated entry point, this member holds zero.
    pub e_entry: u32,
    /// This member holds the program header table's file offset in bytes. If
    /// the file has no program header table, this member holds zero.
    pub e_phoff: u32,
    /// This member holds the section header table's file offset in bytes. If
    /// the file has no section header table, this member holds zero.
    pub e_shoff: u32,
    /// This member holds processor-specific flags associated with the file.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program
    /// header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table.
    /// Thus the product of `e_phentsize` and `e_phnum` gives the table's size
    /// in bytes. If a file has no program header table, e_phnum holds the value
    /// zero.
    pub e_phnum: u16,
    /// This member holds a section header's size in bytes. A
    /// section header is one entry in the section header table; all entries are
    /// the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table.
    /// Thus the product of `e_shentsize` and `e_shnum` gives the section
    /// header table's size in bytes. If a file has no section header table,
    /// `e_shnum` holds the value zero.
    pub e_shnum: u16,
    /// This member holds the section header table index of the entry associated
    /// with the section name string table. If the file has no section name
    /// string table, this member holds the value `SHN_UNDEF` (0).
    pub e_shstrndx: u16,
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct Elf64Header {
    /// ELF Ident
    pub e_ident: ElfIdent,
    /// Identifies the object file type (executable, shared object, etc)
    pub e_type: ElfHeaderType,
    /// The required architecture for a file.
    pub e_machine: ElfHeaderMachine,
    /// The ELF object file version. (1 = current)
    pub e_version: ElfHeaderVersion,
    /// This member gives the virtual address to which the system first
    /// transfers control, thus starting the process. If the file has no
    /// associated entry point, this member holds zero.
    pub e_entry: u64,
    /// This member holds the program header table's file offset in bytes. If
    /// the file has no program header table, this member holds zero.
    pub e_phoff: u64,
    /// This member holds the section header table's file offset in bytes. If
    /// the file has no section header table, this member holds zero.
    pub e_shoff: u64,
    /// This member holds processor-specific flags associated with the file.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program
    /// header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table.
    /// Thus the product of `e_phentsize` and `e_phnum` gives the table's size
    /// in bytes. If a file has no program header table, e_phnum holds the value
    /// zero.
    pub e_phnum: u16,
    /// This member holds a section header's size in bytes. A
    /// section header is one entry in the section header table; all entries are
    /// the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table.
    /// Thus the product of `e_shentsize` and `e_shnum` gives the section
    /// header table's size in bytes. If a file has no section header table,
    /// `e_shnum` holds the value zero.
    pub e_shnum: u16,
    /// This member holds the section header table index of the entry associated
    /// with the section name string table. If the file has no section name
    /// string table, this member holds the value `SHN_UNDEF` (0).
    pub e_shstrndx: u16,
}
