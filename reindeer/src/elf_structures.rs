//! Structures for parsing of ELF file headers.
//!
//! The standard is [TIS Portable Formats Specification v1.2][elf standard].
//! The man page [elf(5)][man-elf] also contains details.
//! The documentation for 64-bit ELF headers is [System V ABI Draft 2013][sco]
//!
//! Here we assume that all data is little-endian, to make my life easier.
//!
//! [elf standard]: https://refspecs.linuxfoundation.org/elf/elf.pdf
//! [man-elf]: https://man7.org/linux/man-pages/man5/elf.5.html
//! [sco]: https://www.sco.com/developers/gabi/latest/contents.html

use core::{
    mem::size_of,
    num::{NonZeroU16, NonZeroU32, NonZeroU64},
};

use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::elf_aux_structures::*;

macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}

const_assert!(size_of::<ElfIdent>() == 16);
const_assert!(size_of::<Elf32Header>() == 52);
const_assert!(size_of::<Elf64Header>() == 64);
const_assert!(size_of::<Elf32SectionHeader>() == 40);
const_assert!(size_of::<Elf64SectionHeader>() == 64);
const_assert!(size_of::<Elf32ProgramHeader>() == 32);
const_assert!(size_of::<Elf64ProgramHeader>() == 56);

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
    pub e_entry: Option<NonZeroU32>,
    /// This member holds the program header table's file offset in bytes. If
    /// the file has no program header table, this member holds zero.
    pub e_phoff: Option<NonZeroU32>,
    /// This member holds the section header table's file offset in bytes. If
    /// the file has no section header table, this member holds zero.
    pub e_shoff: Option<NonZeroU32>,
    /// This member holds processor-specific flags associated with the file.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program
    /// header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table.
    /// Thus the product of `e_phentsize` and `e_phnum` gives the table's size
    /// in bytes. If a file has no program header table, `e_phnum` is None.
    pub e_phnum: Option<NonZeroU16>,
    /// This member holds a section header's size in bytes. A
    /// section header is one entry in the section header table; all entries are
    /// the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table.
    /// Thus the product of `e_shentsize` and `e_shnum` gives the section
    /// header table's size in bytes. If a file has no section header table,
    /// `e_shnum` is `None`.
    pub e_shnum: Option<NonZeroU16>,
    /// This member holds the section header table index of the entry associated
    /// with the section name string table. If the file has no section name
    /// string table, this member is `None`.
    pub e_shstrndx: Option<NonZeroU16>,
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
    pub e_entry: Option<NonZeroU64>,
    /// This member holds the program header table's file offset in bytes. If
    /// the file has no program header table, this member holds zero.
    pub e_phoff: Option<NonZeroU64>,
    /// This member holds the section header table's file offset in bytes. If
    /// the file has no section header table, this member holds zero.
    pub e_shoff: Option<NonZeroU64>,
    /// This member holds processor-specific flags associated with the file.
    pub e_flags: u32,
    /// This member holds the ELF header's size in bytes.
    pub e_ehsize: u16,
    /// This member holds the size in bytes of one entry in the file's program
    /// header table; all entries are the same size.
    pub e_phentsize: u16,
    /// This member holds the number of entries in the program header table.
    /// Thus the product of `e_phentsize` and `e_phnum` gives the table's size
    /// in bytes. If a file has no program header table, `e_phnum` is None.
    pub e_phnum: Option<NonZeroU16>,
    /// This member holds a section header's size in bytes. A
    /// section header is one entry in the section header table; all entries are
    /// the same size.
    pub e_shentsize: u16,
    /// This member holds the number of entries in the section header table.
    /// Thus the product of `e_shentsize` and `e_shnum` gives the section
    /// header table's size in bytes. If a file has no section header table,
    /// `e_shnum` is `None`.
    pub e_shnum: Option<NonZeroU16>,
    /// This member holds the section header table index of the entry associated
    /// with the section name string table. If the file has no section name
    /// string table, this member is `None`.
    pub e_shstrndx: Option<NonZeroU16>,
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct Elf32SectionHeader {
    /// This member specifies the name of the section. Its value is an index
    /// into the section header string table section.
    pub sh_name: u32,
    /// This member categorizes the section's contents and semantics.
    pub sh_type: ElfSectionType,
    /// Sections support 1-bit flags that describe miscellaneous attributes.
    pub sh_flags: u32,
    /// If the section will appear in the memory image of a process, this member
    /// gives the address at which the section's first byte should reside.
    /// Otherwise, the member contains 0.
    pub sh_addr: Option<NonZeroU32>,
    /// This member's value gives the byte offset from the beginning of the file
    /// to the first byte in the section.
    pub sh_offset: u32,
    /// This member gives the section's size in bytes.
    pub sh_size: u32,
    /// This member holds a section header table index link, whose
    /// interpretation depends on the section type.
    pub sh_link: u32,
    /// This member holds extra information, whose interpretation depends on the
    /// section type.
    pub sh_info: u32,
    /// Some sections have address alignment constraints. For example, if a
    /// section holds a doubleword, the system must ensure doubleword alignment
    /// for the entire section. That is, the value of `sh_addr` must be congruent
    /// to 0, modulo the value of `sh_addralign`. Currently, only 0 and positive
    /// integral powers of two are allowed. Values 0 and 1 mean the section has
    /// no alignment constraints.
    pub sh_addralign: u32,
    /// Some sections hold a table of fixed-size entries, such as a symbol table.
    /// For such a section, this member gives the size in bytes of each entry.
    /// The member contains 0 if the section does not hold a table of fixed-size
    /// entries.
    pub sh_entsize: Option<NonZeroU32>,
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct Elf64SectionHeader {
    /// This member specifies the name of the section. Its value is an index
    /// into the section header string table section.
    pub sh_name: u32,
    /// This member categorizes the section's contents and semantics.
    pub sh_type: ElfSectionType,
    /// Sections support 1-bit flags that describe miscellaneous attributes.
    pub sh_flags: u64,
    /// If the section will appear in the memory image of a process, this member
    /// gives the address at which the section's first byte should reside.
    /// Otherwise, the member contains 0.
    pub sh_addr: Option<NonZeroU64>,
    /// This member's value gives the byte offset from the beginning of the file
    /// to the first byte in the section.
    pub sh_offset: u64,
    /// This member gives the section's size in bytes.
    pub sh_size: u64,
    /// This member holds a section header table index link, whose
    /// interpretation depends on the section type.
    pub sh_link: u32,
    /// This member holds extra information, whose interpretation depends on the
    /// section type.
    pub sh_info: u32,
    /// Some sections have address alignment constraints. For example, if a
    /// section holds a doubleword, the system must ensure doubleword alignment
    /// for the entire section. That is, the value of `sh_addr` must be congruent
    /// to 0, modulo the value of `sh_addralign`. Currently, only 0 and positive
    /// integral powers of two are allowed. Values 0 and 1 mean the section has
    /// no alignment constraints.
    pub sh_addralign: u64,
    /// Some sections hold a table of fixed-size entries, such as a symbol table.
    /// For such a section, this member gives the size in bytes of each entry.
    /// The member contains 0 if the section does not hold a table of fixed-size
    /// entries.
    pub sh_entsize: Option<NonZeroU64>,
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct Elf32ProgramHeader {
    /// This member tells what kind of segment this array element describes or
    /// how to interpret the array element's information.
    pub p_type: ElfSegmentType,
    /// This member gives the offset from the beginning of the file at which the
    /// first byte of the segment resides.
    pub p_offset: u32,
    /// This member gives the virtual address at which the first byte of the
    /// segment resides in memory.
    pub p_vaddr: u32,
    /// On systems for which physical addressing is relevant, this member is
    /// reserved for the segment's physical address.
    pub p_paddr: u32,
    /// This member gives the number of bytes in the file image of the segment;
    /// it may be zero.
    pub p_filesz: Option<NonZeroU32>,
    /// This member gives the number of bytes in the memory image of the segment;
    /// it may be zero.
    pub p_memsz: Option<NonZeroU32>,
    /// This member gives flags relevant to the segment.
    pub p_flags: u32,
    /// This member gives the value to which the segments are aligned in memory
    /// and in the file.
    pub p_align: u32,
}

#[derive(FromBytes, FromZeroes, AsBytes, Debug)]
#[repr(C)]
pub struct Elf64ProgramHeader {
    /// This member tells what kind of segment this array element describes or
    /// how to interpret the array element's information.
    pub p_type: ElfSegmentType,
    /// This member gives flags relevant to the segment.
    pub p_flags: u32,
    /// This member gives the offset from the beginning of the file at which the
    /// first byte of the segment resides.
    pub p_offset: u64,
    /// This member gives the virtual address at which the first byte of the
    /// segment resides in memory.
    pub p_vaddr: u64,
    /// On systems for which physical addressing is relevant, this member is
    /// reserved for the segment's physical address.
    pub p_paddr: u64,
    /// This member gives the number of bytes in the file image of the segment;
    /// it may be zero.
    pub p_filesz: Option<NonZeroU64>,
    /// This member gives the number of bytes in the memory image of the segment;
    /// it may be zero.
    pub p_memsz: Option<NonZeroU64>,
    /// This member gives the value to which the segments are aligned in memory
    /// and in the file.
    pub p_align: u64,
}
