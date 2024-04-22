use std::{env, error::Error, fs::File, io::Read};

use reindeer::{
    elf_aux_structures::ElfSegmentType, range::TryIntoRangeUsize, ElfHeader, ElfProgramHeader,
    ElfSectionHeader, ElfStringTable,
};

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or("/bin/true".into());
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let header = ElfHeader::parse(&buffer).unwrap();
    let _string_table = get_string_table(header, &buffer)?;
    // _print_segment_load_locations(header, &buffer)?;
    _print_section_headers(header, &buffer, _string_table)?;
    println!();
    _print_program_headers(header, &buffer)?;

    for n in 0..header.e_phnum().unwrap().get() {
        let prog_header_loc = header
            .program_header_location(n)
            .unwrap()
            .try_into_usize()?;
        let prog_header = ElfProgramHeader::parse(&header, &buffer[prog_header_loc]).unwrap();
        if prog_header.p_type() != ElfSegmentType::PT_LOAD {
            continue;
        }

        println!("{:?}", prog_header);
    }

    Ok(())
}

fn _print_segment_load_locations(
    header: ElfHeader<'_>,
    buffer: &[u8],
) -> Result<(), Box<dyn Error>> {
    for n in 0..header.e_phnum().unwrap().get() {
        let prog_header_loc = header
            .program_header_location(n)
            .unwrap()
            .try_into_usize()?;

        let program_header = ElfProgramHeader::parse(&header, &buffer[prog_header_loc]).unwrap();
        println!(
            "{:?} into {:?}",
            program_header.file_location(),
            program_header.memory_location()
        );
    }

    Ok(())
}

fn _print_program_headers(header: ElfHeader<'_>, buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    println!(
        "Type           Offset   VirtAddr           PhysAddr           FileSize MemSize  Flags Align"
    );

    for n in 0..header.e_phnum().unwrap().get() {
        let prog_header_loc = header
            .program_header_location(n)
            .unwrap()
            .try_into_usize()?;

        let program_header = ElfProgramHeader::parse(&header, &buffer[prog_header_loc]).unwrap();
        let ElfProgramHeader::Elf64(prog_header) = program_header else {
            panic!()
        };

        println!(
            "{:<15} 0x{:06x} {:018x} {:018x} 0x{:06x} 0x{:06x} {:5} 0x{:<4x}",
            program_header.p_type().name().unwrap_or(&format!("{:#x}", program_header.p_type().0)),
            prog_header.p_offset,
            prog_header.p_vaddr,
            prog_header.p_paddr,
            prog_header.p_filesz.map(Into::into).unwrap_or(0),
            prog_header.p_memsz.map(Into::into).unwrap_or(0),
            prog_header.p_flags,
            prog_header.p_align,
        );
    }

    Ok(())
}

fn get_string_table<'a>(
    header: ElfHeader,
    buffer: &'a [u8],
) -> Result<ElfStringTable<'a>, Box<dyn Error>> {
    let string_table_header_location = header
        .string_table_header_location()
        .unwrap()
        .try_into_usize()?;
    let string_table_header =
        ElfSectionHeader::parse(&header, &buffer[string_table_header_location]).unwrap();
    let string_table_location = string_table_header.location().try_into_usize()?;

    Ok(ElfStringTable::parse(&buffer[string_table_location])?)
}

fn _print_section_headers(
    header: ElfHeader,
    buffer: &[u8],
    string_table: ElfStringTable,
) -> Result<(), Box<dyn Error>> {
    println!(
        "[Nr] Name                  Type            Address          Off    Size   Flags Align"
    );
    for n in 0..header.e_shnum().unwrap().get() {
        let section_header_location = header
            .section_header_location(n)
            .unwrap()
            .try_into_usize()?;
        let section_header =
            ElfSectionHeader::parse(&header, &buffer[section_header_location]).unwrap();
        let name = string_table.section_name(section_header)?;

        let ElfSectionHeader::Elf64(sec_header) = section_header else {
            panic!()
        };

        println!(
            "[{:02}] {:<21} {:<15} {:016x} {:06x} {:06x} {:5x} {:5}",
            n,
            name,
            section_header.sh_type().name().unwrap_or(&format!("{:#x}", section_header.sh_type().0)),
            sec_header.sh_addr.map(|v| v.get()).unwrap_or(0),
            sec_header.sh_offset,
            sec_header.sh_size,
            sec_header.sh_flags,
            sec_header.sh_addralign,
        );
    }

    Ok(())
}
