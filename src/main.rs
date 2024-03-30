use std::{env, error::Error, fs::File, io::Read};

use reindeerlib::{range::as_range_usize, ElfHeader, ElfProgramHeader, ElfSectionHeader};

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or("/bin/true".into());
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let header = ElfHeader::parse(&buffer).unwrap();
    let _string_table = get_string_table(header, &buffer)?;

    _print_section_headers(header, &buffer, _string_table)?;
    println!();
    _print_program_headers(header, &buffer)?;

    Ok(())
}

fn _print_program_headers(header: ElfHeader<'_>, buffer: &[u8]) -> Result<(), Box<dyn Error>> {
    println!(
        "Type           Offset   VirtAddr           PhysAddr           FileSize MemSize  Flags Align"
    );

    for n in 0..header.e_phnum().unwrap().get() {
        let prog_header_loc = as_range_usize(header.program_header_location(n).unwrap())?;

        let program_header = ElfProgramHeader::parse(&header, &buffer[prog_header_loc]).unwrap();
        let ElfProgramHeader::Elf64(prog_header) = program_header else {
            panic!()
        };

        println!(
            "{:<14} 0x{:06x} {:018x} {:018x} 0x{:06x} 0x{:06x} {:5} 0x{:<4x}",
            program_header.type_name(),
            prog_header.p_offset,
            prog_header.p_vaddr,
            prog_header.p_paddr,
            prog_header.p_filesz.map(|v| v.into()).unwrap_or(0),
            prog_header.p_memsz.map(|v| v.into()).unwrap_or(0),
            prog_header.p_flags,
            prog_header.p_align,
        );
    }

    Ok(())
}

fn get_string_table<'a>(header: ElfHeader, buffer: &'a [u8]) -> Result<&'a [u8], Box<dyn Error>> {
    let string_table_header_location =
        as_range_usize(header.string_table_header_location().unwrap())?;
    let string_table_header =
        ElfSectionHeader::parse(&header, &buffer[string_table_header_location]).unwrap();
    let string_table_location = as_range_usize(string_table_header.section_location())?;
    let string_table = &buffer[string_table_location];
    assert_eq!(string_table.first(), Some(0).as_ref());
    assert_eq!(string_table.last(), Some(0).as_ref());

    Ok(string_table)
}

fn _print_section_headers(
    header: ElfHeader,
    buffer: &[u8],
    string_table: &[u8],
) -> Result<(), Box<dyn Error>> {
    println!(
        "[Nr] Name                  Type            Address          Off    Size   Flags Align"
    );
    for n in 0..header.e_shnum().unwrap().get() {
        let section_header_location = as_range_usize(header.section_header_location(n).unwrap())?;
        let section_header =
            ElfSectionHeader::parse(&header, &buffer[section_header_location]).unwrap();
        let name = section_header.name(string_table)?;

        let ElfSectionHeader::Elf64(sec_header) = section_header else {
            panic!()
        };

        println!(
            "[{:02}] {:<21} {:<15} {:016x} {:06x} {:06x} {:5x} {:5}",
            n,
            name,
            section_header.type_name(),
            sec_header.sh_addr.map(|v| v.get()).unwrap_or(0),
            sec_header.sh_offset,
            sec_header.sh_size,
            sec_header.sh_flags,
            sec_header.sh_addralign,
        );
    }

    Ok(())
}
