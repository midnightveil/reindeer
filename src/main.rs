use std::{env, error::Error, fs::File, io::Read};

use reindeerlib::{ElfHeader, ElfSectionHeader};

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or("/bin/true".into());
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let header = ElfHeader::parse(&buffer).unwrap();

    let string_table_header_offset = header.get_string_table_header_offset().unwrap();
    let string_table_header =
        ElfSectionHeader::parse(&header, &buffer[string_table_header_offset]).unwrap();
    let string_table_offset = string_table_header.get_location_within_file();
    let string_table = &buffer[string_table_offset];
    assert_eq!(string_table.first(), Some(0).as_ref());
    assert_eq!(string_table.last(), Some(0).as_ref());

    println!(
        "[Nr] Name                  Type            Address          Off    Size   Flags Align"
    );
    for n in 0..header.get_num_section_headers() {
        let section_header_offset = header.get_section_header_offset(n).unwrap();
        let section_header =
            ElfSectionHeader::parse(&header, &buffer[section_header_offset]).unwrap();
        let name = section_header.get_name(string_table).unwrap();

        let ElfSectionHeader::Elf64(sec_header) = section_header else {
            panic!()
        };

        println!(
            "[{:02}] {:<21} {:<15} {:016x} {:06x} {:06x} {:5x} {:5}",
            n,
            name,
            section_header.get_type_name(),
            sec_header.sh_addr,
            sec_header.sh_offset,
            sec_header.sh_size,
            sec_header.sh_flags,
            sec_header.sh_addralign,
        );
    }

    Ok(())
}
