use std::{env, error::Error, fs::File, io::Read};

use reindeerlib::{
    elf_structures::Elf64SectionHeader,
    ElfHeader, ElfSectionHeader,
};
use zerocopy::{AsBytes, FromBytes};

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args().nth(1).unwrap_or("/bin/true".into());
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let ElfHeader::Elf64(header) = ElfHeader::parse(&buffer).unwrap().0 else {
        panic!()
    };
    println!("{:x?}\n", header);

    assert_eq!(
        header.e_shentsize as usize,
        std::mem::size_of::<Elf64SectionHeader>()
    );
    let (sec_headers, _): (&[Elf64SectionHeader], _) = Elf64SectionHeader::slice_from_prefix(
        &buffer[(header.e_shoff as usize)..],
        header.e_shnum as usize,
    )
    .unwrap();

    assert_ne!(header.e_shstrndx, 0);
    let string_table_hdr = &sec_headers[header.e_shstrndx as usize];
    let start = string_table_hdr.sh_offset as usize;
    let end = (string_table_hdr.sh_offset + string_table_hdr.sh_size) as usize;
    let string_table = &buffer[start..end];

    println!("[Nr] Name                  Type            Address          Off    Size   Flags Align");
    for (i, sec_header) in sec_headers.iter().enumerate() {
        let sec_header_general = ElfSectionHeader::Elf64(sec_header);
        let name = sec_header_general.get_name(string_table).unwrap();

        println!(
            "[{i:02}] {:<21} {:<15} {:016x} {:06x} {:06x} {:5x} {:5}",
            name,
            sec_header_general.get_type_name(),
            sec_header.sh_addr,
            sec_header.sh_offset,
            sec_header.sh_size,
            sec_header.sh_flags,
            sec_header.sh_addralign,
        );
    }

    println!("{:?}", header.as_bytes());

    Ok(())
}
