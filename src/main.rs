use std::{env, error::Error, fs::File, io::Read};

use reindeerlib::{ElfHeader, elf_structures::{Elf64Header, ElfIdent}};
use zerocopy::AsBytes;

fn main() -> Result<(), Box<dyn Error>>{
    let path = env::args().nth(1).unwrap_or("/bin/true".into());
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let header = ElfHeader::parse(&buffer);
    println!("{:?}", header.map(|x| x.0));

    let made_header = Elf64Header {
        e_ident: ElfIdent {
            ei_magic: *b"\x7fELF",
            ei_class: ElfIdent::CLASS_64,
            ei_data: ElfIdent::DATA_2_LSB,
            ei_version: ElfIdent::EV_CURRENT,
            ei_pad: [0; 9],
        },
        e_type: ElfHeader::ET_EXEC,
        e_machine: ElfHeader::EM_NONE, // meh
        e_version: ElfHeader::EV_CURRENT,
        e_entry: 0,
        e_phoff: 0,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: 0,
        e_phentsize: 0,
        e_phnum: 0,
        e_shentsize: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    println!("{:?}", made_header.as_bytes());

    Ok(())
}
