use std::{env, error::Error, fs::File, io::Read};

use reindeerlib::ElfHeader;

fn main() -> Result<(), Box<dyn Error>>{
    let path = env::args().nth(1).unwrap_or("/bin/true".into());
    let mut f = File::open(path)?;
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer)?;

    let header = ElfHeader::parse(&buffer);
    println!("{:?}", header.map(|x| x.0));

    Ok(())
}
