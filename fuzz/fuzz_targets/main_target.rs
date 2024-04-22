#![no_main]

use std::error::Error;

use libfuzzer_sys::{fuzz_target, Corpus};
use reindeer::{
    range::TryIntoRangeUsize, ElfHeader, ElfProgramHeader, ElfSectionHeader, ElfStringTable,
};

fuzz_target!(|buffer: &[u8]| -> Corpus {
    fn inner(buffer: &[u8]) -> Result<(), Box<dyn Error>> {
        let header = ElfHeader::parse(buffer)?;
        let string_table = get_string_table(header, buffer)?;
        let program_headers = parse_program_headers(header, buffer)?;
        let section_headers = parse_section_headers(header, buffer)?;

        let _section_names: Result<Vec<_>, _> = section_headers
            .iter()
            .map(|header| string_table.section_name(*header))
            .collect();

        let _segment_mem_locations: Result<Vec<_>, _> = program_headers
            .iter()
            .map(|header| header.memory_location())
            .collect();
        let _segment_file_locations: Vec<_> = program_headers
            .iter()
            .map(|header| header.file_location())
            .collect();

        Ok(())
    }

    match inner(buffer) {
        Ok(_) => Corpus::Keep,
        Err(_) => Corpus::Reject,
    }
});

fn get_string_table<'a>(
    header: ElfHeader,
    buffer: &'a [u8],
) -> Result<ElfStringTable<'a>, Box<dyn Error>> {
    let string_table_header_location = header
        .string_table_header_location()
        .ok_or("oops, no string table")?
        .try_into_usize()?;
    let string_table_header = ElfSectionHeader::parse(
        header,
        &buffer
            .get(string_table_header_location)
            .ok_or("oob for string table header")?,
    )?;
    let string_table_location = string_table_header.location().try_into_usize()?;
    let string_table = &buffer
        .get(string_table_location)
        .ok_or("oob for string table itself")?;

    Ok(ElfStringTable::parse(&string_table)?)
}

fn parse_program_headers<'a>(
    header: ElfHeader<'a>,
    buffer: &'a [u8],
) -> Result<Vec<ElfProgramHeader<'a>>, Box<dyn Error>> {
    let num_headers = header.e_phnum().ok_or("no program headers")?.get();
    let mut headers = Vec::with_capacity(num_headers.into());

    for n in 0..num_headers {
        let prog_header_loc = header
            .program_header_location(n)
            .ok_or("program header no exist???")?
            .try_into_usize()?;

        let program_header = ElfProgramHeader::parse(
            header,
            &buffer.get(prog_header_loc).ok_or("prog header oob")?,
        )?;

        headers.push(program_header);
    }

    Ok(headers)
}

fn parse_section_headers<'a>(
    header: ElfHeader<'a>,
    buffer: &'a [u8],
) -> Result<Vec<ElfSectionHeader<'a>>, Box<dyn Error>> {
    let num_headers = header.e_shnum().ok_or("no program headers")?.get();
    let mut headers = Vec::with_capacity(num_headers.into());

    for n in 0..header.e_shnum().unwrap().get() {
        let section_header_location = header
            .section_header_location(n)
            .ok_or("section header no exist???")?
            .try_into_usize()?;

        let section_header = ElfSectionHeader::parse(
            header,
            &buffer
                .get(section_header_location)
                .ok_or("section header oob")?,
        )?;

        headers.push(section_header);
    }

    Ok(headers)
}
