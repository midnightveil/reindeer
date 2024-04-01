#![no_main]

use std::error::Error;

use libfuzzer_sys::{fuzz_target, Corpus};
use reindeer::{range::TryIntoRangeUsize, ElfHeader, ElfSectionHeader};

fuzz_target!(|buffer: &[u8]| -> Corpus {
    let Ok(header) = ElfHeader::parse(buffer) else {
        return Corpus::Reject;
    };

    let Ok(_string_table) = get_string_table(header, buffer) else {
        return Corpus::Reject;
    };

    Corpus::Keep
});

fn get_string_table<'a>(header: ElfHeader, buffer: &'a [u8]) -> Result<&'a [u8], Box<dyn Error>> {
    let string_table_header_location = header
        .string_table_header_location()
        .ok_or("oops, no string table")?
        .try_into_usize()?;
    let string_table_header = ElfSectionHeader::parse(
        &header,
        &buffer
            .get(string_table_header_location)
            .ok_or("oob for string table header")?,
    )?;
    let string_table_location = string_table_header.location()?.try_into_usize()?;
    let string_table = &buffer
        .get(string_table_location)
        .ok_or("oob for string table itself")?;

    // TODO: Handle well...
    // assert_eq!(string_table.first(), Some(0).as_ref());
    // assert_eq!(string_table.last(), Some(0).as_ref());

    Ok(string_table)
}
