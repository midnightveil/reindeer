# reindeer

A simple ELF header parser and writer.
Supports little-endian ELF32 and ELF64 formats.

This is version 2.

## Project Structure

- [reindeer](./reindeer/) contains the main library.
- [binaries](./binaries/) contains a few small projects
  - [elf-viewer](./binaries/elf-viewer/) is a simple elf viewer.
- [fuzz](./fuzz/) contains fuzz targets for cargo-fuzz.
