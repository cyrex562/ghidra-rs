use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::pdb_reader_utils::{dump_head, dump_tail, simple_type_name};

/// A read-only snapshot of a module's `SectionContribution` fields.
///
/// [`SectionContribution`](crate::format::pdb2::pdbreader::section_contribution::SectionContribution)
/// itself is not `dyn`-compatible (its `dump_internals` method is generic over `impl
/// std::io::Write`), so it cannot be returned as `&dyn SectionContribution` from this
/// object-safe trait. Implementors of [`ModuleInformation`] are expected to hold their section
/// contribution as a concrete/boxed `SectionContribution` internally and expose this owned
/// snapshot via [`section_contribution`](ModuleInformation::section_contribution).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SectionContributionSnapshot {
    /// The section.
    pub section: u16,
    /// The offset.
    pub offset: i32,
    /// The length.
    pub length: i32,
    /// The module.
    pub module: u16,
    /// The characteristics.
    pub characteristics: u32,
}

/// Trait for the Module Information component of a PDB file. Implementors are only suitable
/// for reading; not for writing or modifying a PDB.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.ModuleInformation`, an abstract Java base
/// class whose `parseAdditionals`/`dumpAdditionals` methods are filled in by version-specific
/// subclasses (`ModuleInformation500`/`ModuleInformation600`). Modeled as a trait (rather than a
/// concrete struct) because this type was selected as a dependency-cycle cut-point.
///
/// [`deserialize`](Self::deserialize) is a required method (rather than a shared default) even
/// though the Java base class implements it concretely, because the shared parsing logic
/// mutates several private fields that only the concrete implementor can own; each
/// version-specific implementor is expected to replicate the shared field layout itself, the
/// same pattern already used by [`SectionContribution`] and its version-specific implementors in
/// this crate.
///
/// We have intended to implement according to the Microsoft PDB API (source); see the API for
/// truth.
pub trait ModuleInformation: std::fmt::Debug {
    /// Returns the module pointer. Not part of the Java class's public getter API, but needed to
    /// reconstruct its package-private `dump()` output.
    fn module_pointer(&self) -> u32;

    /// Returns whether the module has been written to since it was opened.
    fn written_since_open(&self) -> bool;

    /// Returns whether EC symbolic information is enabled. Always `false` for now; see the
    /// `TODO` note carried over from the Java source about only setting this for newer PDBs.
    fn ec_symbolic_information_enabled(&self) -> bool;

    /// Returns the spare bits parsed from the bitfield.
    fn spare(&self) -> i32;

    /// Returns the index to the TSM (Type Server Mapping) list.
    fn index_to_tsm_list(&self) -> i32;

    /// Returns the number of files contributing to the module.
    fn num_files_contributing(&self) -> u16;

    /// Returns the stream number containing debug information.
    fn stream_number_debug_information(&self) -> u16;

    /// Returns the size of the local symbols debug information.
    fn size_local_symbols_debug_information(&self) -> i32;

    /// Returns the size of the older-style line number information.
    fn size_line_number_debug_information(&self) -> i32;

    /// Returns the size of the C13-style line number information.
    fn size_c13_style_line_number_information(&self) -> i32;

    /// Returns the list of offsets for the module.
    fn offsets_array(&self) -> &[i32];

    /// Returns the list of file names for the module.
    fn filenames_array(&self) -> &[String];

    /// Returns the name of the module.
    fn module_name(&self) -> &str;

    /// Returns the name of the object file.
    fn object_file_name(&self) -> &str;

    /// Returns a [`SectionContributionSnapshot`] of the module's SectionContribution. This seems
    /// to be just one of possibly many SectionContributions for the module (at least of
    /// ModuleInformation600; need to check for older PDBs/ModuleInformation500). User should
    /// consult the debugInfo SectionContributionList for full list of SectionContributions,
    /// which also (at least for newer PDBs) has many contributions that all refer to the same
    /// module (contributions are relatively small).
    fn section_contribution(&self) -> SectionContributionSnapshot;

    /// Returns the filename for the offset, if one was stored.
    fn filename_by_offset(&self, offset: i32) -> Option<&str>;

    /// Returns the filename for the index.
    ///
    /// # Panics
    /// Panics if `index` is out of bounds, mirroring Java's `IndexOutOfBoundsException` from
    /// `List.get`.
    fn filename_by_index(&self, index: usize) -> &str {
        self.filenames_array()[index].as_str()
    }

    /// Deserializes the module.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon error parsing a string name.
    fn deserialize(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException>;

    /// Deserializes the Additionals. Filled in by implementors to parse additional data
    /// pertinent to themselves.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon error parsing a string name.
    fn parse_additionals(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException>;

    /// Dumps the Additionals to `writer`. This method is for debugging only.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    fn dump_additionals(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()>;

    /// Dumps this module to `writer`. This method is for debugging only.
    ///
    /// Note: unlike Java's `dump()`, this cannot delegate to `SectionContribution::dump` for the
    /// nested section contribution, since that trait is not `dyn`-compatible. It writes the
    /// fields of the [`SectionContributionSnapshot`] directly instead.
    ///
    /// # Errors
    /// Returns an I/O error if writing to `writer` fails.
    fn dump(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        let name = simple_type_name::<Self>();
        dump_head(writer, name)?;
        write!(writer, "modulePointer: {}", self.module_pointer())?;
        writeln!(writer)?;

        let sc = self.section_contribution();
        write!(writer, "isect: {}", sc.section)?;
        write!(writer, "\noffset: {}", sc.offset)?;
        write!(writer, "\nlength: {}", sc.length)?;
        write!(writer, "\ncharacteristics: 0X{:08X}", sc.characteristics)?;
        write!(writer, "\nimod: {}", sc.module)?;

        write!(writer, "\nwrittenSinceOpen: {}", self.written_since_open())?;
        write!(
            writer,
            "\necSymbolicInformationEnabled: {}",
            self.ec_symbolic_information_enabled()
        )?;
        write!(writer, "\nspare: {}", self.spare())?;
        write!(writer, "\nindexToTSMList: {}", self.index_to_tsm_list())?;
        write!(
            writer,
            "\nstreamNumberDebugInformation: {}",
            self.stream_number_debug_information()
        )?;
        write!(
            writer,
            "\nsizeLocalSymbolsDebugInformation: {}",
            self.size_local_symbols_debug_information()
        )?;
        write!(
            writer,
            "\nsizeLineNumberDebugInformation: {}",
            self.size_line_number_debug_information()
        )?;
        write!(
            writer,
            "\nsizeC13StyleLineNumberInformation: {}",
            self.size_c13_style_line_number_information()
        )?;
        write!(writer, "\nnumFilesContributing: {}", self.num_files_contributing())?;

        self.dump_additionals(writer)?;

        write!(writer, "\nmoduleName: {}", self.module_name())?;
        write!(writer, "\nobjectFileName: {}", self.object_file_name())?;
        writeln!(writer)?;

        dump_tail(writer, name)
    }

    /// Returns the string representation of this module by delegating to [`dump`](Self::dump),
    /// mirroring Java's `toString()`.
    fn to_display_string(&self) -> String {
        let mut buf = Vec::new();
        match self.dump(&mut buf) {
            Ok(()) => String::from_utf8_lossy(&buf).into_owned(),
            Err(e) => format!("Issue in {} toString(): {}", simple_type_name::<Self>(), e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::section_contribution::SectionContribution;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    struct MockSectionContribution {
        isect: u16,
        offset: i32,
        length: i32,
        imod: u16,
        characteristics: u32,
    }

    impl SectionContribution for MockSectionContribution {
        fn section(&self) -> u16 {
            self.isect
        }

        fn offset(&self) -> i32 {
            self.offset
        }

        fn length(&self) -> i32 {
            self.length
        }

        fn module(&self) -> u16 {
            self.imod
        }

        fn characteristics(&self) -> u32 {
            self.characteristics
        }

        fn deserialize(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException> {
            self.isect = reader.parse_unsigned_short_val()?;
            reader.parse_bytes(2)?;
            self.offset = reader.parse_int()?;
            self.length = reader.parse_int()?;
            self.characteristics = reader.parse_unsigned_int_val()?;
            self.imod = reader.parse_unsigned_short_val()?;
            reader.align4();
            Ok(())
        }

        fn dump_internals(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
            write!(writer, "isect: {}", self.isect)
        }
    }

    /// Mock implementation proving [`ModuleInformation`] is object-safe (usable as
    /// `Box<dyn ModuleInformation>`) and exercising real deserialize behavior against a
    /// [`PdbByteReader`], mirroring the base class's bitfield-unpacking quirks.
    #[derive(Debug, Default)]
    struct MockModuleInformation {
        module_pointer: u32,
        section_contribution: MockSectionContribution,
        written_since_open: bool,
        spare: i32,
        index_to_tsm_list: i32,
        stream_number_debug_information: u16,
        size_local_symbols_debug_information: i32,
        size_line_number_debug_information: i32,
        size_c13_style_line_number_information: i32,
        num_files_contributing: u16,
        offsets_array: Vec<i32>,
        filenames_array: Vec<String>,
        filename_by_offset: HashMap<i32, String>,
        module_name: String,
        object_file_name: String,
    }

    impl MockModuleInformation {
        fn add_filename_by_offset(&mut self, offset: i32, filename: String) {
            self.filenames_array.push(filename.clone());
            self.filename_by_offset.insert(offset, filename);
        }

        fn parse_pascal_string(reader: &mut PdbByteReader) -> Result<String, PdbException> {
            let len = reader.parse_unsigned_byte_val()? as usize;
            let bytes = reader.parse_bytes(len)?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
    }

    impl ModuleInformation for MockModuleInformation {
        fn module_pointer(&self) -> u32 {
            self.module_pointer
        }

        fn written_since_open(&self) -> bool {
            self.written_since_open
        }

        fn ec_symbolic_information_enabled(&self) -> bool {
            false
        }

        fn spare(&self) -> i32 {
            self.spare
        }

        fn index_to_tsm_list(&self) -> i32 {
            self.index_to_tsm_list
        }

        fn num_files_contributing(&self) -> u16 {
            self.num_files_contributing
        }

        fn stream_number_debug_information(&self) -> u16 {
            self.stream_number_debug_information
        }

        fn size_local_symbols_debug_information(&self) -> i32 {
            self.size_local_symbols_debug_information
        }

        fn size_line_number_debug_information(&self) -> i32 {
            self.size_line_number_debug_information
        }

        fn size_c13_style_line_number_information(&self) -> i32 {
            self.size_c13_style_line_number_information
        }

        fn offsets_array(&self) -> &[i32] {
            &self.offsets_array
        }

        fn filenames_array(&self) -> &[String] {
            &self.filenames_array
        }

        fn module_name(&self) -> &str {
            &self.module_name
        }

        fn object_file_name(&self) -> &str {
            &self.object_file_name
        }

        fn section_contribution(&self) -> SectionContributionSnapshot {
            SectionContributionSnapshot {
                section: self.section_contribution.section(),
                offset: self.section_contribution.offset(),
                length: self.section_contribution.length(),
                module: self.section_contribution.module(),
                characteristics: self.section_contribution.characteristics(),
            }
        }

        fn filename_by_offset(&self, offset: i32) -> Option<&str> {
            self.filename_by_offset.get(&offset).map(|s| s.as_str())
        }

        fn deserialize(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException> {
            self.module_pointer = reader.parse_unsigned_int_val()?;
            self.section_contribution.deserialize(reader)?;
            let mut bitfield = reader.parse_unsigned_short_val()? as i32;
            self.written_since_open = (bitfield & 0x01) == 0x01;
            bitfield >>= 1;
            self.spare = bitfield & 0x07f;
            bitfield >>= 1;
            self.index_to_tsm_list = bitfield & 0x0ff;
            self.stream_number_debug_information = reader.parse_unsigned_short_val()?;
            self.size_local_symbols_debug_information = reader.parse_int()?;
            self.size_line_number_debug_information = reader.parse_int()?;
            self.size_c13_style_line_number_information = reader.parse_int()?;
            self.num_files_contributing = reader.parse_unsigned_short_val()?;
            reader.align4();
            reader.parse_bytes(4)?;
            self.parse_additionals(reader)?;
            reader.align4();
            Ok(())
        }

        fn parse_additionals(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException> {
            self.module_name = Self::parse_pascal_string(reader)?;
            self.object_file_name = Self::parse_pascal_string(reader)?;
            let offset = reader.parse_int()?;
            self.offsets_array.push(offset);
            let filename = Self::parse_pascal_string(reader)?;
            self.add_filename_by_offset(offset, filename);
            Ok(())
        }

        fn dump_additionals(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
            write!(writer, "\nnumOffsets: {}", self.offsets_array.len())
        }
    }

    fn push_pascal_string(buf: &mut Vec<u8>, s: &str) {
        buf.push(s.len() as u8);
        buf.extend_from_slice(s.as_bytes());
    }

    fn push_align4(buf: &mut Vec<u8>) {
        let pad = (4 - (buf.len() % 4)) % 4;
        buf.extend(std::iter::repeat(0u8).take(pad));
    }

    fn record_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // modulePointer

        // MockSectionContribution: isect, pad(2), offset, length, characteristics, imod, align4
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&[0u8, 0u8]);
        buf.extend_from_slice(&0x1000i32.to_le_bytes());
        buf.extend_from_slice(&0x200i32.to_le_bytes());
        buf.extend_from_slice(&0x20u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        push_align4(&mut buf);

        // bitfield: writtenSinceOpen=1, spare=0x7E, indexToTSMList=0x3F -> 0x00FD
        buf.extend_from_slice(&0x00FDu16.to_le_bytes());

        buf.extend_from_slice(&7u16.to_le_bytes()); // streamNumberDebugInformation
        buf.extend_from_slice(&100i32.to_le_bytes()); // sizeLocalSymbolsDebugInformation
        buf.extend_from_slice(&200i32.to_le_bytes()); // sizeLineNumberDebugInformation
        buf.extend_from_slice(&300i32.to_le_bytes()); // sizeC13StyleLineNumberInformation
        buf.extend_from_slice(&1u16.to_le_bytes()); // numFilesContributing

        push_align4(&mut buf);
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // placeholder for offsetsArray

        push_pascal_string(&mut buf, "MyModule");
        push_pascal_string(&mut buf, "my_module.obj");
        buf.extend_from_slice(&0x2020i32.to_le_bytes()); // offset for the one filename entry
        push_pascal_string(&mut buf, "source.c");

        push_align4(&mut buf);
        buf
    }

    #[test]
    fn deserialize_parses_all_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut module = MockModuleInformation::default();
        module.deserialize(&mut reader).unwrap();

        assert_eq!(module.module_pointer(), 0x1234_5678);
        assert!(module.written_since_open());
        assert!(!module.ec_symbolic_information_enabled());
        assert_eq!(module.spare(), 0x7E);
        assert_eq!(module.index_to_tsm_list(), 0x3F);
        assert_eq!(module.stream_number_debug_information(), 7);
        assert_eq!(module.size_local_symbols_debug_information(), 100);
        assert_eq!(module.size_line_number_debug_information(), 200);
        assert_eq!(module.size_c13_style_line_number_information(), 300);
        assert_eq!(module.num_files_contributing(), 1);
        assert_eq!(module.module_name(), "MyModule");
        assert_eq!(module.object_file_name(), "my_module.obj");
        assert_eq!(module.offsets_array(), &[0x2020]);
        assert_eq!(module.filenames_array(), &["source.c".to_string()]);
        assert_eq!(module.filename_by_offset(0x2020), Some("source.c"));
        assert_eq!(module.filename_by_offset(0), None);
        assert_eq!(module.filename_by_index(0), "source.c");

        let sc = module.section_contribution();
        assert_eq!(sc.section, 1);
        assert_eq!(sc.offset, 0x1000);
        assert_eq!(sc.length, 0x200);
        assert_eq!(sc.module, 2);
        assert_eq!(sc.characteristics, 0x20);
    }

    #[test]
    fn deserialize_insufficient_data_returns_error() {
        let bytes = vec![0x01, 0x02, 0x03];
        let mut reader = PdbByteReader::new(bytes);
        let mut module = MockModuleInformation::default();
        assert!(module.deserialize(&mut reader).is_err());
    }

    #[test]
    fn dump_contains_expected_fields() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut module = MockModuleInformation::default();
        module.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        module.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.starts_with("MockModuleInformation"));
        assert!(output.contains("modulePointer: 305419896"));
        assert!(output.contains("isect: 1"));
        assert!(output.contains("writtenSinceOpen: true"));
        assert!(output.contains("spare: 126"));
        assert!(output.contains("indexToTSMList: 63"));
        assert!(output.contains("numFilesContributing: 1"));
        assert!(output.contains("numOffsets: 1"));
        assert!(output.contains("moduleName: MyModule"));
        assert!(output.contains("objectFileName: my_module.obj"));
        assert!(output.contains("End MockModuleInformation"));
    }

    #[test]
    fn to_display_string_matches_dump() {
        let mut reader = PdbByteReader::new(record_bytes());
        let mut module = MockModuleInformation::default();
        module.deserialize(&mut reader).unwrap();

        let mut buf = Vec::new();
        module.dump(&mut buf).unwrap();
        let expected = String::from_utf8(buf).unwrap();

        assert_eq!(module.to_display_string(), expected);
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let mut reader = PdbByteReader::new(record_bytes());
        let module: Box<dyn ModuleInformation> = {
            let mut m = MockModuleInformation::default();
            m.deserialize(&mut reader).unwrap();
            Box::new(m)
        };

        assert_eq!(module.module_name(), "MyModule");
        assert_eq!(module.filename_by_index(0), "source.c");
        assert!(module.to_display_string().contains("MockModuleInformation"));
    }
}
