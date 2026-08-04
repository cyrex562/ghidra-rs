use std::collections::BTreeMap;

use crate::format::pdb2::pdbreader::msf::msf::MsfError;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::seam_stubs::{AbstractMsSymbol, AbstractPdb, SymbolParser, NIL_STREAM_NUMBER};

/// The symbol, and its serialized length in bytes, returned by a random-access record lookup.
///
/// Mirrors the Java record `SymbolRecords.SymLen(AbstractMsSymbol symbol, int length)`.
pub struct SymLen {
    /// The parsed symbol.
    pub symbol: Box<dyn AbstractMsSymbol>,
    /// The number of bytes the record occupied in the stream, including its length prefix.
    pub length: i32,
}

/// Trait for the Symbol Records component of a PDB file. Implementors are only suitable for
/// reading; not for writing or modifying a PDB.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.SymbolRecords`. Modeled as a trait (rather
/// than a concrete struct) because this type was selected as a dependency-cycle cut-point.
/// [`pdb`](Self::pdb) and [`symbol_parser`](Self::symbol_parser) expose the two collaborators the
/// Java constructor captured as fields (`pdb`, and the implicit static `SymbolParser`), so the
/// default methods below can be written generically in terms of them.
///
/// [`initialize`](Self::initialize) and [`cv_sig_length`](Self::cv_sig_length) are required
/// (rather than default methods), even though the Java class implements them concretely, because
/// their logic mutates several private fields (`getSig`, `cvSignature`,
/// `cvSignatureCase1and2Stream`) that only the concrete implementor can own -- the same pattern
/// already used by [`ModuleInformation::deserialize`](
/// crate::format::pdb2::pdbreader::module_information::ModuleInformation::deserialize).
///
/// We have intended to implement according to the Microsoft PDB API (source); see the API for
/// truth.
pub trait SymbolRecords {
    /// Returns the [`AbstractPdb`] to which these `SymbolRecords` belong.
    fn pdb(&self) -> &dyn AbstractPdb;

    /// Returns the [`SymbolParser`] used to deserialize individual symbol records.
    fn symbol_parser(&self) -> &dyn SymbolParser;

    /// Deserializes and initializes basic `SymbolRecords` information from the stream noted in
    /// the DBI header so that later symbol queries can be done.
    ///
    /// # Errors
    /// Returns [`MsfError`] on file seek or read, invalid parameters, bad file configuration,
    /// inability to read required bytes, not enough data left to parse, or user cancellation.
    fn initialize(&mut self) -> Result<(), MsfError>;

    /// Returns the space occupied by the `cvSignature` for `stream_number`.
    ///
    /// # Errors
    /// Returns [`MsfError`] upon user cancellation or a processing error.
    fn cv_sig_length(&mut self, stream_number: i32) -> Result<i32, MsfError>;

    /// Deserializes the [`AbstractMsSymbol`] symbols from `reader` and returns a map of buffer
    /// offsets to symbols.
    ///
    /// Mirrors the static `SymbolRecords.deserializeSymbolRecords(AbstractPdb, PdbByteReader)`.
    /// Kept as an instance method (rather than a free function) so it can be dispatched through
    /// `self.symbol_parser()`, matching the pattern already used for Java's other all-static
    /// PDB-reader utility class in [`PdbParser`](
    /// crate::format::pdb2::pdbreader::pdb_parser::PdbParser).
    ///
    /// # Errors
    /// Returns [`MsfError`] upon not enough data left to parse or user cancellation.
    fn deserialize_symbol_records(
        &self,
        pdb: &dyn AbstractPdb,
        reader: &mut PdbByteReader,
    ) -> Result<BTreeMap<i64, Box<dyn AbstractMsSymbol>>, MsfError> {
        let mut symbols_by_offset = BTreeMap::new();
        while reader.has_more() {
            pdb.check_cancelled()?;
            let offset = reader.get_index() as i64;
            let symbol = self.symbol_parser().parse_length_and_symbol(pdb, reader)?;
            symbols_by_offset.insert(offset, symbol);
        }
        Ok(symbols_by_offset)
    }

    /// Returns the map of buffer offsets to symbols.
    ///
    /// # Errors
    /// Returns [`MsfError`] on file seek or read, invalid parameters, bad file configuration,
    /// inability to read required bytes, not enough data left to parse, or user cancellation.
    #[deprecated]
    fn symbols_by_offset(&self) -> Result<BTreeMap<i64, Box<dyn AbstractMsSymbol>>, MsfError> {
        let debug_info = match self.pdb().debug_info() {
            Some(debug_info) => debug_info,
            None => return Ok(BTreeMap::new()),
        };
        let stream_number = debug_info.symbol_records_stream_number();
        if stream_number <= 0 {
            return Ok(BTreeMap::new());
        }
        let mut reader = self.pdb().reader_for_stream_number(stream_number, 0, i32::MAX)?;
        self.deserialize_symbol_records(self.pdb(), &mut reader)
    }

    /// Returns the buffer-offset-to-symbol map for the module as specified by `module_number`
    /// (0-based, matching direct `List.get` access on the Java source's package-private
    /// `moduleInformationList` field).
    ///
    /// # Errors
    /// Returns [`MsfError`] on file seek or read, invalid parameters, bad file configuration,
    /// inability to read required bytes, not enough data left to parse, or user cancellation.
    #[deprecated]
    fn module_symbols_by_offset(
        &mut self,
        module_number: i32,
    ) -> Result<BTreeMap<i64, Box<dyn AbstractMsSymbol>>, MsfError> {
        let (stream_number, size_symbols_section) = {
            let debug_info = match self.pdb().debug_info() {
                Some(debug_info) => debug_info,
                None => return Ok(BTreeMap::new()),
            };
            let module_info = debug_info
                .module_information_list()
                .get(module_number as usize)
                .ok_or_else(|| MsfError::Pdb(PdbException::new("module number out of range")))?;
            (
                module_info.stream_number_debug_information() as i32,
                module_info.size_local_symbols_debug_information(),
            )
        };
        if stream_number == NIL_STREAM_NUMBER {
            return Ok(BTreeMap::new());
        }
        let mut reader = self.pdb().reader_for_stream_number(stream_number, 0, i32::MAX)?;
        let mut symbols_reader = reader.get_sub_pdb_byte_reader(size_symbols_section as usize)?;
        let cv_sig_length = self.cv_sig_length(stream_number)?;
        symbols_reader.skip(cv_sig_length as usize);
        self.deserialize_symbol_records(self.pdb(), &mut symbols_reader)
    }

    /// Returns the symbol at `offset` of the stream assigned to `module_number` (1-based,
    /// mirroring `PdbDebugInfo.getModuleInformation`'s documented range), or `None` if the
    /// module has no debug information stream.
    ///
    /// # Errors
    /// Returns [`MsfError`] upon `module_number` out of range, no module information, or user
    /// cancellation.
    fn random_access_record_using_module_number(
        &self,
        module_number: i32,
        offset: i32,
    ) -> Result<Option<SymLen>, MsfError> {
        let stream_number = {
            let debug_info = self
                .pdb()
                .debug_info()
                .ok_or_else(|| MsfError::Pdb(PdbException::new("no debug info")))?;
            let module_info = debug_info
                .module_information(module_number)
                .map_err(MsfError::Pdb)?;
            module_info.stream_number_debug_information() as i32
        };
        if stream_number == NIL_STREAM_NUMBER {
            return Ok(None);
        }
        self.random_access_record(stream_number, offset)
    }

    /// Returns the symbol at `offset` of `stream_number`, or `None` if there was not enough data
    /// remaining to read a record.
    ///
    /// # Errors
    /// Returns [`MsfError`] upon `module_number` out of range, no module information, or user
    /// cancellation.
    fn random_access_record(
        &self,
        stream_number: i32,
        offset: i32,
    ) -> Result<Option<SymLen>, MsfError> {
        let mut reader = match self.pdb().reader_for_stream_number(stream_number, offset, 2) {
            Ok(reader) => reader,
            Err(MsfError::Io(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let record_length = match reader.parse_unsigned_short_val() {
            Ok(record_length) => record_length,
            // Catching this due to not enough data, but letting one from parse() (below) get
            // passed to caller.
            Err(_) => return Ok(None),
        };
        // offset + 2 where 2 is sizeof(short)
        let mut record_reader = match self.pdb().reader_for_stream_number(
            stream_number,
            offset + 2,
            record_length as i32,
        ) {
            Ok(reader) => reader,
            Err(MsfError::Io(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let symbol = self.symbol_parser().parse(self.pdb(), &mut record_reader)?;
        Ok(Some(SymLen { symbol, length: record_length as i32 + 2 }))
    }

    /// Debug method for dumping information from this `SymbolRecords` instance.
    ///
    /// # Errors
    /// Returns [`MsfError`] upon an I/O error writing to `writer`, not enough data to parse, or
    /// user cancellation.
    fn dump(&mut self, writer: &mut dyn std::io::Write) -> Result<(), MsfError> {
        write!(writer, "SymbolRecords-----------------------------------------------\n")?;
        #[allow(deprecated)]
        let symbols_by_offset = self.symbols_by_offset()?;
        self.dump_symbol_map(&symbols_by_offset, writer)?;
        let num_modules = match self.pdb().debug_info() {
            Some(debug_info) => debug_info.num_modules(),
            None => return Ok(()),
        };
        for i in 0..num_modules {
            self.pdb().check_cancelled()?;
            #[allow(deprecated)]
            let map = self.module_symbols_by_offset(i)?;
            write!(writer, "Module({}) List:\n", i)?;
            self.dump_symbol_map(&map, writer)?;
        }
        write!(writer, "\nEnd SymbolRecords-------------------------------------------\n")?;
        Ok(())
    }

    /// Debug method for dumping the symbols from `symbols_by_offset` to `writer`.
    ///
    /// # Errors
    /// Returns [`MsfError`] upon an I/O error writing to `writer` or user cancellation.
    fn dump_symbol_map(
        &self,
        symbols_by_offset: &BTreeMap<i64, Box<dyn AbstractMsSymbol>>,
        writer: &mut dyn std::io::Write,
    ) -> Result<(), MsfError> {
        write!(writer, "SymbolMap---------------------------------------------------")?;
        for (offset, symbol) in symbols_by_offset {
            self.pdb().check_cancelled()?;
            write!(writer, "\n------------------------------------------------------------\n")?;
            write!(writer, "Offset: 0X{:08X}\n", offset)?;
            write!(writer, "{}", symbol.to_display_string())?;
        }
        write!(writer, "\nEnd SymbolMap-----------------------------------------------\n")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
    use crate::format::pdb2::pdbreader::module_information::{
        ModuleInformation, SectionContributionSnapshot,
    };
    use crate::format::seam_stubs::{PdbDebugInfo, PdbReaderOptions};
    use std::cell::RefCell;

    struct MockSymbol {
        name: String,
    }

    impl AbstractParsableItem for MockSymbol {
        fn emit(&self, builder: &mut String) {
            builder.push_str(&self.name);
        }
    }
    impl AbstractMsSymbol for MockSymbol {}

    struct MockSymbolParser;
    impl SymbolParser for MockSymbolParser {
        fn parse_length_and_symbol(
            &self,
            _pdb: &dyn AbstractPdb,
            reader: &mut PdbByteReader,
        ) -> Result<Box<dyn AbstractMsSymbol>, MsfError> {
            let record_length = reader.parse_unsigned_short_val()?;
            let mut record_reader = reader.get_sub_pdb_byte_reader(record_length as usize)?;
            self.parse(_pdb, &mut record_reader)
        }

        fn parse(
            &self,
            _pdb: &dyn AbstractPdb,
            reader: &mut PdbByteReader,
        ) -> Result<Box<dyn AbstractMsSymbol>, MsfError> {
            let id = reader.parse_unsigned_short_val()?;
            Ok(Box::new(MockSymbol { name: format!("Symbol#{id}") }))
        }
    }

    #[derive(Default)]
    struct MockModuleInformation {
        stream_number_debug_information: u16,
        size_local_symbols_debug_information: i32,
    }

    impl std::fmt::Debug for MockModuleInformation {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockModuleInformation").finish()
        }
    }

    impl ModuleInformation for MockModuleInformation {
        fn module_pointer(&self) -> u32 {
            0
        }
        fn written_since_open(&self) -> bool {
            false
        }
        fn ec_symbolic_information_enabled(&self) -> bool {
            false
        }
        fn spare(&self) -> i32 {
            0
        }
        fn index_to_tsm_list(&self) -> i32 {
            0
        }
        fn num_files_contributing(&self) -> u16 {
            0
        }
        fn stream_number_debug_information(&self) -> u16 {
            self.stream_number_debug_information
        }
        fn size_local_symbols_debug_information(&self) -> i32 {
            self.size_local_symbols_debug_information
        }
        fn size_line_number_debug_information(&self) -> i32 {
            0
        }
        fn size_c13_style_line_number_information(&self) -> i32 {
            0
        }
        fn offsets_array(&self) -> &[i32] {
            &[]
        }
        fn filenames_array(&self) -> &[String] {
            &[]
        }
        fn module_name(&self) -> &str {
            "mod"
        }
        fn object_file_name(&self) -> &str {
            "mod.obj"
        }
        fn section_contribution(&self) -> SectionContributionSnapshot {
            SectionContributionSnapshot::default()
        }
        fn filename_by_offset(&self, _offset: i32) -> Option<&str> {
            None
        }
        fn deserialize(&mut self, _reader: &mut PdbByteReader) -> Result<(), PdbException> {
            Ok(())
        }
        fn parse_additionals(
            &mut self,
            _reader: &mut PdbByteReader,
        ) -> Result<(), PdbException> {
            Ok(())
        }
        fn dump_additionals(&self, _writer: &mut dyn std::io::Write) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockDebugInfo {
        symbol_records_stream_number: i32,
        modules: Vec<Box<dyn ModuleInformation>>,
    }

    impl PdbDebugInfo for MockDebugInfo {
        fn symbol_records_stream_number(&self) -> i32 {
            self.symbol_records_stream_number
        }
        fn num_modules(&self) -> i32 {
            self.modules.len() as i32
        }
        fn module_information_list(&self) -> &[Box<dyn ModuleInformation>] {
            &self.modules
        }
        fn module_information(
            &self,
            module_number: i32,
        ) -> Result<&dyn ModuleInformation, PdbException> {
            if module_number < 1 || module_number as usize > self.modules.len() {
                return Err(PdbException::new("module number out of range"));
            }
            Ok(self.modules[(module_number - 1) as usize].as_ref())
        }
    }

    struct MockPdb {
        options: PdbReaderOptions,
        debug_info: Option<MockDebugInfo>,
        // Maps stream_number -> full stream bytes.
        streams: RefCell<std::collections::HashMap<i32, Vec<u8>>>,
    }

    impl AbstractPdb for MockPdb {
        fn pdb_reader_options(&self) -> &PdbReaderOptions {
            &self.options
        }

        fn get_type_record(
            &self,
            _record_number: crate::format::seam_stubs::RecordNumber,
        ) -> Box<dyn crate::format::pdb2::pdbreader::r#type::abstract_ms_type::AbstractMsType>
        {
            unreachable!("not exercised by this test")
        }

        fn debug_info(&self) -> Option<&dyn PdbDebugInfo> {
            self.debug_info.as_ref().map(|d| d as &dyn PdbDebugInfo)
        }

        fn reader_for_stream_number(
            &self,
            stream_number: i32,
            stream_offset: i32,
            num_to_read: i32,
        ) -> Result<PdbByteReader, MsfError> {
            let streams = self.streams.borrow();
            let bytes = streams.get(&stream_number).ok_or_else(|| {
                MsfError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "no such stream"))
            })?;
            let start = stream_offset as usize;
            if start > bytes.len() {
                return Err(MsfError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "offset past end of stream",
                )));
            }
            let end = std::cmp::min(bytes.len(), start + num_to_read.max(0) as usize);
            Ok(PdbByteReader::new(bytes[start..end].to_vec()))
        }
    }

    struct MockSymbolRecords {
        pdb: MockPdb,
        parser: MockSymbolParser,
        initialized: bool,
        cv_signature: i32,
    }

    impl SymbolRecords for MockSymbolRecords {
        fn pdb(&self) -> &dyn AbstractPdb {
            &self.pdb
        }

        fn symbol_parser(&self) -> &dyn SymbolParser {
            &self.parser
        }

        fn initialize(&mut self) -> Result<(), MsfError> {
            self.initialized = true;
            Ok(())
        }

        fn cv_sig_length(&mut self, stream_number: i32) -> Result<i32, MsfError> {
            let reader = self.pdb().reader_for_stream_number(stream_number, 0, 4)?;
            let _ = reader;
            self.cv_signature = 4;
            Ok(4)
        }
    }

    fn symbol_record_bytes(id: u16) -> Vec<u8> {
        // length-prefixed record: [u16 recordLength][u16 symbolTypeId]
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&id.to_le_bytes());
        buf
    }

    fn make_records(pdb: MockPdb) -> MockSymbolRecords {
        MockSymbolRecords { pdb, parser: MockSymbolParser, initialized: false, cv_signature: -1 }
    }

    fn options() -> PdbReaderOptions {
        PdbReaderOptions {
            one_byte_charset: crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset::Utf8,
            two_byte_charset:
                crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset::Utf16Le,
        }
    }

    /// Proves [`SymbolRecords`] is object-safe (usable as `Box<dyn SymbolRecords>`) and exercises
    /// real deserialization/random-access behavior against mock collaborators, mirroring the
    /// Java class's stream-reading and offset-map logic.
    #[test]
    fn boxed_trait_object_deserializes_symbol_records() {
        let mut stream_bytes = Vec::new();
        stream_bytes.extend(symbol_record_bytes(0x1001));
        stream_bytes.extend(symbol_record_bytes(0x1002));

        let mut streams = std::collections::HashMap::new();
        streams.insert(7, stream_bytes);

        let pdb = MockPdb {
            options: options(),
            debug_info: Some(MockDebugInfo { symbol_records_stream_number: 7, modules: vec![] }),
            streams: RefCell::new(streams),
        };

        let mut records: Box<dyn SymbolRecords> = Box::new(make_records(pdb));
        records.initialize().unwrap();

        #[allow(deprecated)]
        let by_offset = records.symbols_by_offset().unwrap();
        assert_eq!(by_offset.len(), 2);
        assert_eq!(by_offset[&0].to_display_string(), "Symbol#4097");
        assert_eq!(by_offset[&4].to_display_string(), "Symbol#4098");
    }

    #[test]
    fn symbols_by_offset_is_empty_without_debug_info() {
        let pdb = MockPdb {
            options: options(),
            debug_info: None,
            streams: RefCell::new(std::collections::HashMap::new()),
        };
        let records = make_records(pdb);
        #[allow(deprecated)]
        let by_offset = records.symbols_by_offset().unwrap();
        assert!(by_offset.is_empty());
    }

    #[test]
    fn random_access_record_reads_symbol_at_offset() {
        let mut streams = std::collections::HashMap::new();
        streams.insert(9, symbol_record_bytes(0x2222));

        let pdb = MockPdb {
            options: options(),
            debug_info: Some(MockDebugInfo::default()),
            streams: RefCell::new(streams),
        };
        let records = make_records(pdb);

        let sym_len = records.random_access_record(9, 0).unwrap().unwrap();
        assert_eq!(sym_len.length, 4);
        assert_eq!(sym_len.symbol.to_display_string(), "Symbol#8738");
    }

    #[test]
    fn random_access_record_returns_none_when_stream_missing() {
        let pdb = MockPdb {
            options: options(),
            debug_info: Some(MockDebugInfo::default()),
            streams: RefCell::new(std::collections::HashMap::new()),
        };
        let records = make_records(pdb);
        assert!(records.random_access_record(99, 0).unwrap().is_none());
    }

    #[test]
    fn random_access_record_using_module_number_follows_nil_stream() {
        let module =
            MockModuleInformation { stream_number_debug_information: 0xffff, ..Default::default() };
        let pdb = MockPdb {
            options: options(),
            debug_info: Some(MockDebugInfo {
                symbol_records_stream_number: 0,
                modules: vec![Box::new(module)],
            }),
            streams: RefCell::new(std::collections::HashMap::new()),
        };
        let records = make_records(pdb);
        assert!(records.random_access_record_using_module_number(1, 0).unwrap().is_none());
    }

    #[test]
    fn random_access_record_using_module_number_out_of_range_errors() {
        let pdb = MockPdb {
            options: options(),
            debug_info: Some(MockDebugInfo::default()),
            streams: RefCell::new(std::collections::HashMap::new()),
        };
        let records = make_records(pdb);
        assert!(records.random_access_record_using_module_number(1, 0).is_err());
    }

    #[test]
    fn module_symbols_by_offset_deserializes_after_skipping_cv_sig() {
        let module = MockModuleInformation {
            stream_number_debug_information: 5,
            size_local_symbols_debug_information: 4 + 4, // cv sig (4) + one record (4)
        };
        let mut stream_bytes = vec![4u8, 0, 0, 0]; // cvSignature = 4
        stream_bytes.extend(symbol_record_bytes(0x3003));

        let mut streams = std::collections::HashMap::new();
        streams.insert(5, stream_bytes);

        let pdb = MockPdb {
            options: options(),
            debug_info: Some(MockDebugInfo {
                symbol_records_stream_number: 0,
                modules: vec![Box::new(module)],
            }),
            streams: RefCell::new(streams),
        };
        let mut records = make_records(pdb);

        #[allow(deprecated)]
        let by_offset = records.module_symbols_by_offset(0).unwrap();
        assert_eq!(by_offset.len(), 1);
        // The record's offset is measured within `symbols_reader` *after* the cv-sig skip,
        // mirroring `symbolsReader.skip(getCvSigLength(streamNumber))` in the Java source.
        assert_eq!(by_offset[&4].to_display_string(), "Symbol#12291");
    }

    #[test]
    fn dump_writes_header_and_footer() {
        let pdb = MockPdb {
            options: options(),
            debug_info: None,
            streams: RefCell::new(std::collections::HashMap::new()),
        };
        let mut records: Box<dyn SymbolRecords> = Box::new(make_records(pdb));

        let mut buf = Vec::new();
        records.dump(&mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("SymbolRecords---"));
        assert!(output.contains("SymbolMap---"));
    }
}
