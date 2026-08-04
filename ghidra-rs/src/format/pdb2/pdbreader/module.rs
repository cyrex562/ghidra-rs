use crate::format::pdb2::pdbreader::global_reference_iterator::GlobalReferenceIterator;
use crate::format::pdb2::pdbreader::global_reference_offset_iterator::GlobalReferenceOffsetIterator;
use crate::format::pdb2::pdbreader::module_information::ModuleInformation;
use crate::format::pdb2::pdbreader::ms_symbol_iterator::MsSymbolIterator;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::seam_stubs::{C11LinesLike, C13SectionIteratorLike, NIL_STREAM_NUMBER};
use crate::util::exception::CancelledException;

/// Error returned by the [`Module`] trait's default methods, combining the checked exceptions
/// declared on the mirrored Java methods (`CancelledException`, `PdbException`).
#[derive(Debug)]
pub enum ModuleError {
    Cancelled(CancelledException),
    Pdb(PdbException),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleError::Cancelled(e) => write!(f, "{}", e),
            ModuleError::Pdb(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ModuleError {}

impl From<CancelledException> for ModuleError {
    fn from(e: CancelledException) -> Self {
        ModuleError::Cancelled(e)
    }
}

impl From<PdbException> for ModuleError {
    fn from(e: PdbException) -> Self {
        ModuleError::Pdb(e)
    }
}

/// The precomputed stream-location fields produced by the Java constructor's
/// `precalculateStreamLocations()`.
///
/// Returned by [`precalculate_stream_locations`] for a concrete [`Module`] implementor's own
/// constructor to store and expose via [`Module`]'s section-location accessor methods.
#[derive(Debug, Clone, Copy, Default)]
pub struct PrecalculatedStreamLocations {
    pub stream_number: i32,
    pub offset_symbols: i32,
    pub offset_lines: i32,
    pub offset_c13_lines: i32,
    pub offset_global_refs: i32,
    pub size_symbols: i32,
    pub size_lines: i32,
    pub size_c13_lines: i32,
    pub size_global_refs: i32,
}

/// Computes the stream-location fields for a module's debug information stream, mirroring the
/// Java constructor's private `precalculateStreamLocations()`.
///
/// A concrete implementor of [`Module`] calls this with the `ModuleInformation` it was
/// constructed from, and the length of the resolved debug-information stream (obtained via its
/// own `AbstractPdb`/`Msf` access as `Some(pdb.getMsf().getStream(streamNumber).getLength())`,
/// or `None` if the stream number is nil or the stream could not be resolved, mirroring the
/// Java constructor's early return in both of those cases).
pub fn precalculate_stream_locations(
    module_information: &dyn ModuleInformation,
    stream_length: Option<i32>,
) -> PrecalculatedStreamLocations {
    let stream_number = module_information.stream_number_debug_information() as i32;
    let mut locations = PrecalculatedStreamLocations { stream_number, ..Default::default() };
    if stream_number == NIL_STREAM_NUMBER {
        return locations;
    }
    let Some(length) = stream_length else {
        return locations;
    };

    locations.size_symbols = module_information.size_local_symbols_debug_information();
    locations.size_lines = module_information.size_line_number_debug_information();
    locations.size_c13_lines = module_information.size_c13_style_line_number_information();

    locations.offset_symbols = 0;
    locations.offset_lines = locations.size_symbols;
    locations.offset_c13_lines = locations.offset_lines + locations.size_lines;
    locations.offset_global_refs = locations.offset_c13_lines + locations.size_c13_lines;
    // Note that sizeGlobalRefs includes the size field found within the stream and the field
    // should have a value that is 4 less than this size here. Note that if additional data is
    // added to this stream by MSFT after these globals at a future date, this calculation will
    // not be correct.
    locations.size_global_refs = length - locations.offset_global_refs;

    locations
}

/// Trait representing Module Stream data of a PDB file: a better interface for getting
/// information for any particular module (stream) in a more random-access manner than the
/// `ModuleInformation` and children classes parsed from the DBI stream (which describe, or are
/// control information for, the stream from which a `Module` is parsed).
///
/// Implementors are only suitable for reading; not for writing or modifying a PDB.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.Module`. Modeled as a trait (rather than a
/// concrete struct) because this type was selected as a dependency-cycle cut-point: the Java
/// constructor pulls in `AbstractPdb` directly, and its methods pull in `AbstractPdb`'s
/// `PdbDebugInfo`/`SymbolRecords` (for [`Self::symbol_iterator`]), the not-yet-ported
/// `C11Lines`/`C13SectionIterator` (for [`Self::line_information`]/[`Self::c13_section_iterator`]),
/// and [`GlobalReferenceIterator`] (for [`Self::global_reference_iterator`]) -- collaborators
/// that would recreate the cycle this port needs to break. Following the precedent set by
/// [`GlobalReferenceIterator`] and
/// [`SymbolRecords`](crate::format::pdb2::pdbreader::symbol_records::SymbolRecords), the
/// constructor's stream-location precalculation is exposed as the free function
/// [`precalculate_stream_locations`], and each method whose Java counterpart constructs a
/// collaborator via `AbstractPdb` is split into a default method plus a `make_*`/`parse_*` hook
/// that a concrete implementor fills in using whatever `AbstractPdb` access it holds.
///
/// The package-private `dump(Writer)` method (and its private helpers) is not part of the
/// class's public API and is not ported here.
///
/// We have intended to implement according to the Microsoft PDB API (source); see the API for
/// truth.
pub trait Module {
    /// Returns the `ModuleInformation` this `Module` was constructed from.
    fn module_information(&self) -> &dyn ModuleInformation;

    /// Returns the stream number of this module's debug information stream (mirrors the private
    /// field `streamNumber`), typically the `stream_number` field of the
    /// [`PrecalculatedStreamLocations`] returned by [`precalculate_stream_locations`].
    fn stream_number(&self) -> i32;

    fn offset_symbols(&self) -> i32;
    fn size_symbols(&self) -> i32;
    fn offset_lines(&self) -> i32;
    fn size_lines(&self) -> i32;
    fn offset_c13_lines(&self) -> i32;
    fn size_c13_lines(&self) -> i32;
    fn offset_global_refs(&self) -> i32;
    fn size_global_refs(&self) -> i32;

    /// Returns a [`PdbByteReader`] over the complete contents of this module's debug information
    /// stream, or `None` if the stream cannot be read (mirrors the Java constructor's
    /// `pdb.getMsf().getStream(streamNumber)` plus the `IOException` caught and swallowed (as a
    /// `null`/`DUMMY` result) by callers of `AbstractPdb.getReaderForStreamNumber`).
    ///
    /// # Errors
    /// Returns [`CancelledException`] upon user cancellation.
    fn full_stream_reader(&self) -> Result<Option<PdbByteReader>, CancelledException>;

    /// Returns the space occupied by the `cvSignature` for `stream_number`. Stands in for the
    /// Java constructor call `pdb.getDebugInfo().getSymbolRecords().getCvSigLength(streamNumber)`.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or a processing error.
    fn cv_sig_length(&self, stream_number: i32) -> Result<i32, ModuleError>;

    /// Constructs a new [`MsSymbolIterator`] over the symbols section, initialized at `offset`
    /// within `stream_number`'s stream, covering `length` bytes. Stands in for the Java
    /// constructor call `new MsSymbolIterator(pdb, streamNumber, startingOffset, lengthSymbols)`.
    fn make_symbol_iterator(
        &self,
        stream_number: i32,
        offset: i32,
        length: i32,
    ) -> Box<dyn MsSymbolIterator>;

    /// Parses the C11 Lines information from `reader`. Stands in for the static factory call
    /// `C11Lines.parse(pdb, reader)`.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon issue reading this module's
    /// stream.
    fn parse_c11_lines(&self, reader: PdbByteReader) -> Result<Box<dyn C11LinesLike>, ModuleError>;

    /// Constructs a `C13SectionIterator` over `reader`, covering all C13 sections. Stands in for
    /// the Java constructor call `new C13SectionIterator<>(reader, clazz, true, pdb.getMonitor())`
    /// (with `clazz` fixed at the unfiltered `C13Section.class`, the only instantiation this
    /// class itself performs).
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon not enough data left to parse.
    fn make_c13_section_iterator(
        &self,
        reader: PdbByteReader,
    ) -> Result<Box<dyn C13SectionIteratorLike>, ModuleError>;

    /// Constructs a new [`GlobalReferenceIterator`] over `reader`. Stands in for the Java
    /// constructor call `new GlobalReferenceIterator(pdb, globalRefsReader)`.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon not enough data left to parse.
    fn make_global_reference_iterator(
        &self,
        reader: PdbByteReader,
    ) -> Result<Box<dyn GlobalReferenceIterator>, ModuleError>;

    /// Returns a [`PdbByteReader`] over `size` bytes of this module's stream starting at
    /// `offset`, or a dummy (empty) reader if the section is empty or cannot be read.
    ///
    /// Mirrors the private method `Module.getReader(int, int, String)` (the `sectionName`
    /// parameter, used only for log messages on error, is dropped).
    ///
    /// # Errors
    /// Returns [`CancelledException`] upon user cancellation.
    fn read_section(&self, offset: i32, mut size: i32) -> Result<PdbByteReader, CancelledException> {
        if self.stream_number() == NIL_STREAM_NUMBER {
            return Ok(PdbByteReader::dummy());
        }
        let Some(mut reader) = self.full_stream_reader()? else {
            return Ok(PdbByteReader::dummy());
        };
        reader.skip(offset.max(0) as usize);
        if size == -1 {
            size = match reader.parse_int() {
                Ok(v) => v,
                Err(_) => return Ok(PdbByteReader::dummy()),
            };
        }
        if size == 0 {
            return Ok(PdbByteReader::dummy());
        }
        match reader.get_sub_pdb_byte_reader(size as usize) {
            Ok(sub) => Ok(sub),
            Err(_) => Ok(PdbByteReader::dummy()),
        }
    }

    /// Returns the C11 Lines for this module, or `None` if there is no line information.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon issue reading this module's
    /// stream.
    fn line_information(&self) -> Result<Option<Box<dyn C11LinesLike>>, ModuleError> {
        if self.size_lines() == 0 {
            return Ok(None);
        }
        let reader = self.read_section(self.offset_lines(), self.size_lines())?;
        Ok(Some(self.parse_c11_lines(reader)?))
    }

    /// Returns an [`MsSymbolIterator`] for the symbols of this module.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon invalid `cvSignature`.
    fn symbol_iterator(&self) -> Result<Box<dyn MsSymbolIterator>, ModuleError> {
        let starting_offset = self.cv_sig_length(self.stream_number())?;
        let length_symbols = self.module_information().size_local_symbols_debug_information();
        Ok(self.make_symbol_iterator(self.stream_number(), starting_offset, length_symbols))
    }

    /// Returns a `C13SectionIterator` that iterates over all C13 sections of this module.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon not enough data left to parse.
    fn c13_section_iterator(&self) -> Result<Box<dyn C13SectionIteratorLike>, ModuleError> {
        let reader = self.read_section(self.offset_c13_lines(), self.size_c13_lines())?;
        self.make_c13_section_iterator(reader)
    }

    /// Returns a [`GlobalReferenceOffsetIterator`], but note that there is no determined end for
    /// iteration other than running out of data... it is very unlikely that it should be
    /// iterated until it is out of data. Context should probably be used. For instance, if the
    /// global symbol that is first in this iterator is a GPROC32, then it should probably be
    /// iterated over nested blocks until the closing END is found for the GPROC32.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon not enough data left to parse.
    fn global_reference_offset_iterator(
        &self,
    ) -> Result<GlobalReferenceOffsetIterator, ModuleError> {
        let reader = self.read_section(self.offset_global_refs(), self.size_global_refs())?;
        Ok(GlobalReferenceOffsetIterator::new(reader)?)
    }

    /// Returns a [`GlobalReferenceIterator`]. Iterations of the `GlobalReferenceIterator` return
    /// new `MsSymbolIterator`s, but note that there is no determined end for each
    /// `MsSymbolIterator` other than running out of data... it is very unlikely that it should
    /// be iterated until it is out of data. Context should probably be used. For instance, if
    /// the global symbol that is first in this iterator is a GPROC32, then it should probably be
    /// iterated over nested blocks until the closing END is found for the GPROC32.
    ///
    /// # Errors
    /// Returns [`ModuleError`] upon user cancellation or upon not enough data left to parse.
    fn global_reference_iterator(&self) -> Result<Box<dyn GlobalReferenceIterator>, ModuleError> {
        let reader = self.read_section(self.offset_global_refs(), self.size_global_refs())?;
        self.make_global_reference_iterator(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::ms_symbol_iterator::NoSuchElementError;
    use crate::format::pdb2::pdbreader::module_information::SectionContributionSnapshot;
    use crate::format::pdb2::pdbreader::parsing_iterator::ParsingIterator;
    use crate::format::seam_stubs::AbstractMsSymbol;

    /// Minimal [`ModuleInformation`] fixture carrying just the fields
    /// [`precalculate_stream_locations`] and [`Module`]'s default methods consult.
    #[derive(Debug, Default)]
    struct FixtureModuleInformation {
        stream_number_debug_information: u16,
        size_local_symbols_debug_information: i32,
        size_line_number_debug_information: i32,
        size_c13_style_line_number_information: i32,
    }

    impl ModuleInformation for FixtureModuleInformation {
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
            self.size_line_number_debug_information
        }
        fn size_c13_style_line_number_information(&self) -> i32 {
            self.size_c13_style_line_number_information
        }
        fn offsets_array(&self) -> &[i32] {
            &[]
        }
        fn filenames_array(&self) -> &[String] {
            &[]
        }
        fn module_name(&self) -> &str {
            "FixtureModule"
        }
        fn object_file_name(&self) -> &str {
            "fixture.obj"
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
        fn parse_additionals(&mut self, _reader: &mut PdbByteReader) -> Result<(), PdbException> {
            Ok(())
        }
        fn dump_additionals(&self, _writer: &mut dyn std::io::Write) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FixtureSymbol;
    impl AbstractMsSymbol for FixtureSymbol {}

    struct FixtureSymbolIterator {
        stream_number: i32,
        offset: i64,
    }

    impl MsSymbolIterator for FixtureSymbolIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn peek(&self) -> Result<&dyn AbstractMsSymbol, NoSuchElementError> {
            Err(NoSuchElementError)
        }
        fn next(&mut self) -> Result<Box<dyn AbstractMsSymbol>, NoSuchElementError> {
            Err(NoSuchElementError)
        }
        fn get_current_offset(&self) -> i64 {
            self.offset
        }
        fn init_get(&mut self) {}
        fn init_get_by_offset(&mut self, _offset: i64) {}
        fn get_stream_number(&self) -> i32 {
            self.stream_number
        }
    }

    struct FixtureC11Lines;
    impl C11LinesLike for FixtureC11Lines {}

    struct FixtureC13Section;
    impl crate::format::seam_stubs::C13SectionLike for FixtureC13Section {}

    struct FixtureC13SectionIterator {
        remaining: usize,
    }

    impl C13SectionIteratorLike for FixtureC13SectionIterator {
        fn has_next(&self) -> bool {
            self.remaining > 0
        }
        fn next(&mut self) -> Option<Box<dyn crate::format::seam_stubs::C13SectionLike>> {
            if self.remaining == 0 {
                return None;
            }
            self.remaining -= 1;
            Some(Box::new(FixtureC13Section))
        }
    }

    struct FixtureGlobalReferenceIterator {
        symbols_stream_number: i32,
        offset_iterator: GlobalReferenceOffsetIterator,
        cached: Option<Box<dyn MsSymbolIterator>>,
    }

    impl GlobalReferenceIterator for FixtureGlobalReferenceIterator {
        fn symbols_stream_number(&self) -> i32 {
            self.symbols_stream_number
        }
        fn offset_iterator_mut(&mut self) -> &mut GlobalReferenceOffsetIterator {
            &mut self.offset_iterator
        }
        fn cached_mut(&mut self) -> &mut Option<Box<dyn MsSymbolIterator>> {
            &mut self.cached
        }
        fn make_symbol_iterator(
            &self,
            stream_number: i32,
            offset: u32,
            _max_length: i32,
        ) -> Box<dyn MsSymbolIterator> {
            Box::new(FixtureSymbolIterator { stream_number, offset: offset as i64 })
        }
    }

    /// A concrete implementor backing everything with fixed byte buffers instead of a real
    /// `AbstractPdb`/`Msf`, proving [`Module`] is object-safe (usable as `Box<dyn Module>`) while
    /// exercising real stream-section slicing (via [`Module::read_section`]) and hook wiring.
    struct FixtureModule {
        module_information: FixtureModuleInformation,
        locations: PrecalculatedStreamLocations,
        stream_bytes: Vec<u8>,
        cv_sig_length: i32,
    }

    impl FixtureModule {
        fn new(module_information: FixtureModuleInformation, stream_bytes: Vec<u8>) -> Self {
            let locations = precalculate_stream_locations(
                &module_information,
                Some(stream_bytes.len() as i32),
            );
            FixtureModule { module_information, locations, stream_bytes, cv_sig_length: 0 }
        }
    }

    impl Module for FixtureModule {
        fn module_information(&self) -> &dyn ModuleInformation {
            &self.module_information
        }
        fn stream_number(&self) -> i32 {
            self.locations.stream_number
        }
        fn offset_symbols(&self) -> i32 {
            self.locations.offset_symbols
        }
        fn size_symbols(&self) -> i32 {
            self.locations.size_symbols
        }
        fn offset_lines(&self) -> i32 {
            self.locations.offset_lines
        }
        fn size_lines(&self) -> i32 {
            self.locations.size_lines
        }
        fn offset_c13_lines(&self) -> i32 {
            self.locations.offset_c13_lines
        }
        fn size_c13_lines(&self) -> i32 {
            self.locations.size_c13_lines
        }
        fn offset_global_refs(&self) -> i32 {
            self.locations.offset_global_refs
        }
        fn size_global_refs(&self) -> i32 {
            self.locations.size_global_refs
        }
        fn full_stream_reader(&self) -> Result<Option<PdbByteReader>, CancelledException> {
            Ok(Some(PdbByteReader::new(self.stream_bytes.clone())))
        }
        fn cv_sig_length(&self, _stream_number: i32) -> Result<i32, ModuleError> {
            Ok(self.cv_sig_length)
        }
        fn make_symbol_iterator(
            &self,
            stream_number: i32,
            offset: i32,
            _length: i32,
        ) -> Box<dyn MsSymbolIterator> {
            Box::new(FixtureSymbolIterator { stream_number, offset: offset as i64 })
        }
        fn parse_c11_lines(
            &self,
            _reader: PdbByteReader,
        ) -> Result<Box<dyn C11LinesLike>, ModuleError> {
            Ok(Box::new(FixtureC11Lines))
        }
        fn make_c13_section_iterator(
            &self,
            reader: PdbByteReader,
        ) -> Result<Box<dyn C13SectionIteratorLike>, ModuleError> {
            // Fixture convention: each section consumes 3 bytes of the c13 section.
            Ok(Box::new(FixtureC13SectionIterator { remaining: reader.num_remaining() / 3 }))
        }
        fn make_global_reference_iterator(
            &self,
            reader: PdbByteReader,
        ) -> Result<Box<dyn GlobalReferenceIterator>, ModuleError> {
            let offset_iterator = GlobalReferenceOffsetIterator::new(reader)?;
            Ok(Box::new(FixtureGlobalReferenceIterator {
                symbols_stream_number: 99,
                offset_iterator,
                cached: None,
            }))
        }
    }

    fn le_u32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    /// Builds a stream buffer laid out as: [symbols][lines][c13][global-refs], where the
    /// global-refs section is itself `[size_field][offset...]` matching
    /// [`GlobalReferenceOffsetIterator`]'s expected format.
    fn build_stream(
        symbols: &[u8],
        lines: &[u8],
        c13: &[u8],
        global_ref_offsets: &[u32],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(symbols);
        buf.extend_from_slice(lines);
        buf.extend_from_slice(c13);
        let size_field = (global_ref_offsets.len() as u32) * 4;
        buf.extend_from_slice(&le_u32(size_field));
        for offset in global_ref_offsets {
            buf.extend_from_slice(&le_u32(*offset));
        }
        buf
    }

    #[test]
    fn precalculate_stream_locations_returns_defaults_for_nil_stream() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: NIL_STREAM_NUMBER as u16,
            ..Default::default()
        };
        let locations = precalculate_stream_locations(&module_information, Some(100));
        assert_eq!(locations.stream_number, NIL_STREAM_NUMBER);
        assert_eq!(locations.size_symbols, 0);
        assert_eq!(locations.size_global_refs, 0);
    }

    #[test]
    fn precalculate_stream_locations_returns_defaults_when_stream_unresolved() {
        let module_information =
            FixtureModuleInformation { stream_number_debug_information: 7, ..Default::default() };
        let locations = precalculate_stream_locations(&module_information, None);
        assert_eq!(locations.stream_number, 7);
        assert_eq!(locations.offset_global_refs, 0);
    }

    #[test]
    fn precalculate_stream_locations_lays_out_sections_sequentially() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 3,
            size_local_symbols_debug_information: 10,
            size_line_number_debug_information: 20,
            size_c13_style_line_number_information: 30,
        };
        let locations = precalculate_stream_locations(&module_information, Some(70));
        assert_eq!(locations.offset_symbols, 0);
        assert_eq!(locations.offset_lines, 10);
        assert_eq!(locations.offset_c13_lines, 30);
        assert_eq!(locations.offset_global_refs, 60);
        assert_eq!(locations.size_global_refs, 10);
    }

    #[test]
    fn line_information_is_none_when_size_lines_is_zero() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 1,
            ..Default::default()
        };
        let module = FixtureModule::new(module_information, build_stream(&[], &[], &[], &[]));
        assert!(module.line_information().unwrap().is_none());
    }

    #[test]
    fn line_information_parses_when_lines_present() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 1,
            size_line_number_debug_information: 4,
            ..Default::default()
        };
        let module =
            FixtureModule::new(module_information, build_stream(&[], &[1, 2, 3, 4], &[], &[]));
        assert!(module.line_information().unwrap().is_some());
    }

    #[test]
    fn symbol_iterator_uses_stream_number_and_cv_sig_length_offset() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 5,
            size_local_symbols_debug_information: 16,
            ..Default::default()
        };
        let mut module =
            FixtureModule::new(module_information, build_stream(&[0; 16], &[], &[], &[]));
        module.cv_sig_length = 4;
        let iter = module.symbol_iterator().unwrap();
        assert_eq!(iter.get_stream_number(), 5);
        assert_eq!(iter.get_current_offset(), 4);
    }

    #[test]
    fn c13_section_iterator_yields_expected_sections() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 1,
            size_c13_style_line_number_information: 6,
            ..Default::default()
        };
        let module =
            FixtureModule::new(module_information, build_stream(&[], &[], &[9; 6], &[]));
        let mut iter = module.c13_section_iterator().unwrap();
        assert!(iter.has_next());
        assert!(iter.next().is_some());
        assert!(iter.has_next());
        assert!(iter.next().is_some());
        assert!(!iter.has_next());
        assert!(iter.next().is_none());
    }

    #[test]
    fn global_reference_offset_iterator_reads_offsets_from_section() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 1,
            ..Default::default()
        };
        let module =
            FixtureModule::new(module_information, build_stream(&[], &[], &[], &[0x10, 0x20]));
        let mut iter = module.global_reference_offset_iterator().unwrap();
        assert_eq!(iter.next().unwrap(), 0x10);
        assert_eq!(iter.next().unwrap(), 0x20);
        assert!(matches!(
            iter.next(),
            Err(crate::format::pdb2::pdbreader::parsing_iterator::ParsingIteratorError::NoSuchElement)
        ));
    }

    #[test]
    fn global_reference_iterator_wires_offset_iterator_into_hook() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 1,
            ..Default::default()
        };
        let module =
            FixtureModule::new(module_information, build_stream(&[], &[], &[], &[0x30]));
        let mut iter = module.global_reference_iterator().unwrap();
        assert!(iter.has_next().unwrap());
        let sym_iter = iter.next().unwrap();
        assert_eq!(sym_iter.get_stream_number(), 99);
        assert_eq!(sym_iter.get_current_offset(), 0x30);
    }

    #[test]
    fn nil_stream_number_yields_dummy_sections() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: NIL_STREAM_NUMBER as u16,
            ..Default::default()
        };
        let module = FixtureModule::new(module_information, Vec::new());
        assert!(module.line_information().unwrap().is_none());
        let mut iter = module.c13_section_iterator().unwrap();
        assert!(!iter.has_next());
    }

    #[test]
    fn boxed_trait_object_is_usable() {
        let module_information = FixtureModuleInformation {
            stream_number_debug_information: 2,
            size_c13_style_line_number_information: 3,
            ..Default::default()
        };
        let module: Box<dyn Module> =
            Box::new(FixtureModule::new(module_information, build_stream(&[], &[], &[1; 3], &[])));
        assert_eq!(module.module_information().module_name(), "FixtureModule");
        assert!(module.c13_section_iterator().unwrap().has_next());
    }
}
