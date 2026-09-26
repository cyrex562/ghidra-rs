use std::io;

use thiserror::Error;

use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::seam_stubs::{MsfFileReaderLike, MsfStreamLike};
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Error returned by [`Msf::deserialize`], combining the checked exceptions declared on
/// `Msf.deserialize()` (`IOException`, `PdbException`, `CancelledException`).
#[derive(Error, Debug)]
pub enum MsfError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Pdb(#[from] PdbException),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

/// Returns the floor (greatest integer less than or equal to) of the result upon dividing
/// `dividend` by a divisor which is the power-of-two of `log2_divisor`.
///
/// Mirrors the static `Msf.floorDivisionWithLog2Divisor(int, int)`.
pub fn floor_division_with_log2_divisor(dividend: i32, log2_divisor: i32) -> i32 {
    (dividend + (1 << log2_divisor) - 1) >> log2_divisor
}

/// Represents the Multi-Stream Format File used for Windows PDB files. We have intended to
/// implement to the Microsoft PDB API (source); see the API for truth.
///
/// Implementors represent the real formats. The file format represents a kind of file system
/// within a file and is based upon pages in order to try to optimize disk I/O and system
/// update. There was also a mechanism to allow for ping-ponged commit for file updates. Our
/// implementation is only used for reading the file format; it is not intended to write or
/// modify an existing file.
///
/// The file format consists of a first page that contains identifying header information that
/// consists of an ID string, and limited parameters needed for pointing to directory
/// information and the Free Page Map. We do not use the latter information.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.msf.Msf`. Splits Java's
/// `AutoCloseable.close()` (checked `IOException`) out as [`Msf::close`], and models
/// `MsfFileReader`/`MsfStream` -- both still-unported concrete classes -- via the
/// [`MsfFileReaderLike`]/[`MsfStreamLike`] placeholder traits from
/// [`seam_stubs`](crate::format::seam_stubs) so this trait stays object-safe.
pub trait Msf {
    /// Returns the filename.
    fn filename(&self) -> &str;

    /// Returns the [`TaskMonitor`].
    fn monitor(&self) -> &dyn TaskMonitor;

    /// Checks whether this monitor has been cancelled.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the monitor has been cancelled.
    fn check_cancelled(&self) -> Result<(), CancelledException>;

    /// Returns the page size employed by this MSF.
    fn page_size(&self) -> i32;

    /// Returns the number of streams found in this MSF.
    fn num_streams(&self) -> i32;

    /// Returns the file reader.
    fn file_reader(&self) -> &dyn MsfFileReaderLike;

    /// Closes resources used by this MSF.
    ///
    /// # Errors
    /// Returns an I/O error under circumstances found when closing the underlying file.
    fn close(&mut self) -> io::Result<()>;

    /// Returns the stream specified by `stream_number`, or `None` if there is no stream for
    /// that number. `stream_number` must be less than the number returned by
    /// [`num_streams`](Self::num_streams).
    fn stream(&self, stream_number: i32) -> Option<Box<dyn MsfStreamLike>>;

    //==========================================================================================
    // Package-Protected Utilities
    //==========================================================================================

    /// Returns the identification bytes required by this format.
    fn identification(&self) -> Vec<u8>;

    /// Returns the offset (in bytes) of the page size within the header.
    fn page_size_offset(&self) -> i32;

    /// Deserializes the Free Page Map page number from `reader`.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    fn parse_free_page_map_page_number(
        &mut self,
        reader: &mut PdbByteReader,
    ) -> Result<(), PdbException>;

    /// Deserializes the value of the number of pages in the MSF.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    fn parse_current_num_pages(&mut self, reader: &mut PdbByteReader) -> Result<(), PdbException>;

    /// Creates the following components: StreamTable, FreePageMap, and DirectoryStream.
    fn create(&mut self);

    /// Sets parameters for the file based on version and page size.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unknown value for configuration.
    fn configure_parameters(&mut self) -> Result<(), PdbException>;

    /// Returns the size of the page number (in bytes) when serialized to disk.
    fn page_number_size(&self) -> i32;

    //==========================================================================================
    // Class Internals
    //==========================================================================================

    /// Returns the Log2 value of the page size employed by this MSF.
    fn log2_page_size(&self) -> i32;

    /// Returns the mask used for masking off the upper bits of a value used to get the
    /// mod-page-size of the value (page sizes must be a power of two for this to work).
    fn page_size_mod_mask(&self) -> i32;

    /// Returns the number of pages found in sequence that compose the Free Page Map (for this
    /// MSF) when on disk.
    fn num_sequential_free_page_map_pages(&self) -> i32;

    /// Returns the page number containing the header of this MSF file.
    fn header_page_number(&self) -> i32;

    /// Returns the stream number containing the directory of this MSF file.
    fn directory_stream_number(&self) -> i32;

    //==========================================================================================
    // Internal Data Methods
    //==========================================================================================

    /// Returns the number of pages contained in this MSF file.
    fn num_pages(&self) -> i32;

    /// Returns the first page number of the current Free Page Map.
    fn current_free_page_map_first_page_number(&self) -> i32;

    /// Performs required initialization of this class, needed before trying to read any
    /// streams. Initialization includes deserializing the remainder of the header as well as
    /// stream directory information.
    ///
    /// # Errors
    /// Returns [`MsfError`] on file seek or read, invalid parameters, bad file configuration,
    /// inability to read required bytes, unknown value for configuration, or user cancellation.
    fn deserialize(&mut self) -> Result<(), MsfError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::exception::CancelledException;
    use crate::util::task::DummyMonitor;

    struct MockMsf {
        filename: String,
        monitor: DummyMonitor,
        page_size: i32,
        num_pages: i32,
        deserialized: bool,
    }

    impl MockMsf {
        fn new() -> Self {
            MockMsf {
                filename: "test.pdb".to_string(),
                monitor: DummyMonitor,
                page_size: 4096,
                num_pages: 0,
                deserialized: false,
            }
        }
    }

    impl Msf for MockMsf {
        fn filename(&self) -> &str {
            &self.filename
        }

        fn monitor(&self) -> &dyn TaskMonitor {
            &self.monitor
        }

        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.monitor.is_cancelled() {
                Err(CancelledException("cancelled".to_string()))
            } else {
                Ok(())
            }
        }

        fn page_size(&self) -> i32 {
            self.page_size
        }

        fn num_streams(&self) -> i32 {
            0
        }

        fn file_reader(&self) -> &dyn MsfFileReaderLike {
            struct NoFileReader;
            impl MsfFileReaderLike for NoFileReader {}
            // A `'static` placeholder is fine here: the mock never actually reads a file.
            Box::leak(Box::new(NoFileReader))
        }

        fn close(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn stream(&self, _stream_number: i32) -> Option<Box<dyn MsfStreamLike>> {
            None
        }

        fn identification(&self) -> Vec<u8> {
            b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0".to_vec()
        }

        fn page_size_offset(&self) -> i32 {
            32
        }

        fn parse_free_page_map_page_number(
            &mut self,
            reader: &mut PdbByteReader,
        ) -> Result<(), PdbException> {
            reader.parse_int()?;
            Ok(())
        }

        fn parse_current_num_pages(
            &mut self,
            reader: &mut PdbByteReader,
        ) -> Result<(), PdbException> {
            self.num_pages = reader.parse_int()?;
            Ok(())
        }

        fn create(&mut self) {}

        fn configure_parameters(&mut self) -> Result<(), PdbException> {
            if self.page_size <= 0 {
                return Err(PdbException::new("bad page size"));
            }
            Ok(())
        }

        fn page_number_size(&self) -> i32 {
            4
        }

        fn log2_page_size(&self) -> i32 {
            12
        }

        fn page_size_mod_mask(&self) -> i32 {
            self.page_size - 1
        }

        fn num_sequential_free_page_map_pages(&self) -> i32 {
            1
        }

        fn header_page_number(&self) -> i32 {
            0
        }

        fn directory_stream_number(&self) -> i32 {
            0
        }

        fn num_pages(&self) -> i32 {
            self.num_pages
        }

        fn current_free_page_map_first_page_number(&self) -> i32 {
            1
        }

        fn deserialize(&mut self) -> Result<(), MsfError> {
            if self.monitor.is_cancelled() {
                return Err(CancelledException("cancelled".to_string()).into());
            }
            self.configure_parameters()?;
            self.deserialized = true;
            Ok(())
        }
    }

    #[test]
    fn floor_division_matches_expected_values() {
        // page_size = 4096 = 1 << 12; a stream of 10000 bytes needs ceil(10000 / 4096) = 3 pages.
        assert_eq!(floor_division_with_log2_divisor(10000, 12), 3);
        assert_eq!(floor_division_with_log2_divisor(4096, 12), 1);
        assert_eq!(floor_division_with_log2_divisor(0, 12), 0);
        assert_eq!(floor_division_with_log2_divisor(1, 12), 1);
    }

    #[test]
    fn mock_msf_reports_basic_properties() {
        let msf = MockMsf::new();
        assert_eq!(msf.filename(), "test.pdb");
        assert_eq!(msf.page_size(), 4096);
        assert_eq!(msf.log2_page_size(), 12);
        assert_eq!(msf.page_size_mod_mask(), 4095);
        assert!(msf.stream(0).is_none());
    }

    #[test]
    fn deserialize_parses_header_fields_via_reader() {
        let mut msf = MockMsf::new();
        let mut reader = PdbByteReader::new(vec![0x02, 0x00, 0x00, 0x00]);
        msf.parse_current_num_pages(&mut reader).unwrap();
        assert_eq!(msf.num_pages(), 2);
    }

    #[test]
    fn deserialize_succeeds_when_not_cancelled() {
        let mut msf = MockMsf::new();
        assert!(msf.check_cancelled().is_ok());
        assert!(msf.deserialize().is_ok());
        assert!(msf.deserialized);
    }

    #[test]
    fn deserialize_fails_on_bad_configuration() {
        let mut msf = MockMsf::new();
        msf.page_size = 0;
        assert!(matches!(msf.deserialize(), Err(MsfError::Pdb(_))));
    }

    #[test]
    fn object_safety_via_boxed_trait_object() {
        let mut boxed: Box<dyn Msf> = Box::new(MockMsf::new());
        assert_eq!(boxed.page_size(), 4096);
        assert!(boxed.close().is_ok());
    }
}
