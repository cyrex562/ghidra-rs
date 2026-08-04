use std::path::Path;

use crate::format::pdb2::pdbreader::msf::msf::MsfError;
use crate::format::seam_stubs::{AbstractPdb, PdbReaderOptions};
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::util::task::TaskMonitor;

/// `VC2` MSF version identifier (0x013048ea).
pub const VC2_ID: i32 = 19941610;
/// `VC4` MSF version identifier (0x01306c1f).
pub const VC4_ID: i32 = 19950623;
/// `VC41` MSF version identifier (0x01306cde).
pub const VC41_ID: i32 = 19950814;
/// `VC50` MSF version identifier (0x013091f3).
pub const VC50_ID: i32 = 19960307;
/// `VC98` MSF version identifier (0x0130ba2c).
pub const VC98_ID: i32 = 19970604;
/// `VC70DEP` MSF version identifier (0x0131084c).
pub const VC70DEP_ID: i32 = 19990604;
/// `VC70` MSF version identifier (0x01312e94).
pub const VC70_ID: i32 = 20000404;
/// `VC80` MSF version identifier (0x0131a5b5).
pub const VC80_ID: i32 = 20030901;
/// `VC110` MSF version identifier (0x01329141).
pub const VC110_ID: i32 = 20091201;
/// `VC140` MSF version identifier (0x013351dc).
pub const VC140_ID: i32 = 20140508;

/// Parser for detecting the appropriate [`AbstractPdb`] for the input given, and returning it
/// (not yet deserialized).
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser`. Java's three overloaded static
/// `parse` methods (by filename, by `File`, by `ByteProvider`) become the three methods below.
/// Java's `parse(String, ...)` delegated to `parse(File, ...)`, which itself opened a
/// `FileByteProvider` via `FileSystemService` and delegated to `parse(ByteProvider, ...)`; that
/// wiring is an implementation detail left to implementors, not part of this seam.
///
/// Takes `&self` (rather than being free functions/associated functions, as in Java's all-static
/// utility class) so this can be used as `Box<dyn PdbParser>`/`&dyn PdbParser` at the call sites
/// that currently depend on the concrete class, breaking the dependency cycle.
pub trait PdbParser {
    /// Opens the PDB file at `filename`, determines its version, and returns an [`AbstractPdb`]
    /// appropriate for that version; it will not have been deserialized.
    ///
    /// # Errors
    /// Returns [`MsfError`] on I/O issues, parsing issues, or user cancellation.
    fn parse_filename(
        &self,
        filename: &str,
        pdb_options: &PdbReaderOptions,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AbstractPdb>, MsfError>;

    /// Opens the PDB file at `file`, determines its version, and returns an [`AbstractPdb`]
    /// appropriate for that version; it will not have been deserialized.
    ///
    /// # Errors
    /// Returns [`MsfError`] on I/O issues, parsing issues, or user cancellation.
    fn parse_file(
        &self,
        file: &Path,
        pdb_options: &PdbReaderOptions,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AbstractPdb>, MsfError>;

    /// Reads from `byte_provider`, determines the PDB version, and returns an [`AbstractPdb`]
    /// appropriate for that version; it will not have been deserialized.
    ///
    /// # Errors
    /// Returns [`MsfError`] on I/O issues, parsing issues, or user cancellation.
    fn parse_byte_provider(
        &self,
        byte_provider: Box<dyn ByteProvider>,
        pdb_options: &PdbReaderOptions,
        monitor: &dyn TaskMonitor,
    ) -> Result<Box<dyn AbstractPdb>, MsfError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbCharset;
    use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
    use crate::util::exception::CancelledException;
    use std::io;

    struct StubPdb;

    impl AbstractPdb for StubPdb {
        fn pdb_reader_options(&self) -> &PdbReaderOptions {
            unreachable!("not exercised by this test")
        }

        fn get_type_record(
            &self,
            _record_number: crate::format::seam_stubs::RecordNumber,
        ) -> Box<dyn crate::format::seam_stubs::AbstractMsType> {
            unreachable!("not exercised by this test")
        }
    }

    /// Mock implementation proving [`PdbParser`] is object-safe and can dispatch on the version
    /// identifier the way `PdbParser.parse(ByteProvider, ...)` does in Java.
    struct MockPdbParser;

    impl PdbParser for MockPdbParser {
        fn parse_filename(
            &self,
            filename: &str,
            pdb_options: &PdbReaderOptions,
            monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AbstractPdb>, MsfError> {
            if filename.is_empty() {
                return Err(MsfError::Io(io::Error::new(io::ErrorKind::NotFound, "empty filename")));
            }
            self.parse_file(Path::new(filename), pdb_options, monitor)
        }

        fn parse_file(
            &self,
            file: &Path,
            pdb_options: &PdbReaderOptions,
            monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AbstractPdb>, MsfError> {
            if monitor.is_cancelled() {
                return Err(MsfError::Cancelled(CancelledException::new("cancelled")));
            }
            let _ = (file, pdb_options);
            Ok(Box::new(StubPdb))
        }

        fn parse_byte_provider(
            &self,
            _byte_provider: Box<dyn ByteProvider>,
            _pdb_options: &PdbReaderOptions,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn AbstractPdb>, MsfError> {
            Err(MsfError::Pdb(PdbException::new("Unknown PDB Version: 0")))
        }
    }

    struct StubMonitor {
        cancelled: bool,
    }

    impl TaskMonitor for StubMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn set_show_progress_value(&self, _show: bool) {}
        fn set_message(&self, _message: &str) {}
        fn get_message(&self) -> String {
            String::new()
        }
        fn set_progress(&self, _value: i64) {}
        fn initialize(&self, _max: i64) {}
        fn set_maximum(&self, _max: i64) {}
        fn get_maximum(&self) -> i64 {
            0
        }
        fn set_indeterminate(&self, _indeterminate: bool) {}
        fn is_indeterminate(&self) -> bool {
            false
        }
        fn check_cancelled(&self) -> Result<(), CancelledException> {
            if self.cancelled {
                Err(CancelledException::new("cancelled"))
            } else {
                Ok(())
            }
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            -1
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    fn options() -> PdbReaderOptions {
        PdbReaderOptions {
            one_byte_charset: PdbCharset::Utf8,
            two_byte_charset: PdbCharset::Utf16Le,
        }
    }

    #[test]
    fn is_object_safe() {
        let parser: Box<dyn PdbParser> = Box::new(MockPdbParser);
        let result = parser.parse_filename(
            "foo.pdb",
            &options(),
            &StubMonitor { cancelled: false },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn empty_filename_is_io_error() {
        let parser = MockPdbParser;
        let result = parser.parse_filename("", &options(), &StubMonitor { cancelled: false });
        match result {
            Err(MsfError::Io(_)) => {}
            _ => panic!("expected MsfError::Io for empty filename"),
        }
    }

    #[test]
    fn cancelled_monitor_yields_cancelled_error() {
        let parser = MockPdbParser;
        let result = parser.parse_file(
            Path::new("foo.pdb"),
            &options(),
            &StubMonitor { cancelled: true },
        );
        match result {
            Err(MsfError::Cancelled(_)) => {}
            _ => panic!("expected MsfError::Cancelled for cancelled monitor"),
        }
    }

    #[test]
    fn version_ids_match_java_constants() {
        assert_eq!(VC2_ID, 0x013048ea);
        assert_eq!(VC4_ID, 0x01306c1f);
        assert_eq!(VC41_ID, 0x01306cde);
        assert_eq!(VC50_ID, 0x013091f3);
        assert_eq!(VC98_ID, 0x0130ba2c);
        assert_eq!(VC70DEP_ID, 0x0131084c);
        assert_eq!(VC70_ID, 0x01312e94);
        assert_eq!(VC80_ID, 0x0131a5b5);
        assert_eq!(VC110_ID, 0x01329141);
        assert_eq!(VC140_ID, 0x013351dc);
    }
}
