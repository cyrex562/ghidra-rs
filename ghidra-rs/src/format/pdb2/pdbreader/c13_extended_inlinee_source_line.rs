use crate::format::pdb2::pdbreader::c13_inlinee_source_line::C13InlineeSourceLine;
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::util::task::TaskMonitor;

/// An extended version of the PDB C13 inlinee source line record that has extra file IDs.
#[derive(Debug, Clone)]
pub struct C13ExtendedInlineeSourceLine {
    base: C13InlineeSourceLine,
    extra_file_ids: Vec<i32>,
}

impl C13ExtendedInlineeSourceLine {
    /// The base size of a C13 Extended Inlinee Source Line record in bytes.
    pub const BASE_RECORD_SIZE: usize = 16;

    /// Parses a `C13ExtendedInlineeSourceLine` from the given reader.
    ///
    /// `monitor` is accepted for parity with the Java source but is not consulted during parsing.
    ///
    /// # Errors
    /// Returns [`PdbException`] if there is not enough data to parse the required fields.
    pub fn parse(
        reader: &mut PdbByteReader,
        _monitor: &dyn TaskMonitor,
    ) -> Result<Self, PdbException> {
        let base = C13InlineeSourceLine::parse(reader)?;
        let num_extra_files = reader.parse_unsigned_int_val()?;

        let mut extra_file_ids = Vec::with_capacity(num_extra_files as usize);
        for _ in 0..num_extra_files {
            let file_id = reader.parse_int()?;
            extra_file_ids.push(file_id);
        }

        Ok(C13ExtendedInlineeSourceLine { base, extra_file_ids })
    }

    /// Returns the number of extra file IDs.
    pub fn num_extra_file_ids(&self) -> usize {
        self.extra_file_ids.len()
    }

    /// Returns the list of extra file IDs.
    pub fn extra_file_ids(&self) -> &[i32] {
        &self.extra_file_ids
    }

    /// Returns the base inlinee source line record.
    pub fn base(&self) -> &C13InlineeSourceLine {
        &self.base
    }
}

impl std::fmt::Display for C13ExtendedInlineeSourceLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.base)?;
        for id in &self.extra_file_ids {
            write!(f, " 0x{:06x}", id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::util::exception::CancelledException;
    use crate::util::task::CancelledListener;

    struct NoOpTaskMonitor;
    impl TaskMonitor for NoOpTaskMonitor {
        fn is_cancelled(&self) -> bool {
            false
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
            Ok(())
        }
        fn increment_progress(&self, _amount: i64) {}
        fn get_progress(&self) -> i64 {
            0
        }
        fn cancel(&self) {}
        fn add_cancelled_listener(&self, _listener: Box<dyn CancelledListener>) {}
        fn remove_cancelled_listener(&self, _listener: &dyn CancelledListener) {}
        fn set_cancel_enabled(&self, _enabled: bool) {}
        fn is_cancel_enabled(&self) -> bool {
            true
        }
        fn clear_cancelled(&self) {}
    }

    #[test]
    fn parse_extended_with_no_extra_files() {
        // Base record (12 bytes) + num_extra_files (4 bytes) = 16 bytes
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, // inlinee
            0x9a, 0xbc, 0xde, 0xf0, // file_id
            0x11, 0x22, 0x33, 0x44, // source_line_num
            0x00, 0x00, 0x00, 0x00, // num_extra_files = 0
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let result = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.num_extra_file_ids(), 0);
        assert_eq!(record.extra_file_ids().len(), 0);
    }

    #[test]
    fn parse_extended_with_single_extra_file() {
        // Base record (12 bytes) + num_extra_files (4 bytes) + 1 file_id (4 bytes) = 20 bytes
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, // inlinee
            0x9a, 0xbc, 0xde, 0xf0, // file_id
            0x11, 0x22, 0x33, 0x44, // source_line_num
            0x01, 0x00, 0x00, 0x00, // num_extra_files = 1
            0xaa, 0xbb, 0xcc, 0xdd, // extra file id
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let result = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.num_extra_file_ids(), 1);
        assert_eq!(record.extra_file_ids()[0], 0xddccbbaa_u32 as i32);
    }

    #[test]
    fn parse_extended_with_multiple_extra_files() {
        // Base record (12 bytes) + num_extra_files (4 bytes) + 3 file_ids (12 bytes) = 28 bytes
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, // inlinee
            0x9a, 0xbc, 0xde, 0xf0, // file_id
            0x11, 0x22, 0x33, 0x44, // source_line_num
            0x03, 0x00, 0x00, 0x00, // num_extra_files = 3
            0xaa, 0xbb, 0xcc, 0xdd, // extra file id 1
            0xee, 0xff, 0x00, 0x11, // extra file id 2
            0x22, 0x33, 0x44, 0x55, // extra file id 3
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let result = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor);
        assert!(result.is_ok());
        let record = result.unwrap();
        assert_eq!(record.num_extra_file_ids(), 3);
        assert_eq!(record.extra_file_ids().len(), 3);
    }

    #[test]
    fn parse_insufficient_data_for_base() {
        let bytes = vec![0x12, 0x34, 0x56];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let result = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_num_extra_files() {
        // Base record (12 bytes) but only 2 bytes for num_extra_files
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let result = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn parse_insufficient_data_for_extra_files() {
        // Base record (12 bytes) + num_extra_files (4 bytes) says 2 files, but only 1 file present
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, // inlinee
            0x9a, 0xbc, 0xde, 0xf0, // file_id
            0x11, 0x22, 0x33, 0x44, // source_line_num
            0x02, 0x00, 0x00, 0x00, // num_extra_files = 2
            0xaa, 0xbb, 0xcc, 0xdd, // extra file id 1 only
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let result = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor);
        assert!(result.is_err());
    }

    #[test]
    fn display_format_no_extra_files() {
        let bytes = vec![
            0x12, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let record = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x000000012, 0x000034, 120");
    }

    #[test]
    fn display_format_with_extra_files() {
        let bytes = vec![
            0x12, 0x00, 0x00, 0x00, // inlinee
            0x34, 0x00, 0x00, 0x00, // file_id
            0x78, 0x00, 0x00, 0x00, // source_line_num
            0x02, 0x00, 0x00, 0x00, // num_extra_files = 2
            0xab, 0x00, 0x00, 0x00, // extra file id 1
            0xcd, 0x00, 0x00, 0x00, // extra file id 2
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let record = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor).unwrap();
        let display_str = format!("{}", record);
        assert_eq!(display_str, "0x000000012, 0x000034, 120 0x0000ab 0x0000cd");
    }

    #[test]
    fn clone_semantics() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x02, 0x00,
            0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let record1 = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor).unwrap();
        let record2 = record1.clone();
        assert_eq!(record1.num_extra_file_ids(), record2.num_extra_file_ids());
        assert_eq!(record1.extra_file_ids(), record2.extra_file_ids());
    }

    #[test]
    fn base_record_access() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, // inlinee
            0x9a, 0xbc, 0xde, 0xf0, // file_id
            0x11, 0x22, 0x33, 0x44, // source_line_num
            0x01, 0x00, 0x00, 0x00, // num_extra_files = 1
            0xaa, 0xbb, 0xcc, 0xdd, // extra file id
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let record = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor).unwrap();
        assert_eq!(record.base().inlinee(), 0x78563412);
        assert_eq!(record.base().file_id(), 0xf0debc9a_u32 as i32);
        assert_eq!(record.base().source_line_num(), 0x44332211);
    }

    #[test]
    fn debug_output() {
        let bytes = vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x01, 0x00,
            0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
        ];
        let mut reader = PdbByteReader::new(bytes);
        let monitor = NoOpTaskMonitor;
        let record = C13ExtendedInlineeSourceLine::parse(&mut reader, &monitor).unwrap();
        let debug_str = format!("{:?}", record);
        assert!(debug_str.contains("C13ExtendedInlineeSourceLine"));
    }
}
