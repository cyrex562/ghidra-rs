use crate::format::pdb2::pdbreader::parsing_iterator::{ParsingIterator, ParsingIteratorError};
use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;

/// Iterator for Global Reference Offsets section of module stream.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.GlobalReferenceOffsetIterator`.
pub struct GlobalReferenceOffsetIterator {
    reader: PdbByteReader,
    current_global_reference_offset: Option<u32>,
}

impl GlobalReferenceOffsetIterator {
    /// Creates a new iterator of Global Reference Offsets.
    ///
    /// `reader` must contain only Global Reference Offsets information and be in a newly
    /// constructed state.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse, or if the header's size
    /// field is inconsistent with the reader's limit.
    pub fn new(mut reader: PdbByteReader) -> Result<Self, PdbException> {
        Self::process_header(&mut reader)?;
        Ok(GlobalReferenceOffsetIterator { reader, current_global_reference_offset: None })
    }

    /// Reads and validates the size field; leaves the reader pointing at the first record.
    fn process_header(reader: &mut PdbByteReader) -> Result<(), PdbException> {
        let size_field = reader.parse_int()?;
        if size_field as i64 + 4 != reader.get_limit() as i64 {
            return Err(PdbException::new(format!(
                "Error in module global refs size field: {} != {}",
                size_field,
                reader.get_limit()
            )));
        }
        Ok(())
    }

    fn find(&mut self) {
        match self.reader.parse_unsigned_int_val() {
            Ok(value) => self.current_global_reference_offset = Some(value),
            Err(e) => {
                Msg::error_with_error(
                    "GlobalReferenceOffsetIterator",
                    &"Problem seen in find()",
                    &e,
                );
                self.current_global_reference_offset = None;
            }
        }
    }
}

impl ParsingIterator<u32> for GlobalReferenceOffsetIterator {
    fn has_next(&mut self) -> Result<bool, CancelledException> {
        if self.current_global_reference_offset.is_none() {
            self.find();
        }
        Ok(self.current_global_reference_offset.is_some())
    }

    fn next(&mut self) -> Result<u32, ParsingIteratorError> {
        if self.has_next().map_err(ParsingIteratorError::Cancelled)? {
            return Ok(self.current_global_reference_offset.take().unwrap());
        }
        Err(ParsingIteratorError::NoSuchElement)
    }

    fn peek(&mut self) -> Result<u32, ParsingIteratorError> {
        if self.has_next().map_err(ParsingIteratorError::Cancelled)? {
            return Ok(self.current_global_reference_offset.unwrap());
        }
        Err(ParsingIteratorError::NoSuchElement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader_with_offsets(offsets: &[u32]) -> PdbByteReader {
        let mut bytes = Vec::new();
        let size_field = (offsets.len() as u32) * 4;
        bytes.extend_from_slice(&size_field.to_le_bytes());
        for offset in offsets {
            bytes.extend_from_slice(&offset.to_le_bytes());
        }
        PdbByteReader::new(bytes)
    }

    #[test]
    fn new_rejects_inconsistent_size_field() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100i32.to_le_bytes());
        bytes.extend_from_slice(&0x11223344u32.to_le_bytes());
        let reader = PdbByteReader::new(bytes);
        let result = GlobalReferenceOffsetIterator::new(reader);
        assert!(result.is_err());
    }

    #[test]
    fn new_accepts_consistent_empty_size_field() {
        let reader = reader_with_offsets(&[]);
        let result = GlobalReferenceOffsetIterator::new(reader);
        assert!(result.is_ok());
    }

    #[test]
    fn has_next_false_for_empty_iterator() {
        let reader = reader_with_offsets(&[]);
        let mut iter = GlobalReferenceOffsetIterator::new(reader).unwrap();
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn iterates_all_offsets_in_order() {
        let reader = reader_with_offsets(&[0x11223344, 0x55667788, 0xaabbccdd]);
        let mut iter = GlobalReferenceOffsetIterator::new(reader).unwrap();
        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 0x11223344);
        assert_eq!(iter.next().unwrap(), 0x55667788);
        assert_eq!(iter.next().unwrap(), 0xaabbccdd);
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn next_errors_when_exhausted() {
        let reader = reader_with_offsets(&[]);
        let mut iter = GlobalReferenceOffsetIterator::new(reader).unwrap();
        assert!(matches!(iter.next(), Err(ParsingIteratorError::NoSuchElement)));
    }

    #[test]
    fn peek_does_not_advance() {
        let reader = reader_with_offsets(&[0xdeadbeef, 0xfeedface]);
        let mut iter = GlobalReferenceOffsetIterator::new(reader).unwrap();
        assert_eq!(iter.peek().unwrap(), 0xdeadbeef);
        assert_eq!(iter.peek().unwrap(), 0xdeadbeef);
        assert_eq!(iter.next().unwrap(), 0xdeadbeef);
        assert_eq!(iter.peek().unwrap(), 0xfeedface);
    }

    #[test]
    fn peek_errors_when_exhausted() {
        let reader = reader_with_offsets(&[]);
        let mut iter = GlobalReferenceOffsetIterator::new(reader).unwrap();
        assert!(matches!(iter.peek(), Err(ParsingIteratorError::NoSuchElement)));
    }
}
