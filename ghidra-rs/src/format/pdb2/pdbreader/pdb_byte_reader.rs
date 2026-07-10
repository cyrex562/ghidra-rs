use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::pdb2::pdbreader::string_parse_type::StringParseType;
use crate::format::seam_stubs::{AbstractPdb, Guid};

/// Encoding used to decode a length-prefixed or null-terminated string parsed by
/// [`PdbByteReader`]. Stands in for `java.nio.charset.Charset`, covering the encodings PDB
/// string parsing actually selects between (one-byte charsets and UTF-16LE `wchar_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbCharset {
    /// A single-byte charset (e.g. US-ASCII, Windows-1252).
    OneByte,
    /// UTF-8.
    Utf8,
    /// UTF-16, little-endian (`wchar_t` on Windows).
    Utf16Le,
}

impl PdbCharset {
    fn decode(self, bytes: &[u8]) -> String {
        match self {
            PdbCharset::OneByte => bytes.iter().map(|&b| b as char).collect(),
            PdbCharset::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            PdbCharset::Utf16Le => {
                let units: Vec<u16> =
                    bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                String::from_utf16_lossy(&units)
            }
        }
    }
}

/// `PdbByteReader` is a utility used for administering out portions of a byte array. The
/// requests are made with a `parse...` method, which interprets data, pointed to by a current
/// `index` into the byte array, into the type requested.
///
/// `PdbByteReader` is intended for PDB (Program Data Base) / MSF (Multi-Stream File) buffer
/// processing which has data stored in a Least-Significant-Byte-First format. Requested values
/// are read out appropriately.
///
/// When an `unsigned` value is requested, it is returned in a native Rust unsigned integer type
/// rather than the artificially-widened signed type Java's port used (Java has no unsigned
/// primitives smaller than its return type).
///
/// Other utility methods exist for setting/getting the `index` or for moving the `index` along
/// to align or pad-out according to how a C/C++ structure would be padded in memory.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.PdbByteReader`.
pub struct PdbByteReader {
    /// byte array containing data to be parsed
    bytes: Vec<u8>,
    /// fixed length of the byte array
    limit: usize,
    /// current index into the byte array from which the next parse method will act
    index: usize,
    /// offset to begin alignment for methods that need to calculate alignment
    align_marker: usize,
}

impl PdbByteReader {
    /// Constructor for a `PdbByteReader`. Takes the bytes of data to be read in particular
    /// increments and formats.
    pub fn new(bytes: Vec<u8>) -> Self {
        let limit = bytes.len();
        PdbByteReader { bytes, limit, index: 0, align_marker: 0 }
    }

    /// Returns an empty `PdbByteReader`, mirroring the Java `DUMMY` static instance (a fresh,
    /// independent instance here, since Rust has no shared-mutable-static equivalent).
    pub fn dummy() -> Self {
        PdbByteReader::new(Vec::new())
    }

    /// Resets the index of the `PdbByteReader` back to zero.
    pub fn reset(&mut self) {
        self.index = 0;
        self.align_marker = 0;
    }

    /// Returns the number of bytes remaining in the `PdbByteReader`.
    pub fn num_remaining(&self) -> usize {
        self.limit - self.index
    }

    /// Returns the current index of the `PdbByteReader`.
    pub fn get_index(&self) -> usize {
        self.index
    }

    /// Returns the limit of the `PdbByteReader`.
    pub fn get_limit(&self) -> usize {
        self.limit
    }

    /// Sets the index to the value specified. Silently fails when outside of array.
    pub fn set_index(&mut self, index: usize) {
        if index < self.limit {
            self.index = index;
        }
    }

    /// Returns true if there are more bytes remaining in the `PdbByteReader`.
    pub fn has_more(&self) -> bool {
        self.index < self.limit
    }

    /// Returns true if there are more bytes remaining in the `PdbByteReader` which are non-pad
    /// bytes.
    pub fn has_more_non_pad(&self) -> bool {
        if !self.has_more() {
            return false;
        }
        self.bytes[self.index] <= 0xf0
    }

    /// Parses a single byte (unsigned char) of data from the `PdbByteReader` and returns its
    /// positive value.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_unsigned_byte_val(&mut self) -> Result<u8, PdbException> {
        self.check_limit(1)?;
        let v = self.bytes[self.index];
        self.index += 1;
        Ok(v)
    }

    /// Parses and returns, the specified-size integer type value (16 or 32).
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unhandled size specified in arguments.
    pub fn parse_var_sized_int(&mut self, size: u32) -> Result<i32, PdbException> {
        match size {
            16 => Ok(self.parse_short()? as i32),
            32 => self.parse_int(),
            _ => Err(PdbException::new("Bad int size")),
        }
    }

    /// Parses and returns an unsigned integer, the specified-size unsigned integer type value
    /// (8 or 16).
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unhandled size specified in arguments.
    pub fn parse_small_var_sized_uint(&mut self, size: u32) -> Result<u32, PdbException> {
        match size {
            8 => Ok(self.parse_unsigned_byte_val()? as u32),
            16 => Ok(self.parse_unsigned_short_val()? as u32),
            _ => Err(PdbException::new("Bad int size")),
        }
    }

    /// Parses and returns an unsigned integer, the specified-size unsigned integer type value
    /// (8, 16, or 32).
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unhandled size specified in arguments.
    pub fn parse_var_sized_uint(&mut self, size: u32) -> Result<u64, PdbException> {
        match size {
            8 => Ok(self.parse_unsigned_byte_val()? as u64),
            16 => Ok(self.parse_unsigned_short_val()? as u64),
            32 => Ok(self.parse_unsigned_int_val()? as u64),
            _ => Err(PdbException::new("Bad int size")),
        }
    }

    /// Parses and returns a value intended to be used as an **offset**, using the specified-size
    /// integer type value (16 or 32). When 16, an **unsigned** short is parsed; when 32, an
    /// **unsigned** int is parsed.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unhandled size specified in arguments.
    pub fn parse_var_sized_offset(&mut self, size: u32) -> Result<u64, PdbException> {
        match size {
            16 => Ok(self.parse_unsigned_short_val()? as u64),
            32 => Ok(self.parse_unsigned_int_val()? as u64),
            _ => Err(PdbException::new("Bad offset size")),
        }
    }

    /// Parses and returns a value intended to be used as a **count**, using the specified-size
    /// integer type value (16 or 32). When 16, an **unsigned** short is parsed; when 32, a
    /// **signed** int is parsed.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unhandled size specified in arguments.
    pub fn parse_var_sized_count(&mut self, size: u32) -> Result<i32, PdbException> {
        match size {
            16 => Ok(self.parse_unsigned_short_val()? as i32),
            32 => self.parse_int(),
            _ => Err(PdbException::new("Bad count size")),
        }
    }

    /// Parses and returns a short from the `PdbByteReader`.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_short(&mut self) -> Result<i16, PdbException> {
        self.check_limit(2)?;
        let v = i16::from_le_bytes([self.bytes[self.index], self.bytes[self.index + 1]]);
        self.index += 2;
        Ok(v)
    }

    /// Parses an unsigned short from the `PdbByteReader` and returns its positive value.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_unsigned_short_val(&mut self) -> Result<u16, PdbException> {
        self.check_limit(2)?;
        let v = u16::from_le_bytes([self.bytes[self.index], self.bytes[self.index + 1]]);
        self.index += 2;
        Ok(v)
    }

    /// Parses and returns an integer from the `PdbByteReader`.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_int(&mut self) -> Result<i32, PdbException> {
        self.check_limit(4)?;
        let bytes: [u8; 4] = self.bytes[self.index..self.index + 4].try_into().unwrap();
        let v = i32::from_le_bytes(bytes);
        self.index += 4;
        Ok(v)
    }

    /// Parses an unsigned int from the `PdbByteReader` and returns its positive value.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_unsigned_int_val(&mut self) -> Result<u32, PdbException> {
        self.check_limit(4)?;
        let bytes: [u8; 4] = self.bytes[self.index..self.index + 4].try_into().unwrap();
        let v = u32::from_le_bytes(bytes);
        self.index += 4;
        Ok(v)
    }

    /// Parses and returns a (64-bit) long from the `PdbByteReader`.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_long(&mut self) -> Result<i64, PdbException> {
        self.check_limit(8)?;
        let bytes: [u8; 8] = self.bytes[self.index..self.index + 8].try_into().unwrap();
        let v = i64::from_le_bytes(bytes);
        self.index += 8;
        Ok(v)
    }

    /// Parses a (64-bit) unsigned long from the `PdbByteReader` and returns its positive value.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_unsigned_long_val(&mut self) -> Result<u64, PdbException> {
        self.check_limit(8)?;
        let bytes: [u8; 8] = self.bytes[self.index..self.index + 8].try_into().unwrap();
        let v = u64::from_le_bytes(bytes);
        self.index += 8;
        Ok(v)
    }

    /// Parses and returns a short-valued-length-prefixed byte array from the `PdbByteReader`
    /// (not including the 2 bytes of the short-valued-length). An unsigned short is first
    /// parsed. This value tells the number of bytes to be read and returned.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_short_length_prefixed_byte_array(&mut self) -> Result<Vec<u8>, PdbException> {
        self.check_limit(2)?;
        let length = self.parse_unsigned_short_val()? as usize;
        self.parse_bytes(length)
    }

    /// Returns the remaining bytes in the `PdbByteReader` as a byte array.
    pub fn parse_bytes_remaining(&mut self) -> Vec<u8> {
        let remaining = self.limit - self.index;
        let selected = self.bytes[self.index..self.index + remaining].to_vec();
        self.index += remaining;
        selected
    }

    /// Extracts and returns a byte array of bytes from the `PdbByteReader`, the number of which
    /// is specified by the parameter.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_bytes(&mut self, num: usize) -> Result<Vec<u8>, PdbException> {
        self.check_limit(num)?;
        let selected = self.bytes[self.index..self.index + num].to_vec();
        self.index += num;
        Ok(selected)
    }

    /// Returns a sub-`PdbByteReader` starting at the current index location and limited to the
    /// length. The parent `PdbByteReader` index gets moved forward by length.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn get_sub_pdb_byte_reader(&mut self, length: usize) -> Result<PdbByteReader, PdbException> {
        Ok(PdbByteReader::new(self.parse_bytes(length)?))
    }

    /// Parses a GUID from the `PdbByteReader`.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon not enough data left to parse.
    pub fn parse_guid(&mut self) -> Result<Guid, PdbException> {
        self.check_limit(16)?;
        let data1 = self.parse_int()?;
        let data2 = self.parse_short()?;
        let data3 = self.parse_short()?;
        let data4 = self.parse_bytes(8)?;
        Ok(Guid::new(data1, data2, data3, data4))
    }

    /// Parses a string, as indicated by `st_type`, from the `PdbByteReader` and returns it.
    /// Where needed, uses one of the string encoding options as retained in the associated PDB
    /// reader options.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon unhandled string parse type.
    pub fn parse_string(
        &mut self,
        pdb: &dyn AbstractPdb,
        st_type: StringParseType,
    ) -> Result<String, PdbException> {
        match st_type {
            StringParseType::StringNt => {
                Ok(self.parse_null_terminated_string(pdb.pdb_reader_options().one_byte_charset()))
            }
            StringParseType::StringSt => {
                self.parse_byte_length_prefixed_string(pdb.pdb_reader_options().one_byte_charset())
            }
            StringParseType::StringUtf8St => self.parse_byte_length_prefixed_utf8_string(),
            StringParseType::StringUtf8Nt => Ok(self.parse_null_terminated_utf8_string()),
            StringParseType::StringWcharNt => {
                Ok(self.parse_null_terminated_wchar_string(pdb.pdb_reader_options().two_byte_charset()))
            }
        }
    }

    /// Parses and returns a byte-valued-length-prefixed String from the `PdbByteReader`. The
    /// string length is determined by the first byte of data (not returned)--there is not a null
    /// terminator in the source bytes. This number of bytes is extracted and converted to a
    /// String and returned.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon error parsing the string.
    pub fn parse_byte_length_prefixed_string(
        &mut self,
        charset: PdbCharset,
    ) -> Result<String, PdbException> {
        let length = self.parse_unsigned_byte_val()? as usize;
        if length == 0 {
            return Ok(String::new());
        }
        let selected = self.parse_bytes(length)?;
        Ok(charset.decode(&selected))
    }

    /// Parses and returns a byte-valued-length-prefixed UTF8 String from the `PdbByteReader`.
    /// The string length is determined by the first byte of data (not returned)--there is not a
    /// null terminator in the source bytes. This number of bytes is extracted and converted to a
    /// String and returned.
    ///
    /// # Errors
    /// Returns [`PdbException`] upon error parsing the string.
    pub fn parse_byte_length_prefixed_utf8_string(&mut self) -> Result<String, PdbException> {
        let length = self.parse_unsigned_byte_val()? as usize;
        if length == 0 {
            return Ok(String::new());
        }
        let selected = self.parse_bytes(length)?;
        Ok(PdbCharset::Utf8.decode(&selected))
    }

    /// Parses a null-terminated string from the `PdbByteReader` and returns the String (minus
    /// the terminating null character). If no null, returns up to end of `PdbByteReader`.
    pub fn parse_null_terminated_string(&mut self, charset: PdbCharset) -> String {
        let offset = self.index;
        let width = 1;
        let end = self.find_null_terminator_index(width);
        self.index = end + width;
        if end == offset {
            return String::new();
        }
        charset.decode(&self.bytes[offset..end])
    }

    /// Parses a null-terminated UTF-8 string from the `PdbByteReader` and returns the String
    /// (minus the terminating null character). If no null, returns up to end of `PdbByteReader`.
    pub fn parse_null_terminated_utf8_string(&mut self) -> String {
        let offset = self.index;
        let width = 1;
        let end = self.find_null_terminator_index(width);
        self.index = end + width;
        if end == offset {
            return String::new();
        }
        PdbCharset::Utf8.decode(&self.bytes[offset..end])
    }

    /// Parses a null-terminated `wchar_t` string from the `PdbByteReader` and returns the String
    /// (minus the terminating null character). If no null, returns up to end of
    /// `PdbByteReader`.
    pub fn parse_null_terminated_wchar_string(&mut self, charset: PdbCharset) -> String {
        let offset = self.index;
        let width = 2;
        let end = self.find_null_terminator_index(width);
        self.index = end + width;
        if end == offset {
            return String::new();
        }
        charset.decode(&self.bytes[offset..end])
    }

    /// Stores the current index value as a marker for performing alignment. [`Self::align4`]
    /// calculates alignment based on this marker.
    pub fn mark_align(&mut self, align_marker_in: usize) {
        self.align_marker = align_marker_in;
    }

    /// Moves the index of the `PdbByteReader` to align on a 4-byte boundary of the initializing
    /// byte array, modified by an alignment modifier passed in by [`Self::mark_align`].
    ///
    /// Returns the number added to the index.
    pub fn align4(&mut self) -> usize {
        let excess = (self.index.wrapping_sub(self.align_marker)) & 0x03;
        let pad = if excess == 0 { 0 } else { 4 - excess };
        self.index += pad;
        pad
    }

    /// This is a specialized method for PDB that should only be used when the Subject Matter
    /// Expert knows it is appropriate to use. It looks for and removes padding bytes that are
    /// indications of and take the place of alignment padding.
    ///
    /// Returns the number of padding bytes removed (also the increase in index).
    pub fn skip_padding(&mut self) -> usize {
        let initial_index = self.index;
        while self.index < self.limit && (self.bytes[self.index] & 0xf0) == 0xf0 {
            self.index += 1;
        }
        self.index - initial_index
    }

    /// This method skips the number of bytes specified. Does not skip beyond the end.
    pub fn skip(&mut self, num: usize) {
        if num > self.limit - self.index {
            self.index = self.limit;
        } else {
            self.index += num;
        }
    }

    /// Debug method used to dump bytes of the `PdbByteReader` to a String in a pretty format.
    /// Includes header of internal values.
    pub fn dump(&self) -> String {
        self.dump_range(0, self.limit)
    }

    /// Debug method used to dump a specified number of bytes of the `PdbByteReader` in a pretty
    /// format, starting at the current index. Includes header of internal values.
    pub fn dump_max(&self, max: usize) -> String {
        self.dump_range(self.index, self.index + max)
    }

    /// Debug method used to dump a specified number of bytes of the `PdbByteReader` in a pretty
    /// format, starting at `first` and continuing to one less than `last`. First dumped are the
    /// number of bytes in the `PdbByteReader`, followed by the current index, followed by the
    /// `first`/`last` parameter values, followed by the bytes specified (or up to end of buffer
    /// if it comes first).
    pub fn dump_range(&self, first: usize, last: usize) -> String {
        let last = if last > self.limit { self.limit } else { last };
        let mut builder = String::new();
        builder.push_str("limit: ");
        builder.push_str(&self.limit.to_string());
        builder.push_str("\nindex: ");
        builder.push_str(&self.index.to_string());
        builder.push_str("\nfirst: ");
        builder.push_str(&first.to_string());
        builder.push_str("\nlast: ");
        builder.push_str(&last.to_string());
        builder.push_str(&self.dump_bytes_range(first, last));
        builder
    }

    /// Debug method used to dump bytes of the `PdbByteReader` to a String in a pretty format.
    pub fn dump_bytes(&self) -> String {
        self.dump_bytes_range(0, self.limit)
    }

    /// Debug method used to dump a specified number of bytes of the `PdbByteReader` in a pretty
    /// format, starting at the current index.
    pub fn dump_bytes_max(&self, max: usize) -> String {
        self.dump_bytes_range(self.index, self.index + max)
    }

    /// Debug method used to dump a specified number of bytes of the `PdbByteReader` in a pretty
    /// format, starting at `first` and continuing to one less than `last`. Only the bytes are
    /// dumped.
    pub fn dump_bytes_range(&self, first: usize, last: usize) -> String {
        if first > last || first > self.limit {
            return String::new();
        }
        let last = if last > self.limit { self.limit } else { last };
        let mut builder = String::new();
        let mut i = first;
        while i < last {
            builder.push_str(&format!("\n{:06x}", i));
            let mut j = 0;
            while j < 16 && i < last {
                builder.push_str(&format!(" {:02x}", self.bytes[i]));
                j += 1;
                i += 1;
            }
        }
        builder
    }

    /// Checks if `num_needed` bytes is available between `index` and `limit`. Returns
    /// [`PdbException`] if space is not available. The `num_needed` value is the amount that the
    /// caller intends to increment `index` by, and the resultant value is allowed to hit
    /// `limit`, but not exceed `limit`, as the `index` value is that of what would be the next
    /// byte to read, if one was going to read again.
    fn check_limit(&self, num_needed: usize) -> Result<(), PdbException> {
        match self.index.checked_add(num_needed) {
            Some(end) if end <= self.limit => Ok(()),
            Some(_) => Err(PdbException::new("Needed data is not available.")),
            None => Err(PdbException::new("Needed data beyond max.")),
        }
    }

    /// Returns the index of the first character of the null terminator of any width.
    fn find_null_terminator_index(&self, width: usize) -> usize {
        let mut count = 0;
        let mut finder_index = self.index;
        while finder_index < self.limit {
            let b = self.bytes[finder_index];
            finder_index += 1;
            if b == 0x00 {
                count += 1;
                if count == width {
                    return finder_index - width;
                }
            } else {
                count = 0;
            }
        }
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePdb {
        options: crate::format::seam_stubs::PdbReaderOptions,
    }

    impl AbstractPdb for FakePdb {
        fn pdb_reader_options(&self) -> &crate::format::seam_stubs::PdbReaderOptions {
            &self.options
        }
    }

    #[test]
    fn new_reader_starts_at_zero_with_correct_limit() {
        let reader = PdbByteReader::new(vec![1, 2, 3]);
        assert_eq!(reader.get_index(), 0);
        assert_eq!(reader.get_limit(), 3);
        assert_eq!(reader.num_remaining(), 3);
    }

    #[test]
    fn parse_unsigned_byte_val_reads_and_advances() {
        let mut reader = PdbByteReader::new(vec![0xff, 0x01]);
        assert_eq!(reader.parse_unsigned_byte_val().unwrap(), 0xff);
        assert_eq!(reader.get_index(), 1);
        assert_eq!(reader.parse_unsigned_byte_val().unwrap(), 0x01);
    }

    #[test]
    fn parse_unsigned_byte_val_fails_when_out_of_data() {
        let mut reader = PdbByteReader::new(vec![]);
        assert!(reader.parse_unsigned_byte_val().is_err());
    }

    #[test]
    fn parse_short_and_unsigned_short_are_little_endian() {
        let mut reader = PdbByteReader::new(vec![0xfe, 0xff]);
        let mut reader2 = PdbByteReader::new(vec![0xfe, 0xff]);
        assert_eq!(reader.parse_short().unwrap(), -2);
        assert_eq!(reader2.parse_unsigned_short_val().unwrap(), 0xfffe);
    }

    #[test]
    fn parse_int_and_unsigned_int_are_little_endian() {
        let mut reader = PdbByteReader::new(vec![0x01, 0x00, 0x00, 0x00]);
        assert_eq!(reader.parse_int().unwrap(), 1);
        let mut reader2 = PdbByteReader::new(vec![0xff, 0xff, 0xff, 0xff]);
        assert_eq!(reader2.parse_unsigned_int_val().unwrap(), 0xffff_ffff);
    }

    #[test]
    fn parse_long_and_unsigned_long_round_trip() {
        let bytes = 0x1234_5678_9abc_def0u64.to_le_bytes().to_vec();
        let mut reader = PdbByteReader::new(bytes.clone());
        assert_eq!(reader.parse_unsigned_long_val().unwrap(), 0x1234_5678_9abc_def0u64);
        let mut reader2 = PdbByteReader::new(bytes);
        assert_eq!(reader2.parse_long().unwrap(), 0x1234_5678_9abc_def0u64 as i64);
    }

    #[test]
    fn parse_var_sized_int_dispatches_on_size() {
        let mut reader = PdbByteReader::new(vec![0x05, 0x00]);
        assert_eq!(reader.parse_var_sized_int(16).unwrap(), 5);
        let mut reader2 = PdbByteReader::new(vec![0x05, 0x00, 0x00, 0x00]);
        assert_eq!(reader2.parse_var_sized_int(32).unwrap(), 5);
        let mut reader3 = PdbByteReader::new(vec![]);
        assert!(reader3.parse_var_sized_int(64).is_err());
    }

    #[test]
    fn parse_bytes_extracts_and_advances() {
        let mut reader = PdbByteReader::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(reader.parse_bytes(3).unwrap(), vec![1, 2, 3]);
        assert_eq!(reader.get_index(), 3);
        assert!(reader.parse_bytes(10).is_err());
    }

    #[test]
    fn parse_bytes_remaining_consumes_rest() {
        let mut reader = PdbByteReader::new(vec![1, 2, 3]);
        reader.skip(1);
        assert_eq!(reader.parse_bytes_remaining(), vec![2, 3]);
        assert!(!reader.has_more());
    }

    #[test]
    fn get_sub_pdb_byte_reader_advances_parent_and_scopes_child() {
        let mut reader = PdbByteReader::new(vec![1, 2, 3, 4]);
        let mut sub = reader.get_sub_pdb_byte_reader(2).unwrap();
        assert_eq!(reader.get_index(), 2);
        assert_eq!(sub.get_limit(), 2);
        assert_eq!(sub.parse_bytes(2).unwrap(), vec![1, 2]);
    }

    #[test]
    fn parse_guid_reads_fields_in_order() {
        let mut bytes = vec![];
        bytes.extend_from_slice(&1i32.to_le_bytes());
        bytes.extend_from_slice(&2i16.to_le_bytes());
        bytes.extend_from_slice(&3i16.to_le_bytes());
        bytes.extend_from_slice(&[9u8; 8]);
        let mut reader = PdbByteReader::new(bytes);
        let guid = reader.parse_guid().unwrap();
        assert_eq!(guid.data1, 1);
        assert_eq!(guid.data2, 2);
        assert_eq!(guid.data3, 3);
        assert_eq!(guid.data4, vec![9u8; 8]);
    }

    #[test]
    fn parse_null_terminated_string_stops_at_null() {
        let mut reader = PdbByteReader::new(b"abc\0def".to_vec());
        let s = reader.parse_null_terminated_string(PdbCharset::OneByte);
        assert_eq!(s, "abc");
        assert_eq!(reader.get_index(), 4);
    }

    #[test]
    fn parse_null_terminated_string_returns_all_when_no_null() {
        let mut reader = PdbByteReader::new(b"abc".to_vec());
        let s = reader.parse_null_terminated_string(PdbCharset::OneByte);
        assert_eq!(s, "abc");
        assert_eq!(reader.get_index(), 3);
    }

    #[test]
    fn parse_null_terminated_wchar_string_uses_two_byte_terminator() {
        let mut bytes = vec![];
        bytes.extend_from_slice("hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>().as_slice());
        bytes.extend_from_slice(&[0, 0]);
        let mut reader = PdbByteReader::new(bytes);
        let s = reader.parse_null_terminated_wchar_string(PdbCharset::Utf16Le);
        assert_eq!(s, "hi");
    }

    #[test]
    fn parse_byte_length_prefixed_string_reads_length_then_bytes() {
        let mut bytes = vec![3u8];
        bytes.extend_from_slice(b"xyz");
        let mut reader = PdbByteReader::new(bytes);
        let s = reader.parse_byte_length_prefixed_string(PdbCharset::OneByte).unwrap();
        assert_eq!(s, "xyz");
    }

    #[test]
    fn parse_byte_length_prefixed_string_handles_zero_length() {
        let mut reader = PdbByteReader::new(vec![0u8]);
        let s = reader.parse_byte_length_prefixed_string(PdbCharset::OneByte).unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn parse_string_dispatches_via_abstract_pdb() {
        let fake_pdb = FakePdb {
            options: crate::format::seam_stubs::PdbReaderOptions {
                one_byte_charset: PdbCharset::OneByte,
                two_byte_charset: PdbCharset::Utf16Le,
            },
        };
        let mut reader = PdbByteReader::new(b"hi\0".to_vec());
        let s = reader.parse_string(&fake_pdb, StringParseType::StringNt).unwrap();
        assert_eq!(s, "hi");
    }

    #[test]
    fn align4_pads_to_boundary() {
        let mut reader = PdbByteReader::new(vec![0; 10]);
        reader.skip(3);
        let pad = reader.align4();
        assert_eq!(pad, 1);
        assert_eq!(reader.get_index(), 4);
    }

    #[test]
    fn align4_no_pad_when_already_aligned() {
        let mut reader = PdbByteReader::new(vec![0; 10]);
        reader.skip(4);
        assert_eq!(reader.align4(), 0);
    }

    #[test]
    fn mark_align_shifts_alignment_base() {
        let mut reader = PdbByteReader::new(vec![0; 10]);
        reader.mark_align(2);
        reader.skip(3);
        // index=3, alignMarker=2 -> excess = 1 -> pad = 3
        assert_eq!(reader.align4(), 3);
    }

    #[test]
    fn skip_padding_consumes_high_nibble_f_bytes() {
        let mut reader = PdbByteReader::new(vec![0xf1, 0xf2, 0x00, 0xf3]);
        assert_eq!(reader.skip_padding(), 2);
        assert_eq!(reader.get_index(), 2);
    }

    #[test]
    fn skip_does_not_go_past_end() {
        let mut reader = PdbByteReader::new(vec![1, 2, 3]);
        reader.skip(100);
        assert_eq!(reader.get_index(), 3);
        assert!(!reader.has_more());
    }

    #[test]
    fn has_more_non_pad_detects_pad_bytes() {
        let reader = PdbByteReader::new(vec![0xf1]);
        assert!(!reader.has_more_non_pad());
        let reader2 = PdbByteReader::new(vec![0x10]);
        assert!(reader2.has_more_non_pad());
    }

    #[test]
    fn set_index_silently_ignores_out_of_range() {
        let mut reader = PdbByteReader::new(vec![1, 2, 3]);
        reader.set_index(1);
        assert_eq!(reader.get_index(), 1);
        reader.set_index(100);
        assert_eq!(reader.get_index(), 1);
    }

    #[test]
    fn reset_clears_index_and_align_marker() {
        let mut reader = PdbByteReader::new(vec![1, 2, 3]);
        reader.skip(2);
        reader.mark_align(1);
        reader.reset();
        assert_eq!(reader.get_index(), 0);
        assert_eq!(reader.align4(), 0);
    }

    #[test]
    fn dump_bytes_range_formats_hex_rows() {
        let reader = PdbByteReader::new(vec![0xde, 0xad, 0xbe, 0xef]);
        let s = reader.dump_bytes_range(0, 4);
        assert_eq!(s, "\n000000 de ad be ef");
    }

    #[test]
    fn dump_includes_header_fields() {
        let reader = PdbByteReader::new(vec![1, 2]);
        let s = reader.dump();
        assert!(s.contains("limit: 2"));
        assert!(s.contains("index: 0"));
    }

    #[test]
    fn dummy_is_empty() {
        let reader = PdbByteReader::dummy();
        assert_eq!(reader.get_limit(), 0);
        assert!(!reader.has_more());
    }
}
