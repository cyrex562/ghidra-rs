//! Port of `ghidra.app.util.bin.BinaryReader`.
//!
//! [`BinaryReader`] is the concrete Java class: a cursor over a shared [`ByteProvider`] that
//! decodes integers and strings in a chosen byte order. It is a plain struct holding the
//! provider as `Rc<dyn ByteProvider>` -- the shared-handle convention the crate's filesystem
//! ports already use for providers that outlive a single borrow -- so that
//! [`clone_at`](BinaryReader::clone_at) / [`as_big_endian`](BinaryReader::as_big_endian) share
//! the underlying bytes exactly as the Java clones share the provider reference.
//!
//! [`LegacyBinaryReader`] is the transitional trait that stood in for this class before it was
//! ported (every implementor was a test double or an ad-hoc adapter over a byte source).
//! Consumers are being migrated onto the struct module by module; the struct implements the
//! trait so migrated producers can still feed not-yet-migrated consumers.

use std::cell::RefCell;
use std::fmt;
use std::io::{self, Read};
use std::rc::Rc;
use std::sync::Arc;

use crate::app::util::bin::byte_array_provider::ByteArrayProvider;
use crate::app::util::bin::byte_provider::ByteProvider;
use crate::app::util::bin::invalid_data_exception::InvalidDataException;
use crate::filesystem::ghidra::g_binary_reader::GByteStore;
use crate::util::big_endian_data_converter;
use crate::util::data_converter::DataConverter;
use crate::util::little_endian_data_converter;

/// The size of a BYTE, in bytes.
pub const SIZEOF_BYTE: u64 = 1;
/// The size of a SHORT, in bytes.
pub const SIZEOF_SHORT: u64 = 2;
/// The size of an INTEGER, in bytes.
pub const SIZEOF_INT: u64 = 4;
/// The size of a LONG, in bytes.
pub const SIZEOF_LONG: u64 = 8;

/// Java: `MAX_SANE_BUFFER = Integer.MAX_VALUE - 1024`, the conservative cap on the size of a
/// null-terminated string read before it is reported as run-on.
const MAX_SANE_BUFFER: u64 = i32::MAX as u64 - 1024;

/// Java: `DataConverter.getInstance(isBigEndian)`.
fn converter_for(is_big_endian: bool) -> &'static dyn DataConverter {
    if is_big_endian {
        &big_endian_data_converter::INSTANCE
    } else {
        &little_endian_data_converter::INSTANCE
    }
}

/// Reads typed values from a generic [`ByteProvider`] in either big-endian or little-endian
/// order, maintaining a current position that the `read_next_*` methods advance automatically.
///
/// Mirrors `ghidra.app.util.bin.BinaryReader`.
///
/// Integer widths follow the crate's established reader API rather than Java's `int`/`long`
/// promotion: [`read_byte`](Self::read_byte) returns the raw `u8` (cast to `i8` for Java's signed
/// `byte`), and the unsigned variants return the zero-extended value in the next wider unsigned
/// type (`u16` for a byte, `u32` for a short, `u64` for an int). Java's `IOException` is
/// [`io::Error`]; Java's `EOFException` is an [`io::ErrorKind::UnexpectedEof`] error.
#[derive(Clone)]
pub struct BinaryReader {
    provider: Rc<dyn ByteProvider>,
    converter: &'static dyn DataConverter,
    current_index: u64,
}

impl fmt::Debug for BinaryReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BinaryReader")
            .field("little_endian", &self.is_little_endian())
            .field("current_index", &self.current_index)
            .field("length", &self.provider.length())
            .finish()
    }
}

impl BinaryReader {
    /// Constructs a reader over `provider`, positioned at index 0, using the given endianness.
    ///
    /// Mirrors `BinaryReader(ByteProvider, boolean)`.
    pub fn new(provider: Rc<dyn ByteProvider>, is_little_endian: bool) -> Self {
        Self::with_converter(provider, converter_for(!is_little_endian), 0)
    }

    /// Constructs a reader over `provider` using `converter` to decode values, positioned at
    /// `initial_index`.
    ///
    /// Mirrors `BinaryReader(ByteProvider, DataConverter, long)`.
    pub fn with_converter(
        provider: Rc<dyn ByteProvider>,
        converter: &'static dyn DataConverter,
        initial_index: u64,
    ) -> Self {
        BinaryReader { provider, converter, current_index: initial_index }
    }

    /// Constructs a reader over an in-memory copy of `bytes`.
    ///
    /// Shorthand for Java's `new BinaryReader(new ByteArrayProvider(bytes), isLittleEndian)`.
    pub fn from_bytes(bytes: impl Into<Arc<[u8]>>, is_little_endian: bool) -> Self {
        Self::new(Rc::new(ByteArrayProvider::new(bytes)), is_little_endian)
    }

    /// Returns a clone of this reader, sharing the same provider and endianness, positioned at
    /// `new_index`. Mirrors `clone(long)`.
    pub fn clone_at(&self, new_index: u64) -> BinaryReader {
        BinaryReader::with_converter(Rc::clone(&self.provider), self.converter, new_index)
    }

    /// Returns an independent clone of this reader positioned at the same index. Mirrors
    /// `clone()`; equivalent to [`Clone::clone`].
    pub fn clone_reader(&self) -> BinaryReader {
        self.clone_at(self.current_index)
    }

    /// Returns a big-endian clone of this reader, positioned at the same index. Mirrors
    /// `asBigEndian()`.
    pub fn as_big_endian(&self) -> BinaryReader {
        BinaryReader::with_converter(
            Rc::clone(&self.provider),
            &big_endian_data_converter::INSTANCE,
            self.current_index,
        )
    }

    /// Returns a little-endian clone of this reader, positioned at the same index. Mirrors
    /// `asLittleEndian()`.
    pub fn as_little_endian(&self) -> BinaryReader {
        BinaryReader::with_converter(
            Rc::clone(&self.provider),
            &little_endian_data_converter::INSTANCE,
            self.current_index,
        )
    }

    /// Returns true if this reader extracts values in little-endian order.
    pub fn is_little_endian(&self) -> bool {
        !self.converter.is_big_endian()
    }

    /// Returns true if this reader extracts values in big-endian order.
    pub fn is_big_endian(&self) -> bool {
        self.converter.is_big_endian()
    }

    /// Sets the endianness used to extract values. Mirrors `setLittleEndian(boolean)`.
    pub fn set_little_endian(&mut self, is_little_endian: bool) {
        self.converter = converter_for(!is_little_endian);
    }

    /// Returns the length of the underlying provider.
    ///
    /// Java declares `throws IOException`; the ported [`ByteProvider::length`] is infallible, so
    /// this always returns `Ok`.
    pub fn length(&self) -> io::Result<u64> {
        Ok(self.provider.length())
    }

    /// Returns true if `index` is a valid index in the underlying provider.
    pub fn is_valid_index(&self, index: u64) -> bool {
        self.provider.is_valid_index(index)
    }

    /// Returns true if the range `[start_index, start_index + count)` is entirely valid.
    ///
    /// Mirrors `isValidRange(long, int)`: the end of the range is checked first to fail fast,
    /// and a range that wraps past the end of the 64-bit index space is invalid.
    pub fn is_valid_range(&self, start_index: u64, count: usize) -> bool {
        let mut count = count as u64;
        if count > 1 {
            // check the end of the range first to fail fast
            let end_index = start_index.wrapping_add(count - 1);
            if end_index < start_index {
                // the requested range wraps around the int64 to 0, so fail
                return false;
            }
            if !self.provider.is_valid_index(end_index) {
                return false;
            }
            count -= 1; // don't check the last element twice
        }
        (0..count).all(|i| self.provider.is_valid_index(start_index.wrapping_add(i)))
    }

    /// Returns true if there is at least one more byte at the current position.
    pub fn has_next(&self) -> bool {
        self.provider.is_valid_index(self.current_index)
    }

    /// Returns true if there are at least `count` more bytes at the current position. Mirrors
    /// `hasNext(int)`.
    pub fn has_next_count(&self, count: usize) -> bool {
        self.is_valid_range(self.current_index, count)
    }

    /// Advances the current index so that it aligns to `align_value` (if not already aligned),
    /// returning the number of bytes skipped. An `align_value` of 0 leaves the index unchanged.
    ///
    /// Mirrors `align(int)`, which uses `NumericUtilities.getUnsignedAlignedValue`.
    pub fn align(&mut self, align_value: u64) -> u64 {
        let prev = self.current_index;
        self.current_index = unsigned_aligned_value(prev, align_value);
        self.current_index.wrapping_sub(prev)
    }

    /// Sets the current index to `index`, returning the previous index.
    pub fn set_pointer_index(&mut self, index: u64) -> u64 {
        std::mem::replace(&mut self.current_index, index)
    }

    /// Returns the current index.
    pub fn get_pointer_index(&self) -> u64 {
        self.current_index
    }

    /// Returns the underlying provider. Mirrors `getByteProvider()`.
    pub fn get_byte_provider(&self) -> &Rc<dyn ByteProvider> {
        &self.provider
    }

    /// Returns a stream that reads the bytes at the current position, advancing this reader's
    /// index as it goes and reporting end-of-stream once the index leaves the provider.
    ///
    /// Mirrors `getInputStream()`.
    pub fn get_input_stream(&mut self) -> BinaryReaderInputStream<'_> {
        BinaryReaderInputStream { reader: self }
    }

    // ── peek (non-advancing) ─────────────────────────────────────────────────

    /// Returns the byte at the current index without advancing. Mirrors `peekNextByte()`.
    pub fn peek_next_byte(&self) -> io::Result<u8> {
        self.read_byte(self.current_index)
    }

    /// Returns the short at the current index without advancing. Mirrors `peekNextShort()`.
    pub fn peek_next_short(&self) -> io::Result<i16> {
        self.read_short(self.current_index)
    }

    /// Returns the int at the current index without advancing. Mirrors `peekNextInt()`.
    pub fn peek_next_int(&self) -> io::Result<i32> {
        self.read_int(self.current_index)
    }

    /// Returns the long at the current index without advancing. Mirrors `peekNextLong()`.
    pub fn peek_next_long(&self) -> io::Result<i64> {
        self.read_long(self.current_index)
    }

    // ── readNext (advancing) ─────────────────────────────────────────────────

    /// Reads the byte at the current index and advances by one. Mirrors `readNextByte()`.
    pub fn read_next_byte(&mut self) -> io::Result<u8> {
        let b = self.read_byte(self.current_index)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_BYTE);
        Ok(b)
    }

    /// Reads the unsigned byte at the current index and advances by one. Mirrors
    /// `readNextUnsignedByte()`.
    pub fn read_next_unsigned_byte(&mut self) -> io::Result<u16> {
        Ok(self.read_next_byte()? as u16)
    }

    /// Reads the short at the current index and advances by two. Mirrors `readNextShort()`.
    pub fn read_next_short(&mut self) -> io::Result<i16> {
        self.read_next_short_with(self.converter)
    }

    /// Reads the short at the current index using `dc` and advances by two. Mirrors
    /// `readNextShort(DataConverter)`.
    pub fn read_next_short_with(&mut self, dc: &dyn DataConverter) -> io::Result<i16> {
        let s = self.read_short_with(dc, self.current_index)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_SHORT);
        Ok(s)
    }

    /// Reads the unsigned short at the current index and advances by two. Mirrors
    /// `readNextUnsignedShort()`.
    pub fn read_next_unsigned_short(&mut self) -> io::Result<u32> {
        Ok(self.read_next_short()? as u16 as u32)
    }

    /// Reads the unsigned short at the current index using `dc` and advances by two. Mirrors
    /// `readNextUnsignedShort(DataConverter)`.
    pub fn read_next_unsigned_short_with(&mut self, dc: &dyn DataConverter) -> io::Result<u32> {
        Ok(self.read_next_short_with(dc)? as u16 as u32)
    }

    /// Reads the int at the current index and advances by four. Mirrors `readNextInt()`.
    pub fn read_next_int(&mut self) -> io::Result<i32> {
        self.read_next_int_with(self.converter)
    }

    /// Reads the int at the current index using `dc` and advances by four. Mirrors
    /// `readNextInt(DataConverter)`.
    pub fn read_next_int_with(&mut self, dc: &dyn DataConverter) -> io::Result<i32> {
        let i = self.read_int_with(dc, self.current_index)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_INT);
        Ok(i)
    }

    /// Reads the unsigned int at the current index and advances by four. Mirrors
    /// `readNextUnsignedInt()`.
    pub fn read_next_unsigned_int(&mut self) -> io::Result<u64> {
        Ok(self.read_next_int()? as u32 as u64)
    }

    /// Reads the unsigned int at the current index using `dc` and advances by four. Mirrors
    /// `readNextUnsignedInt(DataConverter)`.
    pub fn read_next_unsigned_int_with(&mut self, dc: &dyn DataConverter) -> io::Result<u64> {
        Ok(self.read_next_int_with(dc)? as u32 as u64)
    }

    /// Reads the long at the current index and advances by eight. Mirrors `readNextLong()`.
    pub fn read_next_long(&mut self) -> io::Result<i64> {
        self.read_next_long_with(self.converter)
    }

    /// Reads the long at the current index using `dc` and advances by eight. Mirrors
    /// `readNextLong(DataConverter)`.
    pub fn read_next_long_with(&mut self, dc: &dyn DataConverter) -> io::Result<i64> {
        let l = self.read_long_with(dc, self.current_index)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_LONG);
        Ok(l)
    }

    /// Reads a signed, sign-extended integer of `len` (0 to 8) bytes and advances by `len`.
    /// Mirrors `readNextValue(int)`.
    pub fn read_next_value(&mut self, len: usize) -> io::Result<i64> {
        self.read_next_value_with(self.converter, len)
    }

    /// Mirrors `readNextValue(DataConverter, int)`.
    pub fn read_next_value_with(&mut self, dc: &dyn DataConverter, len: usize) -> io::Result<i64> {
        let v = self.read_value_with(dc, self.current_index, len)?;
        self.current_index = self.current_index.wrapping_add(len as u64);
        Ok(v)
    }

    /// Reads an unsigned integer of `len` (0 to 8) bytes and advances by `len`. Mirrors
    /// `readNextUnsignedValue(int)`.
    pub fn read_next_unsigned_value(&mut self, len: usize) -> io::Result<u64> {
        self.read_next_unsigned_value_with(self.converter, len)
    }

    /// Mirrors `readNextUnsignedValue(DataConverter, int)`.
    pub fn read_next_unsigned_value_with(
        &mut self,
        dc: &dyn DataConverter,
        len: usize,
    ) -> io::Result<u64> {
        let v = self.read_unsigned_value_with(dc, self.current_index, len)?;
        self.current_index = self.current_index.wrapping_add(len as u64);
        Ok(v)
    }

    /// Reads an unsigned int32 and advances by four, returning it only if it fits in
    /// `0..=i32::MAX` (a positive Java `int`). The result is therefore always safe to cast to
    /// `i32` or use as an allocation size.
    ///
    /// Mirrors `readNextUnsignedIntExact()`.
    ///
    /// # Errors
    ///
    /// [`InvalidDataException`] if the read fails (carrying the read error as its source), or
    /// with `"Value out of range for positive java 32 bit unsigned int: <value>"` if the value
    /// exceeds `i32::MAX` (Java's `ensureInt32u`). The pointer has advanced in the latter case,
    /// as in Java.
    pub fn read_next_unsigned_int_exact(&mut self) -> Result<u32, InvalidDataException> {
        self.read_next_unsigned_int_exact_with(self.converter)
    }

    /// Mirrors `readNextUnsignedIntExact(DataConverter)`.
    pub fn read_next_unsigned_int_exact_with(
        &mut self,
        dc: &dyn DataConverter,
    ) -> Result<u32, InvalidDataException> {
        let v = self
            .read_next_unsigned_int_with(dc)
            .map_err(|e| InvalidDataException::with_message_and_source(e.to_string(), e))?;
        ensure_int32u(v as i64)?;
        Ok(v as u32)
    }

    /// Reads `n_elements` bytes and advances past them. Mirrors `readNextByteArray(int)`.
    pub fn read_next_byte_array(&mut self, n_elements: usize) -> io::Result<Vec<u8>> {
        let b = self.read_byte_array(self.current_index, n_elements)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_BYTE * n_elements as u64);
        Ok(b)
    }

    /// Reads `n_elements` shorts and advances past them. Mirrors `readNextShortArray(int)`.
    pub fn read_next_short_array(&mut self, n_elements: usize) -> io::Result<Vec<i16>> {
        let s = self.read_short_array(self.current_index, n_elements)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_SHORT * n_elements as u64);
        Ok(s)
    }

    /// Reads `n_elements` ints and advances past them. Mirrors `readNextIntArray(int)`.
    pub fn read_next_int_array(&mut self, n_elements: usize) -> io::Result<Vec<i32>> {
        let i = self.read_int_array(self.current_index, n_elements)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_INT * n_elements as u64);
        Ok(i)
    }

    /// Reads `n_elements` longs and advances past them. Mirrors `readNextLongArray(int)`.
    pub fn read_next_long_array(&mut self, n_elements: usize) -> io::Result<Vec<i64>> {
        let l = self.read_long_array(self.current_index, n_elements)?;
        self.current_index = self.current_index.wrapping_add(SIZEOF_LONG * n_elements as u64);
        Ok(l)
    }

    // ── strings (advancing) ──────────────────────────────────────────────────

    /// Reads a null-terminated US-ASCII string and advances past it and its terminator. Mirrors
    /// `readNextAsciiString()`.
    pub fn read_next_ascii_string(&mut self) -> io::Result<String> {
        self.read_next_string(Charset::UsAscii, 1)
    }

    /// Reads a fixed length US-ASCII string of `length` bytes (trailing nulls removed) and
    /// advances by `length`. Mirrors `readNextAsciiString(int)`.
    pub fn read_next_ascii_string_fixed(&mut self, length: usize) -> io::Result<String> {
        self.read_next_string_fixed(length, Charset::UsAscii, 1)
    }

    /// Reads a null-terminated UTF-16 string in this reader's endianness and advances past it
    /// and its terminator. Mirrors `readNextUnicodeString()`.
    pub fn read_next_unicode_string(&mut self) -> io::Result<String> {
        self.read_next_string(self.utf16_charset(), 2)
    }

    /// Reads a fixed length UTF-16 string of `char_count` 16-bit characters (trailing nulls
    /// removed) and advances by `char_count * 2`. Mirrors `readNextUnicodeString(int)`.
    pub fn read_next_unicode_string_fixed(&mut self, char_count: usize) -> io::Result<String> {
        self.read_next_string_fixed(char_count, self.utf16_charset(), 2)
    }

    /// Reads a null-terminated UTF-8 string and advances past it and its terminator. Mirrors
    /// `readNextUtf8String()`.
    pub fn read_next_utf8_string(&mut self) -> io::Result<String> {
        self.read_next_string(Charset::Utf8, 1)
    }

    /// Reads a fixed length UTF-8 string of `length` bytes (trailing nulls removed) and advances
    /// by `length`. Mirrors `readNextUtf8String(int)`.
    pub fn read_next_utf8_string_fixed(&mut self, length: usize) -> io::Result<String> {
        self.read_next_string_fixed(length, Charset::Utf8, 1)
    }

    /// Reads a null-terminated string of `char_len`-byte characters in `charset`, advancing past
    /// it and its terminator. Mirrors `readNextString(Charset, int)`.
    pub fn read_next_string(&mut self, charset: Charset, char_len: usize) -> io::Result<String> {
        let bytes = self.read_until_null_term(self.current_index, char_len)?;
        self.current_index =
            self.current_index.wrapping_add(bytes.len() as u64 + char_len as u64);
        Ok(charset.decode(&bytes))
    }

    /// Reads a fixed length string of `char_count` characters of `char_len` bytes each in
    /// `charset` (trailing nulls removed), advancing by `char_count * char_len`. Mirrors
    /// `readNextString(int, Charset, int)`.
    pub fn read_next_string_fixed(
        &mut self,
        char_count: usize,
        charset: Charset,
        char_len: usize,
    ) -> io::Result<String> {
        let bytes = self.read_byte_array(self.current_index, char_count * char_len)?;
        self.current_index = self.current_index.wrapping_add(bytes.len() as u64);
        let str_len = length_without_trailing_null_terms(&bytes, char_len);
        Ok(charset.decode(&bytes[..str_len]))
    }

    // ── strings (indexed) ────────────────────────────────────────────────────

    /// Reads a null-terminated US-ASCII string at `index`. Mirrors `readAsciiString(long)`.
    pub fn read_ascii_string(&self, index: u64) -> io::Result<String> {
        self.read_string(index, Charset::UsAscii, 1)
    }

    /// Reads a fixed length US-ASCII string of `length` bytes at `index`, trailing nulls
    /// removed. Mirrors `readAsciiString(long, int)`.
    pub fn read_ascii_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        self.read_string_fixed(index, length, Charset::UsAscii, 1)
    }

    /// Reads a null-terminated UTF-16 string at `index` in this reader's endianness. Mirrors
    /// `readUnicodeString(long)`.
    pub fn read_unicode_string(&self, index: u64) -> io::Result<String> {
        self.read_string(index, self.utf16_charset(), 2)
    }

    /// Reads a fixed length UTF-16 string of `char_count` characters at `index`, trailing nulls
    /// removed. Mirrors `readUnicodeString(long, int)`.
    pub fn read_unicode_string_fixed(&self, index: u64, char_count: usize) -> io::Result<String> {
        self.read_string_fixed(index, char_count, self.utf16_charset(), 2)
    }

    /// Reads a null-terminated UTF-8 string at `index`. Mirrors `readUtf8String(long)`.
    pub fn read_utf8_string(&self, index: u64) -> io::Result<String> {
        self.read_string(index, Charset::Utf8, 1)
    }

    /// Reads a fixed length UTF-8 string of `length` bytes at `index`, trailing nulls removed.
    /// Mirrors `readUtf8String(long, int)`.
    pub fn read_utf8_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        self.read_string_fixed(index, length, Charset::Utf8, 1)
    }

    /// Reads a fixed length string of `char_count` characters of `char_len` bytes each at
    /// `index`, trailing null characters removed. Mirrors `readString(long, int, Charset, int)`.
    pub fn read_string_fixed(
        &self,
        index: u64,
        char_count: usize,
        charset: Charset,
        char_len: usize,
    ) -> io::Result<String> {
        let bytes = self.read_byte_array(index, char_count * char_len)?;
        let str_len = length_without_trailing_null_terms(&bytes, char_len);
        Ok(charset.decode(&bytes[..str_len]))
    }

    /// Reads a null-terminated string of `char_len`-byte characters at `index`. Mirrors
    /// `readString(long, Charset, int)`.
    pub fn read_string(&self, index: u64, charset: Charset, char_len: usize) -> io::Result<String> {
        let bytes = self.read_until_null_term(index, char_len)?;
        Ok(charset.decode(&bytes))
    }

    /// Reads `char_len`-byte characters starting at `index` until an all-zero character, and
    /// returns the bytes before it.
    ///
    /// Mirrors the private `readUntilNullTerm(long, int)`, including its EOF reporting: failing
    /// on the very first character is `"Attempted to read string at 0x.."`, running out of data
    /// (or wrapping the 64-bit index) after that is `"Unterminated string at 0x..0x.."`, and
    /// exceeding `MAX_SANE_BUFFER` is `"Run-on unterminated string at 0x..0x.."`. All are
    /// [`io::ErrorKind::UnexpectedEof`] (Java's `EOFException`).
    pub fn read_until_null_term(&self, index: u64, char_len: usize) -> io::Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        let mut cur_pos = index;
        // loop while we haven't wrapped the index value around to 0
        while cur_pos >= index {
            if buf.len() as u64 + char_len as u64 >= MAX_SANE_BUFFER {
                // gracefully handle hitting the limit of the buffer before it fails
                return Err(eof(format!(
                    "Run-on unterminated string at 0x{index:x}..0x{cur_pos:x}"
                )));
            }
            match self.read_byte_array(cur_pos, char_len) {
                Ok(bytes) => {
                    if is_null_term(&bytes) {
                        return Ok(buf);
                    }
                    buf.extend_from_slice(&bytes);
                }
                Err(_) => {
                    if buf.is_empty() {
                        // failed trying to read the first byte
                        return Err(eof(format!("Attempted to read string at 0x{index:x}")));
                    }
                    break; // fall thru to report an unterminated string
                }
            }
            match cur_pos.checked_add(char_len as u64) {
                Some(next) => cur_pos = next,
                None => {
                    cur_pos = cur_pos.wrapping_add(char_len as u64);
                    break;
                }
            }
        }
        // we've wrapped around the end of a 64bit address space (or run out of data)
        Err(eof(format!("Unterminated string at 0x{index:x}..0x{cur_pos:x}")))
    }

    fn utf16_charset(&self) -> Charset {
        if self.is_big_endian() {
            Charset::Utf16Be
        } else {
            Charset::Utf16Le
        }
    }

    // ── indexed reads ────────────────────────────────────────────────────────

    /// Returns the byte at `index`. Mirrors `readByte(long)`.
    pub fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.read_byte(index)
    }

    /// Returns the unsigned byte at `index`. Mirrors `readUnsignedByte(long)`.
    pub fn read_unsigned_byte(&self, index: u64) -> io::Result<u16> {
        Ok(self.read_byte(index)? as u16)
    }

    /// Returns the short at `index`. Mirrors `readShort(long)`.
    pub fn read_short(&self, index: u64) -> io::Result<i16> {
        self.read_short_with(self.converter, index)
    }

    /// Returns the short at `index` decoded with `dc`. Mirrors `readShort(DataConverter, long)`.
    pub fn read_short_with(&self, dc: &dyn DataConverter, index: u64) -> io::Result<i16> {
        let bytes = self.read_exact(index, SIZEOF_SHORT)?;
        Ok(dc.get_short(&bytes))
    }

    /// Returns the unsigned short at `index`. Mirrors `readUnsignedShort(long)`.
    pub fn read_unsigned_short(&self, index: u64) -> io::Result<u32> {
        Ok(self.read_short(index)? as u16 as u32)
    }

    /// Mirrors `readUnsignedShort(DataConverter, long)`.
    pub fn read_unsigned_short_with(&self, dc: &dyn DataConverter, index: u64) -> io::Result<u32> {
        Ok(self.read_short_with(dc, index)? as u16 as u32)
    }

    /// Returns the int at `index`. Mirrors `readInt(long)`.
    pub fn read_int(&self, index: u64) -> io::Result<i32> {
        self.read_int_with(self.converter, index)
    }

    /// Returns the int at `index` decoded with `dc`. Mirrors `readInt(DataConverter, long)`.
    pub fn read_int_with(&self, dc: &dyn DataConverter, index: u64) -> io::Result<i32> {
        let bytes = self.read_exact(index, SIZEOF_INT)?;
        Ok(dc.get_int(&bytes))
    }

    /// Returns the unsigned int at `index`. Mirrors `readUnsignedInt(long)`.
    pub fn read_unsigned_int(&self, index: u64) -> io::Result<u64> {
        Ok(self.read_int(index)? as u32 as u64)
    }

    /// Mirrors `readUnsignedInt(DataConverter, long)`.
    pub fn read_unsigned_int_with(&self, dc: &dyn DataConverter, index: u64) -> io::Result<u64> {
        Ok(self.read_int_with(dc, index)? as u32 as u64)
    }

    /// Returns the long at `index`. Mirrors `readLong(long)`.
    pub fn read_long(&self, index: u64) -> io::Result<i64> {
        self.read_long_with(self.converter, index)
    }

    /// Returns the long at `index` decoded with `dc`. Mirrors `readLong(DataConverter, long)`.
    pub fn read_long_with(&self, dc: &dyn DataConverter, index: u64) -> io::Result<i64> {
        let bytes = self.read_exact(index, SIZEOF_LONG)?;
        Ok(dc.get_long(&bytes))
    }

    /// Returns the signed, sign-extended integer of `len` (0 to 8) bytes at `index`. Mirrors
    /// `readValue(long, int)`.
    pub fn read_value(&self, index: u64, len: usize) -> io::Result<i64> {
        self.read_value_with(self.converter, index, len)
    }

    /// Mirrors `readValue(DataConverter, long, int)`.
    ///
    /// # Errors
    ///
    /// An [`io::ErrorKind::InvalidInput`] error if `len` exceeds 8 (Java throws an unchecked
    /// `IndexOutOfBoundsException` from the converter), or the provider's read error.
    pub fn read_value_with(&self, dc: &dyn DataConverter, index: u64, len: usize) -> io::Result<i64> {
        check_value_len(len)?;
        let bytes = self.read_exact(index, len as u64)?;
        if len == 0 {
            return Ok(0);
        }
        Ok(dc.get_signed_value(&bytes, len))
    }

    /// Returns the unsigned integer of `len` (0 to 8) bytes at `index`. Mirrors
    /// `readUnsignedValue(long, int)`.
    pub fn read_unsigned_value(&self, index: u64, len: usize) -> io::Result<u64> {
        self.read_unsigned_value_with(self.converter, index, len)
    }

    /// Mirrors `readUnsignedValue(DataConverter, long, int)`. See
    /// [`read_value_with`](Self::read_value_with) for the errors.
    pub fn read_unsigned_value_with(
        &self,
        dc: &dyn DataConverter,
        index: u64,
        len: usize,
    ) -> io::Result<u64> {
        check_value_len(len)?;
        let bytes = self.read_exact(index, len as u64)?;
        Ok(dc.get_value(&bytes, len))
    }

    /// Returns `n_elements` bytes starting at `index`. Mirrors `readByteArray(long, int)`.
    pub fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        self.read_exact(index, n_elements as u64)
    }

    /// Returns `n_elements` shorts starting at `index`. Mirrors `readShortArray(long, int)`.
    pub fn read_short_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i16>> {
        (0..n_elements as u64)
            .map(|i| self.read_short(index.wrapping_add(i * SIZEOF_SHORT)))
            .collect()
    }

    /// Returns `n_elements` ints starting at `index`. Mirrors `readIntArray(long, int)`.
    pub fn read_int_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i32>> {
        (0..n_elements as u64)
            .map(|i| self.read_int(index.wrapping_add(i * SIZEOF_INT)))
            .collect()
    }

    /// Returns `n_elements` longs starting at `index`. Mirrors `readLongArray(long, int)`.
    pub fn read_long_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i64>> {
        (0..n_elements as u64)
            .map(|i| self.read_long(index.wrapping_add(i * SIZEOF_LONG)))
            .collect()
    }

    /// Reads `len` bytes at `index`, guaranteeing the result is exactly `len` long even if a
    /// provider returns a short read.
    fn read_exact(&self, index: u64, len: u64) -> io::Result<Vec<u8>> {
        let bytes = self.provider.read_bytes(index, len)?;
        if (bytes.len() as u64) < len {
            return Err(eof(format!(
                "Unable to read {len} bytes at 0x{index:x} (only {} available)",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    // ── reader functions ─────────────────────────────────────────────────────

    /// Reads an object from the current position using `func`, which should use the
    /// `read_next_*` methods to consume the bytes it reads. Mirrors
    /// `readNext(ReaderFunction<T>)`.
    pub fn read_next<T>(
        &mut self,
        func: impl FnOnce(&mut BinaryReader) -> io::Result<T>,
    ) -> io::Result<T> {
        func(self)
    }

    /// Reads an object from the current position by handing `func` a stream over this reader
    /// (see [`get_input_stream`](Self::get_input_stream)). Mirrors
    /// `readNext(InputStreamReaderFunction<T>)`.
    pub fn read_next_from_stream<T>(
        &mut self,
        func: impl FnOnce(&mut dyn Read) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut is = self.get_input_stream();
        func(&mut is)
    }

    /// Reads a variable length integer using `func` and returns it if it fits in a Java `int`.
    /// Mirrors `readNextVarInt(ReaderFunction<Long>)`.
    pub fn read_next_var_int(
        &mut self,
        func: impl FnOnce(&mut BinaryReader) -> io::Result<i64>,
    ) -> Result<i32, InvalidDataException> {
        let value = func(self).map_err(read_failed)?;
        ensure_int32s(value)?;
        Ok(value as i32)
    }

    /// Reads a variable length integer from a stream over this reader using `func` (e.g.
    /// `|mut is| Leb128::signed(&mut is)`) and returns it if it fits in a Java `int`. Mirrors
    /// `readNextVarInt(InputStreamReaderFunction<Long>)`.
    pub fn read_next_var_int_from_stream(
        &mut self,
        func: impl FnOnce(&mut dyn Read) -> io::Result<i64>,
    ) -> Result<i32, InvalidDataException> {
        let value = self.read_next_from_stream(func).map_err(read_failed)?;
        ensure_int32s(value)?;
        Ok(value as i32)
    }

    /// Reads a variable length unsigned integer using `func` and returns it if it fits in
    /// `0..=i32::MAX`. Mirrors `readNextUnsignedVarIntExact(ReaderFunction<Long>)`.
    pub fn read_next_unsigned_var_int_exact(
        &mut self,
        func: impl FnOnce(&mut BinaryReader) -> io::Result<i64>,
    ) -> Result<u32, InvalidDataException> {
        let value = func(self).map_err(read_failed)?;
        ensure_int32u(value)?;
        Ok(value as u32)
    }

    /// Reads a variable length unsigned integer from a stream over this reader using `func`
    /// (e.g. `|mut is| Leb128::unsigned(&mut is)`) and returns it if it fits in `0..=i32::MAX`. Mirrors
    /// `readNextUnsignedVarIntExact(InputStreamReaderFunction<Long>)`.
    pub fn read_next_unsigned_var_int_exact_from_stream(
        &mut self,
        func: impl FnOnce(&mut dyn Read) -> io::Result<i64>,
    ) -> Result<u32, InvalidDataException> {
        let value = self.read_next_from_stream(func).map_err(read_failed)?;
        ensure_int32u(value)?;
        Ok(value as u32)
    }
}

/// The character sets `BinaryReader`'s string methods decode with (the subset of
/// `java.nio.charset.StandardCharsets` the Java class uses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// `US_ASCII`: bytes above 0x7F decode to U+FFFD, as Java's decoder does.
    UsAscii,
    /// `UTF_8`, with malformed sequences replaced by U+FFFD.
    Utf8,
    /// `UTF_16LE`, with unpaired surrogates replaced by U+FFFD.
    Utf16Le,
    /// `UTF_16BE`, with unpaired surrogates replaced by U+FFFD.
    Utf16Be,
}

impl Charset {
    /// Decodes `bytes` the way `new String(bytes, charset)` does.
    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            Charset::UsAscii => bytes
                .iter()
                .map(|&b| if b < 0x80 { b as char } else { char::REPLACEMENT_CHARACTER })
                .collect(),
            Charset::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
            Charset::Utf16Le | Charset::Utf16Be => {
                let big = self == Charset::Utf16Be;
                let units: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|p| {
                        if big {
                            u16::from_be_bytes([p[0], p[1]])
                        } else {
                            u16::from_le_bytes([p[0], p[1]])
                        }
                    })
                    .collect();
                let mut s = String::from_utf16_lossy(&units);
                if bytes.len() % 2 != 0 {
                    // Java reports a trailing odd byte as a malformed character.
                    s.push(char::REPLACEMENT_CHARACTER);
                }
                s
            }
        }
    }
}

/// A [`Read`] stream over a [`BinaryReader`]'s current position; each byte read advances the
/// reader. End-of-stream is reported once the reader's index is no longer valid.
///
/// Mirrors the private `BinaryReader.BinaryReaderInputStream`.
pub struct BinaryReaderInputStream<'a> {
    reader: &'a mut BinaryReader,
}

impl Read for BinaryReaderInputStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;
        while n < buf.len() && self.reader.has_next() {
            buf[n] = self.reader.read_next_byte()?;
            n += 1;
        }
        Ok(n)
    }
}

fn eof(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

fn read_failed(e: io::Error) -> InvalidDataException {
    InvalidDataException::with_message_and_source(e.to_string(), e)
}

fn check_value_len(len: usize) -> io::Result<()> {
    if len > 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("size exceeds sizeof long: {len}"),
        ));
    }
    Ok(())
}

/// Java: `BinaryReader.ensureInt32u(long)`, which rejects values outside `0..=Integer.MAX_VALUE`
/// (reporting the value as unsigned).
fn ensure_int32u(value: i64) -> Result<(), InvalidDataException> {
    if !(0..=i32::MAX as i64).contains(&value) {
        return Err(InvalidDataException::with_message(format!(
            "Value out of range for positive java 32 bit unsigned int: {}",
            value as u64
        )));
    }
    Ok(())
}

/// Java: `BinaryReader.ensureInt32s(long)`.
fn ensure_int32s(value: i64) -> Result<(), InvalidDataException> {
    if !(i32::MIN as i64..=i32::MAX as i64).contains(&value) {
        return Err(InvalidDataException::with_message(format!(
            "Value out of range for java 32 bit signed int: {value}"
        )));
    }
    Ok(())
}

/// Java: `NumericUtilities.getUnsignedAlignedValue(long, long)`, evaluated with Java's signed
/// 64-bit arithmetic on the bit pattern of `unsigned_value`.
fn unsigned_aligned_value(unsigned_value: u64, alignment: u64) -> u64 {
    let alignment = alignment as i64;
    let mut value = unsigned_value as i64;
    if alignment == 0 || value.wrapping_rem(alignment) == 0 {
        return unsigned_value;
    }
    let negative = value < 0;
    if negative {
        value = value.wrapping_add(alignment).wrapping_neg();
    }
    let mut aligned = value
        .wrapping_add(alignment)
        .wrapping_sub(1)
        .wrapping_div(alignment)
        .wrapping_mul(alignment);
    if negative {
        aligned = aligned.wrapping_neg();
    }
    aligned as u64
}

fn is_null_term(chunk: &[u8]) -> bool {
    chunk.iter().all(|&b| b == 0)
}

/// Java: `getLengthWithoutTrailingNullTerms(byte[], int)`.
fn length_without_trailing_null_terms(bytes: &[u8], char_len: usize) -> usize {
    let char_len_i = char_len as isize;
    let mut term_pos = bytes.len() as isize - char_len_i;
    while term_pos >= 0 && is_null_term(&bytes[term_pos as usize..term_pos as usize + char_len]) {
        term_pos -= char_len_i;
    }
    (term_pos + char_len_i).max(0) as usize
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Transitional: the pre-port reader trait
// ════════════════════════════════════════════════════════════════════════════════════════════

/// The trait that stood in for `BinaryReader` before the concrete class was ported.
///
/// Being retired: consumers are migrating onto the [`BinaryReader`] struct module by module.
/// New code must take `&mut BinaryReader` instead. [`BinaryReader`] implements this trait so a
/// real reader can still be handed to a not-yet-migrated consumer.
pub trait LegacyBinaryReader {
    /// Returns the length of the underlying byte provider.
    fn length(&self) -> io::Result<u64>;

    /// Returns true if `index` is a valid position in the underlying byte provider.
    fn is_valid_index(&self, index: u64) -> bool;

    /// Returns the current index value.
    fn get_pointer_index(&self) -> u64;

    /// Sets the current index to `index`, returning the previous index value.
    fn set_pointer_index(&mut self, index: u64) -> u64;

    /// Returns true if this reader extracts values in little-endian order.
    fn is_little_endian(&self) -> bool;

    /// Sets the endianness used to extract values.
    fn set_little_endian(&mut self, is_little_endian: bool);

    /// Returns the BYTE at `index`. Does not affect the pointer index.
    fn read_byte(&self, index: u64) -> io::Result<u8>;

    /// Returns `n_elements` bytes starting at `index`. Does not affect the pointer index.
    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>>;

    /// Returns the underlying byte provider.
    fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>>;

    /// Returns an independent clone of this reader, sharing the same provider, positioned at
    /// `new_index`.
    fn clone_at(&self, new_index: u64) -> Box<dyn LegacyBinaryReader>;

    // ── default methods ──────────────────────────────────────────────────────

    /// Returns true if this reader extracts values in big-endian order.
    fn is_big_endian(&self) -> bool {
        !self.is_little_endian()
    }

    /// Returns an independent clone of this reader positioned at the same index.
    fn clone_reader(&self) -> Box<dyn LegacyBinaryReader> {
        self.clone_at(self.get_pointer_index())
    }

    /// Returns a clone of this reader forced into big-endian mode.
    fn as_big_endian(&self) -> Box<dyn LegacyBinaryReader> {
        let mut clone = self.clone_at(self.get_pointer_index());
        clone.set_little_endian(false);
        clone
    }

    /// Returns a clone of this reader forced into little-endian mode.
    fn as_little_endian(&self) -> Box<dyn LegacyBinaryReader> {
        let mut clone = self.clone_at(self.get_pointer_index());
        clone.set_little_endian(true);
        clone
    }

    /// Returns true if the range `[start_index, start_index + count)` is valid and does not wrap
    /// around the end of the index space.
    fn is_valid_range(&self, start_index: u64, count: usize) -> bool {
        if count == 0 {
            return true;
        }
        if start_index.checked_add((count - 1) as u64).is_none() {
            return false;
        }
        for i in 0..count as u64 {
            if !self.is_valid_index(start_index + i) {
                return false;
            }
        }
        true
    }

    /// Returns true if there is more data that could be read at the current position.
    fn has_next(&self) -> bool {
        self.is_valid_index(self.get_pointer_index())
    }

    /// Returns true if there are at least `count` more bytes that could be read at the current
    /// position.
    fn has_next_count(&self, count: usize) -> bool {
        self.is_valid_range(self.get_pointer_index(), count)
    }

    /// Advances the current index so that it aligns to `align_value` (if not already aligned).
    /// Returns the number of bytes required to align.
    fn align(&mut self, align_value: u64) -> u64 {
        let prev = self.get_pointer_index();
        let aligned = unsigned_aligned_value(prev, align_value);
        self.set_pointer_index(aligned);
        aligned.wrapping_sub(prev)
    }

    fn peek_next_byte(&self) -> io::Result<u8> {
        self.read_byte(self.get_pointer_index())
    }

    fn peek_next_short(&self) -> io::Result<i16> {
        self.read_short(self.get_pointer_index())
    }

    fn peek_next_int(&self) -> io::Result<i32> {
        self.read_int(self.get_pointer_index())
    }

    fn peek_next_long(&self) -> io::Result<i64> {
        self.read_long(self.get_pointer_index())
    }

    fn read_unsigned_byte(&self, index: u64) -> io::Result<u16> {
        Ok(self.read_byte(index)? as u16)
    }

    fn read_short(&self, index: u64) -> io::Result<i16> {
        let b = self.read_byte_array(index, 2)?;
        Ok(converter_for(!self.is_little_endian()).get_short(&b))
    }

    fn read_unsigned_short(&self, index: u64) -> io::Result<u32> {
        Ok(self.read_short(index)? as u16 as u32)
    }

    fn read_int(&self, index: u64) -> io::Result<i32> {
        let b = self.read_byte_array(index, 4)?;
        Ok(converter_for(!self.is_little_endian()).get_int(&b))
    }

    fn read_unsigned_int(&self, index: u64) -> io::Result<u64> {
        Ok(self.read_int(index)? as u32 as u64)
    }

    fn read_long(&self, index: u64) -> io::Result<i64> {
        let b = self.read_byte_array(index, 8)?;
        Ok(converter_for(!self.is_little_endian()).get_long(&b))
    }

    /// Returns the signed value of the integer (of the specified length, 0 to 8) at `index`,
    /// sign-extended into an `i64`.
    fn read_value(&self, index: u64, len: usize) -> io::Result<i64> {
        check_value_len(len)?;
        let b = self.read_byte_array(index, len)?;
        if len == 0 {
            return Ok(0);
        }
        Ok(converter_for(!self.is_little_endian()).get_signed_value(&b, len))
    }

    /// Returns the unsigned value of the integer (of the specified length, 0 to 8) at `index`.
    fn read_unsigned_value(&self, index: u64, len: usize) -> io::Result<u64> {
        check_value_len(len)?;
        let b = self.read_byte_array(index, len)?;
        Ok(converter_for(!self.is_little_endian()).get_value(&b, len))
    }

    fn read_short_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i16>> {
        (0..n_elements as u64).map(|i| self.read_short(index + i * SIZEOF_SHORT)).collect()
    }

    fn read_int_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i32>> {
        (0..n_elements as u64).map(|i| self.read_int(index + i * SIZEOF_INT)).collect()
    }

    fn read_long_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i64>> {
        (0..n_elements as u64).map(|i| self.read_long(index + i * SIZEOF_LONG)).collect()
    }

    /// Reads a null-terminated US-ASCII string starting at `index`.
    fn read_ascii_string(&self, index: u64) -> io::Result<String> {
        Ok(Charset::UsAscii.decode(&self.read_until_null_term(index, 1)?))
    }

    /// Reads a fixed length US-ASCII string of `length` bytes starting at `index`, trailing
    /// nulls removed.
    fn read_ascii_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        let bytes = self.read_byte_array(index, length)?;
        Ok(Charset::UsAscii.decode(&bytes[..length_without_trailing_null_terms(&bytes, 1)]))
    }

    /// Reads a null-terminated UTF-8 string starting at `index`.
    fn read_utf8_string(&self, index: u64) -> io::Result<String> {
        Ok(Charset::Utf8.decode(&self.read_until_null_term(index, 1)?))
    }

    /// Reads a fixed length UTF-8 string of `length` bytes starting at `index`, trailing nulls
    /// removed.
    fn read_utf8_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        let bytes = self.read_byte_array(index, length)?;
        Ok(Charset::Utf8.decode(&bytes[..length_without_trailing_null_terms(&bytes, 1)]))
    }

    /// Reads a null-terminated UTF-16 string starting at `index`, using this reader's endianness.
    fn read_unicode_string(&self, index: u64) -> io::Result<String> {
        let bytes = self.read_until_null_term(index, 2)?;
        Ok(legacy_utf16(self.is_little_endian()).decode(&bytes))
    }

    /// Reads a fixed length UTF-16 string of `char_count` characters starting at `index`,
    /// trailing null characters removed.
    fn read_unicode_string_fixed(&self, index: u64, char_count: usize) -> io::Result<String> {
        let bytes = self.read_byte_array(index, char_count * 2)?;
        let trimmed = &bytes[..length_without_trailing_null_terms(&bytes, 2)];
        Ok(legacy_utf16(self.is_little_endian()).decode(trimmed))
    }

    /// Reads bytes starting at `index` until a null terminator of `char_len` bytes is found (not
    /// included in the result). Same EOF reporting as [`BinaryReader::read_until_null_term`].
    fn read_until_null_term(&self, index: u64, char_len: usize) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut cur = index;
        loop {
            if buf.len() as u64 + char_len as u64 >= MAX_SANE_BUFFER {
                return Err(eof(format!("Run-on unterminated string at 0x{index:x}..0x{cur:x}")));
            }
            let chunk = match self.read_byte_array(cur, char_len) {
                Ok(chunk) => chunk,
                Err(_) if buf.is_empty() => {
                    return Err(eof(format!("Attempted to read string at 0x{index:x}")));
                }
                Err(_) => {
                    return Err(eof(format!("Unterminated string at 0x{index:x}..0x{cur:x}")));
                }
            };
            if is_null_term(&chunk) {
                return Ok(buf);
            }
            buf.extend_from_slice(&chunk);
            cur = match cur.checked_add(char_len as u64) {
                Some(next) => next,
                None => {
                    return Err(eof(format!(
                        "Unterminated string at 0x{index:x}..0x{:x}",
                        cur.wrapping_add(char_len as u64)
                    )));
                }
            };
        }
    }

    fn read_next_byte(&mut self) -> io::Result<u8> {
        let v = self.read_byte(self.get_pointer_index())?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + SIZEOF_BYTE);
        Ok(v)
    }

    fn read_next_unsigned_byte(&mut self) -> io::Result<u16> {
        Ok(self.read_next_byte()? as u16)
    }

    fn read_next_short(&mut self) -> io::Result<i16> {
        let v = self.read_short(self.get_pointer_index())?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + SIZEOF_SHORT);
        Ok(v)
    }

    fn read_next_unsigned_short(&mut self) -> io::Result<u32> {
        Ok(self.read_next_short()? as u16 as u32)
    }

    fn read_next_int(&mut self) -> io::Result<i32> {
        let v = self.read_int(self.get_pointer_index())?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + SIZEOF_INT);
        Ok(v)
    }

    fn read_next_unsigned_int(&mut self) -> io::Result<u64> {
        Ok(self.read_next_int()? as u32 as u64)
    }

    fn read_next_long(&mut self) -> io::Result<i64> {
        let v = self.read_long(self.get_pointer_index())?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + SIZEOF_LONG);
        Ok(v)
    }

    fn read_next_value(&mut self, len: usize) -> io::Result<i64> {
        let v = self.read_value(self.get_pointer_index(), len)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + len as u64);
        Ok(v)
    }

    fn read_next_unsigned_value(&mut self, len: usize) -> io::Result<u64> {
        let v = self.read_unsigned_value(self.get_pointer_index(), len)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + len as u64);
        Ok(v)
    }

    /// See [`BinaryReader::read_next_unsigned_int_exact`].
    fn read_next_unsigned_int_exact(&mut self) -> Result<u32, InvalidDataException> {
        let v = self
            .read_next_unsigned_int()
            .map_err(|e| InvalidDataException::with_message_and_source(e.to_string(), e))?;
        ensure_int32u(v as i64)?;
        Ok(v as u32)
    }

    fn read_next_byte_array(&mut self, n_elements: usize) -> io::Result<Vec<u8>> {
        let v = self.read_byte_array(self.get_pointer_index(), n_elements)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + (SIZEOF_BYTE * n_elements as u64));
        Ok(v)
    }

    fn read_next_short_array(&mut self, n_elements: usize) -> io::Result<Vec<i16>> {
        let v = self.read_short_array(self.get_pointer_index(), n_elements)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + (SIZEOF_SHORT * n_elements as u64));
        Ok(v)
    }

    fn read_next_int_array(&mut self, n_elements: usize) -> io::Result<Vec<i32>> {
        let v = self.read_int_array(self.get_pointer_index(), n_elements)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + (SIZEOF_INT * n_elements as u64));
        Ok(v)
    }

    fn read_next_long_array(&mut self, n_elements: usize) -> io::Result<Vec<i64>> {
        let v = self.read_long_array(self.get_pointer_index(), n_elements)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + (SIZEOF_LONG * n_elements as u64));
        Ok(v)
    }

    fn read_next_ascii_string(&mut self) -> io::Result<String> {
        let bytes = self.read_until_null_term(self.get_pointer_index(), 1)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + bytes.len() as u64 + 1);
        Ok(Charset::UsAscii.decode(&bytes))
    }

    fn read_next_ascii_string_fixed(&mut self, length: usize) -> io::Result<String> {
        let s = self.read_ascii_string_fixed(self.get_pointer_index(), length)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + length as u64);
        Ok(s)
    }

    fn read_next_utf8_string(&mut self) -> io::Result<String> {
        let bytes = self.read_until_null_term(self.get_pointer_index(), 1)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + bytes.len() as u64 + 1);
        Ok(Charset::Utf8.decode(&bytes))
    }

    fn read_next_utf8_string_fixed(&mut self, length: usize) -> io::Result<String> {
        let s = self.read_utf8_string_fixed(self.get_pointer_index(), length)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + length as u64);
        Ok(s)
    }

    fn read_next_unicode_string(&mut self) -> io::Result<String> {
        let bytes = self.read_until_null_term(self.get_pointer_index(), 2)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + bytes.len() as u64 + 2);
        Ok(legacy_utf16(self.is_little_endian()).decode(&bytes))
    }

    fn read_next_unicode_string_fixed(&mut self, char_count: usize) -> io::Result<String> {
        let s = self.read_unicode_string_fixed(self.get_pointer_index(), char_count)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + (char_count as u64 * 2));
        Ok(s)
    }

    /// Reads an object from the current position using `func`. Mirrors
    /// `BinaryReader.readNext(ReaderFunction<T>)`.
    fn read_next<T>(&mut self, func: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T>
    where
        Self: Sized,
    {
        func(self)
    }

    /// Mirrors `BinaryReader.readNextVarInt(ReaderFunction<Long>)`.
    fn read_next_var_int(
        &mut self,
        func: impl FnOnce(&mut Self) -> io::Result<i64>,
    ) -> Result<i32, InvalidDataException>
    where
        Self: Sized,
    {
        let value = func(self).map_err(read_failed)?;
        ensure_int32s(value)?;
        Ok(value as i32)
    }

    /// Mirrors `BinaryReader.readNextUnsignedVarIntExact(ReaderFunction<Long>)`.
    fn read_next_unsigned_var_int_exact(
        &mut self,
        func: impl FnOnce(&mut Self) -> io::Result<i64>,
    ) -> Result<u32, InvalidDataException>
    where
        Self: Sized,
    {
        let value = func(self).map_err(read_failed)?;
        ensure_int32u(value)?;
        Ok(value as u32)
    }
}

fn legacy_utf16(little_endian: bool) -> Charset {
    if little_endian {
        Charset::Utf16Le
    } else {
        Charset::Utf16Be
    }
}

/// Read-only [`GByteStore`] view of a [`ByteProvider`], so the real reader can satisfy
/// [`LegacyBinaryReader::get_byte_provider`] while that trait is being retired.
struct ProviderByteStore(Rc<dyn ByteProvider>);

impl GByteStore for ProviderByteStore {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.0.length())
    }
    fn is_valid_index(&mut self, index: u64) -> bool {
        self.0.is_valid_index(index)
    }
    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        self.0.read_byte(index)
    }
    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        self.0.read_bytes(index, length as u64)
    }
    fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ByteProvider is read-only"))
    }
    fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ByteProvider is read-only"))
    }
    fn get_file(&self) -> Option<std::path::PathBuf> {
        self.0.get_file()
    }
}

impl LegacyBinaryReader for BinaryReader {
    fn length(&self) -> io::Result<u64> {
        BinaryReader::length(self)
    }
    fn is_valid_index(&self, index: u64) -> bool {
        BinaryReader::is_valid_index(self, index)
    }
    fn get_pointer_index(&self) -> u64 {
        self.current_index
    }
    fn set_pointer_index(&mut self, index: u64) -> u64 {
        BinaryReader::set_pointer_index(self, index)
    }
    fn is_little_endian(&self) -> bool {
        BinaryReader::is_little_endian(self)
    }
    fn set_little_endian(&mut self, is_little_endian: bool) {
        BinaryReader::set_little_endian(self, is_little_endian)
    }
    fn read_byte(&self, index: u64) -> io::Result<u8> {
        BinaryReader::read_byte(self, index)
    }
    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
        BinaryReader::read_byte_array(self, index, n_elements)
    }
    fn get_byte_provider(&self) -> Rc<RefCell<dyn GByteStore>> {
        Rc::new(RefCell::new(ProviderByteStore(Rc::clone(&self.provider))))
    }
    fn clone_at(&self, new_index: u64) -> Box<dyn LegacyBinaryReader> {
        Box::new(BinaryReader::clone_at(self, new_index))
    }
    fn is_valid_range(&self, start_index: u64, count: usize) -> bool {
        BinaryReader::is_valid_range(self, start_index, count)
    }
    fn align(&mut self, align_value: u64) -> u64 {
        BinaryReader::align(self, align_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::leb128::Leb128;
    use crate::util::big_endian_data_converter;

    /// Java test helper `br(boolean isLE, int... values)`.
    fn br(is_le: bool, values: &[i32]) -> BinaryReader {
        let bytes: Vec<u8> = values.iter().map(|&v| v as u8).collect();
        BinaryReader::from_bytes(bytes, is_le)
    }

    fn assert_eof<T: fmt::Debug>(r: io::Result<T>) {
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_clone() {
        let mut reader = BinaryReader::from_bytes(vec![0u8; 1024], true);
        reader.set_pointer_index(0x100);
        let reader_clone = reader.clone_at(0x200);
        assert_eq!(reader.get_pointer_index(), 0x100);
        assert_eq!(reader_clone.get_pointer_index(), 0x200);
        assert!(reader_clone.is_little_endian());
        assert!(Rc::ptr_eq(reader.get_byte_provider(), reader_clone.get_byte_provider()));
    }

    #[test]
    fn as_big_endian_and_as_little_endian_keep_index_and_provider() {
        let mut r = br(true, &[0, 0, 0, 1, 1, 0, 0, 0]);
        r.set_pointer_index(4);
        let be = r.as_big_endian();
        assert!(be.is_big_endian() && !be.is_little_endian());
        assert_eq!(be.get_pointer_index(), 4);
        assert_eq!(be.read_int(0).unwrap(), 1);
        let le = be.as_little_endian();
        assert!(le.is_little_endian());
        assert_eq!(le.read_int(4).unwrap(), 1);
        // the original is unchanged
        assert!(r.is_little_endian());
        r.set_little_endian(false);
        assert_eq!(r.read_int(0).unwrap(), 1);
    }

    #[test]
    fn test_read_byte() {
        let r = br(true, &[1, 2, 127, 255, 0]);
        assert_eq!(r.read_byte(0).unwrap(), 1);
        assert_eq!(r.read_byte(1).unwrap(), 2);
        assert_eq!(r.read_byte(2).unwrap(), 127);
        assert_eq!(r.read_byte(3).unwrap() as i8, -1);
        assert_eq!(r.read_byte(4).unwrap(), 0);
        assert!(r.read_byte(5).is_err());
        assert_eq!(r.read_unsigned_byte(3).unwrap(), 255);
        assert!(r.read_unsigned_byte(5).is_err());
    }

    #[test]
    fn test_read_next_byte_and_unsigned_byte() {
        let mut r = br(true, &[1, 2, 127, 255, 0]);
        assert_eq!(r.read_next_byte().unwrap(), 1);
        assert_eq!(r.read_next_byte().unwrap(), 2);
        assert_eq!(r.read_next_byte().unwrap(), 127);
        assert_eq!(r.read_next_byte().unwrap() as i8, -1);
        assert_eq!(r.read_next_byte().unwrap(), 0);
        assert!(r.read_next_byte().is_err());
        // a failed read does not advance
        assert_eq!(r.get_pointer_index(), 5);

        let mut r = br(true, &[1, 2, 127, 255, 0]);
        let got: Vec<u16> = (0..5).map(|_| r.read_next_unsigned_byte().unwrap()).collect();
        assert_eq!(got, vec![1, 2, 127, 255, 0]);
        assert!(r.read_next_unsigned_byte().is_err());
    }

    #[test]
    fn test_read_short_le() {
        let r = br(true, &[1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80]);
        assert_eq!(r.read_short(0).unwrap(), 1);
        assert_eq!(r.read_short(2).unwrap(), i16::MAX);
        assert_eq!(r.read_short(4).unwrap(), -1);
        assert_eq!(r.read_short(6).unwrap(), i16::MIN);
        assert!(r.read_short(8).is_err());
        assert_eq!(r.read_unsigned_short(2).unwrap(), 0x7fff);
        assert_eq!(r.read_unsigned_short(4).unwrap(), 0xffff);
        assert_eq!(r.read_unsigned_short(6).unwrap(), 0x8000);
        assert!(r.read_unsigned_short(8).is_err());
    }

    #[test]
    fn test_read_next_short_le_and_be() {
        let mut r = br(true, &[1, 0, 0xff, 0x7f, 0xff, 0xff, 0x00, 0x80]);
        assert_eq!(r.read_next_short().unwrap(), 1);
        assert_eq!(r.read_next_short().unwrap(), i16::MAX);
        assert_eq!(r.read_next_short().unwrap(), -1);
        assert_eq!(r.read_next_short().unwrap(), i16::MIN);
        assert!(r.read_next_short().is_err());

        let mut r = br(false, &[0, 1, 0x7f, 0xff, 0xff, 0xff, 0x80, 0x00]);
        assert_eq!(r.read_next_unsigned_short().unwrap(), 1);
        assert_eq!(r.read_next_unsigned_short().unwrap(), 0x7fff);
        assert_eq!(r.read_next_unsigned_short().unwrap(), 0xffff);
        assert_eq!(r.read_next_unsigned_short().unwrap(), 0x8000);
        assert!(r.read_next_unsigned_short().is_err());
    }

    #[test]
    fn test_read_int_and_unsigned_int() {
        let data = [1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0x80];
        let r = br(true, &data);
        assert_eq!(r.read_int(0).unwrap(), 1);
        assert_eq!(r.read_int(4).unwrap(), i32::MAX);
        assert_eq!(r.read_int(8).unwrap(), -1);
        assert_eq!(r.read_int(12).unwrap(), i32::MIN);
        assert!(r.read_int(16).is_err());
        assert_eq!(r.read_unsigned_int(8).unwrap(), 0xffff_ffff);
        assert_eq!(r.read_unsigned_int(12).unwrap(), i32::MAX as u64 + 1);

        let mut r = br(true, &data);
        assert_eq!(r.read_next_unsigned_int().unwrap(), 1);
        assert_eq!(r.read_next_unsigned_int().unwrap(), i32::MAX as u64);
        assert_eq!(r.read_next_unsigned_int().unwrap(), 0xffff_ffff);
        assert_eq!(r.read_next_unsigned_int().unwrap(), 0x8000_0000);
        assert!(r.read_next_unsigned_int().is_err());
    }

    #[test]
    fn test_read_long_both_endians() {
        let r = br(true, &[1, 2, 3, 4, 5, 6, 7, 0x88]);
        assert_eq!(r.read_long(0).unwrap(), 0x8807_0605_0403_0201u64 as i64);
        let r = br(false, &[1, 2, 3, 4, 5, 6, 7, 0x88]);
        assert_eq!(r.read_long(0).unwrap(), 0x0102_0304_0506_0788);
        let mut r = br(false, &[0, 0, 0, 0, 0, 0, 0, 1, 9]);
        assert_eq!(r.peek_next_long().unwrap(), 1);
        assert_eq!(r.read_next_long().unwrap(), 1);
        assert_eq!(r.get_pointer_index(), 8);
        assert!(r.read_next_long().is_err());
    }

    #[test]
    fn data_converter_overloads_override_reader_endianness() {
        let mut r = br(true, &[0, 0, 0, 2, 0, 3]);
        let be = &big_endian_data_converter::INSTANCE;
        assert_eq!(r.read_int_with(be, 0).unwrap(), 2);
        assert_eq!(r.read_next_int_with(be).unwrap(), 2);
        assert_eq!(r.read_next_short_with(be).unwrap(), 3);
        assert!(r.is_little_endian());
    }

    #[test]
    fn test_uint32_max() {
        let mut r = br(true, &[0xff, 0xff, 0xff, 0x7f, 0xff]);
        assert_eq!(r.read_next_unsigned_int_exact().unwrap(), i32::MAX as u32);
    }

    #[test]
    fn test_uint32_overflow() {
        let mut r = br(true, &[0xff, 0xff, 0xff, 0xff, 0xff]);
        let err = r.read_next_unsigned_int_exact().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Value out of range for positive java 32 bit unsigned int: 4294967295"
        );
        // InvalidDataException is an IOException in Java
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let mut r = br(false, &[0x80, 0, 0, 0]);
        assert_eq!(
            r.read_next_unsigned_int_exact().unwrap_err().to_string(),
            "Value out of range for positive java 32 bit unsigned int: 2147483648"
        );
    }

    #[test]
    fn read_next_unsigned_int_exact_keeps_the_read_error() {
        let mut r = br(false, &[0, 0]);
        let err = r.read_next_unsigned_int_exact().unwrap_err();
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn read_value_sign_and_zero_extends() {
        let r = br(false, &[0xff, 0xfe, 0x01]);
        assert_eq!(r.read_value(0, 2).unwrap(), -2);
        assert_eq!(r.read_unsigned_value(0, 2).unwrap(), 0xfffe);
        assert_eq!(r.read_value(1, 2).unwrap(), -511); // 0xfe01
        assert_eq!(r.read_value(0, 0).unwrap(), 0);
        let r = br(true, &[0xfe, 0xff, 0x01]);
        assert_eq!(r.read_value(0, 2).unwrap(), -2);
        assert_eq!(r.read_unsigned_value(0, 3).unwrap(), 0x01fffe);
        assert_eq!(r.read_value(0, 9).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        let mut r = br(true, &[0xfe, 0xff, 0x01]);
        assert_eq!(r.read_next_value(1).unwrap(), -2);
        assert_eq!(r.read_next_unsigned_value(2).unwrap(), 0x01ff);
        assert_eq!(r.get_pointer_index(), 3);
    }

    #[test]
    fn arrays_read_and_advance() {
        let mut r = br(false, &[0, 1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4]);
        assert_eq!(r.read_short_array(0, 2).unwrap(), vec![1, 2]);
        assert_eq!(r.read_int_array(4, 2).unwrap(), vec![3, 4]);
        assert_eq!(r.read_long_array(4, 1).unwrap(), vec![0x0000_0003_0000_0004]);
        assert_eq!(r.read_next_short_array(2).unwrap(), vec![1, 2]);
        assert_eq!(r.read_next_int_array(2).unwrap(), vec![3, 4]);
        assert_eq!(r.get_pointer_index(), 12);
        r.set_pointer_index(0);
        assert_eq!(r.read_next_byte_array(3).unwrap(), vec![0, 1, 0]);
        assert_eq!(r.get_pointer_index(), 3);
        assert!(r.read_next_long_array(2).is_err());
        assert_eq!(r.read_byte_array(0, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn has_next_and_valid_range() {
        let mut r = br(true, &[1, 2, 3, 4]);
        assert!(r.has_next());
        assert!(r.has_next_count(4));
        assert!(!r.has_next_count(5));
        assert!(r.has_next_count(0));
        assert!(r.is_valid_range(3, 1));
        assert!(!r.is_valid_range(3, 2));
        assert!(!r.is_valid_range(u64::MAX, 2)); // wraps
        r.set_pointer_index(4);
        assert!(!r.has_next());
        assert_eq!(r.length().unwrap(), 4);
    }

    #[test]
    fn align_matches_numeric_utilities() {
        let mut r = br(true, &[0; 32]);
        r.set_pointer_index(3);
        assert_eq!(r.align(4), 1);
        assert_eq!(r.get_pointer_index(), 4);
        assert_eq!(r.align(4), 0);
        assert_eq!(r.align(0), 0);
        r.set_pointer_index(9);
        assert_eq!(r.align(8), 7);
        assert_eq!(r.get_pointer_index(), 16);
        assert_eq!(unsigned_aligned_value(0x11, 0x10), 0x20);
    }

    #[test]
    fn set_pointer_index_returns_old() {
        let mut r = br(true, &[0; 4]);
        assert_eq!(r.set_pointer_index(3), 0);
        assert_eq!(r.set_pointer_index(1), 3);
    }

    // ── UTF-16 (Java test cases) ─────────────────────────────────────────────

    const A: i32 = b'A' as i32;
    const B: i32 = b'B' as i32;
    const C: i32 = b'C' as i32;

    #[test]
    fn test_read_unicode_string_fixedlen() {
        let r = br(true, &[1, 1, 1, A, 0, B, 0, C, 0, 0, 0x80, 0]);
        assert_eq!(r.read_unicode_string_fixed(3, 4).unwrap(), "ABC\u{8000}");
        let r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C, 0x80, 0, 0]);
        assert_eq!(r.read_unicode_string_fixed(3, 4).unwrap(), "ABC\u{8000}");
    }

    #[test]
    fn test_read_unicode_string_nullterm() {
        let r = br(true, &[1, 1, 1, A, 0, B, 0, C, 0, 0, 0x80, 0, 0]);
        assert_eq!(r.read_unicode_string(3).unwrap(), "ABC\u{8000}");
        let r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C, 0x80, 0, 0, 0]);
        assert_eq!(r.read_unicode_string(3).unwrap(), "ABC\u{8000}");
        let r = br(false, &[1, 1, 1, 0, 0, 0, B, 0, C, 0x80, 0, 0, 0]);
        assert_eq!(r.read_unicode_string(3).unwrap(), "");
    }

    #[test]
    fn test_read_unicode_string_eof_cases() {
        let r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C]);
        let err = r.read_unicode_string(3).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "Unterminated string at 0x3..0x9");
        assert_eof(r.read_unicode_string(9));
        let err = r.read_unicode_string(10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(err.to_string(), "Attempted to read string at 0xa");
        // missing full terminator
        let r = br(false, &[0, A, 0, B, 0, C, 0]);
        assert_eof(r.read_unicode_string(0));
    }

    #[test]
    fn test_read_next_unicode_string() {
        let mut r = br(true, &[1, 1, 1, A, 0, B, 0, C, 0, 0, 0x80, 0, 0, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string().unwrap(), "ABC\u{8000}");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C, 0x80, 0, 0, 0, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string().unwrap(), "ABC\u{8000}");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C, 0, b' ' as i32, 0, 0, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string().unwrap(), "ABC ");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(false, &[1, 1, 1, 0, 0, 0, B, 0, C, 0, 0, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string().unwrap(), "");
        assert_eq!(r.read_next_unicode_string().unwrap(), "BC");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);
    }

    #[test]
    fn test_read_next_unicode_string_fixedlen() {
        let mut r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C, 0, b' ' as i32, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string_fixed(4).unwrap(), "ABC ");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(false, &[1, 1, 1, 0, A, 0, B, 0, C, 0, 0, 0, 0, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string_fixed(5).unwrap(), "ABC");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(false, &[1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42]);
        r.set_pointer_index(3);
        assert_eq!(r.read_next_unicode_string_fixed(5).unwrap(), "");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);
    }

    #[test]
    fn test_read_next_unicode_string_at_and_to_eof() {
        let mut r = br(false, &[0, A, 0, B, 0, C, 0, 0]);
        assert_eq!(r.read_next_unicode_string().unwrap(), "ABC");
        assert!(r.read_next_unicode_string().is_err());
        let mut r = br(false, &[0, A, 0, B, 0, C]);
        assert_eof(r.read_next_unicode_string());
        assert_eq!(r.get_pointer_index(), 0);
    }

    // ── ASCII / UTF-8 (Java test cases) ──────────────────────────────────────

    #[test]
    fn test_read_ascii_string() {
        let r = br(true, &[A, B, C, 0, 42]);
        assert_eq!(r.read_ascii_string(0).unwrap(), "ABC");
        let r = br(true, &[A, B, C]);
        assert_eof(r.read_ascii_string(0));
        assert_eof(r.read_ascii_string(3));
        assert_eof(r.read_ascii_string(4));
        let r = br(true, &[b' ' as i32, A, B, C, b' ' as i32, 0, 42]);
        assert_eq!(r.read_ascii_string(0).unwrap(), " ABC ");
        let r = br(true, &[A, B, C, b'\t' as i32, b'D' as i32, b'E' as i32, b'F' as i32, 0, 42]);
        assert_eq!(r.read_ascii_string(0).unwrap(), "ABC\tDEF");
    }

    #[test]
    fn ascii_decoding_replaces_high_bytes_like_java() {
        let r = br(true, &[A, 0xe9, 0]);
        assert_eq!(r.read_ascii_string(0).unwrap(), "A\u{fffd}");
    }

    #[test]
    fn test_read_next_ascii_string() {
        let mut r = br(true, &[b' ' as i32, A, B, C, b' ' as i32, 0, 42]);
        assert_eq!(r.read_next_ascii_string().unwrap(), " ABC ");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(true, &[b' ' as i32, A, B, C, b' ' as i32, 0, 42]);
        r.set_pointer_index(5);
        assert_eq!(r.read_next_ascii_string().unwrap(), "");
        assert_eq!(r.read_next_unsigned_byte().unwrap(), 42);

        let mut r = br(true, &[A, B, C, 0]);
        assert_eq!(r.read_next_ascii_string().unwrap(), "ABC");
        assert!(r.read_next_ascii_string().is_err());
    }

    #[test]
    fn test_read_next_ascii_string_fixed_length() {
        let (d, e, f) = (b'D' as i32, b'E' as i32, b'F' as i32);
        let mut r = br(true, &[A, B, C, d, e, f, 0, 42]);
        assert_eq!(r.read_next_ascii_string_fixed(3).unwrap(), "ABC");
        assert_eq!(r.read_next_ascii_string_fixed(4).unwrap(), "DEF");
        assert_eq!(r.read_next_byte().unwrap(), 42);

        let mut r = br(true, &[A, B, b' ' as i32, 0, d, e, f, 0, 42]);
        assert_eq!(r.read_next_ascii_string_fixed(4).unwrap(), "AB ");
        assert_eq!(r.read_next_ascii_string().unwrap(), "DEF");
        assert_eq!(r.read_next_byte().unwrap(), 42);

        let mut r = br(true, &[0, 0, 0, d, e, f, 0, 42]);
        assert_eq!(r.read_next_ascii_string_fixed(3).unwrap(), "");
        assert_eq!(r.read_next_ascii_string().unwrap(), "DEF");
        assert_eq!(r.read_next_byte().unwrap(), 42);
        assert_eq!(r.read_ascii_string_fixed(0, 3).unwrap(), "");
    }

    #[test]
    fn test_read_utf8_string() {
        let r = br(true, &[-22, -87, -107, -61, -65, 0]);
        assert_eq!(r.read_utf8_string(0).unwrap(), "\u{aa55}\u{00ff}");
        let mut r = br(true, &[-22, -87, -107, -61, -65, 0, -22, -87, -107, 0]);
        assert_eq!(r.read_next_utf8_string().unwrap(), "\u{aa55}\u{00ff}");
        assert_eq!(r.read_next_utf8_string().unwrap(), "\u{aa55}");
        // bad data -> replacement char
        let r = br(true, &[-22, -87, A, 0]);
        assert_eq!(r.read_utf8_string(0).unwrap(), "\u{fffd}A");
        let mut r = br(true, &[A, B, 0, 0, C]);
        assert_eq!(r.read_next_utf8_string_fixed(4).unwrap(), "AB");
        assert_eq!(r.get_pointer_index(), 4);
        assert_eq!(r.read_utf8_string_fixed(0, 2).unwrap(), "AB");
    }

    // ── streams / reader functions / LEB128 ──────────────────────────────────

    #[test]
    fn input_stream_advances_reader_and_stops_at_end() {
        let mut r = br(true, &[1, 2, 3]);
        r.set_pointer_index(1);
        let mut buf = Vec::new();
        r.get_input_stream().read_to_end(&mut buf).unwrap();
        assert_eq!(buf, vec![2, 3]);
        assert_eq!(r.get_pointer_index(), 3);
    }

    #[test]
    fn uleb128_via_stream_function() {
        // 624485 = 0xE5 0x8E 0x26 (DWARF spec example)
        let mut r = br(true, &[0xe5, 0x8e, 0x26, 0x7f]);
        let v = r.read_next_unsigned_var_int_exact_from_stream(|mut is| Leb128::unsigned(&mut is)).unwrap();
        assert_eq!(v, 624485);
        assert_eq!(r.get_pointer_index(), 3);
        // single byte 0x7f unsigned is 127
        assert_eq!(r.read_next_var_int_from_stream(|mut is| Leb128::unsigned(&mut is)).unwrap(), 127);
    }

    #[test]
    fn sleb128_via_stream_function() {
        // -123456 = 0xC0 0xBB 0x78; 0x7f signed is -1; 0x80 0x7f is -128
        let mut r = br(true, &[0xc0, 0xbb, 0x78, 0x7f, 0x80, 0x7f]);
        assert_eq!(r.read_next_var_int_from_stream(|mut is| Leb128::signed(&mut is)).unwrap(), -123456);
        assert_eq!(r.read_next_var_int_from_stream(|mut is| Leb128::signed(&mut is)).unwrap(), -1);
        assert_eq!(r.read_next_var_int_from_stream(|mut is| Leb128::signed(&mut is)).unwrap(), -128);
        assert_eq!(r.get_pointer_index(), 6);
    }

    #[test]
    fn leb128_range_checks() {
        // 2^31 unsigned: 0x80 0x80 0x80 0x80 0x08
        let mut r = br(true, &[0x80, 0x80, 0x80, 0x80, 0x08]);
        let err = r
            .read_next_unsigned_var_int_exact_from_stream(|mut is| Leb128::unsigned(&mut is))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Value out of range for positive java 32 bit unsigned int: 2147483648"
        );
        // -1 is not an unsigned int32
        let mut r = br(true, &[0x7f]);
        let err =
            r.read_next_unsigned_var_int_exact_from_stream(|mut is| Leb128::signed(&mut is)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Value out of range for positive java 32 bit unsigned int: 18446744073709551615"
        );
        let mut r = br(true, &[0x80, 0x80, 0x80, 0x80, 0x08]);
        let err = r.read_next_var_int_from_stream(|mut is| Leb128::unsigned(&mut is)).unwrap_err();
        assert_eq!(err.to_string(), "Value out of range for java 32 bit signed int: 2147483648");
        // truncated LEB128 -> read error
        let mut r = br(true, &[0x80]);
        assert!(r.read_next_var_int_from_stream(|mut is| Leb128::unsigned(&mut is)).is_err());
    }

    #[test]
    fn reader_functions() {
        let mut r = br(false, &[0, 5, 0, 0, 0, 7]);
        let v = r.read_next(|rd| Ok(rd.read_next_short()? as i32 * 2)).unwrap();
        assert_eq!(v, 10);
        assert_eq!(r.read_next_var_int(|rd| Ok(rd.read_next_int()? as i64)).unwrap(), 7);
        let mut r = br(false, &[]);
        assert!(r.read_next_var_int(|_| Ok(i64::from(i32::MAX) + 1)).is_err());
        assert_eq!(r.read_next_unsigned_var_int_exact(|_| Ok(42)).unwrap(), 42);
        assert!(r.read_next_unsigned_var_int_exact(|_| Ok(-1)).is_err());
        let v = r.read_next_from_stream(|is| {
            let mut b = Vec::new();
            is.read_to_end(&mut b)?;
            Ok(b.len())
        });
        assert_eq!(v.unwrap(), 0);
    }

    // ── legacy trait bridge ──────────────────────────────────────────────────

    fn legacy_int(r: &mut dyn LegacyBinaryReader) -> io::Result<i32> {
        r.read_next_int()
    }

    #[test]
    fn struct_satisfies_legacy_trait() {
        let mut r = br(false, &[0, 0, 0, 9, A, 0]);
        assert_eq!(legacy_int(&mut r).unwrap(), 9);
        assert_eq!(r.get_pointer_index(), 4);
        let legacy: &dyn LegacyBinaryReader = &r;
        assert_eq!(legacy.read_ascii_string(4).unwrap(), "A");
        let store = legacy.get_byte_provider();
        assert_eq!(store.borrow_mut().length().unwrap(), 6);
        assert!(store.borrow_mut().write_byte(0, 1).is_err());
        let mut clone = legacy.clone_at(0);
        assert!(clone.is_big_endian());
        assert_eq!(clone.read_next_int().unwrap(), 9);
    }
}
