use std::cell::RefCell;
use std::io;
use std::rc::Rc;

use crate::app::util::bin::invalid_data_exception::InvalidDataException;
use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

/// The size of a BYTE, in bytes.
pub const SIZEOF_BYTE: u64 = 1;
/// The size of a SHORT, in bytes.
pub const SIZEOF_SHORT: u64 = 2;
/// The size of an INTEGER, in bytes.
pub const SIZEOF_INT: u64 = 4;
/// The size of a LONG, in bytes.
pub const SIZEOF_LONG: u64 = 8;

const MAX_SANE_BUFFER: usize = usize::MAX - 1024;

/// Reads typed values from a generic byte provider in either big-endian or little-endian order,
/// maintaining a current position that the `read_next_*` methods advance automatically.
///
/// Mirrors `ghidra.app.util.bin.BinaryReader` from the original Ghidra source. The original is a
/// concrete class; it is ported here as a trait so that other seams can depend on the reader's
/// behavior without depending on a specific concrete implementation (breaking the dependency
/// cycle between `BinaryReader` and its many consumers/producers).
///
/// Implementors need only supply the small set of required methods below; every other
/// `BinaryReader` method (peeking, `read_next_*`, string decoding, arrays, ...) is provided as a
/// default method built on top of them.
pub trait BinaryReader {
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

    /// Returns the signed BYTE at `index`. Does not affect [`get_pointer_index`](Self::get_pointer_index).
    fn read_byte(&self, index: u64) -> io::Result<u8>;

    /// Returns `n_elements` bytes starting at `index`. Does not affect
    /// [`get_pointer_index`](Self::get_pointer_index).
    fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>>;

    /// Returns the underlying byte provider.
    fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>>;

    /// Returns an independent clone of this reader, sharing the same provider, positioned at
    /// `new_index`.
    fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader>;

    // ── default methods ──────────────────────────────────────────────────────

    /// Returns true if this reader extracts values in big-endian order.
    fn is_big_endian(&self) -> bool {
        !self.is_little_endian()
    }

    /// Returns an independent clone of this reader positioned at the same index.
    fn clone_reader(&self) -> Box<dyn BinaryReader> {
        self.clone_at(self.get_pointer_index())
    }

    /// Returns a clone of this reader forced into big-endian mode.
    fn as_big_endian(&self) -> Box<dyn BinaryReader> {
        let mut clone = self.clone_at(self.get_pointer_index());
        clone.set_little_endian(false);
        clone
    }

    /// Returns a clone of this reader forced into little-endian mode.
    fn as_little_endian(&self) -> Box<dyn BinaryReader> {
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
        // Ensure the range doesn't wrap around the end of the u64 index space.
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
        let rem = prev % align_value;
        if rem == 0 {
            return 0;
        }
        let aligned = prev + (align_value - rem);
        self.set_pointer_index(aligned);
        aligned - prev
    }

    // ── peek (non-advancing) ──────────────────────────────────────────────────

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

    // ── indexed reads ─────────────────────────────────────────────────────────

    fn read_unsigned_byte(&self, index: u64) -> io::Result<u16> {
        Ok(self.read_byte(index)? as u16)
    }

    fn read_short(&self, index: u64) -> io::Result<i16> {
        let b = self.read_byte_array(index, 2)?;
        Ok(if self.is_little_endian() {
            i16::from_le_bytes([b[0], b[1]])
        } else {
            i16::from_be_bytes([b[0], b[1]])
        })
    }

    fn read_unsigned_short(&self, index: u64) -> io::Result<u32> {
        Ok(self.read_short(index)? as u16 as u32)
    }

    fn read_int(&self, index: u64) -> io::Result<i32> {
        let b = self.read_byte_array(index, 4)?;
        Ok(if self.is_little_endian() {
            i32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            i32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    }

    fn read_unsigned_int(&self, index: u64) -> io::Result<u64> {
        Ok(self.read_int(index)? as u32 as u64)
    }

    fn read_long(&self, index: u64) -> io::Result<i64> {
        let b = self.read_byte_array(index, 8)?;
        Ok(if self.is_little_endian() {
            i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        })
    }

    /// Returns the signed value of the integer (of the specified length, 1 to 8) at `index`,
    /// sign-extended into an `i64`.
    fn read_value(&self, index: u64, len: usize) -> io::Result<i64> {
        if len == 0 {
            return Ok(0);
        }
        let b = self.read_byte_array(index, len)?;
        let mut ordered = b;
        if self.is_little_endian() {
            ordered.reverse();
        }
        let mut value: i64 = if ordered[0] & 0x80 != 0 { -1 } else { 0 };
        for byte in ordered {
            value = (value << 8) | (byte as i64);
        }
        Ok(value)
    }

    /// Returns the unsigned value of the integer (of the specified length, 1 to 8) at `index`.
    fn read_unsigned_value(&self, index: u64, len: usize) -> io::Result<u64> {
        if len == 0 {
            return Ok(0);
        }
        let b = self.read_byte_array(index, len)?;
        let mut ordered = b;
        if self.is_little_endian() {
            ordered.reverse();
        }
        let mut value: u64 = 0;
        for byte in ordered {
            value = (value << 8) | (byte as u64);
        }
        Ok(value)
    }

    fn read_short_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i16>> {
        let mut arr = Vec::with_capacity(n_elements);
        let mut idx = index;
        for _ in 0..n_elements {
            arr.push(self.read_short(idx)?);
            idx += SIZEOF_SHORT;
        }
        Ok(arr)
    }

    fn read_int_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i32>> {
        let mut arr = Vec::with_capacity(n_elements);
        let mut idx = index;
        for _ in 0..n_elements {
            arr.push(self.read_int(idx)?);
            idx += SIZEOF_INT;
        }
        Ok(arr)
    }

    fn read_long_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<i64>> {
        let mut arr = Vec::with_capacity(n_elements);
        let mut idx = index;
        for _ in 0..n_elements {
            arr.push(self.read_long(idx)?);
            idx += SIZEOF_LONG;
        }
        Ok(arr)
    }

    // ── strings (indexed) ────────────────────────────────────────────────────

    /// Reads a null-terminated US-ASCII string starting at `index`.
    fn read_ascii_string(&self, index: u64) -> io::Result<String> {
        let bytes = self.read_until_null_term(index, 1)?;
        Ok(bytes.iter().map(|&b| b as char).collect())
    }

    /// Reads a fixed length US-ASCII string of `length` bytes starting at `index`. Trailing null
    /// terminator bytes are removed.
    fn read_ascii_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        let bytes = self.read_byte_array(index, length)?;
        let trimmed = &bytes[..length_without_trailing_null_terms(&bytes, 1)];
        Ok(trimmed.iter().map(|&b| b as char).collect())
    }

    /// Reads a null-terminated UTF-8 string starting at `index`.
    fn read_utf8_string(&self, index: u64) -> io::Result<String> {
        let bytes = self.read_until_null_term(index, 1)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Reads a fixed length UTF-8 string of `length` bytes starting at `index`. Trailing null
    /// terminator bytes are removed.
    fn read_utf8_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        let bytes = self.read_byte_array(index, length)?;
        let trimmed = &bytes[..length_without_trailing_null_terms(&bytes, 1)];
        Ok(String::from_utf8_lossy(trimmed).into_owned())
    }

    /// Reads a null-terminated UTF-16 string starting at `index`, using this reader's endianness.
    fn read_unicode_string(&self, index: u64) -> io::Result<String> {
        let bytes = self.read_until_null_term(index, 2)?;
        Ok(decode_utf16(&bytes, self.is_little_endian()))
    }

    /// Reads a fixed length UTF-16 string of `char_count` characters starting at `index`.
    /// Trailing null terminator characters are removed.
    fn read_unicode_string_fixed(&self, index: u64, char_count: usize) -> io::Result<String> {
        let bytes = self.read_byte_array(index, char_count * 2)?;
        let trimmed = &bytes[..length_without_trailing_null_terms(&bytes, 2)];
        Ok(decode_utf16(trimmed, self.is_little_endian()))
    }

    /// Reads bytes starting at `index` until a null terminator of `char_len` bytes is found (not
    /// included in the result).
    fn read_until_null_term(&self, index: u64, char_len: usize) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut cur = index;
        loop {
            if buf.len() + char_len >= MAX_SANE_BUFFER {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("Run-on unterminated string at {index:#x}..{cur:#x}"),
                ));
            }
            let chunk = self.read_byte_array(cur, char_len)?;
            cur += char_len as u64;
            if is_null_term(&chunk) {
                return Ok(buf);
            }
            buf.extend_from_slice(&chunk);
        }
    }

    // ── readNext (advancing) ─────────────────────────────────────────────────

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

    /// Reads an unsigned int32 value, returning it as a `u32` only if it fits (which it always
    /// does; mirrors `readNextUnsignedIntExact`, whose Java `InvalidDataException` case cannot
    /// occur once the value is represented as an unsigned Rust integer).
    fn read_next_unsigned_int_exact(&mut self) -> Result<u32, InvalidDataException> {
        let v = self
            .read_next_unsigned_int()
            .map_err(InvalidDataException::with_source)?;
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

    // ── strings (advancing) ──────────────────────────────────────────────────

    fn read_next_ascii_string(&mut self) -> io::Result<String> {
        let bytes = self.read_until_null_term(self.get_pointer_index(), 1)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + bytes.len() as u64 + 1);
        Ok(bytes.iter().map(|&b| b as char).collect())
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
        Ok(String::from_utf8_lossy(&bytes).into_owned())
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
        Ok(decode_utf16(&bytes, self.is_little_endian()))
    }

    fn read_next_unicode_string_fixed(&mut self, char_count: usize) -> io::Result<String> {
        let s = self.read_unicode_string_fixed(self.get_pointer_index(), char_count)?;
        let idx = self.get_pointer_index();
        self.set_pointer_index(idx + (char_count as u64 * 2));
        Ok(s)
    }

    // ── generic reader-function helpers (not object-safe: require `Self: Sized`) ────

    /// Reads an object from the current position using `func`. Mirrors
    /// `BinaryReader.readNext(ReaderFunction<T>)`.
    fn read_next<T>(&mut self, func: impl FnOnce(&mut Self) -> io::Result<T>) -> io::Result<T>
    where
        Self: Sized,
    {
        func(self)
    }

    /// Reads a variable length integer from the current position using `func`, returning it (if
    /// it fits) as a signed 32 bit integer. Mirrors `BinaryReader.readNextVarInt(ReaderFunction<Long>)`.
    fn read_next_var_int(
        &mut self,
        func: impl FnOnce(&mut Self) -> io::Result<i64>,
    ) -> Result<i32, InvalidDataException>
    where
        Self: Sized,
    {
        let value = func(self).map_err(InvalidDataException::with_source)?;
        if !(i32::MIN as i64..=i32::MAX as i64).contains(&value) {
            return Err(InvalidDataException::with_message(format!(
                "Value out of range for java 32 bit signed int: {value}"
            )));
        }
        Ok(value as i32)
    }

    /// Reads a variable length unsigned integer from the current position using `func`, returning
    /// it (if it fits) as an unsigned 32 bit integer. Mirrors
    /// `BinaryReader.readNextUnsignedVarIntExact(ReaderFunction<Long>)`.
    fn read_next_unsigned_var_int_exact(
        &mut self,
        func: impl FnOnce(&mut Self) -> io::Result<i64>,
    ) -> Result<u32, InvalidDataException>
    where
        Self: Sized,
    {
        let value = func(self).map_err(InvalidDataException::with_source)?;
        if !(0..=i32::MAX as i64).contains(&value) {
            return Err(InvalidDataException::with_message(format!(
                "Value out of range for positive java 32 bit unsigned int: {value}"
            )));
        }
        Ok(value as u32)
    }
}

fn is_null_term(chunk: &[u8]) -> bool {
    chunk.iter().all(|&b| b == 0)
}

fn length_without_trailing_null_terms(bytes: &[u8], char_len: usize) -> usize {
    let char_len_i = char_len as isize;
    let mut term_pos = bytes.len() as isize - char_len_i;
    while term_pos >= 0 && is_null_term(&bytes[term_pos as usize..term_pos as usize + char_len]) {
        term_pos -= char_len_i;
    }
    (term_pos + char_len_i).max(0) as usize
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    /// Minimal in-memory [`ByteProvider`] used only to back the mock reader below.
    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "eof"))
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, _index: u64, _value: u8) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
        fn write_bytes(&mut self, _index: u64, _values: &[u8]) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "read-only"))
        }
    }

    /// A trivial mock [`BinaryReader`] impl, proving the trait is object-safe (usable behind
    /// `Box<dyn BinaryReader>`) and usable via its default methods.
    struct MockReader {
        provider: Rc<RefCell<dyn ByteProvider>>,
        little_endian: bool,
        current_index: u64,
    }

    impl MockReader {
        fn new(data: Vec<u8>, little_endian: bool) -> Self {
            MockReader {
                provider: Rc::new(RefCell::new(VecProvider(data))),
                little_endian,
                current_index: 0,
            }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            self.provider.borrow_mut().length()
        }
        fn is_valid_index(&self, index: u64) -> bool {
            self.provider.borrow_mut().is_valid_index(index)
        }
        fn get_pointer_index(&self) -> u64 {
            self.current_index
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.current_index;
            self.current_index = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            self.little_endian
        }
        fn set_little_endian(&mut self, is_little_endian: bool) {
            self.little_endian = is_little_endian;
        }
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.provider.borrow_mut().read_byte(index)
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            self.provider.borrow_mut().read_bytes(index, n_elements)
        }
        fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
            Rc::clone(&self.provider)
        }
        fn clone_at(&self, new_index: u64) -> Box<dyn BinaryReader> {
            Box::new(MockReader {
                provider: Rc::clone(&self.provider),
                little_endian: self.little_endian,
                current_index: new_index,
            })
        }
    }

    fn boxed_reader(data: Vec<u8>, little_endian: bool) -> Box<dyn BinaryReader> {
        Box::new(MockReader::new(data, little_endian))
    }

    #[test]
    fn object_safe_read_next_int_advances_pointer() {
        let mut r = boxed_reader(vec![0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00], true);
        assert_eq!(r.read_next_int().unwrap(), 1);
        assert_eq!(r.get_pointer_index(), 4);
        assert_eq!(r.read_next_int().unwrap(), 2);
        assert_eq!(r.get_pointer_index(), 8);
    }

    #[test]
    fn peek_does_not_advance() {
        let r = boxed_reader(vec![0xAB, 0xCD], false);
        assert_eq!(r.peek_next_byte().unwrap(), 0xAB);
        assert_eq!(r.get_pointer_index(), 0);
    }

    #[test]
    fn clone_at_is_independent() {
        let r = boxed_reader(vec![1, 2, 3, 4], false);
        let mut clone = r.clone_at(2);
        assert_eq!(clone.read_next_byte().unwrap(), 3);
        assert_eq!(r.get_pointer_index(), 0);
    }

    #[test]
    fn as_big_endian_and_little_endian_round_trip() {
        let r = boxed_reader(vec![0, 0, 0, 1], true);
        assert!(r.is_little_endian());
        let be = r.as_big_endian();
        assert!(be.is_big_endian());
        let le = be.as_little_endian();
        assert!(le.is_little_endian());
    }

    #[test]
    fn read_next_ascii_string_stops_at_null() {
        let mut r = boxed_reader(b"hi\0bye\0".to_vec(), false);
        assert_eq!(r.read_next_ascii_string().unwrap(), "hi");
        assert_eq!(r.get_pointer_index(), 3);
        assert_eq!(r.read_next_ascii_string().unwrap(), "bye");
        assert_eq!(r.get_pointer_index(), 7);
    }

    #[test]
    fn read_ascii_string_fixed_trims_trailing_nulls() {
        let r = boxed_reader(b"AB\0\0".to_vec(), false);
        assert_eq!(r.read_ascii_string_fixed(0, 4).unwrap(), "AB");
    }

    #[test]
    fn read_next_unicode_string_decodes_utf16() {
        let mut data = vec![b'A', 0x00, b'B', 0x00, 0x00, 0x00];
        data.extend_from_slice(b"tail");
        let mut r = boxed_reader(data, true);
        assert_eq!(r.read_next_unicode_string().unwrap(), "AB");
        assert_eq!(r.get_pointer_index(), 6);
    }

    #[test]
    fn read_next_utf8_string_decodes() {
        let mut r = boxed_reader(b"caf\xc3\xa9\0".to_vec(), false);
        assert_eq!(r.read_next_utf8_string().unwrap(), "caf\u{e9}");
    }

    #[test]
    fn has_next_reflects_bounds() {
        let mut r = boxed_reader(vec![1, 2], false);
        assert!(r.has_next());
        r.set_pointer_index(2);
        assert!(!r.has_next());
    }

    #[test]
    fn align_advances_to_next_boundary() {
        let mut r = boxed_reader(vec![0u8; 32], false);
        r.set_pointer_index(3);
        assert_eq!(r.align(4), 1);
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn read_value_sign_extends() {
        let r = boxed_reader(vec![0xFF, 0xFF], false);
        assert_eq!(r.read_value(0, 2).unwrap(), -1i64);
    }

    #[test]
    fn read_unsigned_value_zero_extends() {
        let r = boxed_reader(vec![0xFF, 0xFF], false);
        assert_eq!(r.read_unsigned_value(0, 2).unwrap(), 0xFFFF);
    }

    #[test]
    fn read_next_int_array_advances_by_all_elements() {
        let mut r = boxed_reader(vec![0, 0, 0, 1, 0, 0, 0, 2], false);
        assert_eq!(r.read_next_int_array(2).unwrap(), vec![1, 2]);
        assert_eq!(r.get_pointer_index(), 8);
    }

    #[test]
    fn read_next_unsigned_int_exact_succeeds() {
        let mut r = boxed_reader(vec![0, 0, 0, 1], false);
        assert_eq!(r.read_next_unsigned_int_exact().unwrap(), 1u32);
    }

    // ── generic helpers require a concrete (Sized) reader, not the trait object ─────

    #[test]
    fn read_next_with_closure_reads_and_advances() {
        let mut r = MockReader::new(vec![0x01, 0x02, 0x03], false);
        let v = r.read_next(|reader| reader.read_next_byte()).unwrap();
        assert_eq!(v, 0x01);
        assert_eq!(r.get_pointer_index(), 1);
    }

    #[test]
    fn read_next_var_int_rejects_out_of_range() {
        let mut r = MockReader::new(vec![], false);
        let err = r
            .read_next_var_int(|_| Ok(i64::from(i32::MAX) + 1))
            .unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn read_next_unsigned_var_int_exact_accepts_in_range() {
        let mut r = MockReader::new(vec![], false);
        let v = r.read_next_unsigned_var_int_exact(|_| Ok(42)).unwrap();
        assert_eq!(v, 42u32);
    }
}
