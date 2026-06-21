use std::cell::RefCell;
use std::io;
use std::rc::Rc;

/// Abstracts seekable, index-addressed byte storage consumed by [`GBinaryReader`].
///
/// Implementors provide random-access reads and writes by absolute byte index.
/// Because most concrete providers (e.g. file-backed ones) mutate internal seek
/// position on every access, all methods take `&mut self`.
pub trait ByteProvider {
    fn length(&mut self) -> io::Result<u64>;
    fn is_valid_index(&mut self, index: u64) -> bool;
    fn read_byte(&mut self, index: u64) -> io::Result<u8>;
    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>>;
    fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()>;
    fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()>;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Endian {
    Little,
    Big,
}

/// Reads and writes typed values from a [`ByteProvider`] in a chosen byte order.
///
/// The reader maintains a current index that `readNext*` methods advance
/// automatically.  The `clone_at` method creates a second reader sharing the
/// same provider but starting at a different position.
pub struct GBinaryReader {
    provider: Rc<RefCell<dyn ByteProvider>>,
    endian: Endian,
    current_index: u64,
}

impl GBinaryReader {
    pub const SIZEOF_BYTE: u64 = 1;
    pub const SIZEOF_SHORT: u64 = 2;
    pub const SIZEOF_INT: u64 = 4;
    pub const SIZEOF_LONG: u64 = 8;

    /// Creates a reader over `provider` in the specified byte order.
    pub fn new(provider: Rc<RefCell<dyn ByteProvider>>, is_little_endian: bool) -> Self {
        GBinaryReader {
            provider,
            endian: if is_little_endian { Endian::Little } else { Endian::Big },
            current_index: 0,
        }
    }

    /// Returns a reader sharing the same provider, positioned at `new_index`.
    pub fn clone_at(&self, new_index: u64) -> Self {
        GBinaryReader {
            provider: Rc::clone(&self.provider),
            endian: self.endian,
            current_index: new_index,
        }
    }

    pub fn is_little_endian(&self) -> bool {
        self.endian == Endian::Little
    }

    pub fn set_little_endian(&mut self, is_little_endian: bool) {
        self.endian = if is_little_endian { Endian::Little } else { Endian::Big };
    }

    pub fn length(&self) -> io::Result<u64> {
        self.provider.borrow_mut().length()
    }

    /// `isValidIndex(int)` — reinterprets the signed Java `int` as an unsigned
    /// 32-bit value before checking (mirrors `index & GConv.INT_MASK` in Java).
    pub fn is_valid_index_int(&self, index: i32) -> bool {
        self.provider.borrow_mut().is_valid_index(index as u32 as u64)
    }

    pub fn is_valid_index(&self, index: u64) -> bool {
        self.provider.borrow_mut().is_valid_index(index)
    }

    /// Advances the current index to the next multiple of `align_value`.
    /// Returns the number of bytes skipped (0 if already aligned).
    pub fn align(&mut self, align_value: u64) -> u64 {
        let rem = self.current_index % align_value;
        if rem == 0 {
            return 0;
        }
        let skip = align_value - rem;
        self.current_index += skip;
        skip
    }

    /// `setPointerIndex(int)` — zero-extends the Java signed int to `u64`.
    pub fn set_pointer_index_int(&mut self, index: i32) {
        self.current_index = index as u32 as u64;
    }

    pub fn set_pointer_index(&mut self, index: u64) {
        self.current_index = index;
    }

    pub fn get_pointer_index(&self) -> u64 {
        self.current_index
    }

    // ── peek (non-advancing) ─────────────────────────────────────────────────

    pub fn peek_next_byte(&self) -> io::Result<u8> {
        self.read_byte(self.current_index)
    }

    pub fn peek_next_short(&self) -> io::Result<i16> {
        self.read_short(self.current_index)
    }

    pub fn peek_next_int(&self) -> io::Result<i32> {
        self.read_int(self.current_index)
    }

    pub fn peek_next_long(&self) -> io::Result<i64> {
        self.read_long(self.current_index)
    }

    // ── readNext (advancing) ─────────────────────────────────────────────────

    pub fn read_next_byte(&mut self) -> io::Result<u8> {
        let v = self.read_byte(self.current_index)?;
        self.current_index += Self::SIZEOF_BYTE;
        Ok(v)
    }

    pub fn read_next_byte_clamped(&mut self, min: u8, max: u8, exceptions: &[u8]) -> io::Result<u8> {
        let v = self.read_byte_clamped(self.current_index, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_BYTE;
        Ok(v)
    }

    pub fn read_next_short(&mut self) -> io::Result<i16> {
        let v = self.read_short(self.current_index)?;
        self.current_index += Self::SIZEOF_SHORT;
        Ok(v)
    }

    pub fn read_next_short_clamped(&mut self, min: i16, max: i16, exceptions: &[i16]) -> io::Result<i16> {
        let v = self.read_short_clamped(self.current_index, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_SHORT;
        Ok(v)
    }

    pub fn read_next_int(&mut self) -> io::Result<i32> {
        let v = self.read_int(self.current_index)?;
        self.current_index += Self::SIZEOF_INT;
        Ok(v)
    }

    pub fn read_next_int_clamped(&mut self, min: i32, max: i32, exceptions: &[i32]) -> io::Result<i32> {
        let v = self.read_int_clamped(self.current_index, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_INT;
        Ok(v)
    }

    pub fn read_next_long(&mut self) -> io::Result<i64> {
        let v = self.read_long(self.current_index)?;
        self.current_index += Self::SIZEOF_LONG;
        Ok(v)
    }

    pub fn read_next_long_clamped(&mut self, min: i64, max: i64, exceptions: &[i64]) -> io::Result<i64> {
        let v = self.read_long_clamped(self.current_index, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_LONG;
        Ok(v)
    }

    pub fn read_next_ascii_string(&mut self) -> io::Result<String> {
        let s = self.read_ascii_string(self.current_index)?;
        self.current_index += s.len() as u64 + 1;
        Ok(s)
    }

    pub fn read_next_ascii_string_fixed(&mut self, length: u64) -> io::Result<String> {
        let s = self.read_ascii_string_fixed(self.current_index, length as usize)?;
        self.current_index += length;
        Ok(s)
    }

    pub fn read_next_unicode_string(&mut self) -> io::Result<String> {
        let s = self.read_unicode_string(self.current_index)?;
        self.current_index += (s.len() as u64 + 1) * 2;
        Ok(s)
    }

    pub fn read_next_unicode_string_fixed(&mut self, length: u64) -> io::Result<String> {
        let s = self.read_unicode_string_fixed(self.current_index, length as usize)?;
        self.current_index += length * 2;
        Ok(s)
    }

    pub fn read_next_byte_array(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let v = self.read_byte_array(self.current_index, n)?;
        self.current_index += n as u64;
        Ok(v)
    }

    pub fn read_next_byte_array_clamped(&mut self, n: usize, min: u8, max: u8, exceptions: &[u8]) -> io::Result<Vec<u8>> {
        let v = self.read_byte_array_clamped(self.current_index, n, min, max, exceptions)?;
        self.current_index += n as u64;
        Ok(v)
    }

    pub fn read_next_short_array(&mut self, n: usize) -> io::Result<Vec<i16>> {
        let v = self.read_short_array(self.current_index, n)?;
        self.current_index += Self::SIZEOF_SHORT * n as u64;
        Ok(v)
    }

    pub fn read_next_short_array_clamped(&mut self, n: usize, min: i16, max: i16, exceptions: &[i16]) -> io::Result<Vec<i16>> {
        let v = self.read_short_array_clamped(self.current_index, n, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_SHORT * n as u64;
        Ok(v)
    }

    pub fn read_next_int_array(&mut self, n: usize) -> io::Result<Vec<i32>> {
        let v = self.read_int_array(self.current_index, n)?;
        self.current_index += Self::SIZEOF_INT * n as u64;
        Ok(v)
    }

    pub fn read_next_int_array_clamped(&mut self, n: usize, min: i32, max: i32, exceptions: &[i32]) -> io::Result<Vec<i32>> {
        let v = self.read_int_array_clamped(self.current_index, n, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_INT * n as u64;
        Ok(v)
    }

    pub fn read_next_long_array(&mut self, n: usize) -> io::Result<Vec<i64>> {
        let v = self.read_long_array(self.current_index, n)?;
        self.current_index += Self::SIZEOF_LONG * n as u64;
        Ok(v)
    }

    pub fn read_next_long_array_clamped(&mut self, n: usize, min: i64, max: i64, exceptions: &[i64]) -> io::Result<Vec<i64>> {
        let v = self.read_long_array_clamped(self.current_index, n, min, max, exceptions)?;
        self.current_index += Self::SIZEOF_LONG * n as u64;
        Ok(v)
    }

    // ── indexed reads ─────────────────────────────────────────────────────────

    /// Reads printable ASCII bytes (0x20–0x7E) until a non-printable byte or EOF.
    /// Returns the trimmed string (mirrors Java `readAsciiString(long)`).
    pub fn read_ascii_string(&self, index: u64) -> io::Result<String> {
        let mut buf = String::new();
        let mut i = index;
        loop {
            let b = self.provider.borrow_mut().read_byte(i)?;
            i += 1;
            if (32..=126).contains(&b) {
                buf.push(b as char);
            } else {
                break;
            }
        }
        Ok(buf.trim().to_string())
    }

    /// Reads exactly `length` bytes as Latin-1 characters, trimmed.
    pub fn read_ascii_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        let mut buf = String::new();
        let mut i = index;
        for _ in 0..length {
            let b = self.provider.borrow_mut().read_byte(i)?;
            i += 1;
            buf.push(b as char);
        }
        Ok(buf.trim().to_string())
    }

    /// Reads a double-null-terminated UTF-16LE string.
    /// Stops when a 0x0000 code unit is found or all provider bytes are exhausted.
    pub fn read_unicode_string(&self, index: u64) -> io::Result<String> {
        let total = self.length()?;
        let mut buf = String::new();
        let mut i = index;
        let mut bytes_seen: u64 = 0;
        while bytes_seen < total {
            let lo = self.provider.borrow_mut().read_byte(i)? as u16;
            i += 1;
            let hi = self.provider.borrow_mut().read_byte(i)? as u16;
            i += 1;
            let code_unit = lo | (hi << 8);
            if code_unit == 0 {
                break;
            }
            buf.push(char::from_u32(code_unit as u32).unwrap_or(char::REPLACEMENT_CHARACTER));
            bytes_seen += 2;
        }
        Ok(buf.trim().to_string())
    }

    /// Reads `length` UTF-16LE code units, ignoring null terminators, trimmed.
    pub fn read_unicode_string_fixed(&self, index: u64, length: usize) -> io::Result<String> {
        let mut buf = String::new();
        let mut i = index;
        for _ in 0..length {
            let lo = self.provider.borrow_mut().read_byte(i)? as u16;
            i += 1;
            let hi = self.provider.borrow_mut().read_byte(i)? as u16;
            i += 1;
            let code_unit = lo | (hi << 8);
            buf.push(char::from_u32(code_unit as u32).unwrap_or(char::REPLACEMENT_CHARACTER));
        }
        Ok(buf.trim().to_string())
    }

    pub fn read_byte(&self, index: u64) -> io::Result<u8> {
        self.provider.borrow_mut().read_byte(index)
    }

    pub fn read_byte_clamped(&self, index: u64, min: u8, max: u8, exceptions: &[u8]) -> io::Result<u8> {
        let b = self.read_byte(index)?;
        Ok(Self::clamp_byte(b, min, max, exceptions))
    }

    pub fn read_short(&self, index: u64) -> io::Result<i16> {
        let b = self.provider.borrow_mut().read_bytes(index, 2)?;
        Ok(match self.endian {
            Endian::Little => i16::from_le_bytes([b[0], b[1]]),
            Endian::Big => i16::from_be_bytes([b[0], b[1]]),
        })
    }

    pub fn read_short_clamped(&self, index: u64, min: i16, max: i16, exceptions: &[i16]) -> io::Result<i16> {
        let s = self.read_short(index)?;
        Ok(Self::clamp_short(s, min, max, exceptions))
    }

    pub fn read_int(&self, index: u64) -> io::Result<i32> {
        let b = self.provider.borrow_mut().read_bytes(index, 4)?;
        Ok(match self.endian {
            Endian::Little => i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endian::Big => i32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        })
    }

    pub fn read_int_clamped(&self, index: u64, min: i32, max: i32, exceptions: &[i32]) -> io::Result<i32> {
        let i = self.read_int(index)?;
        Ok(Self::clamp_int(i, min, max, exceptions))
    }

    pub fn read_long(&self, index: u64) -> io::Result<i64> {
        let b = self.provider.borrow_mut().read_bytes(index, 8)?;
        Ok(match self.endian {
            Endian::Little => i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            Endian::Big => i64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        })
    }

    pub fn read_long_clamped(&self, index: u64, min: i64, max: i64, exceptions: &[i64]) -> io::Result<i64> {
        let l = self.read_long(index)?;
        Ok(Self::clamp_long(l, min, max, exceptions))
    }

    pub fn read_byte_array(&self, index: u64, n: usize) -> io::Result<Vec<u8>> {
        self.provider.borrow_mut().read_bytes(index, n)
    }

    pub fn read_byte_array_clamped(&self, index: u64, n: usize, min: u8, max: u8, exceptions: &[u8]) -> io::Result<Vec<u8>> {
        let mut arr = self.read_byte_array(index, n)?;
        for b in &mut arr {
            *b = Self::clamp_byte(*b, min, max, exceptions);
        }
        Ok(arr)
    }

    pub fn read_short_array(&self, index: u64, n: usize) -> io::Result<Vec<i16>> {
        let mut arr = Vec::with_capacity(n);
        let mut idx = index;
        for _ in 0..n {
            arr.push(self.read_short(idx)?);
            idx += Self::SIZEOF_SHORT;
        }
        Ok(arr)
    }

    pub fn read_short_array_clamped(&self, index: u64, n: usize, min: i16, max: i16, exceptions: &[i16]) -> io::Result<Vec<i16>> {
        let mut arr = self.read_short_array(index, n)?;
        for s in &mut arr {
            *s = Self::clamp_short(*s, min, max, exceptions);
        }
        Ok(arr)
    }

    pub fn read_int_array(&self, index: u64, n: usize) -> io::Result<Vec<i32>> {
        let mut arr = Vec::with_capacity(n);
        let mut idx = index;
        for _ in 0..n {
            arr.push(self.read_int(idx)?);
            idx += Self::SIZEOF_INT;
        }
        Ok(arr)
    }

    pub fn read_int_array_clamped(&self, index: u64, n: usize, min: i32, max: i32, exceptions: &[i32]) -> io::Result<Vec<i32>> {
        let mut arr = self.read_int_array(index, n)?;
        for i in &mut arr {
            *i = Self::clamp_int(*i, min, max, exceptions);
        }
        Ok(arr)
    }

    pub fn read_long_array(&self, index: u64, n: usize) -> io::Result<Vec<i64>> {
        let mut arr = Vec::with_capacity(n);
        let mut idx = index;
        for _ in 0..n {
            arr.push(self.read_long(idx)?);
            idx += Self::SIZEOF_LONG;
        }
        Ok(arr)
    }

    pub fn read_long_array_clamped(&self, index: u64, n: usize, min: i64, max: i64, exceptions: &[i64]) -> io::Result<Vec<i64>> {
        let mut arr = self.read_long_array(index, n)?;
        for l in &mut arr {
            *l = Self::clamp_long(*l, min, max, exceptions);
        }
        Ok(arr)
    }

    /// Reads `n` null-terminated ASCII strings consecutively starting at `index`.
    /// Advances `index` by each string's trimmed length after each read,
    /// matching the Java source (does not skip the terminating byte).
    pub fn read_ascii_string_array(&self, index: u64, n: usize) -> io::Result<Vec<String>> {
        let mut arr = Vec::with_capacity(n);
        let mut idx = index;
        for _ in 0..n {
            let s = self.read_ascii_string(idx)?;
            idx += if s.is_empty() { 1 } else { s.len() as u64 };
            arr.push(s);
        }
        Ok(arr)
    }

    // ── writes ────────────────────────────────────────────────────────────────

    pub fn write_byte(&self, index: u64, value: u8) -> io::Result<()> {
        self.provider.borrow_mut().write_byte(index, value)
    }

    pub fn write_short(&self, index: u64, value: i16) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        self.provider.borrow_mut().write_bytes(index, &bytes)
    }

    pub fn write_int(&self, index: u64, value: i32) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        self.provider.borrow_mut().write_bytes(index, &bytes)
    }

    pub fn write_long(&self, index: u64, value: i64) -> io::Result<()> {
        let bytes = match self.endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        self.provider.borrow_mut().write_bytes(index, &bytes)
    }

    pub fn get_byte_provider(&self) -> Rc<RefCell<dyn ByteProvider>> {
        Rc::clone(&self.provider)
    }

    // ── clamping helpers ──────────────────────────────────────────────────────

    fn clamp_byte(b: u8, min: u8, max: u8, exceptions: &[u8]) -> u8 {
        assert!(max >= min, "maxClamp < minClamp not allowed");
        assert!(exceptions.len() % 2 == 0, "exceptions must be pairs of (flag, replacement) bytes");
        for pair in exceptions.chunks(2) {
            if b == pair[0] {
                return pair[1];
            }
        }
        b.clamp(min, max)
    }

    fn clamp_short(s: i16, min: i16, max: i16, exceptions: &[i16]) -> i16 {
        assert!(max >= min, "maxClamp < minClamp not allowed");
        assert!(exceptions.len() % 2 == 0, "exceptions must be pairs of (flag, replacement) shorts");
        for pair in exceptions.chunks(2) {
            if s == pair[0] {
                return pair[1];
            }
        }
        s.clamp(min, max)
    }

    fn clamp_int(i: i32, min: i32, max: i32, exceptions: &[i32]) -> i32 {
        assert!(max >= min, "maxClamp < minClamp not allowed");
        assert!(exceptions.len() % 2 == 0, "exceptions must be pairs of (flag, replacement) ints");
        for pair in exceptions.chunks(2) {
            if i == pair[0] {
                return pair[1];
            }
        }
        i.clamp(min, max)
    }

    fn clamp_long(l: i64, min: i64, max: i64, exceptions: &[i64]) -> i64 {
        assert!(max >= min, "maxClamp < minClamp not allowed");
        assert!(exceptions.len() % 2 == 0, "exceptions must be pairs of (flag, replacement) longs");
        for pair in exceptions.chunks(2) {
            if l == pair[0] {
                return pair[1];
            }
        }
        l.clamp(min, max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── test helper: in-memory ByteProvider ──────────────────────────────────

    struct VecProvider(Vec<u8>);

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.0.len() as u64)
        }
        fn is_valid_index(&mut self, index: u64) -> bool {
            index < self.0.len() as u64
        }
        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.0.get(index as usize).copied().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range")
            })
        }
        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past end"));
            }
            Ok(self.0[start..end].to_vec())
        }
        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            let idx = index as usize;
            if idx >= self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "index out of range"));
            }
            self.0[idx] = value;
            Ok(())
        }
        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            let end = start + values.len();
            if end > self.0.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "write past end"));
            }
            self.0[start..end].copy_from_slice(values);
            Ok(())
        }
    }

    fn reader(data: Vec<u8>, little_endian: bool) -> GBinaryReader {
        GBinaryReader::new(Rc::new(RefCell::new(VecProvider(data))), little_endian)
    }

    // ── constants ─────────────────────────────────────────────────────────────

    #[test]
    fn sizeof_constants_match_java() {
        assert_eq!(GBinaryReader::SIZEOF_BYTE, 1);
        assert_eq!(GBinaryReader::SIZEOF_SHORT, 2);
        assert_eq!(GBinaryReader::SIZEOF_INT, 4);
        assert_eq!(GBinaryReader::SIZEOF_LONG, 8);
    }

    // ── endianness ────────────────────────────────────────────────────────────

    #[test]
    fn endian_flag_round_trip() {
        let mut r = reader(vec![0u8; 8], true);
        assert!(r.is_little_endian());
        r.set_little_endian(false);
        assert!(!r.is_little_endian());
        r.set_little_endian(true);
        assert!(r.is_little_endian());
    }

    // ── length / valid index ──────────────────────────────────────────────────

    #[test]
    fn length_delegates_to_provider() {
        assert_eq!(reader(vec![1, 2, 3], false).length().unwrap(), 3);
    }

    #[test]
    fn is_valid_index_bounds() {
        let r = reader(vec![0u8; 4], false);
        assert!(r.is_valid_index(0));
        assert!(r.is_valid_index(3));
        assert!(!r.is_valid_index(4));
    }

    #[test]
    fn is_valid_index_int_reinterprets_signed() {
        let r = reader(vec![0u8; 4], false);
        // -1 as u32 = 0xFFFF_FFFF = 4294967295, out of range for a 4-byte provider
        assert!(!r.is_valid_index_int(-1));
        assert!(r.is_valid_index_int(0));
        assert!(r.is_valid_index_int(3));
    }

    // ── align ─────────────────────────────────────────────────────────────────

    #[test]
    fn align_already_aligned_is_noop() {
        let mut r = reader(vec![0u8; 32], false);
        r.set_pointer_index(16);
        assert_eq!(r.align(16), 0);
        assert_eq!(r.get_pointer_index(), 16);
    }

    #[test]
    fn align_advances_to_next_boundary() {
        let mut r = reader(vec![0u8; 32], false);
        r.set_pointer_index(3);
        assert_eq!(r.align(4), 1);
        assert_eq!(r.get_pointer_index(), 4);

        r.set_pointer_index(123);
        assert_eq!(r.align(16), 5);
        assert_eq!(r.get_pointer_index(), 128);
    }

    // ── pointer index ─────────────────────────────────────────────────────────

    #[test]
    fn set_and_get_pointer_index() {
        let mut r = reader(vec![0u8; 8], false);
        r.set_pointer_index(7);
        assert_eq!(r.get_pointer_index(), 7);
    }

    #[test]
    fn set_pointer_index_int_zero_extends() {
        let mut r = reader(vec![0u8; 8], false);
        r.set_pointer_index_int(-1);
        assert_eq!(r.get_pointer_index(), u32::MAX as u64);
    }

    // ── read_byte ─────────────────────────────────────────────────────────────

    #[test]
    fn read_byte_at_index() {
        let r = reader(vec![0xAB, 0xCD], false);
        assert_eq!(r.read_byte(0).unwrap(), 0xAB);
        assert_eq!(r.read_byte(1).unwrap(), 0xCD);
    }

    // ── read_short ────────────────────────────────────────────────────────────

    #[test]
    fn read_short_little_endian() {
        let r = reader(vec![0x01, 0x00], true);
        assert_eq!(r.read_short(0).unwrap(), 1i16);
    }

    #[test]
    fn read_short_big_endian() {
        let r = reader(vec![0x00, 0x01], false);
        assert_eq!(r.read_short(0).unwrap(), 1i16);
    }

    #[test]
    fn read_short_negative_big_endian() {
        let r = reader(vec![0xFF, 0xFF], false);
        assert_eq!(r.read_short(0).unwrap(), -1i16);
    }

    // ── read_int ─────────────────────────────────────────────────────────────

    #[test]
    fn read_int_little_endian() {
        let r = reader(vec![0x05, 0x00, 0x00, 0x00], true);
        assert_eq!(r.read_int(0).unwrap(), 5i32);
    }

    #[test]
    fn read_int_big_endian() {
        let r = reader(vec![0x00, 0x00, 0x00, 0x07], false);
        assert_eq!(r.read_int(0).unwrap(), 7i32);
    }

    // ── read_long ────────────────────────────────────────────────────────────

    #[test]
    fn read_long_little_endian() {
        let mut data = vec![0u8; 8];
        data[0] = 1;
        assert_eq!(reader(data, true).read_long(0).unwrap(), 1i64);
    }

    #[test]
    fn read_long_big_endian() {
        let mut data = vec![0u8; 8];
        data[7] = 1;
        assert_eq!(reader(data, false).read_long(0).unwrap(), 1i64);
    }

    // ── peek does not advance ─────────────────────────────────────────────────

    #[test]
    fn peek_methods_do_not_advance_index() {
        let mut r = reader(vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], true);
        r.set_pointer_index(0);
        let _ = r.peek_next_byte().unwrap();
        assert_eq!(r.get_pointer_index(), 0);
        let _ = r.peek_next_short().unwrap();
        assert_eq!(r.get_pointer_index(), 0);
        let _ = r.peek_next_int().unwrap();
        assert_eq!(r.get_pointer_index(), 0);
        let _ = r.peek_next_long().unwrap();
        assert_eq!(r.get_pointer_index(), 0);
    }

    // ── readNext advances index ───────────────────────────────────────────────

    #[test]
    fn read_next_byte_advances() {
        let mut r = reader(vec![0x01, 0x02, 0x03], false);
        assert_eq!(r.read_next_byte().unwrap(), 0x01);
        assert_eq!(r.get_pointer_index(), 1);
        assert_eq!(r.read_next_byte().unwrap(), 0x02);
        assert_eq!(r.get_pointer_index(), 2);
    }

    #[test]
    fn read_next_short_advances() {
        let mut r = reader(vec![0x00, 0x01, 0x00, 0x02], false);
        assert_eq!(r.read_next_short().unwrap(), 1i16);
        assert_eq!(r.get_pointer_index(), 2);
        assert_eq!(r.read_next_short().unwrap(), 2i16);
        assert_eq!(r.get_pointer_index(), 4);
    }

    #[test]
    fn read_next_int_advances() {
        let data = [0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x07].to_vec();
        let mut r = reader(data, false);
        assert_eq!(r.read_next_int().unwrap(), 5i32);
        assert_eq!(r.get_pointer_index(), 4);
        assert_eq!(r.read_next_int().unwrap(), 7i32);
        assert_eq!(r.get_pointer_index(), 8);
    }

    #[test]
    fn read_next_long_advances() {
        let mut data = vec![0u8; 16];
        data[7] = 3;
        data[15] = 9;
        let mut r = reader(data, false);
        assert_eq!(r.read_next_long().unwrap(), 3i64);
        assert_eq!(r.get_pointer_index(), 8);
        assert_eq!(r.read_next_long().unwrap(), 9i64);
        assert_eq!(r.get_pointer_index(), 16);
    }

    // ── ASCII strings ─────────────────────────────────────────────────────────

    #[test]
    fn read_ascii_string_stops_at_non_printable() {
        let mut data = b"Hello".to_vec();
        data.push(0);
        assert_eq!(reader(data, false).read_ascii_string(0).unwrap(), "Hello");
    }

    #[test]
    fn read_ascii_string_fixed_length() {
        let data = b"HelloWorld".to_vec();
        assert_eq!(reader(data, false).read_ascii_string_fixed(0, 5).unwrap(), "Hello");
    }

    #[test]
    fn read_next_ascii_string_advances_past_terminator() {
        let mut data = b"Hi".to_vec();
        data.push(0);
        data.extend_from_slice(b"Bye");
        data.push(0);
        let mut r = reader(data, false);
        assert_eq!(r.read_next_ascii_string().unwrap(), "Hi");
        assert_eq!(r.get_pointer_index(), 3);
        assert_eq!(r.read_next_ascii_string().unwrap(), "Bye");
        assert_eq!(r.get_pointer_index(), 7);
    }

    // ── Unicode strings ───────────────────────────────────────────────────────

    #[test]
    fn read_unicode_string_double_null_terminated() {
        let data = vec![b'A', 0x00, b'B', 0x00, 0x00, 0x00];
        assert_eq!(reader(data, false).read_unicode_string(0).unwrap(), "AB");
    }

    #[test]
    fn read_unicode_string_fixed() {
        let data = vec![b'X', 0x00, b'Y', 0x00];
        assert_eq!(reader(data, false).read_unicode_string_fixed(0, 2).unwrap(), "XY");
    }

    // ── arrays ────────────────────────────────────────────────────────────────

    #[test]
    fn read_byte_array() {
        let r = reader(vec![1, 2, 3, 4, 5], false);
        assert_eq!(r.read_byte_array(1, 3).unwrap(), vec![2u8, 3, 4]);
    }

    #[test]
    fn read_short_array_big_endian() {
        let data = vec![0x00, 0x01, 0x00, 0x02, 0x00, 0x03];
        assert_eq!(reader(data, false).read_short_array(0, 3).unwrap(), vec![1i16, 2, 3]);
    }

    #[test]
    fn read_int_array_little_endian() {
        let data = vec![0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        assert_eq!(reader(data, true).read_int_array(0, 2).unwrap(), vec![1i32, 2]);
    }

    #[test]
    fn read_long_array_big_endian() {
        let mut data = vec![0u8; 16];
        data[7] = 5;
        data[15] = 7;
        assert_eq!(reader(data, false).read_long_array(0, 2).unwrap(), vec![5i64, 7]);
    }

    #[test]
    fn read_next_byte_array_advances() {
        let mut r = reader(vec![1, 2, 3, 4], false);
        assert_eq!(r.read_next_byte_array(2).unwrap(), vec![1u8, 2]);
        assert_eq!(r.get_pointer_index(), 2);
    }

    #[test]
    fn read_next_short_array_advances() {
        let data = vec![0x00, 0x01, 0x00, 0x02];
        let mut r = reader(data, false);
        assert_eq!(r.read_next_short_array(2).unwrap(), vec![1i16, 2]);
        assert_eq!(r.get_pointer_index(), 4);
    }

    // ── writes ────────────────────────────────────────────────────────────────

    #[test]
    fn write_byte_round_trip() {
        let r = reader(vec![0u8; 4], false);
        r.write_byte(2, 0xAB).unwrap();
        assert_eq!(r.read_byte(2).unwrap(), 0xAB);
    }

    #[test]
    fn write_int_big_endian_byte_order() {
        let r = reader(vec![0u8; 4], false);
        r.write_int(0, 0x01020304).unwrap();
        assert_eq!(r.read_byte(0).unwrap(), 0x01);
        assert_eq!(r.read_byte(3).unwrap(), 0x04);
    }

    #[test]
    fn write_int_little_endian_byte_order() {
        let r = reader(vec![0u8; 4], true);
        r.write_int(0, 0x01020304).unwrap();
        assert_eq!(r.read_byte(0).unwrap(), 0x04);
        assert_eq!(r.read_byte(3).unwrap(), 0x01);
    }

    #[test]
    fn write_short_round_trip() {
        let r = reader(vec![0u8; 2], false);
        r.write_short(0, 0x0102).unwrap();
        assert_eq!(r.read_short(0).unwrap(), 0x0102);
    }

    #[test]
    fn write_long_round_trip() {
        let r = reader(vec![0u8; 8], true);
        r.write_long(0, 0x0102030405060708i64).unwrap();
        assert_eq!(r.read_long(0).unwrap(), 0x0102030405060708i64);
    }

    // ── clamping ──────────────────────────────────────────────────────────────

    #[test]
    fn clamp_byte_in_range() {
        let r = reader(vec![50], false);
        assert_eq!(r.read_byte_clamped(0, 20, 100, &[]).unwrap(), 50);
    }

    #[test]
    fn clamp_byte_below_min() {
        let r = reader(vec![10], false);
        assert_eq!(r.read_byte_clamped(0, 20, 100, &[]).unwrap(), 20);
    }

    #[test]
    fn clamp_byte_above_max() {
        let r = reader(vec![200], false);
        assert_eq!(r.read_byte_clamped(0, 20, 100, &[]).unwrap(), 100);
    }

    #[test]
    fn clamp_byte_exception_overrides_clamp() {
        let r = reader(vec![10], false);
        assert_eq!(r.read_byte_clamped(0, 20, 100, &[10, 99]).unwrap(), 99);
    }

    #[test]
    fn clamp_short_exception() {
        let r = reader(vec![0x00, 0x05], false); // big-endian 5
        assert_eq!(r.read_short_clamped(0, 0, 3, &[5, 42]).unwrap(), 42i16);
    }

    #[test]
    fn clamp_int_clamps_value() {
        let r = reader(vec![0x00, 0x00, 0x00, 0x0A], false); // big-endian 10
        assert_eq!(r.read_int_clamped(0, 0, 5, &[]).unwrap(), 5i32);
    }

    #[test]
    fn clamp_long_clamps_value() {
        let mut data = vec![0u8; 8];
        data[7] = 20;
        let r = reader(data, false); // big-endian 20
        assert_eq!(r.read_long_clamped(0, 0, 10, &[]).unwrap(), 10i64);
    }

    #[test]
    #[should_panic(expected = "maxClamp < minClamp not allowed")]
    fn clamp_byte_panics_on_invalid_range() {
        GBinaryReader::clamp_byte(5, 100, 50, &[]);
    }

    #[test]
    #[should_panic(expected = "exceptions must be pairs")]
    fn clamp_byte_panics_on_odd_exceptions() {
        GBinaryReader::clamp_byte(5, 0, 100, &[1]);
    }

    #[test]
    #[should_panic(expected = "maxClamp < minClamp not allowed")]
    fn clamp_int_panics_on_invalid_range() {
        GBinaryReader::clamp_int(5, 10, 5, &[]);
    }

    // ── clone_at ─────────────────────────────────────────────────────────────

    #[test]
    fn clone_at_positions_independently() {
        let r = reader(vec![1, 2, 3, 4], false);
        let mut clone = r.clone_at(2);
        assert_eq!(clone.read_next_byte().unwrap(), 3);
        assert_eq!(r.get_pointer_index(), 0); // original unaffected
    }

    #[test]
    fn clone_at_shares_provider_mutations() {
        let r = reader(vec![0u8; 4], false);
        let clone = r.clone_at(0);
        r.write_byte(0, 0xAB).unwrap();
        assert_eq!(clone.read_byte(0).unwrap(), 0xAB); // sees write from original
    }

    // ── get_byte_provider ────────────────────────────────────────────────────

    #[test]
    fn get_byte_provider_returns_shared_ref() {
        let r = reader(vec![42], false);
        let prov = r.get_byte_provider();
        assert_eq!(prov.borrow_mut().read_byte(0).unwrap(), 42);
    }
}
