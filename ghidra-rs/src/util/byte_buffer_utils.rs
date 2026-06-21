/// A fixed-capacity byte buffer in write mode, analogous to Java's `ByteBuffer.allocate(n)`.
///
/// The buffer tracks how many bytes have been written (`pos`). The total allocated
/// storage is `data.len()`, which matches Java's `capacity()` / `limit()` in write mode.
pub struct WriteBuffer {
    data: Vec<u8>,
    pos: usize,
}

impl WriteBuffer {
    /// Allocate a new write buffer of the given capacity (all bytes initialised to zero).
    pub fn new(capacity: usize) -> Self {
        Self {
            data: vec![0u8; capacity],
            pos: 0,
        }
    }

    /// Total allocated bytes (Java `capacity()` / `limit()` in write mode).
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Number of bytes written so far (Java `position()`).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The slice of bytes that have been written.
    pub fn written(&self) -> &[u8] {
        &self.data[..self.pos]
    }

    /// The full backing storage including unwritten bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Write a single byte, advancing the position.
    pub fn write_byte(&mut self, b: u8) -> Result<(), &'static str> {
        if self.pos >= self.data.len() {
            return Err("buffer overflow");
        }
        self.data[self.pos] = b;
        self.pos += 1;
        Ok(())
    }
}

/// Resize a write-mode buffer, preserving its contents.
///
/// `capacity` must be greater than or equal to the buffer's current capacity (limit in write
/// mode). The returned buffer is in write mode with the same position as the input.
///
/// # Errors
/// Returns an error if `capacity < buf.capacity()`.
pub fn resize(buf: WriteBuffer, capacity: usize) -> Result<WriteBuffer, String> {
    if capacity < buf.capacity() {
        return Err("New capacity must fit current contents".to_string());
    }
    let written = buf.pos;
    let mut resized = WriteBuffer::new(capacity);
    resized.data[..written].copy_from_slice(&buf.data[..written]);
    resized.pos = written;
    Ok(resized)
}

/// Resize a write-mode buffer to twice its current capacity, preserving its contents.
pub fn upsize(buf: WriteBuffer) -> WriteBuffer {
    let new_cap = buf.capacity() * 2;
    resize(buf, new_cap).expect("upsize always doubles, so new capacity >= old capacity")
}

/// Check byte-slice equality with an optional mask applied to every byte.
///
/// Compares every byte of `a` and `b` (the full slice, not just written bytes). Both slices
/// must have equal lengths to be considered equal. If `mask` is `Some`, it must have the
/// same length as `a`.
///
/// # Errors
/// Returns an error if `mask.len() != a.len()`.
pub fn masked_equals(mask: Option<&[u8]>, a: &[u8], b: &[u8]) -> Result<bool, String> {
    let len = a.len();
    if let Some(m) = mask {
        if m.len() != len {
            return Err("mask and a must have equal capacities".to_string());
        }
    }
    if len != b.len() {
        return Ok(false);
    }
    if let Some(m) = mask {
        for i in 0..len {
            if (a[i] & m[i]) != (b[i] & m[i]) {
                return Ok(false);
            }
        }
    } else {
        for i in 0..len {
            if a[i] != b[i] {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- resize ---

    #[test]
    fn resize_grows_buffer_preserving_content() {
        let mut buf = WriteBuffer::new(4);
        buf.write_byte(1).unwrap();
        buf.write_byte(2).unwrap();
        let resized = resize(buf, 8).unwrap();
        assert_eq!(resized.capacity(), 8);
        assert_eq!(resized.position(), 2);
        assert_eq!(resized.written(), &[1u8, 2]);
    }

    #[test]
    fn resize_same_capacity_is_ok() {
        let mut buf = WriteBuffer::new(4);
        buf.write_byte(42).unwrap();
        let resized = resize(buf, 4).unwrap();
        assert_eq!(resized.capacity(), 4);
        assert_eq!(resized.written(), &[42u8]);
    }

    #[test]
    fn resize_shrink_returns_error() {
        let buf = WriteBuffer::new(8);
        assert!(resize(buf, 4).is_err());
    }

    // --- upsize ---

    #[test]
    fn upsize_doubles_capacity() {
        let mut buf = WriteBuffer::new(4);
        buf.write_byte(7).unwrap();
        let larger = upsize(buf);
        assert_eq!(larger.capacity(), 8);
        assert_eq!(larger.written(), &[7u8]);
    }

    // --- masked_equals ---

    #[test]
    fn masked_equals_exact_match_no_mask() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        assert_eq!(masked_equals(None, &a, &b).unwrap(), true);
    }

    #[test]
    fn masked_equals_different_no_mask() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 4];
        assert_eq!(masked_equals(None, &a, &b).unwrap(), false);
    }

    #[test]
    fn masked_equals_different_lengths_returns_false() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2];
        assert_eq!(masked_equals(None, &a, &b).unwrap(), false);
    }

    #[test]
    fn masked_equals_with_mask_matches() {
        // a = 0b1111_0000, b = 0b1010_0000, mask = 0b1111_0000 → masked bytes equal
        let a = [0b1111_0000u8];
        let b = [0b1010_0000u8];
        let mask = [0b1111_0000u8];
        assert_eq!(masked_equals(Some(&mask), &a, &b).unwrap(), false);

        // With mask 0b1000_0000 only the high bit matters; a=0b1111, b=0b1010 both have it set
        let mask2 = [0b1000_0000u8];
        assert_eq!(masked_equals(Some(&mask2), &a, &b).unwrap(), true);
    }

    #[test]
    fn masked_equals_mask_wrong_length_returns_error() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let mask = [0xFFu8, 0xFF];
        assert!(masked_equals(Some(&mask), &a, &b).is_err());
    }

    #[test]
    fn masked_equals_empty_slices() {
        assert_eq!(masked_equals(None, &[], &[]).unwrap(), true);
        assert_eq!(masked_equals(Some(&[]), &[], &[]).unwrap(), true);
    }
}
