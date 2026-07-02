/// CRC-64 checksum using the JONES polynomial (0xC96C5795D7870F42, reflected).
///
/// Initial value is all-ones; the finalisation step XORs the accumulator with all-ones
/// before returning, which matches the Java `CRC64` class in `generic.algorithms`.
pub struct CRC64 {
    crc: u64,
}

static CRC_TABLE: once_cell::sync::Lazy<[u64; 256]> = once_cell::sync::Lazy::new(|| {
    let mut table = [0u64; 256];
    let poly = 0xC96C5795D7870F42u64;
    for b in 0..256 {
        let mut r = b as u64;
        for _ in 0..8 {
            if (r & 1) == 1 {
                r = (r >> 1) ^ poly;
            } else {
                r >>= 1;
            }
        }
        table[b] = r;
    }
    table
});

impl CRC64 {
    pub fn new() -> Self {
        Self { crc: !0u64 }
    }

    /// Feed `buf` into the running checksum.
    ///
    /// Equivalent to the Java `update(byte[] buf, int off, int len)` — callers pass
    /// the desired sub-slice directly: `crc.update(&buf[off..off + len])`.
    pub fn update(&mut self, buf: &[u8]) {
        for &b in buf {
            let index = (b ^ (self.crc as u8)) as usize;
            self.crc = CRC_TABLE[index] ^ (self.crc >> 8);
        }
    }

    /// Return the final CRC-64 value and reset the accumulator for reuse.
    pub fn finish(&mut self) -> u64 {
        let value = !self.crc;
        self.crc = !0u64;
        value
    }
}

impl Default for CRC64 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        let mut crc = CRC64::new();
        assert_eq!(crc.finish(), 0);
    }

    #[test]
    fn check_value_123456789() {
        // CRC-64/JONES check value for the ASCII string "123456789".
        // Source: CRC catalogue — reveng.sourceforge.net/crc-catalogue, CRC-64/JONES entry.
        let mut crc = CRC64::new();
        crc.update(b"123456789");
        assert_eq!(crc.finish(), 0x995dc9bbdf1939fa);
    }

    #[test]
    fn finish_resets_accumulator() {
        let mut crc = CRC64::new();
        crc.update(b"hello");
        let first = crc.finish();
        // After reset, accumulator is fresh; a second empty finish must return 0.
        assert_eq!(crc.finish(), 0);
        // And feeding the same data again gives the same checksum.
        crc.update(b"hello");
        assert_eq!(crc.finish(), first);
    }

    #[test]
    fn incremental_equals_single_pass() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let mut single = CRC64::new();
        single.update(data);
        let expected = single.finish();

        let mut incremental = CRC64::new();
        for chunk in data.chunks(7) {
            incremental.update(chunk);
        }
        assert_eq!(incremental.finish(), expected);
    }
}
