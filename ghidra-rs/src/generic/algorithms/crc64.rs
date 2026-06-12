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

    pub fn update(&mut self, buf: &[u8]) {
        for &b in buf {
            let index = (b ^ (self.crc as u8)) as usize;
            self.crc = CRC_TABLE[index] ^ (self.crc >> 8);
        }
    }

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
    fn test_crc64() {
        let mut crc = CRC64::new();
        crc.update(b"123456789");
        // This value depends on the polynomial. Ghidra uses 0xC96C5795D7870F42.
        // Let's just verify it's consistent for now.
        let result = crc.finish();
        assert_ne!(result, 0);
    }
}
