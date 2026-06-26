use std::io::{self, Read, Write};

/// XOR mask bytes used for obfuscation/de-obfuscation.
///
/// Applied cyclically by byte position. Copied from `ChainedBuffer` — the same
/// constant is shared by `ObfuscatedFileByteProvider` and this stream wrapper.
pub const XOR_MASK_BYTES: &[u8] = &[
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8, 0xc3, 0x48, 0xdd, 0x8b, 0x21, 0xd6, 0x94,
    0x78, 0x35, 0xab, 0x2b, 0x7e, 0xb2, 0x4f, 0x82, 0x4e, 0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e,
    0x7e, 0xe6, 0xb6, 0xbd, 0x56, 0x91, 0x57, 0x72, 0xe6, 0x91, 0xdc, 0x52, 0x2e, 0xf2, 0x1a,
    0xb7, 0xd6, 0x6f, 0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f, 0xf4, 0xdd, 0x11, 0xee,
    0xf2, 0x67, 0xfe, 0x48, 0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24, 0x8e, 0x17, 0x76,
    0x51, 0xe2, 0x60, 0xd7, 0xe6, 0x83, 0x65, 0xd5, 0xf0, 0x7f, 0xf2, 0xa0, 0xd6, 0x4b, 0xbd,
    0x24, 0xd8, 0xab, 0xea, 0x9e, 0xa6, 0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc, 0x69,
    0x11, 0xf8, 0x3c, 0xa7, 0x3f, 0x5d, 0x77, 0x94, 0x3f, 0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56,
    0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40,
];

/// A [`Read`] wrapper that de-obfuscates bytes by XORing them with a cyclic mask.
///
/// Each byte read from the underlying reader is XORed with
/// `XOR_MASK_BYTES[position % XOR_MASK_BYTES.len()]`, where `position` is the
/// cumulative number of bytes consumed from the stream.
pub struct ObfuscatedInputStream<R: Read> {
    delegate: R,
    current_position: u64,
}

impl<R: Read> ObfuscatedInputStream<R> {
    /// Wraps `delegate` in a de-obfuscating stream.
    pub fn new(delegate: R) -> Self {
        ObfuscatedInputStream { delegate, current_position: 0 }
    }

    /// Copies all bytes from `input` to `output`, de-obfuscating on the fly.
    ///
    /// This implements the functionality of the Java CLI entry point.
    pub fn deobfuscate(input: R, output: &mut impl Write) -> io::Result<()> {
        let mut stream = ObfuscatedInputStream::new(input);
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf)? {
                0 => break,
                n => output.write_all(&buf[..n])?,
            }
        }
        Ok(())
    }
}

impl<R: Read> Read for ObfuscatedInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.delegate.read(buf)?;
        let mask_len = XOR_MASK_BYTES.len() as u64;
        for i in 0..n {
            let mask_index = (self.current_position % mask_len) as usize;
            buf[i] ^= XOR_MASK_BYTES[mask_index];
            self.current_position += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_stream(data: &[u8]) -> ObfuscatedInputStream<Cursor<Vec<u8>>> {
        ObfuscatedInputStream::new(Cursor::new(data.to_vec()))
    }

    fn obfuscate(plaintext: &[u8]) -> Vec<u8> {
        plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ XOR_MASK_BYTES[i % XOR_MASK_BYTES.len()])
            .collect()
    }

    #[test]
    fn single_byte_xored_with_mask_position_0() {
        let obfuscated = obfuscate(&[0x00]);
        let mut stream = make_stream(&obfuscated);
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 1);
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn first_few_bytes_deobfuscated() {
        let plaintext = b"hello";
        let obfuscated = obfuscate(plaintext);
        let mut stream = make_stream(&obfuscated);
        let mut buf = vec![0u8; plaintext.len()];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn xor_is_own_inverse() {
        let original = b"test data for round-trip";
        let obfuscated = obfuscate(original);
        let mut stream = make_stream(&obfuscated);
        let mut result = Vec::new();
        io::copy(&mut stream, &mut result).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn mask_wraps_at_128_bytes() {
        // A 256-byte message — the mask must wrap correctly at position 128
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let obfuscated = obfuscate(&plaintext);
        let mut stream = make_stream(&obfuscated);
        let mut result = Vec::new();
        io::copy(&mut stream, &mut result).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn position_maintained_across_multiple_reads() {
        let plaintext: Vec<u8> = (0u8..16).collect();
        let obfuscated = obfuscate(&plaintext);
        let mut stream = make_stream(&obfuscated);
        let mut out = vec![0u8; 16];
        // Read in two parts of unequal size to verify position bookkeeping
        stream.read_exact(&mut out[..5]).unwrap();
        stream.read_exact(&mut out[5..]).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn empty_stream_returns_zero() {
        let mut stream = make_stream(&[]);
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn deobfuscate_copies_to_output() {
        let plaintext = b"deobfuscate helper test";
        let obfuscated = obfuscate(plaintext);
        let mut output: Vec<u8> = Vec::new();
        ObfuscatedInputStream::deobfuscate(Cursor::new(obfuscated), &mut output).unwrap();
        assert_eq!(output, plaintext);
    }
}
