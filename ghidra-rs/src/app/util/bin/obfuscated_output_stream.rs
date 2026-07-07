use std::io::{self, Write};

use super::obfuscated_input_stream::XOR_MASK_BYTES;

/// A [`Write`] wrapper that obfuscates bytes before writing them to the underlying stream.
///
/// Each byte is XORed with `XOR_MASK_BYTES[position % XOR_MASK_BYTES.len()]`, where
/// `position` is the cumulative number of bytes written through this wrapper.
pub struct ObfuscatedOutputStream<W: Write> {
    delegate: W,
    current_position: u64,
}

impl<W: Write> ObfuscatedOutputStream<W> {
    /// Wraps `delegate` in an obfuscating stream.
    pub fn new(delegate: W) -> Self {
        ObfuscatedOutputStream { delegate, current_position: 0 }
    }

    /// Consumes the wrapper and returns the inner writer.
    pub fn into_inner(self) -> W {
        self.delegate
    }
}

impl<W: Write> Write for ObfuscatedOutputStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mask_len = XOR_MASK_BYTES.len() as u64;
        let mut tmp: Vec<u8> = Vec::with_capacity(buf.len());
        for (i, &byte) in buf.iter().enumerate() {
            let mask_index = ((self.current_position + i as u64) % mask_len) as usize;
            tmp.push(byte ^ XOR_MASK_BYTES[mask_index]);
        }
        let written = self.delegate.write(&tmp)?;
        self.current_position += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.delegate.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::obfuscated_input_stream::ObfuscatedInputStream;
    use std::io::Cursor;

    fn obfuscate(plaintext: &[u8]) -> Vec<u8> {
        plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ XOR_MASK_BYTES[i % XOR_MASK_BYTES.len()])
            .collect()
    }

    #[test]
    fn write_single_byte_applies_mask_at_position_0() {
        let mut buf: Vec<u8> = Vec::new();
        let mut stream = ObfuscatedOutputStream::new(&mut buf);
        stream.write_all(&[0x00]).unwrap();
        drop(stream);
        assert_eq!(buf, &[XOR_MASK_BYTES[0]]);
    }

    #[test]
    fn write_matches_expected_obfuscation() {
        let plaintext = b"hello";
        let expected = obfuscate(plaintext);
        let mut buf: Vec<u8> = Vec::new();
        let mut stream = ObfuscatedOutputStream::new(&mut buf);
        stream.write_all(plaintext).unwrap();
        drop(stream);
        assert_eq!(buf, expected);
    }

    #[test]
    fn round_trip_with_input_stream() {
        let plaintext = b"round-trip obfuscation test";
        let mut obfuscated: Vec<u8> = Vec::new();
        {
            let mut out = ObfuscatedOutputStream::new(&mut obfuscated);
            out.write_all(plaintext).unwrap();
        }
        let mut result = Vec::new();
        ObfuscatedInputStream::deobfuscate(Cursor::new(obfuscated), &mut result).unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn mask_wraps_at_128_bytes() {
        let plaintext: Vec<u8> = (0u8..=255).collect();
        let expected = obfuscate(&plaintext);
        let mut buf: Vec<u8> = Vec::new();
        let mut stream = ObfuscatedOutputStream::new(&mut buf);
        stream.write_all(&plaintext).unwrap();
        drop(stream);
        assert_eq!(buf, expected);
    }

    #[test]
    fn position_maintained_across_multiple_writes() {
        let plaintext: Vec<u8> = (0u8..16).collect();
        let expected = obfuscate(&plaintext);
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut stream = ObfuscatedOutputStream::new(&mut buf);
            stream.write_all(&plaintext[..5]).unwrap();
            stream.write_all(&plaintext[5..]).unwrap();
        }
        assert_eq!(buf, expected);
    }

    #[test]
    fn empty_write_is_noop() {
        let mut buf: Vec<u8> = Vec::new();
        let mut stream = ObfuscatedOutputStream::new(&mut buf);
        stream.write_all(&[]).unwrap();
        drop(stream);
        assert!(buf.is_empty());
    }

    #[test]
    fn into_inner_returns_delegate() {
        let buf: Vec<u8> = Vec::new();
        let mut stream = ObfuscatedOutputStream::new(buf);
        stream.write_all(b"x").unwrap();
        let inner = stream.into_inner();
        assert_eq!(inner.len(), 1);
    }
}
