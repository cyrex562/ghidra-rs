//! Port of `ghidra.app.util.bin.UnlimitedByteProviderWrapper`.
//!
//! A [`ByteProviderWrapper`] that permits reading beyond EOF: every non-negative index is valid,
//! and bytes past the end of the wrapped range read as zero. Used by `ElfHeader` so that missing
//! or truncated headers parse as zero-filled rather than failing.
//!
//! Java's class extends `ByteProviderWrapper` and overrides three methods; the Rust port composes
//! a [`ByteProviderWrapper`] and delegates everything else to it. Indices are `u64` in the crate's
//! `ByteProvider`, so Java's "negative index" failure cannot arise.

use std::io;
use std::ops::Deref;
use std::path::PathBuf;

use crate::filesystem::gfilesystem::fsrl::Fsrl;

use super::byte_provider::ByteProvider;
use super::byte_provider_wrapper::ByteProviderWrapper;

/// A [`ByteProvider`] that reads zeros beyond the end of the wrapped range.
///
/// Mirrors `ghidra.app.util.bin.UnlimitedByteProviderWrapper`.
pub struct UnlimitedByteProviderWrapper<P> {
    inner: ByteProviderWrapper<P>,
    provider: P,
    sub_offset: u64,
    sub_length: u64,
}

impl<P> UnlimitedByteProviderWrapper<P>
where
    P: Deref + Clone,
    P::Target: ByteProvider,
{
    /// Wraps the whole of `provider`, keeping its FSRL.
    ///
    /// Mirrors `UnlimitedByteProviderWrapper(ByteProvider)`.
    pub fn new(provider: P) -> Self {
        let fsrl = provider.get_fsrl().cloned();
        Self::with_fsrl(provider, fsrl)
    }

    /// Wraps the whole of `provider`, tagged with `fsrl`.
    ///
    /// Mirrors `UnlimitedByteProviderWrapper(ByteProvider, FSRL)`.
    pub fn with_fsrl(provider: P, fsrl: Option<Fsrl>) -> Self {
        let len = provider.length();
        Self::with_range_and_fsrl(provider, 0, len, fsrl)
    }

    /// Wraps a sub-range of `provider`.
    ///
    /// Mirrors `UnlimitedByteProviderWrapper(ByteProvider, long, long)`.
    pub fn with_range(provider: P, sub_offset: u64, sub_length: u64) -> Self {
        Self::with_range_and_fsrl(provider, sub_offset, sub_length, None)
    }

    /// Wraps a sub-range of `provider`, tagged with `fsrl`.
    ///
    /// Mirrors `UnlimitedByteProviderWrapper(ByteProvider, long, long, FSRL)`.
    pub fn with_range_and_fsrl(
        provider: P,
        sub_offset: u64,
        sub_length: u64,
        fsrl: Option<Fsrl>,
    ) -> Self {
        UnlimitedByteProviderWrapper {
            inner: ByteProviderWrapper::with_range_and_fsrl(
                provider.clone(),
                sub_offset,
                sub_length,
                fsrl,
            ),
            provider,
            sub_offset,
            sub_length,
        }
    }
}

impl<P> ByteProvider for UnlimitedByteProviderWrapper<P>
where
    P: Deref + Clone,
    P::Target: ByteProvider,
{
    fn get_file(&self) -> Option<PathBuf> {
        self.inner.get_file()
    }

    fn get_name(&self) -> Option<String> {
        self.inner.get_name()
    }

    fn get_absolute_path(&self) -> Option<String> {
        self.inner.get_absolute_path()
    }

    fn length(&self) -> u64 {
        self.inner.length()
    }

    /// Every index is valid (Java: `index >= 0`, which an unsigned index always is).
    fn is_valid_index(&self, _index: u64) -> bool {
        true
    }

    fn close(&mut self) -> io::Result<()> {
        self.inner.close()
    }

    fn read_byte(&self, index: u64) -> io::Result<u8> {
        if index >= self.sub_length {
            return Ok(0);
        }
        self.provider.read_byte(self.sub_offset + index)
    }

    fn read_bytes(&self, index: u64, length: u64) -> io::Result<Vec<u8>> {
        if index >= self.sub_length {
            return Ok(vec![0u8; length as usize]);
        }
        if index.saturating_add(length) > self.sub_length {
            let mut bytes = vec![0u8; length as usize];
            let partial =
                self.provider.read_bytes(self.sub_offset + index, self.sub_length - index)?;
            bytes[..partial.len()].copy_from_slice(&partial);
            return Ok(bytes);
        }
        self.provider.read_bytes(self.sub_offset + index, length)
    }

    fn get_fsrl(&self) -> Option<&Fsrl> {
        self.inner.get_fsrl()
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;

    fn base() -> Rc<dyn ByteProvider> {
        Rc::new(ByteArrayProvider::new(vec![1u8, 2, 3, 4]))
    }

    #[test]
    fn reads_within_range_pass_through() {
        let w = UnlimitedByteProviderWrapper::new(base());
        assert_eq!(w.length(), 4);
        assert_eq!(w.read_byte(2).unwrap(), 3);
        assert_eq!(w.read_bytes(0, 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn reads_beyond_eof_are_zero() {
        let w = UnlimitedByteProviderWrapper::new(base());
        assert_eq!(w.read_byte(100).unwrap(), 0);
        assert_eq!(w.read_bytes(10, 3).unwrap(), vec![0, 0, 0]);
        assert!(w.is_valid_index(u64::MAX));
    }

    #[test]
    fn straddling_read_is_zero_padded() {
        let w = UnlimitedByteProviderWrapper::new(base());
        assert_eq!(w.read_bytes(2, 4).unwrap(), vec![3, 4, 0, 0]);
    }

    #[test]
    fn sub_range_is_offset_and_unlimited() {
        let w = UnlimitedByteProviderWrapper::with_range(base(), 1, 2);
        assert_eq!(w.length(), 2);
        assert_eq!(w.read_bytes(0, 3).unwrap(), vec![2, 3, 0]);
        assert_eq!(w.read_byte(2).unwrap(), 0);
    }

    #[test]
    fn binary_reader_reads_zero_past_eof() {
        let reader =
            BinaryReader::new(Rc::new(UnlimitedByteProviderWrapper::new(base())), true);
        assert_eq!(reader.read_int(2).unwrap(), 0x0000_0403);
        assert_eq!(reader.read_long(8).unwrap(), 0);
    }
}
