use std::io::{self, Read};

use crate::filesystem::ghidra::g_binary_reader::ByteProvider;

fn available_impl<P: ByteProvider>(provider: &mut P, current_position: u64) -> io::Result<usize> {
    let len = provider.length()?;
    Ok(len.saturating_sub(current_position).min(i32::MAX as u64) as usize)
}

fn skip_impl<P: ByteProvider>(
    provider: &mut P,
    current_position: &mut u64,
    n: i64,
) -> io::Result<i64> {
    if n <= 0 {
        return Ok(0);
    }
    let len = provider.length()?;
    let new_position = len.min(current_position.saturating_add(n as u64));
    let skipped = new_position - *current_position;
    *current_position = new_position;
    Ok(skipped as i64)
}

fn read_impl<P: ByteProvider>(
    provider: &mut P,
    current_position: &mut u64,
    buf: &mut [u8],
) -> io::Result<usize> {
    let len = provider.length()?;
    if *current_position >= len {
        return Ok(0);
    }
    let to_read = buf.len().min((len - *current_position) as usize);
    let bytes = provider.read_bytes(*current_position, to_read)?;
    buf[..to_read].copy_from_slice(&bytes);
    *current_position += to_read as u64;
    Ok(to_read)
}

/// An [`std::io::Read`] stream that reads from a [`ByteProvider`].
///
/// Does not close the underlying `ByteProvider` when dropped. See
/// [`ClosingByteProviderInputStream`] for a variant that owns (and drops) the
/// provider it wraps.
pub struct ByteProviderInputStream<'a, P: ByteProvider> {
    provider: &'a mut P,
    current_position: u64,
    mark_position: u64,
}

impl<'a, P: ByteProvider> ByteProviderInputStream<'a, P> {
    /// Creates a stream that reads from `provider` starting at `start_position`.
    pub fn new(provider: &'a mut P, start_position: u64) -> Self {
        ByteProviderInputStream {
            provider,
            current_position: start_position,
            mark_position: start_position,
        }
    }

    /// Returns the number of bytes remaining, capped at `i32::MAX` to mirror
    /// Java's `InputStream.available()` contract.
    pub fn available(&mut self) -> io::Result<usize> {
        available_impl(self.provider, self.current_position)
    }

    /// Always returns `true`: this stream supports [`Self::mark`]/[`Self::reset`].
    pub fn mark_supported(&self) -> bool {
        true
    }

    /// Records the current position so a later [`Self::reset`] can return to it.
    pub fn mark(&mut self) {
        self.mark_position = self.current_position;
    }

    /// Moves the current position back to the last [`Self::mark`] (or the start
    /// position, if `mark` was never called).
    pub fn reset(&mut self) {
        self.current_position = self.mark_position;
    }

    /// Advances the current position by up to `n` bytes, stopping at the end of
    /// the provider. Returns the number of bytes actually skipped.
    pub fn skip(&mut self, n: i64) -> io::Result<i64> {
        skip_impl(self.provider, &mut self.current_position, n)
    }
}

impl<'a, P: ByteProvider> Read for ByteProviderInputStream<'a, P> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_impl(self.provider, &mut self.current_position, buf)
    }
}

/// An [`std::io::Read`] stream that reads from a [`ByteProvider`] it owns.
///
/// Unlike [`ByteProviderInputStream`], this stream drops the underlying
/// provider when [`Self::close`] is called, mirroring `ByteProviderInputStream.
/// ClosingInputStream` closing the provider it wraps. Once closed, reads
/// behave as if the stream were at end-of-file.
pub struct ClosingByteProviderInputStream<P: ByteProvider> {
    provider: Option<P>,
    current_position: u64,
    mark_position: u64,
}

impl<P: ByteProvider> ClosingByteProviderInputStream<P> {
    /// Creates a stream that reads from (and owns) `provider`, starting at
    /// `start_position`.
    pub fn new(provider: P, start_position: u64) -> Self {
        ClosingByteProviderInputStream {
            provider: Some(provider),
            current_position: start_position,
            mark_position: start_position,
        }
    }

    /// Drops the underlying provider. Idempotent: closing an already-closed
    /// stream is a no-op.
    pub fn close(&mut self) {
        self.provider = None;
    }

    /// Returns the number of bytes remaining, or `0` if the stream is closed.
    pub fn available(&mut self) -> io::Result<usize> {
        match &mut self.provider {
            Some(provider) => available_impl(provider, self.current_position),
            None => Ok(0),
        }
    }

    /// Always returns `true`: this stream supports [`Self::mark`]/[`Self::reset`].
    pub fn mark_supported(&self) -> bool {
        true
    }

    /// Records the current position so a later [`Self::reset`] can return to it.
    pub fn mark(&mut self) {
        self.mark_position = self.current_position;
    }

    /// Moves the current position back to the last [`Self::mark`] (or the start
    /// position, if `mark` was never called).
    pub fn reset(&mut self) {
        self.current_position = self.mark_position;
    }

    /// Advances the current position by up to `n` bytes, stopping at the end of
    /// the provider. Returns `0` if the stream is closed.
    pub fn skip(&mut self, n: i64) -> io::Result<i64> {
        match &mut self.provider {
            Some(provider) => skip_impl(provider, &mut self.current_position, n),
            None => Ok(0),
        }
    }
}

impl<P: ByteProvider> Read for ClosingByteProviderInputStream<P> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.provider {
            Some(provider) => read_impl(provider, &mut self.current_position, buf),
            None => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecProvider {
        data: Vec<u8>,
    }

    impl VecProvider {
        fn new(data: &[u8]) -> Self {
            VecProvider { data: data.to_vec() }
        }
    }

    impl ByteProvider for VecProvider {
        fn length(&mut self) -> io::Result<u64> {
            Ok(self.data.len() as u64)
        }

        fn is_valid_index(&mut self, index: u64) -> bool {
            (index as usize) < self.data.len()
        }

        fn read_byte(&mut self, index: u64) -> io::Result<u8> {
            self.data
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }

        fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + length;
            if end > self.data.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"));
            }
            Ok(self.data[start..end].to_vec())
        }

        fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
            self.data[index as usize] = value;
            Ok(())
        }

        fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
            let start = index as usize;
            self.data[start..start + values.len()].copy_from_slice(values);
            Ok(())
        }
    }

    #[test]
    fn reads_full_stream() {
        let mut p = VecProvider::new(&[1, 2, 3, 4, 5]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        let mut buf = [0u8; 5];
        assert_eq!(stream.read(&mut buf).unwrap(), 5);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn starts_at_given_position() {
        let mut p = VecProvider::new(&[10, 20, 30, 40]);
        let mut stream = ByteProviderInputStream::new(&mut p, 2);
        let mut buf = [0u8; 2];
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [30, 40]);
    }

    #[test]
    fn partial_read_when_buffer_smaller_than_remaining() {
        let mut p = VecProvider::new(&[1, 2, 3, 4]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        let mut buf = [0u8; 2];
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [1, 2]);
        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [3, 4]);
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn available_reflects_remaining_bytes() {
        let mut p = VecProvider::new(&[1, 2, 3, 4, 5]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        assert_eq!(stream.available().unwrap(), 5);
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        assert_eq!(stream.available().unwrap(), 3);
    }

    #[test]
    fn mark_supported_is_true() {
        let mut p = VecProvider::new(&[1, 2, 3]);
        let stream = ByteProviderInputStream::new(&mut p, 0);
        assert!(stream.mark_supported());
    }

    #[test]
    fn mark_and_reset_roundtrip() {
        let mut p = VecProvider::new(&[1, 2, 3, 4, 5]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        stream.mark();
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);
        stream.reset();
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);
    }

    #[test]
    fn reset_without_mark_returns_to_start_position() {
        let mut p = VecProvider::new(&[1, 2, 3, 4, 5]);
        let mut stream = ByteProviderInputStream::new(&mut p, 1);
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        stream.reset();
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [2, 3]);
    }

    #[test]
    fn skip_advances_position() {
        let mut p = VecProvider::new(&[1, 2, 3, 4, 5]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        assert_eq!(stream.skip(2).unwrap(), 2);
        let mut buf = [0u8; 1];
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3]);
    }

    #[test]
    fn skip_clamps_at_end_of_stream() {
        let mut p = VecProvider::new(&[1, 2, 3]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        assert_eq!(stream.skip(10).unwrap(), 3);
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn skip_non_positive_returns_zero() {
        let mut p = VecProvider::new(&[1, 2, 3]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        assert_eq!(stream.skip(0).unwrap(), 0);
        assert_eq!(stream.skip(-5).unwrap(), 0);
    }

    #[test]
    fn empty_buffer_read_returns_zero() {
        let mut p = VecProvider::new(&[1, 2, 3]);
        let mut stream = ByteProviderInputStream::new(&mut p, 0);
        assert_eq!(stream.read(&mut []).unwrap(), 0);
    }

    #[test]
    fn closing_stream_reads_like_base_stream() {
        let p = VecProvider::new(&[1, 2, 3, 4]);
        let mut stream = ClosingByteProviderInputStream::new(p, 0);
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 4);
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn close_causes_subsequent_reads_to_report_eof() {
        let p = VecProvider::new(&[1, 2, 3, 4]);
        let mut stream = ClosingByteProviderInputStream::new(p, 0);
        stream.close();
        let mut buf = [0u8; 4];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
        assert_eq!(stream.available().unwrap(), 0);
        assert_eq!(stream.skip(2).unwrap(), 0);
    }

    #[test]
    fn close_is_idempotent() {
        let p = VecProvider::new(&[1, 2, 3]);
        let mut stream = ClosingByteProviderInputStream::new(p, 0);
        stream.close();
        stream.close();
        let mut buf = [0u8; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn closing_stream_mark_and_reset() {
        let p = VecProvider::new(&[1, 2, 3, 4, 5]);
        let mut stream = ClosingByteProviderInputStream::new(p, 0);
        let mut buf = [0u8; 2];
        stream.read(&mut buf).unwrap();
        stream.mark();
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);
        stream.reset();
        stream.read(&mut buf).unwrap();
        assert_eq!(buf, [3, 4]);
    }
}
