use std::cell::{Cell, RefCell};
use std::io::{self, Read};

use super::decoder_exception::DecoderException;

/// Size, in bytes, of a single page in a [`LinkedByteBuffer`].
pub const BUFFER_SIZE: usize = 1024;

/// A byte buffer that is stored as a linked list of pages. Each page holds
/// `BUFFER_SIZE` bytes (except for a trailing 1-byte page holding a pad value).
/// A [`Position`] acts as an iterator over the whole buffer. The buffer can be
/// populated from a stream, either all at once or "as needed" when a
/// [`Position`] iterates past the current cached set of bytes.
///
/// The Java original links pages together with an `ArrayIter` linked list and
/// null-checks a "next" reference to detect the frontier. Because pages are
/// only ever appended (never removed or reordered), this port stores pages in
/// a growable arena and has a `Position` remember an integer page index
/// instead of holding a raw reference into page memory; this sidesteps the
/// aliasing that the Java version relies on garbage collection to manage,
/// while preserving identical page-boundary semantics.
pub struct LinkedByteBuffer {
    pages: RefCell<Vec<Vec<u8>>>,
    byte_count: Cell<usize>,
    max_count: usize,
    current_page: Cell<usize>,
    current_pos: Cell<usize>,
    pad_value: u8,
    as_needed_stream: RefCell<Option<Box<dyn Read>>>,
    description: String,
}

impl LinkedByteBuffer {
    pub fn new(max: usize, pad: u8, desc: &str) -> Self {
        Self {
            pages: RefCell::new(vec![vec![0u8; BUFFER_SIZE]]),
            byte_count: Cell::new(0),
            max_count: max,
            current_page: Cell::new(0),
            current_pos: Cell::new(0),
            pad_value: pad,
            as_needed_stream: RefCell::new(None),
            description: desc.to_string(),
        }
    }

    /// Close the "as needed" stream, if configured.
    pub fn close(&self) -> io::Result<()> {
        self.as_needed_stream.borrow_mut().take();
        Ok(())
    }

    /// Set up this buffer so that it reads in pages as needed. The initial page is read
    /// immediately. Additional pages are read via `read_next_page` through the `Position`
    /// methods. Returns the starting `Position` for the buffer.
    pub fn ingest_stream_as_needed(&self, stream: Box<dyn Read>) -> io::Result<Position<'_>> {
        *self.as_needed_stream.borrow_mut() = Some(stream);
        let pos = {
            let mut guard = self.as_needed_stream.borrow_mut();
            let stream = guard.as_mut().unwrap();
            self.read_page(&mut **stream, 0)?
        };
        self.current_pos.set(pos);
        if pos < BUFFER_SIZE {
            self.pad();
        }
        Ok(self.get_start_position())
    }

    /// Ingest stream up to the first 0 byte or until `max_count` bytes is reached.
    /// Store the bytes on the heap in `BUFFER_SIZE` chunks.
    pub fn ingest_stream_to_next_terminator(&self, stream: &mut dyn Read) -> io::Result<()> {
        let mut tok = Self::read_one(stream)?;
        if !matches!(tok, Some(b) if b > 0) {
            return Ok(());
        }
        loop {
            if self.byte_count.get() > self.max_count {
                return Err(self.buffer_size_exceeded());
            }
            loop {
                if self.current_pos.get() == BUFFER_SIZE {
                    break;
                }
                let cp = self.current_page.get();
                let pos = self.current_pos.get();
                self.pages.borrow_mut()[cp][pos] = tok.unwrap();
                self.current_pos.set(pos + 1);
                tok = Self::read_one(stream)?;
                if !matches!(tok, Some(b) if b > 0) {
                    break;
                }
            }
            self.byte_count.set(self.byte_count.get() + self.current_pos.get());
            if !matches!(tok, Some(b) if b > 0) {
                return Ok(());
            }
            self.push_page(BUFFER_SIZE);
        }
    }

    /// Read the stream until the end of stream is encountered or until `max_count` bytes
    /// is reached. Store the bytes on the heap in `BUFFER_SIZE` chunks.
    pub fn ingest_stream(&self, stream: &mut dyn Read) -> io::Result<()> {
        while self.byte_count.get() < self.max_count {
            let cp = self.current_page.get();
            let pos = self.read_page(stream, cp)?;
            if pos < BUFFER_SIZE {
                self.current_pos.set(self.current_pos.get() + pos);
                break;
            }
            self.push_page(BUFFER_SIZE);
        }
        Ok(())
    }

    /// Ingest bytes directly from a byte array.
    /// If these bytes would cause the total number of bytes ingested to exceed
    /// the maximum (`max_count`) bytes set for this buffer, an error is returned.
    /// This can be called multiple times to read in different chunks.
    pub fn ingest_bytes(&self, byte_array: &[u8], off: usize, sz: usize) -> io::Result<()> {
        for i in 0..sz {
            let tok = byte_array[off + i];
            if self.current_pos.get() == BUFFER_SIZE {
                self.push_page(BUFFER_SIZE);
            }
            let cp = self.current_page.get();
            let pos = self.current_pos.get();
            self.pages.borrow_mut()[cp][pos] = tok;
            self.current_pos.set(pos + 1);
            self.byte_count.set(self.byte_count.get() + 1);
            if self.byte_count.get() > self.max_count {
                return Err(self.buffer_size_exceeded());
            }
        }
        Ok(())
    }

    /// Add the pad value to the end of the buffer.
    pub fn pad(&self) {
        if self.current_pos.get() == BUFFER_SIZE {
            self.byte_count.set(self.byte_count.get() + self.current_pos.get());
            self.push_page(1);
        }
        let cp = self.current_page.get();
        let pos = self.current_pos.get();
        self.pages.borrow_mut()[cp][pos] = self.pad_value;
        self.current_pos.set(pos + 1);
    }

    /// Return the `Position` at the start of the buffer.
    pub fn get_start_position(&self) -> Position<'_> {
        Position { buffer: self, page: 0, current: 0 }
    }

    fn buffer_size_exceeded(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Response buffer size exceeded for: {}", self.description),
        )
    }

    fn push_page(&self, size: usize) {
        self.pages.borrow_mut().push(vec![0u8; size]);
        let new_page = self.pages.borrow().len() - 1;
        self.current_page.set(new_page);
        self.current_pos.set(0);
    }

    /// Read a page of data into the given page slot. The page must already be allocated and
    /// will be entirely filled, unless end-of-stream is reached. The number of bytes
    /// actually read into the page is returned.
    fn read_page(&self, stream: &mut dyn Read, page_idx: usize) -> io::Result<usize> {
        let len = self.max_count.saturating_sub(self.byte_count.get()).min(BUFFER_SIZE);
        let mut pos = 0usize;
        loop {
            let read_len = {
                let mut pages = self.pages.borrow_mut();
                stream.read(&mut pages[page_idx][pos..len])?
            };
            if read_len == 0 {
                break;
            }
            pos += read_len;
            if pos >= len {
                break;
            }
        }
        self.byte_count.set(self.byte_count.get() + pos);
        Ok(pos)
    }

    /// Read the next page of data. A new page is appended to the arena and data is read
    /// into it. If the end of stream is reached, padding is added.
    fn read_next_page(&self, _after: usize) -> Result<usize, DecoderException> {
        if self.as_needed_stream.borrow().is_none() {
            return Err(DecoderException::new("Unexpected end of stream"));
        }
        self.push_page(BUFFER_SIZE);
        let new_page = self.current_page.get();
        let pos = {
            let mut guard = self.as_needed_stream.borrow_mut();
            let stream = guard.as_mut().unwrap();
            self.read_page(&mut **stream, new_page)
                .map_err(|e| DecoderException::new(&e.to_string()))?
        };
        self.current_pos.set(pos);
        if pos < BUFFER_SIZE {
            self.pad();
        }
        Ok(new_page)
    }

    /// Read a single byte from `stream`, returning `None` at end of stream.
    fn read_one(stream: &mut dyn Read) -> io::Result<Option<u8>> {
        let mut buf = [0u8; 1];
        if stream.read(&mut buf)? == 0 {
            return Ok(None);
        }
        Ok(Some(buf[0]))
    }
}

/// An iterator into a [`LinkedByteBuffer`].
#[derive(Clone, Copy)]
pub struct Position<'a> {
    buffer: &'a LinkedByteBuffer,
    page: usize,
    current: usize,
}

impl<'a> Position<'a> {
    /// Return the byte at the current `Position`. Does not advance the `Position`.
    pub fn get_byte(&self) -> u8 {
        self.buffer.pages.borrow()[self.page][self.current]
    }

    /// Lookahead exactly one byte, without advancing this `Position`.
    pub fn get_byte_plus1(&self) -> Result<u8, DecoderException> {
        let plus1 = self.current + 1;
        let page_len = self.buffer.pages.borrow()[self.page].len();
        if plus1 == page_len {
            let next_page = self.next_page_index()?;
            Ok(self.buffer.pages.borrow()[next_page][0])
        } else {
            Ok(self.buffer.pages.borrow()[self.page][plus1])
        }
    }

    /// Advance this `Position` by exactly one byte and return the next byte.
    pub fn get_next_byte(&mut self) -> Result<u8, DecoderException> {
        let res = self.buffer.pages.borrow()[self.page][self.current];
        self.current += 1;
        let page_len = self.buffer.pages.borrow()[self.page].len();
        if self.current != page_len {
            return Ok(res);
        }
        self.page = self.next_page_index()?;
        self.current = 0;
        Ok(res)
    }

    /// Advance this `Position` by the specified number of bytes.
    pub fn advance_position(&mut self, mut skip: usize) -> Result<(), DecoderException> {
        loop {
            let page_len = self.buffer.pages.borrow()[self.page].len();
            if page_len - self.current > skip {
                break;
            }
            skip -= page_len - self.current;
            self.page = self.next_page_index()?;
            self.current = 0;
        }
        self.current += skip;
        Ok(())
    }

    fn next_page_index(&self) -> Result<usize, DecoderException> {
        let has_next = self.page + 1 < self.buffer.pages.borrow().len();
        if has_next {
            Ok(self.page + 1)
        } else {
            self.buffer.read_next_page(self.page)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_ingest_bytes_and_read() {
        let buf = LinkedByteBuffer::new(1024, 0x80, "test");
        buf.ingest_bytes(&[1, 2, 3, 4], 0, 4).unwrap();

        let mut pos = buf.get_start_position();
        assert_eq!(pos.get_byte(), 1);
        assert_eq!(pos.get_next_byte().unwrap(), 1);
        assert_eq!(pos.get_next_byte().unwrap(), 2);
        assert_eq!(pos.get_byte_plus1().unwrap(), 4);
        assert_eq!(pos.get_next_byte().unwrap(), 3);
        assert_eq!(pos.get_next_byte().unwrap(), 4);
    }

    #[test]
    fn test_ingest_bytes_exceeds_max() {
        let buf = LinkedByteBuffer::new(2, 0x80, "test");
        let err = buf.ingest_bytes(&[1, 2, 3], 0, 3).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_ingest_bytes_crosses_page_boundary() {
        let buf = LinkedByteBuffer::new(4096, 0x80, "test");
        let data = vec![7u8; BUFFER_SIZE + 10];
        buf.ingest_bytes(&data, 0, data.len()).unwrap();

        let mut pos = buf.get_start_position();
        for _ in 0..BUFFER_SIZE + 10 {
            assert_eq!(pos.get_next_byte().unwrap(), 7);
        }
    }

    #[test]
    fn test_ingest_stream_to_next_terminator() {
        let buf = LinkedByteBuffer::new(1024, 0x80, "test");
        let mut cursor = Cursor::new(vec![0x41, 0x42, 0x00, 0x43]);
        buf.ingest_stream_to_next_terminator(&mut cursor).unwrap();

        let mut pos = buf.get_start_position();
        assert_eq!(pos.get_next_byte().unwrap(), 0x41);
        assert_eq!(pos.get_next_byte().unwrap(), 0x42);
    }

    #[test]
    fn test_ingest_stream_to_next_terminator_leading_zero() {
        let buf = LinkedByteBuffer::new(1024, 0x80, "test");
        let mut cursor = Cursor::new(vec![0x00, 0x41]);
        buf.ingest_stream_to_next_terminator(&mut cursor).unwrap();

        // Nothing was ingested since the very first byte was the terminator.
        assert_eq!(buf.byte_count.get(), 0);
    }

    #[test]
    fn test_ingest_stream() {
        let buf = LinkedByteBuffer::new(1024, 0x80, "test");
        let mut cursor = Cursor::new(vec![1, 2, 3]);
        buf.ingest_stream(&mut cursor).unwrap();

        let mut pos = buf.get_start_position();
        assert_eq!(pos.get_next_byte().unwrap(), 1);
        assert_eq!(pos.get_next_byte().unwrap(), 2);
        assert_eq!(pos.get_next_byte().unwrap(), 3);
    }

    #[test]
    fn test_pad() {
        let buf = LinkedByteBuffer::new(1024, 0xAB, "test");
        buf.ingest_bytes(&[1, 2], 0, 2).unwrap();
        buf.pad();

        let mut pos = buf.get_start_position();
        assert_eq!(pos.get_next_byte().unwrap(), 1);
        assert_eq!(pos.get_next_byte().unwrap(), 2);
        assert_eq!(pos.get_next_byte().unwrap(), 0xAB);
    }

    #[test]
    fn test_ingest_stream_as_needed_reads_beyond_frontier() {
        let buf = LinkedByteBuffer::new(4096, 0x80, "test");
        let data = vec![9u8; BUFFER_SIZE + 5];
        let cursor = Cursor::new(data);
        let mut pos = buf.ingest_stream_as_needed(Box::new(cursor)).unwrap();

        for _ in 0..BUFFER_SIZE + 5 {
            assert_eq!(pos.get_next_byte().unwrap(), 9);
        }
    }

    #[test]
    fn test_get_byte_plus1_at_end_without_as_needed_stream_errors() {
        let buf = LinkedByteBuffer::new(1024, 0x80, "test");
        buf.ingest_bytes(&[1], 0, 1).unwrap();
        // Force the page to look full so get_byte_plus1 must fetch a new page.
        let mut cursor = Cursor::new(vec![0u8; BUFFER_SIZE - 1]);
        buf.ingest_stream(&mut cursor).unwrap();

        // Move to the last byte of the (now full) page so that a plus-1 lookahead must
        // fetch a following page. With no linked next page and no as-needed stream, that
        // fetch fails with "Unexpected end of stream".
        let mut pos = buf.get_start_position();
        pos.advance_position(BUFFER_SIZE - 1).unwrap();
        assert!(pos.get_byte_plus1().is_err());
    }

    #[test]
    fn test_advance_position() {
        let buf = LinkedByteBuffer::new(4096, 0x80, "test");
        let data: Vec<u8> = (0..(BUFFER_SIZE + 10)).map(|i| (i % 256) as u8).collect();
        buf.ingest_bytes(&data, 0, data.len()).unwrap();

        let mut pos = buf.get_start_position();
        pos.advance_position(BUFFER_SIZE + 3).unwrap();
        assert_eq!(pos.get_byte(), data[BUFFER_SIZE + 3]);
    }

    #[test]
    fn test_close_is_idempotent() {
        let buf = LinkedByteBuffer::new(1024, 0x80, "test");
        buf.close().unwrap();
        buf.close().unwrap();
    }
}
