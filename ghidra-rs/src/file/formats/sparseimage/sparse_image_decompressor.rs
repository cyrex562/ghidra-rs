//! Port of `ghidra.file.formats.sparseimage.SparseImageDecompressor`.
//!
//! Expands an Android sparse image (`simg`) into its raw form. Adapted from the AOSP
//! `simg2img` tool.
//!
//! Java's constructor takes a `ByteProvider` and wraps it in a little-endian `BinaryReader`;
//! here the caller supplies that reader directly (the crate's [`BinaryReader`] is a trait with
//! no single concrete provider-backed implementation yet), positioned at the sparse header.

use std::io::{self, Write};

use flate2::Crc;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::filesystem::gfilesystem::g_file_system::GFileSystemError;
use crate::util::task::TaskMonitor;

use super::chunk_header::ChunkHeader;
use super::sparse_constants::{
    CHUNK_TYPE_CRC32, CHUNK_TYPE_DONT_CARE, CHUNK_TYPE_FILL, CHUNK_TYPE_RAW, MAJOR_VERSION_NUMBER,
};
use super::sparse_header::SparseHeader;

/// Size of the scratch buffers used while expanding chunks (1 MiB).
const BUFFER_SIZE: i32 = 1024 * 1024;

/// Expands a sparse image read from `reader` into `out`.
///
/// Mirrors `ghidra.file.formats.sparseimage.SparseImageDecompressor`.
pub struct SparseImageDecompressor<'a> {
    reader: &'a mut dyn BinaryReader,
    crc: Crc,
    buffer_size: i32,
    out: &'a mut dyn Write,
    block_size: i32,
}

impl<'a> SparseImageDecompressor<'a> {
    /// Creates a decompressor reading the sparse image from `reader` (little-endian, positioned
    /// at the sparse header) and writing the expanded image to `out`.
    ///
    /// Mirrors `SparseImageDecompressor(ByteProvider, OutputStream)`.
    pub fn new(reader: &'a mut dyn BinaryReader, out: &'a mut dyn Write) -> Self {
        SparseImageDecompressor { reader, crc: Crc::new(), buffer_size: BUFFER_SIZE, out, block_size: 0 }
    }

    /// Performs the decompression of the file, writing the expanded image to the output.
    ///
    /// Mirrors `decompress(TaskMonitor)`.
    ///
    /// # Errors
    /// On an unsupported major version, an unknown chunk type, a CRC mismatch, an I/O failure,
    /// or cancellation through `monitor`.
    pub fn decompress(&mut self, monitor: &dyn TaskMonitor) -> Result<(), GFileSystemError> {
        let sparse_header = SparseHeader::new(self.reader)?;
        if sparse_header.major_version as u16 != MAJOR_VERSION_NUMBER {
            return Err(io::Error::other("Unsupported major version number.").into());
        }

        self.block_size = sparse_header.blk_sz;

        let mut total_blocks: i32 = 0;
        monitor.set_maximum(sparse_header.total_chunks as i64);
        monitor.set_progress(0);
        for i in 0..sparse_header.total_chunks {
            monitor.check_cancelled()?;
            monitor.set_message(&format!(
                "Processing chunk {i} of {}...",
                sparse_header.total_chunks
            ));

            let chunk_header = ChunkHeader::new(self.reader)?;
            let chunk_type = chunk_header.chunk_type as u16;
            let chunk_size = chunk_header.chunk_sz;

            match chunk_type {
                CHUNK_TYPE_RAW => self.process_raw_chunk(chunk_size, monitor)?,
                CHUNK_TYPE_FILL => self.process_fill_chunk(chunk_size, monitor)?,
                CHUNK_TYPE_DONT_CARE => self.process_skip_chunk(chunk_size, monitor)?,
                CHUNK_TYPE_CRC32 => self.process_crc_chunk()?,
                _ => {
                    return Err(io::Error::other(format!(
                        "Unkown chunk type: {}",
                        chunk_header.chunk_type
                    ))
                    .into());
                }
            }
            total_blocks = total_blocks.wrapping_add(chunk_size);
            monitor.increment_progress(1);
        }
        let total_size = total_blocks as i64 * sparse_header.blk_sz as i64;
        monitor.set_message(&format!("Total bytes: {total_size}"));
        Ok(())
    }

    /// Checks the CRC of everything written by raw and fill chunks so far.
    fn process_crc_chunk(&mut self) -> io::Result<()> {
        let file_crc = self.reader.read_next_int()?;
        let value = self.crc.sum() as i32;
        if file_crc != value {
            return Err(io::Error::other(format!(
                "Computed crc (0x{:x}) did not match the expected crc (0x{:x}).",
                value as u32, file_crc as u32
            )));
        }
        Ok(())
    }

    /// Writes `blocks` blocks of zeros. As in Java, skipped blocks are not added to the CRC.
    fn process_skip_chunk(
        &mut self,
        blocks: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), GFileSystemError> {
        let length = blocks as i64 * self.block_size as i64;
        let buffer_size = self.buffer_size as i64;
        if length > buffer_size {
            let bytes = vec![0u8; self.buffer_size as usize];
            for _ in 0..length / buffer_size {
                monitor.check_cancelled()?;
                self.out.write_all(&bytes)?;
            }
        }
        // Java: `(int) length % bufferSize` -- the cast binds before the remainder.
        let size = (length as i32) % self.buffer_size;
        let size = usize::try_from(size)
            .map_err(|_| io::Error::other(format!("Negative skip remainder: {size}")))?;
        self.out.write_all(&vec![0u8; size])?;
        Ok(())
    }

    /// Writes `blocks` blocks filled with the chunk's 4-byte pattern.
    ///
    /// The pattern is the little-endian fill value re-emitted most-significant byte first,
    /// exactly as the Java source does.
    fn process_fill_chunk(
        &mut self,
        blocks: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), GFileSystemError> {
        let fill_int = self.reader.read_next_int()?;
        let mut length = blocks as i64 * self.block_size as i64;
        let fill_buffer_size = length.min(self.buffer_size as i64).max(0) as usize;
        let src_pattern = fill_int.to_be_bytes();
        let fill_buffer: Vec<u8> = src_pattern.iter().copied().cycle().take(fill_buffer_size).collect();
        while length > 0 {
            monitor.check_cancelled()?;
            let bytes_to_write = length.min(fill_buffer_size as i64) as usize;
            self.crc.update(&fill_buffer[..bytes_to_write]);
            self.out.write_all(&fill_buffer[..bytes_to_write])?;
            length -= bytes_to_write as i64;
        }
        Ok(())
    }

    /// Copies `blocks` blocks of raw data from the input.
    fn process_raw_chunk(
        &mut self,
        blocks: i32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), GFileSystemError> {
        let mut length = blocks as i64 * self.block_size as i64;
        while length > 0 {
            monitor.check_cancelled()?;
            let bytes_to_read = length.min(self.buffer_size as i64) as usize;
            let bytes = self.reader.read_next_byte_array(bytes_to_read)?;
            self.crc.update(&bytes);
            self.out.write_all(&bytes)?;
            length -= bytes_to_read as i64;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::macos::test_support::VecReader;
    use crate::util::task::DummyMonitor;

    const BLK: u32 = 8;

    fn header(total_blks: u32, total_chunks: u32, major: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xED26_FF3Au32.to_le_bytes());
        b.extend_from_slice(&major.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&28u16.to_le_bytes());
        b.extend_from_slice(&12u16.to_le_bytes());
        b.extend_from_slice(&BLK.to_le_bytes());
        b.extend_from_slice(&total_blks.to_le_bytes());
        b.extend_from_slice(&total_chunks.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b
    }

    fn chunk(b: &mut Vec<u8>, chunk_type: u16, chunk_sz: u32, body: &[u8]) {
        b.extend_from_slice(&chunk_type.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&chunk_sz.to_le_bytes());
        b.extend_from_slice(&(12 + body.len() as u32).to_le_bytes());
        b.extend_from_slice(body);
    }

    fn crc_of(data: &[u8]) -> u32 {
        let mut c = Crc::new();
        c.update(data);
        c.sum()
    }

    fn expand(image: Vec<u8>) -> Result<Vec<u8>, GFileSystemError> {
        let mut reader = VecReader::little_endian(image);
        let mut out = Vec::new();
        SparseImageDecompressor::new(&mut reader, &mut out).decompress(&DummyMonitor)?;
        Ok(out)
    }

    /// A tiny image: 1 raw block, 2 fill blocks, 1 don't-care block, then a CRC chunk over the
    /// raw + fill output (skip output is not part of the CRC, as in the Java source).
    fn tiny_image() -> (Vec<u8>, Vec<u8>) {
        let raw = b"RAWBLOCK";
        let fill_value: u32 = 0x4433_2211; // on disk: 11 22 33 44
        let mut expected = raw.to_vec();
        // Java emits the little-endian-read int most-significant byte first: 44 33 22 11.
        expected.extend([0x44, 0x33, 0x22, 0x11].repeat(4));
        let crc = crc_of(&expected);
        expected.extend([0u8; BLK as usize]);

        let mut img = header(4, 4, 1);
        chunk(&mut img, CHUNK_TYPE_RAW, 1, raw);
        chunk(&mut img, CHUNK_TYPE_FILL, 2, &fill_value.to_le_bytes());
        chunk(&mut img, CHUNK_TYPE_DONT_CARE, 1, &[]);
        chunk(&mut img, CHUNK_TYPE_CRC32, 0, &crc.to_le_bytes());
        (img, expected)
    }

    #[test]
    fn expands_raw_fill_skip_and_checks_crc() {
        let (img, expected) = tiny_image();
        assert_eq!(expand(img).unwrap(), expected);
    }

    #[test]
    fn crc_mismatch_is_reported() {
        let mut img = header(1, 2, 1);
        chunk(&mut img, CHUNK_TYPE_RAW, 1, b"ABCDEFGH");
        chunk(&mut img, CHUNK_TYPE_CRC32, 0, &0x1234_5678u32.to_le_bytes());
        let err = expand(img).unwrap_err().to_string();
        let actual = crc_of(b"ABCDEFGH");
        assert_eq!(
            err,
            format!("Computed crc (0x{actual:x}) did not match the expected crc (0x12345678).")
        );
    }

    #[test]
    fn unsupported_major_version() {
        let err = expand(header(0, 0, 2)).unwrap_err().to_string();
        assert_eq!(err, "Unsupported major version number.");
    }

    #[test]
    fn unknown_chunk_type_uses_signed_short_value() {
        let mut img = header(1, 1, 1);
        chunk(&mut img, 0xCAC9, 1, &[]);
        let err = expand(img).unwrap_err().to_string();
        assert_eq!(err, format!("Unkown chunk type: {}", 0xCAC9u16 as i16));
    }

    #[test]
    fn truncated_raw_chunk_errors() {
        let mut img = header(1, 1, 1);
        chunk(&mut img, CHUNK_TYPE_RAW, 1, b"ABC");
        assert!(expand(img).is_err());
    }
}
