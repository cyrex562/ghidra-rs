use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::pe::rich_header::RichHeader;
use crate::format::seam_stubs::{PERichTableDataType, RichHeaderRecord};
use crate::program::model::mem::mem_buffer::MemBuffer;

const MAX_TABLE_SEARCH_COUNT: i32 = 100;

/// Mirrors `ghidra.app.util.bin.format.pe.RichTable`. Top level object model of the Rich header;
/// stores an array of [`RichHeaderRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichTable {
    mask: i32,
    image_offset: i64,
    size: i32,
    records: Vec<RichHeaderRecord>,
}

/// The two Java constructors (`RichTable(MemBuffer)` / `RichTable(BinaryReader)`) both funnel
/// into `parse(Object src, long base)`, which dispatches on the runtime type of `src`. This enum
/// captures that same dispatch without needing an `Object`-style trait object.
enum RichTableSource<'a> {
    Mem(&'a dyn MemBuffer),
    Reader(&'a dyn BinaryReader),
}

impl<'a> RichTableSource<'a> {
    fn read_int(&self, offset: i64) -> std::io::Result<i32> {
        match self {
            RichTableSource::Mem(buf) => buf.get_int(offset as i32).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.message().unwrap_or("memory access exception").to_string(),
                )
            }),
            RichTableSource::Reader(reader) => reader.read_int(offset as u64),
        }
    }
}

impl RichTable {
    pub fn new_from_mem_buffer(buf: &dyn MemBuffer) -> Self {
        let mut table = RichTable { mask: 0, image_offset: 0, size: 0, records: Vec::new() };
        table.parse(RichTableSource::Mem(buf), 0);
        table
    }

    pub fn new_from_reader(reader: &dyn BinaryReader) -> Self {
        let base = reader.get_pointer_index() as i64;
        let mut table = RichTable { mask: 0, image_offset: 0, size: 0, records: Vec::new() };
        table.parse(RichTableSource::Reader(reader), base);
        table
    }

    fn parse(&mut self, src: RichTableSource, base: i64) {
        let mut valid = false;

        let mut offset = base;
        let mut start_offset = base;
        let mut end_offset = base;

        let mut n_sign_dwords: i32 = 0;

        let result: std::io::Result<()> = (|| {
            // Scan forward looking for the Rich signature (or the PE signature, and we've gone
            // too far) -- this sets the upper-bound (endOffset) of the table.
            for _ in 0..MAX_TABLE_SEARCH_COUNT {
                let dw = src.read_int(offset)?;
                if dw == RichHeader::IMAGE_RICH_SIGNATURE {
                    end_offset = offset + 8; // space for the signature and mask
                    break;
                }
                if dw == crate::format::pe::constants::IMAGE_NT_SIGNATURE as i32 {
                    break;
                }
                offset += 4;
            }

            // Ensure we've determined the table-end.
            if end_offset != start_offset {
                // The table mask follows; read it next.
                offset += 4;
                self.mask = src.read_int(offset)?;

                // Now scan backwards until we find the DanS signature -- the lower-bound of the
                // table (startOffset).
                let mut scan_offset = offset - 8;
                loop {
                    let dw = src.read_int(scan_offset)?;
                    if (dw ^ self.mask) == RichHeader::IMAGE_DANS_SIGNATURE {
                        start_offset = scan_offset;
                        n_sign_dwords += 1;
                        valid = true;
                        break;
                    }
                    scan_offset -= 4;
                    n_sign_dwords += 1;

                    if scan_offset < base {
                        break;
                    }
                }

                if valid {
                    // Now that we know the bounds of the table, verify the padding bytes.
                    offset = start_offset + 4;
                    for _ in 0..3 {
                        let v = src.read_int(offset)?;
                        if (v ^ self.mask) != 0 {
                            valid = false;
                            break;
                        }
                        offset += 4;
                    }
                }
            }

            Ok(())
        })();

        if result.is_err() {
            valid = false;
        }

        if !valid {
            self.mask = -1;
            self.image_offset = -1;
            self.size = 0;
            return;
        }

        // nSignDwords includes the 4 dwords of the header (DanS & padding dwords)...
        let num_records = (n_sign_dwords / 2) - 2;

        self.image_offset = start_offset;
        self.size = (end_offset - self.image_offset) as i32;

        let mut records = Vec::with_capacity(num_records.max(0) as usize);

        offset = self.image_offset + 16; // skip the DanS signature and padding dwords

        let result: std::io::Result<()> = (|| {
            for i in 0..num_records {
                let mut data1 = src.read_int(offset)?;
                let mut data2 = src.read_int(offset + 4)?;
                offset += 8;

                data1 ^= self.mask;
                data2 ^= self.mask;

                records.push(RichHeaderRecord::new(i, data1, data2));
            }
            Ok(())
        })();

        if result.is_err() {
            valid = false;
        }

        if !valid {
            self.records = Vec::new();
            self.mask = -1;
            self.image_offset = -1;
            self.size = 0;
            return;
        }

        self.records = records;
    }

    pub fn get_records(&self) -> &[RichHeaderRecord] {
        &self.records
    }

    pub fn get_offset(&self) -> i64 {
        self.image_offset
    }

    pub fn get_mask(&self) -> i32 {
        self.mask
    }

    pub fn get_size(&self) -> i32 {
        self.size
    }

    pub fn to_data_type(&self) -> PERichTableDataType {
        PERichTableDataType::new()
    }
}

impl std::fmt::Display for RichTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}[mask={:x}h, numRecords={}]",
            RichHeader::NAME,
            self.mask,
            self.records.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::mem::memory_access_exception::MemoryAccessException;

    fn addr(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1), offset)
    }

    /// A `MemBuffer` backed by an in-memory byte slice, big enough to build a valid Rich header
    /// fixture for `RichTable`'s parser. `get_int` is left at the trait default, which reads via
    /// `get_bytes` respecting `is_big_endian`.
    struct FixtureMemBuffer {
        bytes: Vec<u8>,
    }

    impl MemBuffer for FixtureMemBuffer {
        fn get_address(&self) -> Address {
            addr(0)
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of range"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let n = buf.len().min(self.bytes.len().saturating_sub(start));
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    /// Builds the bytes of a minimal, valid Rich header: `DanS` XORed with `mask`, three mask
    /// padding dwords, one record (compid/count XORed with mask), then the mask and the `Rich`
    /// signature. Bytes are big-endian to match `FixtureMemBuffer::is_big_endian`.
    fn build_rich_header_bytes(mask: i32, compid: i32, count: i32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(RichHeader::IMAGE_DANS_SIGNATURE ^ mask).to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes.extend_from_slice(&(compid ^ mask).to_be_bytes());
        bytes.extend_from_slice(&(count ^ mask).to_be_bytes());
        bytes.extend_from_slice(&RichHeader::IMAGE_RICH_SIGNATURE.to_be_bytes());
        bytes.extend_from_slice(&mask.to_be_bytes());
        bytes
    }

    #[test]
    fn parses_valid_rich_header_from_mem_buffer() {
        let mask = 0x1234_5678;
        let buf = FixtureMemBuffer { bytes: build_rich_header_bytes(mask, 0x0009_0042, 3) };

        let table = RichTable::new_from_mem_buffer(&buf);

        assert_eq!(table.get_mask(), mask);
        assert_eq!(table.get_offset(), 0);
        assert_eq!(table.get_size(), 32);
        assert_eq!(table.get_records().len(), 1);
        assert_eq!(table.get_records()[0].get_index(), 0);
        assert_eq!(table.get_records()[0].get_comp_id().value(), 0x0009_0042);
        assert_eq!(table.get_records()[0].get_object_count(), 3);
    }

    #[test]
    fn invalid_when_no_signature_found() {
        let buf = FixtureMemBuffer { bytes: vec![0u8; 512] };

        let table = RichTable::new_from_mem_buffer(&buf);

        assert_eq!(table.get_mask(), -1);
        assert_eq!(table.get_offset(), -1);
        assert_eq!(table.get_size(), 0);
        assert!(table.get_records().is_empty());
    }

    #[test]
    fn to_string_matches_java_format() {
        let mask = 0x1234_5678;
        let buf = FixtureMemBuffer { bytes: build_rich_header_bytes(mask, 0x0009_0042, 3) };

        let table = RichTable::new_from_mem_buffer(&buf);

        assert_eq!(table.to_string(), "IMAGE_RICH_HEADER[mask=12345678h, numRecords=1]");
    }
}
