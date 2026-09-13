//! Port of `ghidra.app.util.bin.format.ubi.FatArch`.

use std::fmt;
use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// Represents a `fat_arch` structure.
///
/// See [mach-o/fat.h](https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html).
///
/// Port of `ghidra.app.util.bin.format.ubi.FatArch`.
pub struct FatArch {
    cputype: i32,
    cpusubtype: i32,
    offset: i32,
    size: i32,
    align: i32,
}

impl FatArch {
    /// Reads a [`FatArch`] from `reader`.
    ///
    /// Port of `FatArch(BinaryReader)`.
    pub fn new(reader: &mut dyn BinaryReader) -> io::Result<Self> {
        Ok(FatArch {
            cputype: reader.read_next_int()?,
            cpusubtype: reader.read_next_int()?,
            offset: reader.read_next_int()?,
            size: reader.read_next_int()?,
            align: reader.read_next_int()?,
        })
    }

    /// Returns the CPU type of this architecture slice.
    ///
    /// See `ghidra.app.util.bin.format.macho.CpuTypes`.
    ///
    /// Port of `FatArch.getCpuType()`.
    pub fn get_cpu_type(&self) -> i32 {
        self.cputype
    }

    /// Returns the CPU sub-type of this architecture slice.
    ///
    /// See `ghidra.app.util.bin.format.macho.CpuSubTypes`.
    ///
    /// Port of `FatArch.getCpuSubType()`.
    pub fn get_cpu_sub_type(&self) -> i32 {
        self.cpusubtype
    }

    /// Returns the file offset to this object file.
    ///
    /// Port of `FatArch.getOffset()`.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Returns the size of this object file.
    ///
    /// Port of `FatArch.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Returns the alignment as a power of 2.
    ///
    /// Port of `FatArch.getAlign()`.
    pub fn get_align(&self) -> i32 {
        self.align
    }
}

impl fmt::Display for FatArch {
    /// Port of `FatArch.toString()`.
    ///
    /// Mirrors Java's `Integer.toHexString(int)`, which prints the value's raw 32-bit two's
    /// complement bit pattern in lowercase hex, unsigned and unpadded -- hence the `as u32` casts
    /// below rather than signed formatting.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "CPU Type: 0x{:x}", self.cputype as u32)?;
        writeln!(f, "CPU Sub Type: 0x{:x}", self.cpusubtype as u32)?;
        writeln!(f, "Offset: 0x{:x}", self.offset as u32)?;
        writeln!(f, "Size: 0x{:x}", self.size as u32)?;
        writeln!(f, "Align: 0x{:x}", self.align as u32)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Minimal in-memory [`BinaryReader`] sufficient for this module's tests: sequential
    /// big-endian 32-bit reads (matching Mach-O universal binaries, which are always big-endian
    /// at the fat-header level).
    struct MockReader {
        bytes: Vec<u8>,
        pos: u64,
    }

    impl MockReader {
        fn new(bytes: Vec<u8>) -> Self {
            MockReader { bytes, pos: 0 }
        }
    }

    impl BinaryReader for MockReader {
        fn length(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
        fn is_valid_index(&self, index: u64) -> bool {
            index < self.bytes.len() as u64
        }
        fn get_pointer_index(&self) -> u64 {
            self.pos
        }
        fn set_pointer_index(&mut self, index: u64) -> u64 {
            let old = self.pos;
            self.pos = index;
            old
        }
        fn is_little_endian(&self) -> bool {
            false
        }
        fn set_little_endian(&mut self, _is_little_endian: bool) {}
        fn read_byte(&self, index: u64) -> io::Result<u8> {
            self.bytes
                .get(index as usize)
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn read_byte_array(&self, index: u64, n_elements: usize) -> io::Result<Vec<u8>> {
            let start = index as usize;
            let end = start + n_elements;
            self.bytes
                .get(start..end)
                .map(|s| s.to_vec())
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
        fn get_byte_provider(
            &self,
        ) -> Rc<RefCell<dyn crate::filesystem::ghidra::g_binary_reader::ByteProvider>> {
            unimplemented!("not needed by FatArch tests")
        }
        fn clone_at(&self, _new_index: u64) -> Box<dyn BinaryReader> {
            unimplemented!("not needed by FatArch tests")
        }
    }

    fn write_i32_be(buf: &mut Vec<u8>, value: i32) {
        buf.extend_from_slice(&value.to_be_bytes());
    }

    /// `CPU_TYPE_X86_64` / `CPU_SUBTYPE_X86_64_ALL` from `mach-o/fat.h`, used purely as
    /// realistic-looking fixture values.
    const CPU_TYPE_X86_64: i32 = 0x0100_0007u32 as i32;
    const CPU_SUBTYPE_X86_64_ALL: i32 = 3;

    fn sample_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        write_i32_be(&mut buf, CPU_TYPE_X86_64);
        write_i32_be(&mut buf, CPU_SUBTYPE_X86_64_ALL);
        write_i32_be(&mut buf, 0x0000_4000); // offset
        write_i32_be(&mut buf, 0x0010_0000); // size
        write_i32_be(&mut buf, 14); // align (2^14)
        buf
    }

    #[test]
    fn parses_all_five_fields_in_order() {
        let mut reader = MockReader::new(sample_bytes());
        let arch = FatArch::new(&mut reader).unwrap();

        assert_eq!(arch.get_cpu_type(), CPU_TYPE_X86_64);
        assert_eq!(arch.get_cpu_sub_type(), CPU_SUBTYPE_X86_64_ALL);
        assert_eq!(arch.get_offset(), 0x0000_4000);
        assert_eq!(arch.get_size(), 0x0010_0000);
        assert_eq!(arch.get_align(), 14);
    }

    #[test]
    fn advances_reader_by_twenty_bytes() {
        let mut buf = sample_bytes();
        buf.extend(sample_bytes());
        let mut reader = MockReader::new(buf);

        FatArch::new(&mut reader).unwrap();
        assert_eq!(reader.get_pointer_index(), 20);

        let second = FatArch::new(&mut reader).unwrap();
        assert_eq!(second.get_cpu_type(), CPU_TYPE_X86_64);
        assert_eq!(reader.get_pointer_index(), 40);
    }

    #[test]
    fn display_matches_java_tostring_format() {
        let mut reader = MockReader::new(sample_bytes());
        let arch = FatArch::new(&mut reader).unwrap();

        let expected = "CPU Type: 0x1000007\n\
                         CPU Sub Type: 0x3\n\
                         Offset: 0x4000\n\
                         Size: 0x100000\n\
                         Align: 0xe\n";
        assert_eq!(arch.to_string(), expected);
    }

    #[test]
    fn display_formats_negative_fields_as_unsigned_hex() {
        // Integer.toHexString(int) treats its argument as an unsigned 32-bit pattern, so a
        // negative Java int (e.g. cputype with the CPU_ARCH_ABI64 high bit set) prints as its
        // full unsigned hex form, never with a leading '-'.
        let mut buf = Vec::new();
        write_i32_be(&mut buf, -1); // 0xffffffff
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 0);
        write_i32_be(&mut buf, 0);
        let mut reader = MockReader::new(buf);
        let arch = FatArch::new(&mut reader).unwrap();

        assert!(arch.to_string().starts_with("CPU Type: 0xffffffff\n"));
        assert!(!arch.to_string().contains('-'));
    }
}
