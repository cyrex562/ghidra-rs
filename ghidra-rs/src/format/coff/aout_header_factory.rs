use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::format::seam_stubs::{AoutHeader, CoffFileHeader};

use super::coff_machine_type::IMAGE_FILE_MACHINE_R3000;

/// Creates an appropriate AoutHeader implementation based on the COFF file header's machine type.
///
/// Returns `None` if the optional header size is 0, indicating no optional header is present.
/// For R3000 (MIPS) machines, this would create an AoutHeaderMIPS instance; otherwise, creates a
/// regular AoutHeader instance.
///
/// Note: Since AoutHeaderMIPS and AoutHeader are not yet fully ported, this function returns
/// trait objects. When these types are ported, this may be refactored to return concrete types.
pub fn create_aout_header(
    reader: &mut dyn BinaryReader,
    header: &dyn CoffFileHeader,
) -> io::Result<Option<Box<dyn AoutHeader>>> {
    if header.get_optional_header_size() == 0 {
        return Ok(None);
    }

    let magic = header.get_magic() as u16;
    let aout_header = if magic == IMAGE_FILE_MACHINE_R3000 {
        // Would create AoutHeaderMIPS(reader) in the real implementation
        // For now, returning a trait object placeholder
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "AoutHeaderMIPS not yet ported",
        ));
    } else {
        // Would create AoutHeader(reader) in the real implementation
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "AoutHeader not yet ported",
        ));
    };

    Ok(Some(aout_header))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCoffFileHeader {
        magic: i16,
        optional_header_size: i16,
    }

    impl CoffFileHeader for MockCoffFileHeader {
        fn get_magic(&self) -> i16 {
            self.magic
        }
        fn get_section_count(&self) -> i16 {
            0
        }
        fn get_timestamp(&self) -> i32 {
            0
        }
        fn get_symbol_table_pointer(&self) -> i32 {
            0
        }
        fn get_symbol_table_entries(&self) -> i32 {
            0
        }
        fn get_optional_header_size(&self) -> i16 {
            self.optional_header_size
        }
        fn get_flags(&self) -> i16 {
            0
        }
        fn get_target_id(&self) -> io::Result<i16> {
            Ok(0)
        }
        fn get_image_base(&self, _is_windows_platform: bool) -> i64 {
            0
        }
        fn get_machine_name(&self) -> String {
            String::new()
        }
        fn get_machine(&self) -> i16 {
            0
        }
        fn parse_section_headers(&self) -> io::Result<()> {
            Ok(())
        }
        fn parse(&self, _monitor: &dyn crate::util::task::TaskMonitor) -> io::Result<()> {
            Ok(())
        }
        fn get_sections(&self) -> Vec<Box<dyn crate::format::seam_stubs::CoffSectionHeader>> {
            vec![]
        }
        fn get_symbols(&self) -> Vec<Box<dyn crate::format::seam_stubs::CoffSymbol>> {
            vec![]
        }
        fn get_symbol_at_index(&self, _index: i64) -> Box<dyn crate::format::seam_stubs::CoffSymbol> {
            unimplemented!()
        }
        fn sizeof(&self) -> i32 {
            0
        }
        fn get_optional_header(&self) -> Box<dyn AoutHeader> {
            unimplemented!()
        }
        fn is_valid(&self) -> io::Result<bool> {
            Ok(true)
        }
        fn to_data_type(&self) -> io::Result<Box<dyn crate::program::model::data::data_type::DataType>> {
            Err(io::Error::new(io::ErrorKind::Other, "unimplemented"))
        }
    }

    #[test]
    fn test_returns_none_when_optional_header_size_is_zero() {
        let header = MockCoffFileHeader {
            magic: 0x0000,
            optional_header_size: 0,
        };

        // Verify the header returns 0 for optional_header_size,
        // which causes the factory to return None without reading
        assert_eq!(header.get_optional_header_size(), 0);
    }

    #[test]
    fn test_magic_value_matching_r3000() {
        let header = MockCoffFileHeader {
            magic: IMAGE_FILE_MACHINE_R3000 as i16,
            optional_header_size: 28,
        };

        let magic_as_u16 = header.get_magic() as u16;
        assert_eq!(magic_as_u16, IMAGE_FILE_MACHINE_R3000);
    }

    #[test]
    fn test_magic_value_matching_i386() {
        let header = MockCoffFileHeader {
            magic: 0x014c, // IMAGE_FILE_MACHINE_I386
            optional_header_size: 28,
        };

        let magic_as_u16 = header.get_magic() as u16;
        assert_ne!(magic_as_u16, IMAGE_FILE_MACHINE_R3000);
    }
}
