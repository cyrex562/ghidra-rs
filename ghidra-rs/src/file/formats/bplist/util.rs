use crate::filesystem::ghidra::g_binary_reader::ByteProvider;
use crate::program::model::address::Address;
use crate::program::model::mem::Memory;
use super::binary_property_list_constants::BinaryPropertyListConstants;
use std::io;

/// Utility functions for binary property list validation and naming.
///
/// Corresponds to `ghidra.file.formats.bplist.BinaryPropertyListUtil`.

/// Checks if the data from the given byte provider begins with the binary property list magic number.
///
/// Reads the magic bytes from the provider starting at offset 0 and compares them
/// against the expected magic string for binary property lists.
pub fn is_binary_property_list(provider: &mut dyn ByteProvider) -> io::Result<bool> {
    let magic_len = BinaryPropertyListConstants::BINARY_PLIST_MAGIC.len();
    let bytes = provider.read_bytes(0, magic_len)?;
    let magic = String::from_utf8_lossy(&bytes);
    Ok(magic == BinaryPropertyListConstants::BINARY_PLIST_MAGIC)
}

/// Checks if the data at the given address in memory begins with the binary property list magic number.
///
/// Attempts to read the magic bytes from memory at the specified address.
/// Returns false if any error occurs during the read.
pub fn is_binary_property_list_from_memory(memory: &dyn Memory, address: &Address) -> bool {
    let magic_len = BinaryPropertyListConstants::BINARY_PLIST_MAGIC.len();
    let mut bytes = vec![0u8; magic_len];
    let _ = memory.get_bytes(address, &mut bytes);
    let magic = String::from_utf8_lossy(&bytes);
    magic == BinaryPropertyListConstants::BINARY_PLIST_MAGIC
}

/// Generates a name for a binary property list object at the given index.
///
/// Converts the index to a hex string and embeds it in a standard name format.
/// The `i32` index is first zero-extended to `u64` before conversion.
pub fn generate_name(index: i32) -> String {
    generate_name_u64((index as u32) as u64)
}

/// Generates a name for a binary property list object at the given index.
///
/// Converts the index to a hex string and embeds it in a standard name format.
pub fn generate_name_u64(index: u64) -> String {
    format!("BPLIST_Index_{:x}", index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_name_with_small_index() {
        assert_eq!(generate_name(0), "BPLIST_Index_0");
        assert_eq!(generate_name(1), "BPLIST_Index_1");
        assert_eq!(generate_name(10), "BPLIST_Index_a");
        assert_eq!(generate_name(255), "BPLIST_Index_ff");
    }

    #[test]
    fn generate_name_with_large_index() {
        assert_eq!(generate_name(0x1000), "BPLIST_Index_1000");
        assert_eq!(generate_name(0xffffffff), "BPLIST_Index_ffffffff");
    }

    #[test]
    fn generate_name_u64_with_values() {
        assert_eq!(generate_name_u64(0), "BPLIST_Index_0");
        assert_eq!(generate_name_u64(255), "BPLIST_Index_ff");
        assert_eq!(generate_name_u64(0x1000), "BPLIST_Index_1000");
        assert_eq!(generate_name_u64(0xffffffffffffffff), "BPLIST_Index_ffffffffffffffff");
    }

    #[test]
    fn generate_name_int_zero_extends_correctly() {
        let result_i32 = generate_name(-1i32);
        let result_u64 = generate_name_u64(0xffffffffu64);
        assert_eq!(result_i32, result_u64);
        assert_eq!(result_i32, "BPLIST_Index_ffffffff");
    }

    #[test]
    fn generate_name_matches_java_behavior() {
        assert_eq!(generate_name(42), "BPLIST_Index_2a");
        assert_eq!(generate_name(256), "BPLIST_Index_100");
        assert_eq!(generate_name(0x12345678), "BPLIST_Index_12345678");
    }
}
