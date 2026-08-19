use crate::program::model::address::AddressRange;
use crate::program::model::data::isf::IsfObject;
use crate::program::model::mem::{MemoryBlock, MemoryBlockType};
use crate::sarif::managers::MemoryMapBytesFile;

/// Represents a memory map exported to SARIF format.
///
/// Mirrors `sarif.export.mm.ExtMemoryMap` from Ghidra's SARIF export module.
/// Captures essential metadata about a memory block including its name, permissions,
/// attributes, type, and byte location for serialization.
pub struct ExtMemoryMap {
    /// The name of the memory block.
    pub name: String,
    /// The permissions string ("r", "w", "x" combined, e.g., "rwx").
    pub kind: String,
    /// Optional comment associated with the memory block.
    pub comment: Option<String>,
    /// Whether the block is marked as volatile.
    pub is_volatile: bool,
    /// Whether the block is marked as artificial.
    pub is_artificial: bool,
    /// The type of the memory block (e.g., "Default", "Bit Mapped", "Byte Mapped").
    pub r#type: String,
    /// The location of the block's bytes (e.g., "filename:offset" for initialized blocks
    /// or the mapped address for mapped blocks).
    pub location: Option<String>,
}

impl ExtMemoryMap {
    /// Creates a new `ExtMemoryMap` from a memory block and optional bytes file.
    ///
    /// Extracts metadata from the memory block including name, permissions, attributes,
    /// type, and location. If the block is initialized and `write` is true, writes the
    /// block's bytes to the bytes file and records the location.
    ///
    /// # Arguments
    ///
    /// * `range` - The address range of the memory block.
    /// * `block` - The memory block to extract metadata from.
    /// * `bf` - Optional bytes file to write initialized block contents to.
    /// * `write` - Whether to write block contents to the bytes file.
    ///
    /// # Returns
    ///
    /// A new `ExtMemoryMap` with extracted metadata.
    pub fn new(
        range: &AddressRange,
        block: &dyn MemoryBlock,
        bf: Option<&mut MemoryMapBytesFile>,
        write: bool,
    ) -> Self {
        let mut permissions = String::new();
        if block.is_read() {
            permissions.push('r');
        }
        if block.is_write() {
            permissions.push('w');
        }
        if block.is_execute() {
            permissions.push('x');
        }

        let name = block.get_name().to_string();
        let comment = block.get_comment().map(|c| c.to_string());
        let is_volatile = block.is_volatile();
        let is_artificial = block.is_artificial();

        let r#type = block.get_type().java_name().to_string();

        let location = if matches!(block.get_type(), MemoryBlockType::BitMapped | MemoryBlockType::ByteMapped) {
            // For bit-mapped and byte-mapped blocks, get the mapped range
            let source_infos = block.get_source_infos();
            if !source_infos.is_empty() {
                source_infos[0].get_mapped_range().map(|range| {
                    range.min_address().to_string()
                })
            } else {
                None
            }
        } else if block.is_initialized() && write {
            // For initialized blocks, write to bytes file and record location
            if let Some(bytes_file) = bf {
                let _ = bytes_file.write_bytes(range);
                let file_name = bytes_file.file_name();
                let offset = bytes_file.offset();
                Some(format!("{}:{}", file_name, offset))
            } else {
                None
            }
        } else {
            None
        };

        Self {
            name,
            kind: permissions,
            comment,
            is_volatile,
            is_artificial,
            r#type,
            location,
        }
    }
}

impl IsfObject for ExtMemoryMap {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    struct MockMemoryBlock {
        name: String,
        read: bool,
        write: bool,
        execute: bool,
        comment: Option<String>,
        volatile: bool,
        artificial: bool,
        block_type: MemoryBlockType,
        initialized: bool,
    }

    impl MemoryBlock for MockMemoryBlock {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_start(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0)
        }

        fn get_end(&self) -> Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
            Address::new(space, 0xff)
        }

        fn get_size(&self) -> u64 {
            0x100
        }

        fn is_initialized(&self) -> bool {
            self.initialized
        }

        fn get_byte(&self, _addr: &Address) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            Ok(0)
        }

        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            0
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), crate::program::model::mem::MemoryAccessException> {
            Ok(())
        }

        fn is_read(&self) -> bool {
            self.read
        }

        fn is_write(&self) -> bool {
            self.write
        }

        fn is_execute(&self) -> bool {
            self.execute
        }

        fn get_comment(&self) -> Option<&str> {
            self.comment.as_deref()
        }

        fn is_volatile(&self) -> bool {
            self.volatile
        }

        fn is_artificial(&self) -> bool {
            self.artificial
        }

        fn get_type(&self) -> MemoryBlockType {
            self.block_type
        }
    }

    fn test_address_range() -> AddressRange {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let start = Address::new(space.clone(), 0x1000);
        let end = Address::new(space, 0x1fff);
        AddressRange::new(start, end)
    }

    #[test]
    fn extracts_name_from_block() {
        let block = MockMemoryBlock {
            name: "test_block".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.name, "test_block");
    }

    #[test]
    fn builds_permissions_string_with_all_flags() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: true,
            write: true,
            execute: true,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.kind, "rwx");
    }

    #[test]
    fn builds_permissions_string_with_read_only() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: true,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.kind, "r");
    }

    #[test]
    fn builds_permissions_string_with_read_write() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: true,
            write: true,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.kind, "rw");
    }

    #[test]
    fn builds_empty_permissions_string_with_no_flags() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.kind, "");
    }

    #[test]
    fn extracts_comment_when_present() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: Some("test comment".to_string()),
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.comment, Some("test comment".to_string()));
    }

    #[test]
    fn comment_is_none_when_not_present() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert!(ext_map.comment.is_none());
    }

    #[test]
    fn extracts_volatile_flag() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: true,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert!(ext_map.is_volatile);
    }

    #[test]
    fn extracts_artificial_flag() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: true,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert!(ext_map.is_artificial);
    }

    #[test]
    fn type_default_maps_to_java_enum_name() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.r#type, "DEFAULT");
    }

    #[test]
    fn type_bit_mapped_maps_to_java_enum_name() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::BitMapped,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.r#type, "BIT_MAPPED");
    }

    #[test]
    fn type_byte_mapped_maps_to_java_enum_name() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::ByteMapped,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.r#type, "BYTE_MAPPED");
    }

    #[test]
    fn uninitialized_block_has_no_location() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert!(ext_map.location.is_none());
    }

    #[test]
    fn initialized_block_without_write_has_no_location() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: true,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert!(ext_map.location.is_none());
    }

    #[test]
    fn initialized_block_without_bytes_file_has_no_location() {
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: true,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, true);

        assert!(ext_map.location.is_none());
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let block = MockMemoryBlock {
            name: "test".to_string(),
            read: false,
            write: false,
            execute: false,
            comment: None,
            volatile: false,
            artificial: false,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        accepts_isf_object(&ext_map);
    }

    #[test]
    fn all_fields_extracted_together() {
        let block = MockMemoryBlock {
            name: "code".to_string(),
            read: true,
            write: false,
            execute: true,
            comment: Some("executable code".to_string()),
            volatile: false,
            artificial: true,
            block_type: MemoryBlockType::Default,
            initialized: false,
        };
        let range = test_address_range();
        let ext_map = ExtMemoryMap::new(&range, &block, None, false);

        assert_eq!(ext_map.name, "code");
        assert_eq!(ext_map.kind, "rx");
        assert_eq!(ext_map.comment, Some("executable code".to_string()));
        assert!(!ext_map.is_volatile);
        assert!(ext_map.is_artificial);
        assert_eq!(ext_map.r#type, "DEFAULT");
        assert!(ext_map.location.is_none());
    }
}
