//! Port of `ghidra.program.model.data.RepeatedDynamicDataType`.
//!
//! Template for a repeated Dynamic Data Type.
//!
//! Base abstract data type for a Dynamic structure data type that contains some number of
//! repeated data types. After each data type, including the header, there is a terminator value
//! which specifies whether there are any more data structures following. `TerminatorValue` can be
//! 1, 2, 4, or 8 bytes.
//!
//! The dynamic structure looks like this:
//! ```text
//!    RepeatDynamicDataType
//!       Header
//!       TerminatorV1
//!       RepDT1
//!       TerminatorV2
//!       RepDT2
//!       ...
//!       RepDTN-1
//!       TerminatorVN  == TerminateValue
//! ```
//!
//! The Java class is `abstract class RepeatedDynamicDataType extends DynamicDataType`, the same
//! shape [`CountedDynamicDataType`](super::counted_dynamic_data_type::CountedDynamicDataType) and
//! [`StructuredDynamicDataType`](super::structured_dynamic_data_type::StructuredDynamicDataType)
//! already use for the same Java superclass, so this port follows their already-established
//! conventions throughout:
//! - The constructor's fields (`description`, `header`, `baseStruct`, `terminatorValue`,
//!   `terminatorSize`) become `stored_*`/`set_stored_*` accessor pairs.
//! - `getValue`/`getRepresentation` (`null`/`""`) are not repeated here since they already match
//!   [`DataType::get_value`]/[`DataType::get_representation`]'s existing defaults.
//!   `getDescription()`/`getMnemonic(Settings)` *do* differ from their [`DataType`] defaults, so
//!   they are exposed under distinct `repeated_dynamic_*` names.
//! - `DynamicDataType::get_all_components` is filled in under the distinct name
//!   [`repeated_dynamic_all_components`](RepeatedDynamicDataType::repeated_dynamic_all_components)
//!   (a same-named subtrait method does not automatically satisfy a supertrait's own required
//!   method in Rust -- see [`CountedDynamicDataType::counted_all_components`](super::counted_dynamic_data_type::CountedDynamicDataType::counted_all_components)'s
//!   docs, already verified against rustc directly when porting
//!   [`StructuredDynamicDataType`](super::structured_dynamic_data_type::StructuredDynamicDataType)).
//!   A concrete type must delegate `DynamicDataType::get_all_components` to it manually.
//! - Reuses [`seam_stubs::get_data_type_instance`]/[`seam_stubs::ReadOnlyDataTypeComponent`]
//!   rather than the newer real `DataTypeInstance`/`ReadOnlyDataTypeComponent` modules, for the
//!   same `parent: Arc<dyn DynamicDataType>`-from-`&self` reason documented on
//!   [`StructuredDynamicDataType`](super::structured_dynamic_data_type). This also means the
//!   `MemoryBufferImpl`-advancing loop Java uses to track the current read position collapses
//!   into plain [`Address::add`] arithmetic (the seam-stub factory never actually reads through
//!   its `buf` parameter), exactly mirroring
//!   [`CountedDynamicDataType::counted_all_components`](super::counted_dynamic_data_type::CountedDynamicDataType::counted_all_components)'s
//!   identical simplification.
//!
//! The private `moreComponents(Memory, Address)` helper is ported as
//! [`more_components`](RepeatedDynamicDataType::more_components), including its literal
//! byte-for-byte control flow quirks: the `default` (non-1/2/4/8) branch re-reads the *same*
//! address on every iteration rather than advancing it (a quirk preserved here, not "fixed",
//! since porting is meant to be behavior-preserving), and a read failure (standing in for
//! `MemoryAccessException`) falls through to the shared trailing `test != terminator_value`
//! comparison exactly where Java's `try/catch` wraps the whole `switch`. `Msg.error` logging calls
//! throughout `getAllComponents`/`moreComponents` are not ported, matching this crate's
//! established precedent of dropping side-effecting logging while preserving the surrounding
//! control flow and return values.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::mem::{MemBuffer, Memory};
use crate::program::seam_stubs;

/// Reads `size` bytes at `loc` (standing in for `Short.toUnsignedLong(memory.getShort(loc))`,
/// `Integer.toUnsignedLong(memory.getInt(loc))`, and `memory.getLong(loc)`), returning `None` on
/// a short read (standing in for `MemoryAccessException`).
fn read_multi_byte(memory: &dyn Memory, loc: &Address, size: usize, signed: bool) -> Option<i64> {
    let mut buf = vec![0u8; size];
    if memory.get_bytes(loc, &mut buf) != size {
        return None;
    }
    Some(crate::pcode::utils::utils::bytes_to_big_integer(&buf, size, memory.is_big_endian(), signed) as i64)
}

/// Structured Dynamic Data type template for a repeated series of data types, each followed by a
/// terminator value.
///
/// Port of `ghidra.program.model.data.RepeatedDynamicDataType`. See the module-level
/// documentation for the accessor convention standing in for private fields, and for what was
/// left identical to an existing default or exposed under a distinct name.
pub trait RepeatedDynamicDataType: DynamicDataType {
    /// Backing storage for the protected `description` field.
    fn stored_description(&self) -> Option<String>;

    /// Mutator for the protected `description` field's backing storage.
    fn set_stored_description(&mut self, description: Option<String>);

    /// Backing storage for the protected `header` field (nullable in Java).
    fn stored_header(&self) -> Option<Arc<dyn DataType>>;

    /// Mutator for the protected `header` field's backing storage.
    fn set_stored_header(&mut self, header: Option<Arc<dyn DataType>>);

    /// Backing storage for the protected `baseStruct` field.
    fn stored_base_struct(&self) -> Arc<dyn DataType>;

    /// Mutator for the protected `baseStruct` field's backing storage.
    fn set_stored_base_struct(&mut self, base_struct: Arc<dyn DataType>);

    /// Backing storage for the protected `terminatorValue` field.
    fn stored_terminator_value(&self) -> i64;

    /// Mutator for the protected `terminatorValue` field's backing storage.
    fn set_stored_terminator_value(&mut self, terminator_value: i64);

    /// Backing storage for the protected `terminatorSize` field.
    fn stored_terminator_size(&self) -> i32;

    /// Mutator for the protected `terminatorSize` field's backing storage.
    fn set_stored_terminator_size(&mut self, terminator_size: i32);

    /// Port of `RepeatedDynamicDataType.getDescription()`. Exposed under a distinct name since
    /// [`DataType::get_description`] already provides a (different, empty-string) default. A
    /// concrete `impl DataType for ...` should delegate `get_description` to this.
    fn repeated_dynamic_description(&self) -> String {
        self.stored_description().unwrap_or_default()
    }

    /// Port of `RepeatedDynamicDataType.getMnemonic(Settings)`. Exposed under a distinct name
    /// since [`DataType::get_mnemonic`] already provides a (different, but often equivalent)
    /// default. A concrete `impl DataType for ...` should delegate `get_mnemonic` to this.
    fn repeated_dynamic_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of the private `RepeatedDynamicDataType.moreComponents(Memory, Address)`. See the
    /// module docs for the preserved byte-for-byte control-flow quirks.
    fn more_components(&self, memory: &dyn Memory, loc: &Address) -> bool {
        let terminator_size = self.stored_terminator_size();
        let terminator_value = self.stored_terminator_value();
        let mut test: i64 = 0;

        match terminator_size {
            1 => {
                if let Ok(b) = memory.get_byte(loc) {
                    test = b as i64;
                }
            }
            2 => {
                if let Some(v) = read_multi_byte(memory, loc, 2, false) {
                    test = v;
                }
            }
            4 => {
                if let Some(v) = read_multi_byte(memory, loc, 4, false) {
                    test = v;
                }
            }
            8 => {
                if let Some(v) = read_multi_byte(memory, loc, 8, true) {
                    test = v;
                }
            }
            _ => {
                for _ in 0..terminator_size {
                    match memory.get_byte(loc) {
                        Ok(b) => {
                            test = b as i64;
                            if test != terminator_value {
                                return true;
                            }
                        }
                        Err(_) => {
                            // Mirrors Java's try/catch wrapping the whole switch: a read failure
                            // falls through to the trailing comparison below using whatever
                            // `test` was last successfully read (0 if never).
                            return test != terminator_value;
                        }
                    }
                }
                return false;
            }
        }

        test != terminator_value
    }

    /// Template implementation backing the Java class's override of
    /// `DynamicDataType.getAllComponents(MemBuffer)`. See the module docs for why this is exposed
    /// under a distinct name, and for the `ReadOnlyDataTypeComponent`/`DataTypeInstance`
    /// seam-stub choice.
    ///
    /// Returns all components, or `None` if there is no backing [`Memory`], a data-type instance
    /// could not be determined for the repeated base struct, or the running offset overflows the
    /// address space (mirroring Java's `AddressOverflowException` catch, all of which return
    /// `null` in the original).
    fn repeated_dynamic_all_components(
        &self,
        buf: &dyn MemBuffer,
    ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        let memory = buf.get_memory()?;

        let mut comps: Vec<Option<Box<dyn DataTypeComponent>>> = Vec::new();
        let mut ordinal: i32 = 0;
        let mut count_size: i32 = 0;

        if let Some(header) = self.stored_header() {
            let len = header.get_length();
            let field_name = format!("{}_{}", header.get_name(), buf.get_address());
            comps.push(Some(Box::new(seam_stubs::ReadOnlyDataTypeComponent::new(
                Arc::clone(&header),
                len,
                ordinal,
                0,
                field_name,
            ))));
            ordinal += 1;
            count_size = len;
        }

        let mut offset = count_size;
        let mut cur_addr = buf.get_address().add(count_size as i64).ok()?;
        let base_struct = self.stored_base_struct();

        while self.more_components(memory.as_ref(), &cur_addr) {
            let instance = seam_stubs::get_data_type_instance(Arc::clone(&base_struct), buf, false)?;
            let len = instance.get_length();
            let field_name = format!("{}_{}", base_struct.get_name(), cur_addr);
            comps.push(Some(Box::new(seam_stubs::ReadOnlyDataTypeComponent::new(
                instance.get_data_type(),
                len,
                ordinal,
                offset,
                field_name,
            ))));
            offset += len;
            cur_addr = cur_addr.add(len as i64).ok()?;
            ordinal += 1;
        }

        Some(comps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::mem::MemoryAccessException;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn ram_address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
    }
    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    fn leaf(name: &str, length: i32) -> Arc<dyn DataType> {
        Arc::new(MockLeaf { name: name.to_string(), length })
    }

    /// Memory backed by a flat byte array starting at [`ram_address`]`(0)`, with a fixed
    /// terminator byte pattern repeated between each `record_len`-byte record.
    struct MockMemory {
        bytes: Vec<u8>,
        big_endian: bool,
    }
    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            let offset = addr.offset() as usize;
            self.bytes.get(offset).copied().ok_or_else(|| MemoryAccessException::new("oob"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let offset = addr.offset() as usize;
            if offset >= self.bytes.len() {
                return 0;
            }
            let n = dest.len().min(self.bytes.len() - offset);
            dest[..n].copy_from_slice(&self.bytes[offset..offset + n]);
            n
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Err(MemoryAccessException::new("read-only mock"))
        }
    }

    struct MockBuf {
        addr: Address,
        memory: Arc<MockMemory>,
    }
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> Address {
            self.addr.clone()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            0
        }
        fn is_big_endian(&self) -> bool {
            self.memory.big_endian
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(Arc::clone(&self.memory) as Arc<dyn Memory>)
        }
    }

    #[derive(Default)]
    struct TestRepeated {
        name: String,
        description: Option<String>,
        header: Option<Arc<dyn DataType>>,
        base_struct: Option<Arc<dyn DataType>>,
        terminator_value: i64,
        terminator_size: i32,
    }

    impl DataType for TestRepeated {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            -1
        }
        fn get_description(&self) -> String {
            self.repeated_dynamic_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.repeated_dynamic_mnemonic(settings)
        }
    }

    impl crate::program::model::data::built_in_data_type::BuiltInDataType for TestRepeated {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn crate::program::model::data::data_organization::DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for TestRepeated {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
            -1
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            Box::new(MockLeaf { name: "undefined".to_string(), length: 1 })
        }
    }

    impl DynamicDataType for TestRepeated {
        fn get_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            self.repeated_dynamic_all_components(buf)
        }
    }

    impl RepeatedDynamicDataType for TestRepeated {
        fn stored_description(&self) -> Option<String> {
            self.description.clone()
        }
        fn set_stored_description(&mut self, description: Option<String>) {
            self.description = description;
        }
        fn stored_header(&self) -> Option<Arc<dyn DataType>> {
            self.header.clone()
        }
        fn set_stored_header(&mut self, header: Option<Arc<dyn DataType>>) {
            self.header = header;
        }
        fn stored_base_struct(&self) -> Arc<dyn DataType> {
            self.base_struct.clone().expect("base_struct must be set")
        }
        fn set_stored_base_struct(&mut self, base_struct: Arc<dyn DataType>) {
            self.base_struct = Some(base_struct);
        }
        fn stored_terminator_value(&self) -> i64 {
            self.terminator_value
        }
        fn set_stored_terminator_value(&mut self, terminator_value: i64) {
            self.terminator_value = terminator_value;
        }
        fn stored_terminator_size(&self) -> i32 {
            self.terminator_size
        }
        fn set_stored_terminator_size(&mut self, terminator_size: i32) {
            self.terminator_size = terminator_size;
        }
    }

    #[test]
    fn description_and_mnemonic_reflect_stored_state() {
        let mut r = TestRepeated { name: "Rep".to_string(), ..Default::default() };
        assert_eq!(DataType::get_description(&r), "");
        r.set_stored_description(Some("a repeated list".to_string()));
        assert_eq!(DataType::get_description(&r), "a repeated list");

        struct NoSettings;
        impl Settings for NoSettings {}
        assert_eq!(DataType::get_mnemonic(&r, &NoSettings), "Rep");
    }

    #[test]
    fn more_components_single_byte_terminator() {
        let mut r = TestRepeated::default();
        r.set_stored_terminator_size(1);
        r.set_stored_terminator_value(0xFF);
        let memory = MockMemory { bytes: vec![0x05, 0xFF], big_endian: false };
        assert!(r.more_components(&memory, &ram_address(0))); // 0x05 != 0xFF -> more components
        assert!(!r.more_components(&memory, &ram_address(1))); // 0xFF == 0xFF -> terminator found
    }

    #[test]
    fn more_components_multi_byte_terminator_le() {
        let mut r = TestRepeated::default();
        r.set_stored_terminator_size(2);
        r.set_stored_terminator_value(0);
        let memory = MockMemory { bytes: vec![0x00, 0x00, 0x01, 0x00], big_endian: false };
        assert!(!r.more_components(&memory, &ram_address(0))); // 0x0000 == 0 -> terminator
        assert!(r.more_components(&memory, &ram_address(2))); // 0x0001 != 0 -> more components
    }

    #[test]
    fn more_components_default_branch_rereads_same_address() {
        // terminator_size == 3 exercises the default per-byte branch. Since it re-reads the same
        // address every iteration (a preserved Java quirk, see the module docs), a byte equal to
        // terminator_value at that one address is read 3 times and always matches -> false.
        let mut r = TestRepeated::default();
        r.set_stored_terminator_size(3);
        r.set_stored_terminator_value(0x7);
        let memory = MockMemory { bytes: vec![0x7], big_endian: false };
        assert!(!r.more_components(&memory, &ram_address(0)));

        let memory_mismatch = MockMemory { bytes: vec![0x9], big_endian: false };
        assert!(r.more_components(&memory_mismatch, &ram_address(0)));
    }

    #[test]
    fn get_all_components_includes_header_and_repeats_until_terminator() {
        let mut r = TestRepeated { name: "Rep".to_string(), ..Default::default() };
        r.set_stored_header(Some(leaf("header", 1)));
        r.set_stored_base_struct(leaf("record", 2));
        r.set_stored_terminator_size(1);
        r.set_stored_terminator_value(0xFF);

        // header(1 byte) then two 2-byte records (non-terminator markers), then terminator byte.
        let memory = Arc::new(MockMemory { bytes: vec![0, 1, 2, 3, 4, 0xFF], big_endian: false });
        let buf = MockBuf { addr: ram_address(0), memory };

        let comps = DynamicDataType::get_all_components(&r, &buf).expect("components expected");
        // header + 2 records (terminator byte itself is never wrapped as a component).
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].as_ref().unwrap().get_ordinal(), 0);
        assert_eq!(comps[0].as_ref().unwrap().get_offset(), 0);
        assert_eq!(comps[0].as_ref().unwrap().get_length(), 1);
        assert_eq!(comps[1].as_ref().unwrap().get_offset(), 1);
        assert_eq!(comps[2].as_ref().unwrap().get_offset(), 3);
    }

    #[test]
    fn get_all_components_without_header_starts_at_offset_zero() {
        let mut r = TestRepeated { name: "Rep".to_string(), ..Default::default() };
        r.set_stored_base_struct(leaf("record", 1));
        r.set_stored_terminator_size(1);
        r.set_stored_terminator_value(0xFF);

        let memory = Arc::new(MockMemory { bytes: vec![1, 0xFF], big_endian: false });
        let buf = MockBuf { addr: ram_address(0), memory };

        let comps = DynamicDataType::get_all_components(&r, &buf).expect("components expected");
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].as_ref().unwrap().get_offset(), 0);
    }

    #[test]
    fn get_all_components_none_without_memory() {
        struct NoMemBuf;
        impl MemBuffer for NoMemBuf {
            fn get_address(&self) -> Address {
                ram_address(0)
            }
            fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
                Ok(0)
            }
            fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
                0
            }
            fn is_big_endian(&self) -> bool {
                false
            }
        }
        let mut r = TestRepeated { name: "Rep".to_string(), ..Default::default() };
        r.set_stored_base_struct(leaf("record", 1));
        assert!(DynamicDataType::get_all_components(&r, &NoMemBuf).is_none());
    }
}
