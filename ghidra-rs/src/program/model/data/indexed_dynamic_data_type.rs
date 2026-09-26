//! Port of `ghidra.program.model.data.IndexedDynamicDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! Indexed Dynamic Data Type template. Used to create instances of the data type at a given
//! location in memory based on the data found there.
//!
//! This data structure is used when there is a structure with a key field in a header. The key
//! field, which is a number, sets which of a number of structures follows the header.
//!
//! ```text
//!     Header
//!        field a
//!        field b
//!        keyfield (value 1 means struct1 follows
//!                  value 2 means struct2 follows
//!                  .....
//!                  value n means structN follows
//!     Struct1 | Struct2 | ..... | StructN
//! ```
//!
//! The Java class is `public abstract class IndexedDynamicDataType extends DynamicDataType`,
//! already ported as a trait ([`DynamicDataType`]), so this trait extends it directly. It is a
//! *base* abstract class in Java (subclassed by concrete indexed structures, none of which are
//! part of this batch), matching this crate's established convention (see
//! [`RepeatCountDataType`](super::repeat_count_data_type::RepeatCountDataType), the closest
//! sibling of this exact shape) of porting such classes as traits with only test-module `Mock*`
//! implementors.
//!
//! # Private fields as `stored_*` accessors
//!
//! Every Java private field with no public getter is modeled as a required `stored_*` trait
//! method, mirroring [`RepeatCountDataType::stored_repeat_data_type`]'s identical convention.
//! The private `table` field (a `Long -> Integer` index) is *not* modeled as separate stored
//! state: it is always exactly derivable from `stored_keys`/`stored_structs` via
//! [`IndexedDynamicDataType::index_table`] using the *first* (multi-key) Java constructor's exact
//! population rule (populate `keys[i] -> i` only when `keys.length == structs.length`, else leave
//! empty -- reproducing that constructor's early-return-on-mismatch bug verbatim). This rule is
//! only ever actually *read* by [`get_all_components`](DynamicDataType::get_all_components) when
//! `stored_keys().len() != 1`; the second (single-key) Java constructor always forces
//! `keys = new long[] { singleKey }` (length 1), which makes `get_all_components` take the
//! `keys.length == 1` branch instead and never consult the table at all, so recomputing rather
//! than storing the single-key constructor's different (and dead, for this reason) `i -> i`
//! table population doesn't change any observable behavior.
//!
//! The two Java constructors also disagree, in a way worth calling out explicitly, on how `mask`
//! defaults when `0` is passed: the first constructor's `this.mask = mask;` runs *before* its own
//! `if (mask == 0) { mask = 0xFFFFFFFF; }`, and that later line only rebinds the local parameter
//! variable -- never `this.mask` -- so a `0` mask passed to the first constructor is silently
//! kept as `0`, not defaulted, unlike the second constructor's `this.mask = mask == 0 ?
//! 0xFFFFFFFF : mask;`. [`multi_key_mask`]/[`single_key_mask`] reproduce each constructor's rule
//! (bug included) as a pair of free functions a concrete implementor's own constructor can call.
//!
//! # Other adaptations
//!
//! `getAllComponents(MemBuffer)` overrides the abstract (no-default)
//! [`DynamicDataType::get_all_components`]; Rust does not allow a subtrait to redeclare a
//! supertrait method of the same name without making calls through `dyn IndexedDynamicDataType`
//! ambiguous, so the real algorithm is exposed here under the distinct name
//! [`indexed_all_components`](IndexedDynamicDataType::indexed_all_components). A concrete `impl
//! DynamicDataType for ...` should delegate `get_all_components` to it.
//!
//! `getDescription`/`getValue`/`getRepresentation`/`getMnemonic` share a name with an
//! already-provided default method on [`DataType`], so -- mirroring every other `BuiltIn`-derived
//! cut-point trait in this crate -- they are exposed here under distinct `indexed_*` names.
//!
//! `ReadOnlyDataTypeComponent`'s two constructor calls are replaced by a private
//! [`IndexedComponent`] struct implementing [`DataTypeComponent`], mirroring
//! [`RepeatCountDataType`]'s own `RepeatCountComponent` precedent for the identical reason: the
//! real (now-ported) [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent)
//! needs an `Arc<dyn DynamicDataType>` pointing at *this* component's parent, which a bare `&self`
//! default trait method has no way to produce.
//!
//! `MemoryBufferImpl` *is* used directly (now that it is real): unlike the parent-component
//! problem above, constructing one needs only the `Memory`/`Address` obtainable from the `buf`
//! parameter, not anything requiring an owning handle to `self`.
//!
//! The private `getIndex(Memory, Address)` helper is ported as the free function
//! [`read_index`], since it needs no access to any `IndexedDynamicDataType` field beyond the ones
//! already passed as parameters in the Java source.

use std::collections::HashMap;
use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_instance::get_data_type_instance;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::mem::{MemBuffer, Memory, MemoryBufferImpl, MutableMemBuffer};
use crate::program::seam_stubs::share_data_type;
use crate::util::Msg;

/// Port of `IndexedDynamicDataType.NULL_BODY_DESCRIPTION`: structures which do not have a body.
pub const NULL_BODY_DESCRIPTION: &str = "NullBody";

const LOG_ORIGINATOR: &str = "IndexedDynamicDataType";

/// Port of the first (multi-key) constructor's `mask` handling. See the module docs for the bug
/// this preserves: the Java `this.mask = mask;` assignment happens *before* this defaulting
/// check, so a caller-supplied `0` mask is never actually replaced.
pub fn multi_key_mask(mask: i64) -> i64 {
    mask
}

/// Port of the second (single-key) constructor's `mask` handling
/// (`this.mask = mask == 0 ? 0xFFFFFFFF : mask;`), which -- unlike [`multi_key_mask`] --
/// correctly defaults a `0` mask.
pub fn single_key_mask(mask: i64) -> i64 {
    if mask == 0 {
        0xFFFF_FFFFi64
    } else {
        mask
    }
}

/// Private stand-in for `ghidra.program.model.data.ReadOnlyDataTypeComponent`, used by
/// [`IndexedDynamicDataType::indexed_all_components`]. See the module docs for why the real class
/// is not used here.
struct IndexedComponent {
    data_type: Arc<dyn DataType>,
    length: i32,
    ordinal: i32,
    offset: i32,
    field_name: Option<String>,
    comment: Option<String>,
}

impl DataTypeComponent for IndexedComponent {
    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }
    fn get_length(&self) -> i32 {
        self.length
    }
    fn get_ordinal(&self) -> i32 {
        self.ordinal
    }
    fn get_offset(&self) -> i32 {
        self.offset
    }
    fn get_field_name(&self) -> Option<String> {
        self.field_name.clone()
    }
    fn get_comment(&self) -> Option<String> {
        self.comment.clone()
    }
}

/// Port of the private `IndexedDynamicDataType.getIndex(Memory, Address)`.
///
/// Reads `index_size` bytes (1, 2, 4, or 8) at `addr` from `memory`, zero-extending the 1/2/4-byte
/// cases to `i64` (mirroring `Byte`/`Short`/`Integer.toUnsignedLong`) and reading the 8-byte case
/// as a plain signed `i64` (mirroring `Memory.getLong`, which has no wider unsigned counterpart in
/// Java either). Returns `0` -- matching the Java method's own initial `long test = 0;` -- for any
/// other `index_size`, or if the read fails.
fn read_index(memory: &dyn Memory, addr: &Address, index_size: i32) -> i64 {
    match index_size {
        1 => memory.get_byte(addr).map(|b| b as i64).unwrap_or(0),
        2 => {
            let mut bytes = [0u8; 2];
            if memory.get_bytes(addr, &mut bytes) != 2 {
                return 0;
            }
            let raw = if memory.is_big_endian() {
                u16::from_be_bytes(bytes)
            } else {
                u16::from_le_bytes(bytes)
            };
            raw as i64
        }
        4 => {
            let mut bytes = [0u8; 4];
            if memory.get_bytes(addr, &mut bytes) != 4 {
                return 0;
            }
            let raw = if memory.is_big_endian() {
                u32::from_be_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes)
            };
            raw as i64
        }
        8 => {
            let mut bytes = [0u8; 8];
            if memory.get_bytes(addr, &mut bytes) != 8 {
                return 0;
            }
            if memory.is_big_endian() {
                i64::from_be_bytes(bytes)
            } else {
                i64::from_le_bytes(bytes)
            }
        }
        _ => 0,
    }
}

/// Indexed Dynamic Data Type template. See the module docs.
///
/// Port of `ghidra.program.model.data.IndexedDynamicDataType`.
pub trait IndexedDynamicDataType: DynamicDataType {
    /// The description of this data type. Mirrors the private `description` field (no public
    /// Java getter besides the overridden `getDescription()`, ported as
    /// [`indexed_description`](Self::indexed_description)).
    fn stored_description(&self) -> String;

    /// The header data type that holds the keys to the location of the other data types.
    fn stored_header(&self) -> Box<dyn DataType>;

    /// Key value array, one to one mapping to [`stored_structs`](Self::stored_structs).
    fn stored_keys(&self) -> Vec<i64>;

    /// `structs[n]` to use if the key value equals `keys[n]`; a `None` slot mirrors a `null`
    /// entry in Java's `DataType[]`.
    fn stored_structs(&self) -> Vec<Option<Box<dyn DataType>>>;

    /// Index into the header structure that holds the key value.
    fn stored_index_offset(&self) -> i64;

    /// Size of the key value in bytes.
    fn stored_index_size(&self) -> i32;

    /// Mask used on the key value to get the final key. See the module docs for why this must be
    /// stored (rather than derived) and for the two constructors' differing defaulting rules
    /// ([`multi_key_mask`]/[`single_key_mask`]).
    fn stored_mask(&self) -> i64;

    /// Port of the private `IndexedDynamicDataType.table` field, derived rather than stored. See
    /// the module docs for why this is safe (and for the early-return-on-mismatch bug it
    /// preserves from the first Java constructor).
    fn index_table(&self) -> HashMap<i64, i32> {
        let keys = self.stored_keys();
        let structs = self.stored_structs();
        let mut table = HashMap::new();
        if keys.len() == structs.len() {
            for (i, key) in keys.iter().enumerate() {
                table.insert(*key, i as i32);
            }
        }
        table
    }

    /// Port of `IndexedDynamicDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn indexed_description(&self) -> String {
        self.stored_description()
    }

    /// Port of `IndexedDynamicDataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Always `None`.
    fn indexed_value(
        &self,
        buf: &dyn MemBuffer,
        settings: &dyn Settings,
        length: i32,
    ) -> Option<Box<dyn std::any::Any>> {
        let _ = (buf, settings, length);
        None
    }

    /// Port of `IndexedDynamicDataType.getRepresentation(MemBuffer, Settings, int)`, which
    /// overrides the default `DataType.getRepresentation(...)`. Always empty.
    fn indexed_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        String::new()
    }

    /// Port of `IndexedDynamicDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Always this type's name.
    fn indexed_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Port of the protected `IndexedDynamicDataType.getAllComponents(MemBuffer)`, which overrides
    /// the abstract [`DynamicDataType::get_all_components`]. A concrete `impl DynamicDataType for
    /// ...` should delegate `get_all_components` to this.
    ///
    /// Returns `None` (logging an error, mirroring Java's `Msg.error(...); return null;` pattern)
    /// if the memory buffer has no backing [`Memory`], if the index location is unreadable/out of
    /// range, if the selected struct is unknown or `None`, or if the header/struct data-type
    /// instance cannot be determined at the buffer's address.
    fn indexed_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        let memory = buf.get_memory()?;
        let start = buf.get_address();

        // Find index.
        let index_addr = start.add(self.stored_index_offset()).ok()?;
        let index = read_index(memory.as_ref(), &index_addr, self.stored_index_size()) & self.stored_mask();

        let keys = self.stored_keys();
        let struct_index = if keys.len() == 1 {
            Some(if index == keys[0] { 0usize } else { 1usize })
        } else {
            self.index_table().get(&index).map(|i| *i as usize)
        };

        let Some(struct_index) = struct_index else {
            Msg::error(LOG_ORIGINATOR, &format!("ERROR in {} at {}", self.get_name(), start));
            return None;
        };

        let structs = self.stored_structs();
        let Some(Some(data)) = structs.get(struct_index) else {
            Msg::error(LOG_ORIGINATOR, &format!("ERROR in {} at {}", self.get_name(), start));
            return None;
        };

        let num_components = if data.get_description().eq_ignore_ascii_case(NULL_BODY_DESCRIPTION) {
            1
        } else {
            2
        };

        let new_buf = MemoryBufferImpl::new(memory.clone(), start.clone());
        let dti = get_data_type_instance(Some(self.stored_header()), &new_buf, false);
        let Some(dti) = dti else {
            Msg::error(LOG_ORIGINATOR, &format!("ERROR: problem with data at {}", new_buf.get_address()));
            return None;
        };

        let len = dti.get_length();
        let mut comps: Vec<Option<Box<dyn DataTypeComponent>>> = Vec::with_capacity(num_components);
        comps.push(Some(Box::new(IndexedComponent {
            data_type: Arc::from(self.stored_header()),
            length: len,
            ordinal: 0,
            offset: 0,
            field_name: Some(dti.get_data_type().get_name()),
            comment: Some(String::new()),
        })));

        if num_components > 1 {
            let count_size = len;
            let offset = count_size;
            let mut new_buf = MemoryBufferImpl::new(memory.clone(), start.clone());
            if new_buf.advance(count_size).is_err() {
                Msg::error(LOG_ORIGINATOR, &format!("ERROR: problem with data at {}", new_buf.get_address()));
                return None;
            }
            let data_for_instance = structs.into_iter().nth(struct_index).flatten()?;
            let dti2 = get_data_type_instance(Some(data_for_instance), &new_buf, false);
            let Some(dti2) = dti2 else {
                Msg::error(LOG_ORIGINATOR, &format!("ERROR: problem with data at {}", new_buf.get_address()));
                return None;
            };
            let len2 = dti2.get_length();
            let name2 = format!("{}_{}", dti2.get_data_type().get_name(), new_buf.get_address());
            comps.push(Some(Box::new(IndexedComponent {
                data_type: Arc::from(dti2.get_data_type()),
                length: len2,
                ordinal: 1,
                offset,
                field_name: Some(name2),
                comment: Some(String::new()),
            })));
        }

        Some(comps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::mem::MemoryAccessException;

    struct MockSettings;
    impl Settings for MockSettings {}

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        description: String,
    }

    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_description(&self) -> String {
            self.description.clone()
        }
        fn get_length(&self) -> i32 {
            1
        }
    }

    fn leaf(name: &str) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), description: String::new() })
    }

    fn null_body_leaf(name: &str) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), description: NULL_BODY_DESCRIPTION.to_string() })
    }

    /// Re-boxes a `MockLeaf`, preserving both its name and description (unlike constructing a
    /// fresh one via [`leaf`], which always resets the description).
    fn clone_mock_leaf(dt: &dyn DataType) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: dt.get_name(), description: dt.get_description() })
    }

    struct MockIndexed {
        header: Box<dyn DataType>,
        keys: Vec<i64>,
        structs: Vec<Option<Box<dyn DataType>>>,
        index_offset: i64,
        index_size: i32,
        mask: i64,
    }

    impl Clone for MockIndexed {
        fn clone(&self) -> Self {
            MockIndexed {
                header: clone_mock_leaf(self.header.as_ref()),
                keys: self.keys.clone(),
                structs: self
                    .structs
                    .iter()
                    .map(|s| s.as_ref().map(|d| clone_mock_leaf(d.as_ref())))
                    .collect(),
                index_offset: self.index_offset,
                index_size: self.index_size,
                mask: self.mask,
            }
        }
    }

    impl DataType for MockIndexed {
        fn get_name(&self) -> String {
            "indexed".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
    }
    impl BuiltInDataType for MockIndexed {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl Dynamic for MockIndexed {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
            -1
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            leaf("byte")
        }
    }
    impl DynamicDataType for MockIndexed {
        fn get_all_components(
            &self,
            buf: &dyn MemBuffer,
        ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            self.indexed_all_components(buf)
        }
    }
    impl IndexedDynamicDataType for MockIndexed {
        fn stored_description(&self) -> String {
            "mock indexed".to_string()
        }
        fn stored_header(&self) -> Box<dyn DataType> {
            clone_mock_leaf(self.header.as_ref())
        }
        fn stored_keys(&self) -> Vec<i64> {
            self.keys.clone()
        }
        fn stored_structs(&self) -> Vec<Option<Box<dyn DataType>>> {
            self.structs
                .iter()
                .map(|s| s.as_ref().map(|d| clone_mock_leaf(d.as_ref())))
                .collect()
        }
        fn stored_index_offset(&self) -> i64 {
            self.index_offset
        }
        fn stored_index_size(&self) -> i32 {
            self.index_size
        }
        fn stored_mask(&self) -> i64 {
            self.mask
        }
    }

    struct MockMemory {
        bytes: Vec<u8>,
        big_endian: bool,
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            self.big_endian
        }
        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(addr.offset() as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, addr: &Address, dest: &mut [u8]) -> usize {
            let start = addr.offset() as usize;
            if start >= self.bytes.len() {
                return 0;
            }
            let n = dest.len().min(self.bytes.len() - start);
            dest[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }
        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            Ok(())
        }
    }

    struct MockMemBuffer {
        memory: Arc<dyn Memory>,
        address: Address,
    }

    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            let addr = self.address.add_no_wrap(offset as i64).map_err(|e| MemoryAccessException::new(e.to_string()))?;
            self.memory.get_byte(&addr)
        }
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            match self.address.add_no_wrap(offset as i64) {
                Ok(addr) => self.memory.get_bytes(&addr, buf),
                Err(_) => 0,
            }
        }
        fn is_big_endian(&self) -> bool {
            self.memory.is_big_endian()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.memory.clone())
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    fn buffer_at(mem_bytes: Vec<u8>, big_endian: bool, offset: i64) -> MockMemBuffer {
        MockMemBuffer {
            memory: Arc::new(MockMemory { bytes: mem_bytes, big_endian }),
            address: addr(offset),
        }
    }

    fn two_struct_indexed() -> MockIndexed {
        MockIndexed {
            header: leaf("header"),
            keys: vec![1, 2],
            structs: vec![Some(leaf("struct_one")), Some(leaf("struct_two"))],
            index_offset: 0,
            index_size: 1,
            mask: 0xFF,
        }
    }

    #[test]
    fn index_table_maps_keys_to_ordinals_when_lengths_match() {
        let dt = two_struct_indexed();
        let table = dt.index_table();
        assert_eq!(table.get(&1), Some(&0));
        assert_eq!(table.get(&2), Some(&1));
    }

    #[test]
    fn index_table_is_empty_when_lengths_mismatch() {
        let dt = MockIndexed {
            keys: vec![1, 2, 3],
            structs: vec![Some(leaf("a"))],
            ..two_struct_indexed()
        };
        assert!(dt.index_table().is_empty());
    }

    #[test]
    fn multi_key_mask_preserves_the_zero_default_bug() {
        assert_eq!(multi_key_mask(0), 0);
        assert_eq!(multi_key_mask(0xFF), 0xFF);
    }

    #[test]
    fn single_key_mask_defaults_zero_correctly() {
        assert_eq!(single_key_mask(0), 0xFFFF_FFFF);
        assert_eq!(single_key_mask(0xFF), 0xFF);
    }

    #[test]
    fn indexed_description_and_mnemonic() {
        let dt = two_struct_indexed();
        assert_eq!(dt.indexed_description(), "mock indexed");
        assert_eq!(dt.indexed_mnemonic(&MockSettings), "indexed");
    }

    #[test]
    fn indexed_value_and_representation_are_trivial() {
        let dt = two_struct_indexed();
        let buf = buffer_at(vec![1], true, 0);
        assert!(dt.indexed_value(&buf, &MockSettings, 1).is_none());
        assert_eq!(dt.indexed_representation(&buf, &MockSettings, 1), "");
    }

    #[test]
    fn all_components_selects_struct_by_key_and_builds_header_plus_body() {
        let dt = two_struct_indexed();
        // Byte at offset 0 is the key: 2 selects struct_two.
        let buf = buffer_at(vec![2, 0xAA], true, 0);
        let comps = dt.indexed_all_components(&buf).expect("components");
        assert_eq!(comps.len(), 2);
        let header_comp = comps[0].as_ref().unwrap();
        assert_eq!(header_comp.get_field_name(), Some("header".to_string()));
        assert_eq!(header_comp.get_offset(), 0);
        let body_comp = comps[1].as_ref().unwrap();
        assert_eq!(body_comp.get_offset(), 1);
        assert!(body_comp.get_field_name().unwrap().starts_with("struct_two_"));
    }

    #[test]
    fn all_components_selects_first_struct_for_matching_key() {
        let dt = two_struct_indexed();
        let buf = buffer_at(vec![1, 0xAA], true, 0);
        let comps = dt.indexed_all_components(&buf).expect("components");
        let body_comp = comps[1].as_ref().unwrap();
        assert!(body_comp.get_field_name().unwrap().starts_with("struct_one_"));
    }

    #[test]
    fn all_components_null_body_struct_yields_a_single_component() {
        let dt = MockIndexed {
            structs: vec![Some(null_body_leaf("struct_one")), Some(leaf("struct_two"))],
            ..two_struct_indexed()
        };
        let buf = buffer_at(vec![1], true, 0);
        let comps = dt.indexed_all_components(&buf).expect("components");
        assert_eq!(comps.len(), 1);
    }

    #[test]
    fn all_components_unmatched_key_returns_none() {
        let dt = two_struct_indexed();
        let buf = buffer_at(vec![99], true, 0);
        assert!(dt.indexed_all_components(&buf).is_none());
    }

    #[test]
    fn all_components_null_struct_slot_returns_none() {
        let dt = MockIndexed {
            structs: vec![Some(leaf("struct_one")), None],
            ..two_struct_indexed()
        };
        let buf = buffer_at(vec![2], true, 0);
        assert!(dt.indexed_all_components(&buf).is_none());
    }

    #[test]
    fn single_key_style_uses_two_way_branch_regardless_of_table() {
        // Mirrors the second Java constructor: keys always has exactly one entry, so the
        // `keys.length == 1` branch is always taken and `index_table` (which would otherwise be
        // empty here, since `structs.len() != keys.len()`) is never consulted.
        let dt = MockIndexed {
            keys: vec![5],
            structs: vec![Some(leaf("matches")), Some(leaf("else"))],
            index_offset: 0,
            index_size: 1,
            mask: single_key_mask(0),
            header: leaf("header"),
        };
        assert!(dt.index_table().is_empty());

        let matching_buf = buffer_at(vec![5], true, 0);
        let comps = dt.indexed_all_components(&matching_buf).expect("components");
        assert!(comps[1].as_ref().unwrap().get_field_name().unwrap().starts_with("matches_"));

        let other_buf = buffer_at(vec![7], true, 0);
        let comps = dt.indexed_all_components(&other_buf).expect("components");
        assert!(comps[1].as_ref().unwrap().get_field_name().unwrap().starts_with("else_"));
    }

    #[test]
    fn all_components_returns_none_without_backing_memory() {
        struct NoMemoryBuffer(Address);
        impl MemBuffer for NoMemoryBuffer {
            fn get_address(&self) -> Address {
                self.0.clone()
            }
            fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
                Err(MemoryAccessException::new("no memory"))
            }
            fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
                0
            }
            fn is_big_endian(&self) -> bool {
                true
            }
        }

        let dt = two_struct_indexed();
        let buf = NoMemoryBuffer(addr(0));
        assert!(dt.indexed_all_components(&buf).is_none());
    }

    #[test]
    fn read_index_reads_multi_byte_values_respecting_endianness() {
        let mem_be = MockMemory { bytes: vec![0x00, 0x01], big_endian: true };
        assert_eq!(read_index(&mem_be, &addr(0), 2), 1);

        let mem_le = MockMemory { bytes: vec![0x00, 0x01], big_endian: false };
        assert_eq!(read_index(&mem_le, &addr(0), 2), 0x0100);
    }

    #[test]
    fn read_index_unsupported_size_is_zero() {
        let mem = MockMemory { bytes: vec![0xFF, 0xFF, 0xFF], big_endian: true };
        assert_eq!(read_index(&mem, &addr(0), 3), 0);
    }
}
