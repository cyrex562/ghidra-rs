//! Port of `ghidra.program.model.data.RepeatCountDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class is `public abstract class RepeatCountDataType extends DynamicDataType`, already
//! ported as a trait ([`DynamicDataType`]), so this trait extends it directly. It is a *base*
//! abstract class in Java (subclassed by concrete repeat-count structures, none of which are part
//! of this batch), matching this crate's established convention of porting such leaf/near-leaf
//! `DataType`s as traits with only test-module `Mock*` implementors.
//!
//! `getAllComponents(MemBuffer)` overrides the abstract (no-default)
//! [`DynamicDataType::get_all_components`]; Rust does not allow a subtrait to redeclare a
//! supertrait method of the same name without making calls through `dyn RepeatCountDataType`
//! ambiguous (mirroring every other cut-point trait in this crate that hits the same restriction),
//! so the real algorithm is exposed here under the distinct name
//! [`repeat_count_all_components`](RepeatCountDataType::repeat_count_all_components). A concrete
//! `impl DynamicDataType for ...` should delegate `get_all_components` to it.
//!
//! Two of the Java method's own dependencies are themselves not yet ported
//! (`MemoryBufferImpl`/`ReadOnlyDataTypeComponent`), so this port reproduces the same observable
//! algorithm without them:
//! - `MemoryBufferImpl` (a fresh, independently-advanceable [`MemBuffer`] view starting at `buf`'s
//!   address) is replaced by [`OffsetMemBuffer`], a private, purely-additive offset wrapper around
//!   the original `buf` -- avoiding both the not-yet-ported concrete type and the need for any
//!   `&mut` "advance" mutation, since each loop iteration can simply compute a fresh cumulative
//!   offset instead of mutating shared state. This also means the Java `catch
//!   (AddressOverflowException | AddressOutOfBoundsException ...)` guard around
//!   `newBuf.advance(len)` has no counterpart here: no address arithmetic that could overflow or
//!   go out of bounds is performed, since offsets are tracked as plain `i32`s relative to the
//!   original `buf`, not as real advancing addresses. `MemoryAccessException` from the initial
//!   `buf.getByte(0)`/`buf.getByte(1)` reads *is* ported, collapsing to `None` via `?`.
//! - `ReadOnlyDataTypeComponent`'s constructor calls are replaced by a private
//!   [`RepeatCountComponent`] struct implementing [`DataTypeComponent`] (whose every method
//!   already has a default -- see that trait's own documentation -- so only the handful of fields
//!   this class actually sets need overriding).
//! - `new WordDataType()` (for the leading "Size" component's data type) has no concrete
//!   constructible counterpart yet (`WordDataType` is a trait with only `Mock*` test
//!   implementors, per this crate's established convention for such leaf types), so a minimal
//!   local [`WordPlaceholderDataType`] stands in, mirroring
//!   [`DynamicDataType`]'s own `BytePlaceholderDataType` precedent for the identical situation.
//!
//! `getValue`/`getRepresentation`/`getMnemonic` share a name with an already-provided default
//! method on [`DataType`], so -- mirroring every other `BuiltIn`-derived cut-point trait in this
//! crate -- they are exposed here under distinct `repeat_count_*` names.
//!
//! The private `repeatDataType` field is modeled as the required
//! [`stored_repeat_data_type`](RepeatCountDataType::stored_repeat_data_type) accessor, mirroring
//! [`PointerDataType::stored_referenced_data_type`](super::pointer_data_type::PointerDataType::stored_referenced_data_type)'s
//! convention for a private field with no public getter in the Java source.

use std::any::Any;
use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::data_type_instance::get_data_type_instance;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::mem::{MemBuffer, MemoryAccessException};
use crate::program::seam_stubs::share_data_type;

/// Minimal stand-in for `ghidra.program.model.data.WordDataType.dataType`, used for the leading
/// "Size" component's data type until a concrete `WordDataType` singleton is ported. Mirrors
/// [`DynamicDataType`]'s own `BytePlaceholderDataType` precedent.
struct WordPlaceholderDataType;

impl DataType for WordPlaceholderDataType {
    fn get_length(&self) -> i32 {
        2
    }
    fn get_name(&self) -> String {
        "word".to_string()
    }
}

/// Private stand-in for `ghidra.program.model.data.ReadOnlyDataTypeComponent`, used by
/// [`RepeatCountDataType::repeat_count_all_components`]. See the module docs for why the real
/// class is not ported/used here.
struct RepeatCountComponent {
    /// `Arc` rather than `Box` so [`get_data_type`](DataTypeComponent::get_data_type) can hand
    /// back an independent share of it on every call, the same pattern
    /// [`DataTypeInstanceImpl`](crate::program::model::data::data_type_instance)'s own
    /// `get_data_type` uses via
    /// [`share_data_type`](crate::program::seam_stubs::share_data_type).
    data_type: Arc<dyn DataType>,
    length: i32,
    ordinal: i32,
    offset: i32,
    field_name: Option<String>,
    comment: Option<String>,
}

impl DataTypeComponent for RepeatCountComponent {
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

/// A purely-additive offset view over another [`MemBuffer`], standing in for the Java
/// `MemoryBufferImpl` used to walk forward through `buf` one repeated element at a time. See the
/// module docs for why this replaces that not-yet-ported concrete type.
struct OffsetMemBuffer<'a> {
    inner: &'a dyn MemBuffer,
    offset: i32,
}

impl MemBuffer for OffsetMemBuffer<'_> {
    fn get_address(&self) -> Address {
        self.inner.get_address().add_wrap(self.offset as i64)
    }
    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.inner.get_byte(self.offset + offset)
    }
    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.inner.get_bytes(buf, self.offset + offset)
    }
    fn is_big_endian(&self) -> bool {
        self.inner.is_big_endian()
    }
}

/// Base abstract data type for a Dynamic structure data type that contains some number of
/// repeated data types. The first entry contains the number of repeated data types to follow.
/// Immediately following the first element are the repeated data types.
///
/// The dynamic structure looks like this:
/// ```text
///    RepeatDataType
///       number = N   - two bytes, little endian
///       RepDT1
///       repDT2
///       ...
///       repDTN
/// ```
///
/// Port of `ghidra.program.model.data.RepeatCountDataType`. See the module docs for what was
/// ported, added, and omitted.
pub trait RepeatCountDataType: DynamicDataType {
    /// Backing storage for the private `repeatDataType` field: the data type repeated after the
    /// leading count.
    fn stored_repeat_data_type(&self) -> Box<dyn DataType>;

    /// Port of `RepeatCountDataType.getAllComponents(MemBuffer)`, which overrides the abstract
    /// [`DynamicDataType::get_all_components`]. See the module docs for what replaces
    /// `MemoryBufferImpl`/`ReadOnlyDataTypeComponent`/`new WordDataType()`.
    fn repeat_count_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        let b0 = buf.get_byte(0).ok()? as i32;
        let b1 = buf.get_byte(1).ok()? as i32;
        let n = b0 * 16 + b1 + 1;

        let size_component = RepeatCountComponent {
            data_type: Arc::new(WordPlaceholderDataType),
            length: 2,
            ordinal: 0,
            offset: 0,
            field_name: Some("Size".to_string()),
            comment: Some(String::new()),
        };
        let count_size = size_component.get_length();

        let mut comps: Vec<Option<Box<dyn DataTypeComponent>>> = Vec::with_capacity(n as usize);
        comps.push(Some(Box::new(size_component) as Box<dyn DataTypeComponent>));

        let mut offset = count_size;
        for i in 1..n {
            let view = OffsetMemBuffer { inner: buf, offset };
            let dti = get_data_type_instance(Some(self.stored_repeat_data_type()), &view, false)?;
            let len = dti.get_length();
            comps.push(Some(Box::new(RepeatCountComponent {
                data_type: Arc::from(dti.get_data_type()),
                length: len,
                ordinal: i,
                offset,
                field_name: None,
                comment: None,
            }) as Box<dyn DataTypeComponent>));
            offset += len;
        }
        Some(comps)
    }

    /// Port of `RepeatCountDataType.getValue(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getValue(...)`. Always `None`.
    fn repeat_count_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (buf, settings, length);
        None
    }

    /// Port of `RepeatCountDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides
    /// the default `DataType.getRepresentation(...)`. Always `""`.
    fn repeat_count_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        let _ = (buf, settings, length);
        String::new()
    }

    /// Port of `RepeatCountDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`. Returns this type's own name, matching the Java `return
    /// name;` (the protected `BuiltIn`/`DataType` field backing [`DataType::get_name`]).
    fn repeat_count_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, SpecialAddress};
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::{CategoryPath, ROOT};
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::dynamic::Dynamic;
    use std::sync::Arc;

    struct MockSettings;
    impl Settings for MockSettings {}

    /// Stand-in "repeated" data type: a fixed 1-byte value, always producing a
    /// [`DataTypeInstance`](crate::program::model::data::data_type_instance::DataTypeInstance) of
    /// length 1 (mirroring how [`get_data_type_instance`] handles an ordinary fixed-length,
    /// non-`Dynamic`, non-factory data type).
    #[derive(Clone)]
    struct OneByteDataType;
    impl DataType for OneByteDataType {
        fn get_name(&self) -> String {
            "byte1".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            1
        }
    }

    struct FixedMemBuffer {
        bytes: Vec<u8>,
        space: Arc<AddressSpace>,
    }
    impl MemBuffer for FixedMemBuffer {
        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            let start = offset as usize;
            let mut n = 0;
            for (i, slot) in buf.iter_mut().enumerate() {
                match self.bytes.get(start + i) {
                    Some(&b) => {
                        *slot = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
        fn is_big_endian(&self) -> bool {
            true
        }
        fn get_address(&self) -> Address {
            self.space.address(0)
        }
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[derive(Clone)]
    struct MockRepeatCount;

    impl DataType for MockRepeatCount {
        fn get_name(&self) -> String {
            "RepeatCount".to_string()
        }
        fn get_category_path(&self) -> CategoryPath {
            ROOT.clone()
        }
        fn get_length(&self) -> i32 {
            -1
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.repeat_count_mnemonic(settings)
        }
        fn get_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
            self.repeat_count_representation(buf, settings, length)
        }
        fn get_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
            self.repeat_count_value(buf, settings, length)
        }
    }

    impl BuiltInDataType for MockRepeatCount {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockRepeatCount {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.dynamic_length_from_components(buf, max_length)
        }
        fn can_specify_length(&self) -> bool {
            false
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.default_replacement_base_type()
        }
    }

    impl DynamicDataType for MockRepeatCount {
        fn get_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            self.repeat_count_all_components(buf)
        }
    }

    impl RepeatCountDataType for MockRepeatCount {
        fn stored_repeat_data_type(&self) -> Box<dyn DataType> {
            Box::new(OneByteDataType)
        }
    }

    #[test]
    fn mnemonic_returns_the_type_name() {
        let dt = MockRepeatCount;
        assert_eq!(dt.repeat_count_mnemonic(&MockSettings), "RepeatCount");
    }

    #[test]
    fn value_is_always_none() {
        let dt = MockRepeatCount;
        let buf = FixedMemBuffer { bytes: vec![0, 0], space: ram_space() };
        assert!(dt.repeat_count_value(&buf, &MockSettings, 0).is_none());
    }

    #[test]
    fn representation_is_always_empty() {
        let dt = MockRepeatCount;
        let buf = FixedMemBuffer { bytes: vec![0, 0], space: ram_space() };
        assert_eq!(dt.repeat_count_representation(&buf, &MockSettings, 0), "");
    }

    #[test]
    fn all_components_includes_the_leading_size_component() {
        let dt = MockRepeatCount;
        // n = 0*16 + 0 + 1 = 1: just the "Size" component, no repeated elements.
        let buf = FixedMemBuffer { bytes: vec![0x00, 0x00], space: ram_space() };
        let comps = dt.repeat_count_all_components(&buf).unwrap();
        assert_eq!(comps.len(), 1);
        let size = comps[0].as_ref().unwrap();
        assert_eq!(size.get_field_name(), Some("Size".to_string()));
        assert_eq!(size.get_length(), 2);
        assert_eq!(size.get_offset(), 0);
        assert_eq!(size.get_ordinal(), 0);
    }

    #[test]
    fn all_components_lays_out_repeated_elements_after_the_size() {
        let dt = MockRepeatCount;
        // n = 0*16 + 2 + 1 = 3: the Size component plus two 1-byte repeated elements.
        let buf = FixedMemBuffer {
            bytes: vec![0x00, 0x02, 0xAA, 0xBB],
            space: ram_space(),
        };
        let comps = dt.repeat_count_all_components(&buf).unwrap();
        assert_eq!(comps.len(), 3);
        let first = comps[1].as_ref().unwrap();
        assert_eq!(first.get_ordinal(), 1);
        assert_eq!(first.get_offset(), 2);
        assert_eq!(first.get_length(), 1);
        let second = comps[2].as_ref().unwrap();
        assert_eq!(second.get_ordinal(), 2);
        assert_eq!(second.get_offset(), 3);
        assert_eq!(second.get_length(), 1);
    }

    #[test]
    fn all_components_none_when_the_leading_count_read_fails() {
        let dt = MockRepeatCount;
        let buf = FixedMemBuffer { bytes: vec![0x00], space: ram_space() };
        assert!(dt.repeat_count_all_components(&buf).is_none());
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockRepeatCount;
        let dyn_dt: &dyn RepeatCountDataType = &dt;
        assert_eq!(dyn_dt.stored_repeat_data_type().get_name(), "byte1");
    }
}
