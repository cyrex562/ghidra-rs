//! Port of `ghidra.program.model.data.DataTypeInstance`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! Unlike most other `DataType`-family ports in this crate, the Java class is never subclassed
//! anywhere in the Ghidra codebase -- it is a plain, `final`-in-spirit value holder (a `DataType`
//! paired with a fixed `length`) constructed exclusively through its own static
//! `getDataTypeInstance(...)` factory methods, whose (`protected`) constructor no other class can
//! call. Because there is exactly one concrete shape, this port pairs the trait with a private
//! backing struct ([`DataTypeInstanceImpl`]) so the ported factory functions below
//! ([`get_data_type_instance`], [`get_data_type_instance_with_length`],
//! [`get_data_type_instance_at`]) can actually construct and return a working
//! `Box<dyn DataTypeInstance>`, rather than leaving them unmodeled the way e.g.
//! [`PointerDataType`](crate::program::model::data::pointer_data_type::PointerDataType)'s own
//! unconstructible static factories are left unmodeled.
//!
//! `getDataType()`/`getLength()`/`setLength(int)` map directly to
//! [`DataTypeInstance::get_data_type`]/[`DataTypeInstance::get_length`]/
//! [`DataTypeInstance::set_length`]. `toString()` (inherited from `AbstractDataType`, which
//! overrides it to return `getDisplayName()`) is modeled as a blanket `impl
//! std::fmt::Display for dyn DataTypeInstance` below rather than a trait method, since Java's
//! `Object.toString()` has no direct trait-method counterpart in this port.
//!
//! The three static `getDataTypeInstance` overloads are modeled as free functions rather than
//! trait methods (mirroring how [`PointerDataType`]'s own static factories would be modeled if
//! they were constructible) since none of them take a `DataTypeInstance` receiver:
//! - `getDataTypeInstance(DataType, MemBuffer, boolean)` -> [`get_data_type_instance`]
//! - `getDataTypeInstance(DataType, int, boolean)` -> [`get_data_type_instance_with_length`]
//! - `getDataTypeInstance(DataType, MemBuffer, int, boolean)` -> [`get_data_type_instance_at`]
//!
//! Each `instanceof` check in the Java source is resolved against an existing (or, for
//! `Dynamic`/`FactoryDataType`, newly added) downcast stand-in on
//! [`DataType`](crate::program::model::data::data_type::DataType): `instanceof FactoryDataType`
//! -> [`DataType::as_factory`] (new), `instanceof FunctionDefinition` ->
//! [`DataType::is_function_definition_type`] (pre-existing), `instanceof TypeDef` ->
//! [`DataType::is_typedef`] + [`DataType::typedef_base_data_type`] (pre-existing), `instanceof
//! Dynamic` -> [`DataType::as_dynamic`] (new). [`DataType::as_factory`]/[`DataType::as_dynamic`]
//! were added following the exact precedent of [`DataType::as_pointer`]/[`DataType::as_structure`]
//! (a defaulted `None`, overridden by implementors that actually are that kind of datatype) since
//! both `FactoryDataType`/`Dynamic` are already fully ported traits in this crate (unlike a true
//! placeholder, no `seam_stubs.rs` entry is needed here).
//!
//! The `isFunctionDef` branch (shared by [`get_data_type_instance_with_length`]/
//! [`get_data_type_instance_at`]) replaces `dataType` with `new PointerDataType(dataType, -1,
//! dataType.getDataTypeManager())` in Java, purely so the subsequent `dataType.getLength()` call
//! resolves to the pointer's dynamic length (its `DataOrganization`'s pointer size, since the
//! constructed pointer is given length `-1`). This port cannot construct a concrete
//! `PointerDataType` generically (see that trait's own module docs for the identical limitation
//! on its `getPointer(...)` factories), so rather than reproducing the wrapper object, this port
//! computes the same resulting length directly via
//! `data_type.get_data_organization().get_pointer_size()` and leaves `dataType` itself unwrapped.
//! This is a known, deliberate divergence: the returned instance's [`DataTypeInstance::get_data_type`]
//! yields the original function-definition (or typedef-of-function-definition) datatype rather
//! than a pointer to it, while [`DataTypeInstance::get_length`] still reports the correct
//! (pointer-sized) length every caller in this codebase actually observes.
//!
//! The private constructor's own length fallback --
//! `if (length < 1) { length = dt.getLength() > 0 ? dt.getLength() : 1; }` -- recomputes a local
//! variable that is never written back to `this.length` in the Java source (the assignment
//! target `length` there is the constructor parameter/local, not `this.length`), making it dead
//! code; every call site already guards `length < 0` before constructing, so this cannot be
//! observed either way. [`DataTypeInstanceImpl::new`] mirrors the Java source byte-for-byte
//! (including the dead recompute) for fidelity rather than "fixing" it.
//!
//! [`DataTypeInstanceImpl::get_data_type`] hands back a fresh handle sharing the stored
//! `Arc<dyn DataType>` via
//! [`share_data_type`](crate::program::seam_stubs::share_data_type), the same helper already used
//! elsewhere in this crate for re-exposing a shared `DataType` as an owned `Box<dyn DataType>`.

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::seam_stubs::{share_data_type};
use crate::program::model::mem::MemBuffer;

/// An instance of a [`DataType`] that is applicable for a given context. Most data types are not
/// context sensitive and are suitable for use anywhere. Others, like dynamic structures, need to
/// create an instance that wraps the data type.
///
/// It helps for situations where a data type must have a length.
///
/// Port of `ghidra.program.model.data.DataTypeInstance`. See the module-level documentation for
/// why this is paired with a private concrete backing type instead of being left to an
/// implementor, and for how the static `getDataTypeInstance(...)` factories are modeled.
pub trait DataTypeInstance {
    /// Returns the data type.
    fn get_data_type(&self) -> Box<dyn DataType>;

    /// Returns the fixed length of the data type.
    fn get_length(&self) -> i32;

    /// Sets the length of this data type instance.
    fn set_length(&mut self, length: i32);
}

impl std::fmt::Display for dyn DataTypeInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_data_type().get_display_name())
    }
}

/// Sole concrete backing type for [`DataTypeInstance`]. See the module-level documentation for
/// why a single private struct (rather than requiring callers to supply their own implementor) is
/// appropriate here.
struct DataTypeInstanceImpl {
    data_type: Arc<dyn DataType>,
    length: i32,
}

impl DataTypeInstanceImpl {
    /// Port of the private `DataTypeInstance(DataType, int)` constructor, including its dead
    /// length-fallback recompute -- see the module-level documentation.
    fn new(data_type: Box<dyn DataType>, length: i32) -> Self {
        if length < 1 {
            let _ = if data_type.get_length() > 0 {
                data_type.get_length()
            } else {
                1
            };
        }
        DataTypeInstanceImpl {
            data_type: Arc::from(data_type),
            length,
        }
    }
}

impl DataTypeInstance for DataTypeInstanceImpl {
    fn get_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }

    fn get_length(&self) -> i32 {
        self.length
    }

    fn set_length(&mut self, length: i32) {
        self.length = length;
    }
}

/// Determine whether `data_type` (already known not to be a factory type) is, or is a typedef of,
/// a `FunctionDefinition`. Shared by [`get_data_type_instance_with_length`]/
/// [`get_data_type_instance_at`]; port of the shared `isFunctionDef`/`TypeDef` check duplicated
/// in both Java overloads.
fn is_function_definition(data_type: &dyn DataType) -> bool {
    if data_type.is_typedef() {
        data_type
            .typedef_base_data_type()
            .map(|base| base.is_function_definition_type())
            .unwrap_or(false)
    } else {
        data_type.is_function_definition_type()
    }
}

/// Generate a data-type instance. Factory and Dynamic data-types are NOT handled.
///
/// This container does not dictate the placement of a fixed-length type within this container.
/// It is suggested that big-endian use should evaluate the datatype at the far end of the
/// container.
///
/// `use_aligned_length`: if true a fixed-length primitive data type will use its aligned-length,
/// otherwise it will use its raw length. This should generally be true for a
/// `DataTypeComponent` and false for a simple `Data` instance.
///
/// Returns a data-type instance, or `None` if one could not be determined.
///
/// Port of the public static `DataTypeInstance.getDataTypeInstance(DataType, MemBuffer,
/// boolean)`.
pub fn get_data_type_instance(
    data_type: Option<Box<dyn DataType>>,
    buf: &dyn MemBuffer,
    use_aligned_length: bool,
) -> Option<Box<dyn DataTypeInstance>> {
    get_data_type_instance_at(data_type, buf, -1, use_aligned_length)
}

/// Attempt to create a fixed-length data-type instance. Factory and non-sizable Dynamic
/// data-types are NOT handled.
///
/// `length` is used for sizable Dynamic data-types, otherwise ignored. `use_aligned_length` is as
/// described on [`get_data_type_instance`].
///
/// Returns a data-type instance, or `None` if unable to create one.
///
/// Port of the public static `DataTypeInstance.getDataTypeInstance(DataType, int, boolean)`.
pub fn get_data_type_instance_with_length(
    data_type: Option<Box<dyn DataType>>,
    length: i32,
    use_aligned_length: bool,
) -> Option<Box<dyn DataTypeInstance>> {
    let data_type = data_type?;
    if data_type.as_factory().is_some() {
        return None;
    }

    let (data_type, length) = if is_function_definition(data_type.as_ref()) {
        let length = data_type.get_data_organization().get_pointer_size();
        (data_type, length)
    } else if let Some(dynamic) = data_type.as_dynamic() {
        if length <= 0 || !dynamic.can_specify_length() {
            return None;
        }
        (data_type, length)
    } else if use_aligned_length {
        let length = data_type.get_aligned_length();
        (data_type, length)
    } else {
        let length = data_type.get_length();
        (data_type, length)
    };

    if length < 0 {
        return None;
    }
    Some(Box::new(DataTypeInstanceImpl::new(data_type, length)))
}

/// Attempt to create a data-type instance associated with a specific memory location. Factory
/// and Dynamic data-types are handled.
///
/// This container does not dictate the placement of a fixed-length type within this container.
/// It is suggested that big-endian use should evaluate the datatype at the far end of the
/// container.
///
/// `length` is used for sizable Dynamic data-types, otherwise ignored. `use_aligned_length` is as
/// described on [`get_data_type_instance`].
///
/// Returns a data-type instance, or `None` if unable to create one.
///
/// Port of the public static `DataTypeInstance.getDataTypeInstance(DataType, MemBuffer, int,
/// boolean)`.
pub fn get_data_type_instance_at(
    data_type: Option<Box<dyn DataType>>,
    buf: &dyn MemBuffer,
    length: i32,
    use_aligned_length: bool,
) -> Option<Box<dyn DataTypeInstance>> {
    let (data_type, length) = match data_type {
        Some(dt) => {
            if let Some(factory) = dt.as_factory() {
                (factory.get_data_type(buf), -1)
            } else {
                (dt, length)
            }
        }
        None => return None,
    };

    let (data_type, length) = if is_function_definition(data_type.as_ref()) {
        let length = data_type.get_data_organization().get_pointer_size();
        (data_type, length)
    } else if let Some(dynamic) = data_type.as_dynamic() {
        let length = dynamic.get_dynamic_length(buf, length);
        (data_type, length)
    } else if use_aligned_length {
        let length = data_type.get_aligned_length();
        (data_type, length)
    } else {
        let length = data_type.get_length();
        (data_type, length)
    };

    if length < 0 {
        return None;
    }
    Some(Box::new(DataTypeInstanceImpl::new(data_type, length)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::data::factory_data_type::FactoryDataType;

    #[derive(Clone)]
    struct MockDataOrganization {
        pointer_size: i32,
    }
    impl DataOrganization for MockDataOrganization {
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_pointer_size(&self) -> i32 {
            self.pointer_size
        }
        fn get_pointer_shift(&self) -> i32 {
            0
        }
        fn is_signed_char(&self) -> bool {
            true
        }
        fn get_char_size(&self) -> i32 {
            1
        }
        fn get_wide_char_size(&self) -> i32 {
            2
        }
        fn get_short_size(&self) -> i32 {
            2
        }
        fn get_integer_size(&self) -> i32 {
            4
        }
        fn get_long_size(&self) -> i32 {
            4
        }
        fn get_long_long_size(&self) -> i32 {
            8
        }
        fn get_float_size(&self) -> i32 {
            4
        }
        fn get_double_size(&self) -> i32 {
            8
        }
        fn get_long_double_size(&self) -> i32 {
            8
        }
        fn get_absolute_max_alignment(&self) -> i32 {
            crate::program::model::data::data_organization::NO_MAXIMUM_ALIGNMENT
        }
        fn get_machine_alignment(&self) -> i32 {
            4
        }
        fn get_default_alignment(&self) -> i32 {
            1
        }
        fn get_default_pointer_alignment(&self) -> i32 {
            4
        }
        fn get_size_alignment(&self, size: i32) -> i32 {
            size
        }
        fn get_bit_field_packing(
            &self,
        ) -> Box<dyn crate::program::model::data::bit_field_packing::BitFieldPacking> {
            struct P;
            impl crate::program::model::data::bit_field_packing::BitFieldPacking for P {
                fn use_ms_convention(&self) -> bool {
                    false
                }
                fn is_type_alignment_enabled(&self) -> bool {
                    true
                }
                fn get_zero_length_boundary(&self) -> i32 {
                    0
                }
            }
            Box::new(P)
        }
        fn get_size_alignment_count(&self) -> i32 {
            4
        }
        fn get_sizes(&self) -> Vec<i32> {
            vec![1, 2, 4, 8]
        }
        fn get_integer_c_type_approximation(&self, _size: i32, _signed: bool) -> String {
            "int".to_string()
        }
        fn get_alignment(&self, _data_type: &dyn DataType) -> i32 {
            1
        }
    }

    #[derive(Clone)]
    struct MockDataType {
        name: String,
        length: i32,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_aligned_length(&self) -> i32 {
            self.length + 1
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { pointer_size: 4 })
        }
        fn clone_data_type(
            &self,
            _dtm: &dyn crate::program::model::data::data_type_manager::DataTypeManager,
        ) -> Box<dyn DataType> {
            Box::new(self.clone())
        }
    }

    struct MockFunctionDefDataType {
        length: i32,
    }
    impl DataType for MockFunctionDefDataType {
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_data_organization(&self) -> Box<dyn DataOrganization> {
            Box::new(MockDataOrganization { pointer_size: 8 })
        }
        fn is_function_definition_type(&self) -> bool {
            true
        }
    }

    struct MockDynamicDataType {
        can_specify: bool,
    }
    impl DataType for MockDynamicDataType {
        fn get_length(&self) -> i32 {
            -1
        }
        fn as_dynamic(&self) -> Option<&dyn Dynamic> {
            Some(self)
        }
    }
    impl crate::program::model::data::built_in_data_type::BuiltInDataType for MockDynamicDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl Dynamic for MockDynamicDataType {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, max_length: i32) -> i32 {
            max_length
        }
        fn can_specify_length(&self) -> bool {
            self.can_specify
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: "undefined".to_string(),
                length: 1,
            })
        }
    }

    struct MockFactoryDataType {
        produced_name: String,
    }
    impl DataType for MockFactoryDataType {
        fn get_length(&self) -> i32 {
            -1
        }
        fn as_factory(&self) -> Option<&dyn FactoryDataType> {
            Some(self)
        }
    }
    impl crate::program::model::data::built_in_data_type::BuiltInDataType for MockFactoryDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn crate::docking::settings::settings::Settings) {}
    }
    impl FactoryDataType for MockFactoryDataType {
        fn get_data_type(&self, _buf: &dyn MemBuffer) -> Box<dyn DataType> {
            Box::new(MockDataType {
                name: self.produced_name.clone(),
                length: 4,
            })
        }
    }

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut inst: Box<dyn DataTypeInstance> = Box::new(DataTypeInstanceImpl::new(
            Box::new(MockDataType {
                name: "int".to_string(),
                length: 4,
            }),
            4,
        ));
        assert_eq!(inst.get_length(), 4);
        assert_eq!(inst.get_data_type().get_name(), "int");
        inst.set_length(8);
        assert_eq!(inst.get_length(), 8);
    }

    #[test]
    fn display_delegates_to_data_type_display_name() {
        let inst: Box<dyn DataTypeInstance> = Box::new(DataTypeInstanceImpl::new(
            Box::new(MockDataType {
                name: "float".to_string(),
                length: 4,
            }),
            4,
        ));
        let dyn_ref: &dyn DataTypeInstance = inst.as_ref();
        assert_eq!(dyn_ref.to_string(), "float");
    }

    #[test]
    fn with_length_uses_raw_length_by_default() {
        let dt: Box<dyn DataType> = Box::new(MockDataType {
            name: "int".to_string(),
            length: 4,
        });
        let inst = get_data_type_instance_with_length(Some(dt), -1, false).unwrap();
        assert_eq!(inst.get_length(), 4);
    }

    #[test]
    fn with_length_uses_aligned_length_when_requested() {
        let dt: Box<dyn DataType> = Box::new(MockDataType {
            name: "int".to_string(),
            length: 4,
        });
        let inst = get_data_type_instance_with_length(Some(dt), -1, true).unwrap();
        assert_eq!(inst.get_length(), 5);
    }

    #[test]
    fn with_length_rejects_dynamic_type_without_user_length() {
        let dt: Box<dyn DataType> = Box::new(MockDynamicDataType { can_specify: true });
        assert!(get_data_type_instance_with_length(Some(dt), -1, false).is_none());
    }

    #[test]
    fn with_length_rejects_dynamic_type_that_cannot_specify_length() {
        let dt: Box<dyn DataType> = Box::new(MockDynamicDataType { can_specify: false });
        assert!(get_data_type_instance_with_length(Some(dt), 10, false).is_none());
    }

    #[test]
    fn with_length_accepts_dynamic_type_with_user_length() {
        let dt: Box<dyn DataType> = Box::new(MockDynamicDataType { can_specify: true });
        let inst = get_data_type_instance_with_length(Some(dt), 10, false).unwrap();
        assert_eq!(inst.get_length(), 10);
    }

    #[test]
    fn with_length_rejects_factory_type() {
        let dt: Box<dyn DataType> = Box::new(MockFactoryDataType {
            produced_name: "unused".to_string(),
        });
        assert!(get_data_type_instance_with_length(Some(dt), 4, false).is_none());
    }

    #[test]
    fn with_length_uses_pointer_size_for_function_definition() {
        let dt: Box<dyn DataType> = Box::new(MockFunctionDefDataType { length: -1 });
        let inst = get_data_type_instance_with_length(Some(dt), -1, false).unwrap();
        assert_eq!(inst.get_length(), 8);
    }

    #[test]
    fn with_length_none_input_returns_none() {
        assert!(get_data_type_instance_with_length(None, 4, false).is_none());
    }

    #[test]
    fn at_resolves_factory_type_via_buf() {
        let dt: Box<dyn DataType> = Box::new(MockFactoryDataType {
            produced_name: "resolved".to_string(),
        });
        let buf = MockMemBuffer;
        let inst = get_data_type_instance_at(Some(dt), &buf, 99, false).unwrap();
        assert_eq!(inst.get_data_type().get_name(), "resolved");
        assert_eq!(inst.get_length(), 4);
    }

    #[test]
    fn at_uses_dynamic_length_from_buf() {
        let dt: Box<dyn DataType> = Box::new(MockDynamicDataType { can_specify: true });
        let buf = MockMemBuffer;
        let inst = get_data_type_instance_at(Some(dt), &buf, 12, false).unwrap();
        assert_eq!(inst.get_length(), 12);
    }

    #[test]
    fn at_none_input_returns_none() {
        let buf = MockMemBuffer;
        assert!(get_data_type_instance_at(None, &buf, 4, false).is_none());
    }

    #[test]
    fn get_data_type_instance_delegates_with_unspecified_length() {
        let dt: Box<dyn DataType> = Box::new(MockDataType {
            name: "long".to_string(),
            length: 8,
        });
        let buf = MockMemBuffer;
        let inst = get_data_type_instance(Some(dt), &buf, false).unwrap();
        assert_eq!(inst.get_length(), 8);
    }
}
