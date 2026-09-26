//! Port of `ghidra.program.model.data.BooleanDataType`, promoted to a trait because it was
//! selected as a dependency-cycle cut-point.
//!
//! The Java class `extends AbstractUnsignedIntegerDataType`, already ported as a trait
//! ([`AbstractUnsignedIntegerDataType`]), so this trait extends it directly.
//!
//! Several methods here share a name with an already-provided default method on [`DataType`]
//! (`getMnemonic`, `getDecompilerDisplayName`, `getLength`, `getDescription`, `getValue`,
//! `getValueClass`, `getRepresentation`, `getDefaultLabelPrefix`). Rust does not allow a subtrait
//! to override a supertrait's default method by redeclaring it (see this crate's other
//! `Abstract*`/leaf cut-point traits for the same restriction), so those overrides are exposed
//! here under distinct `boolean_*` names. A concrete `impl DataType for ...` should delegate to
//! these.
//!
//! `getOppositeSignednessDataType()` overrides the *required* (no-default)
//! `AbstractIntegerDataType.getOppositeSignednessDataType()` with `return this;` (per the Java
//! source's own `// TODO: only unsigned supported` comment). Since that method is already
//! required on a supertrait, redeclaring it here -- even with a body -- would still create the
//! same ambiguous-call-site problem (Rust's ambiguity check does not care whether the colliding
//! supertrait item has a default), so it is intentionally *not* redeclared; a concrete
//! `impl AbstractIntegerDataType for ...` should have its own `get_opposite_signedness_data_type`
//! return an equivalent `BooleanDataType` instance directly.
//!
//! `getBuiltInSettingsDefinitions()` is not ported: it overrides a method declared on `BuiltIn`,
//! which is not a supertrait reached from `AbstractUnsignedIntegerDataType` in this crate (that
//! trait only extends [`DataType`] + [`BuiltInDataType`] + `ArrayStringable`, mirroring
//! [`AbstractIntegerDataType`]'s own module docs), so there is nothing to override against; the
//! Java override returns an empty array in any case, matching every default this port already
//! provides.
//!
//! `clone(DataTypeManager)` always constructs a *new* `BooleanDataType(dtm)` unconditionally --
//! unlike most other `clone` overrides in this crate, it has no `dtm == getDataTypeManager()`
//! self-return fast path. Left as a required method (no default), matching every other
//! `Abstract*DataType` leaf's `clone` override.
//!
//! `getRepresentation(BigInteger, Settings, int)` is an additional overload with no `DataType`
//! counterpart to collide with, so it is ported directly under its natural name (widened to `i128`
//! standing in for `BigInteger`, matching this crate's established convention elsewhere, e.g.
//! [`AbstractFloatDataType`](super::abstract_float_data_type::AbstractFloatDataType)'s
//! `encode_float_value`).

use std::any::{Any, TypeId};

use crate::docking::settings::settings::Settings;
use crate::program::model::data::abstract_unsigned_integer_data_type::AbstractUnsignedIntegerDataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::mem::MemBuffer;

/// Provides a definition of a Boolean data type in a program.
///
/// Port of `ghidra.program.model.data.BooleanDataType`. See the module-level documentation for
/// the naming conventions used to resolve clashes with [`DataType`](crate::program::model::data::data_type::DataType),
/// and for what was left required or intentionally omitted.
pub trait BooleanDataType: AbstractUnsignedIntegerDataType {
    /// Port of `BooleanDataType.getMnemonic(Settings)`, which overrides the default
    /// `DataType.getMnemonic(Settings)`.
    fn boolean_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        "bool".to_string()
    }

    /// Port of `BooleanDataType.getDecompilerDisplayName(DecompilerLanguage)`, which overrides the
    /// default `DataType.getDecompilerDisplayName(DecompilerLanguage)`. Falls back to
    /// [`DataType::get_name`](crate::program::model::data::data_type::DataType::get_name)
    /// (standing in for the Java `name` field) for every language other than
    /// [`DecompilerLanguage::JavaLanguage`].
    fn boolean_decompiler_display_name(&self, language: DecompilerLanguage) -> String {
        if language == DecompilerLanguage::JavaLanguage {
            "boolean".to_string()
        } else {
            self.get_name()
        }
    }

    /// Port of `BooleanDataType.getCDeclaration()`, which overrides the *default*
    /// `AbstractIntegerDataType.getCDeclaration()` (reached transitively through
    /// [`AbstractUnsignedIntegerDataType`]). Exposed under a distinct name for the same
    /// ambiguous-redeclare reason as every other override in this trait; unlike that default
    /// (which returns `Option<String>` and can report "no appropriate declaration"), this
    /// override always succeeds, matching the Java `return name;` body (falling back to
    /// [`DataType::get_name`](crate::program::model::data::data_type::DataType::get_name)).
    fn boolean_c_declaration(&self) -> String {
        self.get_name()
    }

    /// Port of `BooleanDataType.getLength()`, which overrides the default `DataType.getLength()`.
    /// Always `1` (per the Java source's own `// TODO: Size should probably be based upon data
    /// organization` comment).
    fn boolean_length(&self) -> i32 {
        1
    }

    /// Port of `BooleanDataType.getDescription()`, which overrides the default
    /// `DataType.getDescription()`.
    fn boolean_description(&self) -> String {
        "Boolean".to_string()
    }

    /// Port of `BooleanDataType.getValue(MemBuffer, Settings, int)`, which overrides the default
    /// `DataType.getValue(...)`. Returns `None` on a failed byte read, mirroring the Java
    /// `catch (MemoryAccessException e) { return null; }` branch; otherwise a boxed `bool`
    /// (standing in for `Boolean`).
    fn boolean_value(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> Option<Box<dyn Any>> {
        let _ = (settings, length);
        buf.get_byte(0).ok().map(|b| Box::new(b != 0) as Box<dyn Any>)
    }

    /// Port of `BooleanDataType.getValueClass(Settings)`, which overrides the default
    /// `DataType.getValueClass(Settings)`. Returns the [`TypeId`] of `bool`, standing in for
    /// `Boolean.class`.
    fn boolean_value_class(&self, settings: &dyn Settings) -> Option<TypeId> {
        let _ = settings;
        Some(TypeId::of::<bool>())
    }

    /// Port of `BooleanDataType.getRepresentation(MemBuffer, Settings, int)`, which overrides the
    /// default `DataType.getRepresentation(...)`. Mirrors the Java `(Boolean)
    /// getValue(buf, settings, length)` cast by downcasting
    /// [`boolean_value`](Self::boolean_value)'s result.
    fn boolean_representation(&self, buf: &dyn MemBuffer, settings: &dyn Settings, length: i32) -> String {
        match self.boolean_value(buf, settings, length) {
            None => "??".to_string(),
            Some(value) => {
                let is_true = value.downcast_ref::<bool>().copied().unwrap_or(false);
                if is_true { "TRUE" } else { "FALSE" }.to_string()
            }
        }
    }

    /// Port of `BooleanDataType.getRepresentation(BigInteger, Settings, int)`, an additional
    /// overload with no `DataType` counterpart to collide with. `big_int` stands in for
    /// `BigInteger` (widened to `i128`, matching this crate's established convention for `Object`
    /// values that only ever carry an integer magnitude); `settings`/`bit_length` are unused,
    /// matching the Java original.
    fn boolean_representation_from_big_integer(&self, big_int: i128, settings: &dyn Settings, bit_length: i32) -> String {
        let _ = (settings, bit_length);
        if big_int == 0 { "FALSE" } else { "TRUE" }.to_string()
    }

    /// Port of `BooleanDataType.getDefaultLabelPrefix()`, which overrides the default
    /// `DataType.getDefaultLabelPrefix()`.
    fn boolean_default_label_prefix(&self) -> Option<String> {
        Some("BOOL".to_string())
    }

    /// Returns a new `BooleanDataType` bound to the specified `DataTypeManager`, mirroring
    /// `BooleanDataType.clone(DataTypeManager)`'s unconditional `return new
    /// BooleanDataType(dtm);` (no `dtm == getDataTypeManager()` self-return fast path, unlike most
    /// other `clone` overrides in this crate). Left as a required method (no default); see
    /// [`ByteDataType::byte_clone`](super::byte_data_type::ByteDataType::byte_clone) for why
    /// `clone` overrides generally cannot be defaulted here.
    fn boolean_clone(&self, dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn BooleanDataType>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, SpecialAddress};
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::string_data_instance::StringDataInstance;
    use crate::program::model::mem::MemoryAccessException;

    struct MockSettings;
    impl Settings for MockSettings {}

    struct BytesMemBuffer(Vec<u8>);
    impl MemBuffer for BytesMemBuffer {
        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.0
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("out of bounds"))
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            SpecialAddress::no_address()
        }
    }

    struct MockBooleanDataType;

    impl DataType for MockBooleanDataType {
        fn get_name(&self) -> String {
            "bool".to_string()
        }
        fn get_length(&self) -> i32 {
            self.boolean_length()
        }
        fn is_integer_type(&self) -> bool {
            true
        }
        fn is_signed_integer_type(&self) -> bool {
            false
        }
    }

    impl BuiltInDataType for MockBooleanDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl ArrayStringable for MockBooleanDataType {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            false
        }
        fn string_data_instance(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _length: i32,
        ) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }

    impl AbstractIntegerDataType for MockBooleanDataType {
        fn is_signed(&self) -> bool {
            self.unsigned_is_signed()
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            Box::new(MockBooleanDataType)
        }
    }

    impl AbstractUnsignedIntegerDataType for MockBooleanDataType {}

    impl BooleanDataType for MockBooleanDataType {
        fn boolean_clone(&self, _dtm: Option<Box<dyn DataTypeManager>>) -> Box<dyn BooleanDataType> {
            Box::new(MockBooleanDataType)
        }
    }

    struct MockDataTypeManager;
    impl DataTypeManager for MockDataTypeManager {}

    #[test]
    fn usable_as_trait_object() {
        let dt = MockBooleanDataType;
        let dyn_dt: &dyn BooleanDataType = &dt;
        assert_eq!(dyn_dt.boolean_mnemonic(&MockSettings), "bool");
        assert_eq!(dyn_dt.boolean_length(), 1);
        assert_eq!(DataType::get_length(dyn_dt), 1);
        assert_eq!(dyn_dt.boolean_description(), "Boolean");
        assert_eq!(dyn_dt.boolean_c_declaration(), "bool");
        assert_eq!(dyn_dt.boolean_default_label_prefix(), Some("BOOL".to_string()));
        assert!(!dt.is_signed());
    }

    #[test]
    fn decompiler_display_name_java_language_uses_boolean() {
        let dt = MockBooleanDataType;
        assert_eq!(dt.boolean_decompiler_display_name(DecompilerLanguage::JavaLanguage), "boolean");
        assert_eq!(dt.boolean_decompiler_display_name(DecompilerLanguage::CLanguage), "bool");
    }

    #[test]
    fn value_and_representation_round_trip_true_and_false() {
        let dt = MockBooleanDataType;
        let true_buf = BytesMemBuffer(vec![1]);
        let false_buf = BytesMemBuffer(vec![0]);

        let true_value = dt.boolean_value(&true_buf, &MockSettings, -1).unwrap();
        assert_eq!(*true_value.downcast_ref::<bool>().unwrap(), true);
        assert_eq!(dt.boolean_representation(&true_buf, &MockSettings, -1), "TRUE");
        assert_eq!(dt.boolean_representation(&false_buf, &MockSettings, -1), "FALSE");
        assert_eq!(dt.boolean_value_class(&MockSettings), Some(TypeId::of::<bool>()));
    }

    #[test]
    fn value_and_representation_are_none_and_placeholder_on_read_failure() {
        let dt = MockBooleanDataType;
        let empty_buf = BytesMemBuffer(Vec::new());
        assert!(dt.boolean_value(&empty_buf, &MockSettings, -1).is_none());
        assert_eq!(dt.boolean_representation(&empty_buf, &MockSettings, -1), "??");
    }

    #[test]
    fn representation_from_big_integer_checks_zero() {
        let dt = MockBooleanDataType;
        assert_eq!(dt.boolean_representation_from_big_integer(0, &MockSettings, 1), "FALSE");
        assert_eq!(dt.boolean_representation_from_big_integer(5, &MockSettings, 8), "TRUE");
        assert_eq!(dt.boolean_representation_from_big_integer(-1, &MockSettings, 8), "TRUE");
    }

    #[test]
    fn clone_produces_an_equivalent_instance() {
        let dt = MockBooleanDataType;
        let cloned = dt.boolean_clone(Some(Box::new(MockDataTypeManager)));
        assert_eq!(cloned.boolean_description(), dt.boolean_description());
        assert_eq!(cloned.boolean_c_declaration(), dt.boolean_c_declaration());
    }
}
