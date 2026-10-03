//! Port of `ghidra.program.model.data.VoidDataType`.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::docking::settings::settings_definition::SettingsDefinition;
use crate::program::model::data::built_in::{
    built_in_data_type_methods, built_in_singleton, impl_built_in, same_class, BuiltInBase,
};
use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_manager::DataTypeManager;
use crate::program::model::lang::decompiler_language::DecompilerLanguage;
use crate::program::model::mem::MemBuffer;

/// Special datatype that represents the `void` type (no data, length 0).
///
/// Port of `ghidra.program.model.data.VoidDataType`. Java's static `dataType` is
/// [`VoidDataType::data_type`].
#[derive(Debug, Clone)]
pub struct VoidDataType {
    base: BuiltInBase,
}

impl VoidDataType {
    /// Creates a void datatype bound to `dtm`'s data organization (Java: `new VoidDataType(dtm)`;
    /// `None` is the no-argument constructor).
    pub fn new(dtm: Option<&dyn DataTypeManager>) -> Self {
        Self { base: BuiltInBase::new(None, "void", dtm) }
    }

    /// Port of `VoidDataType.getCTypeDeclaration(DataOrganization)`: `null`, since `void` is a
    /// standard C name and type.
    fn c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
        None
    }

    fn built_in_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
        Vec::new()
    }

    fn decompiler_display_name(&self, _language: DecompilerLanguage) -> String {
        self.base.name().to_string()
    }
}

built_in_singleton!(VoidDataType);
impl_built_in!(VoidDataType);

impl std::fmt::Display for VoidDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.base.name())
    }
}

impl DataType for VoidDataType {
    built_in_data_type_methods!();

    fn get_mnemonic(&self, _settings: &dyn Settings) -> String {
        "void".to_string()
    }

    fn get_length(&self) -> i32 {
        0
    }

    fn get_description(&self) -> String {
        "void datatype".to_string()
    }

    fn get_representation(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> String {
        String::new()
    }

    fn get_value(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Option<Box<dyn std::any::Any>> {
        None
    }

    fn is_equivalent(&self, dt: &dyn DataType) -> bool {
        same_class(self, dt)
    }

    fn is_void_type(&self) -> bool {
        true
    }
}

/// Determine if the specified data type is `void`, looking through a typedef to its base type.
///
/// Port of the static `VoidDataType.isVoidDataType(DataType)`; `None` stands in for `null`.
pub fn is_void_data_type(dt: Option<&dyn DataType>) -> bool {
    let Some(dt) = dt else {
        return false;
    };
    if dt.is_typedef() {
        if let Some(base) = dt.typedef_base_data_type() {
            return base.is_void_type();
        }
    }
    dt.is_void_type()
}

/// The shared `void` datatype (Java: `DataType.VOID`).
pub fn void() -> Arc<dyn DataType> {
    VoidDataType::data_type()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::abstract_integer_data_type::test_support::{buf, LongSettings};
    use crate::program::model::data::built_in::BuiltIn;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::byte_data_type::ByteDataType;

    #[test]
    fn java_constants() {
        let dt = VoidDataType::instance();
        let s = LongSettings::default();
        assert_eq!(dt.get_name(), "void");
        assert_eq!(dt.get_path_name(), "/void");
        assert_eq!(dt.get_length(), 0);
        assert_eq!(dt.get_description(), "void datatype");
        assert_eq!(dt.get_mnemonic(&s), "void");
        assert_eq!(dt.get_representation(&buf(&[1], false), &s, 1), "");
        assert!(dt.get_value(&buf(&[1], false), &s, 1).is_none());
        let org = dt.get_data_organization();
        assert_eq!(dt.get_c_type_declaration(Some(&org)), None);
        assert_eq!(dt.get_decompiler_display_name(DecompilerLanguage::CLanguage), "void");
        assert_eq!(dt.get_settings_definitions().len(), 1);
    }

    #[test]
    fn is_void_data_type_accepts_void_and_rejects_others() {
        assert!(is_void_data_type(Some(VoidDataType::instance().as_ref())));
        assert!(is_void_data_type(Some(&VoidDataType::new(None))));
        assert!(!is_void_data_type(Some(ByteDataType::instance().as_ref())));
        assert!(!is_void_data_type(None));
    }

    #[test]
    fn is_void_data_type_looks_through_typedefs() {
        struct VoidTypedef;
        impl DataType for VoidTypedef {
            fn is_typedef(&self) -> bool {
                true
            }
            fn typedef_base_data_type(&self) -> Option<Box<dyn DataType>> {
                Some(Box::new(VoidDataType::new(None)))
            }
        }
        assert!(is_void_data_type(Some(&VoidTypedef)));
    }

    #[test]
    fn singleton_and_equivalence() {
        let a = void();
        assert!(Arc::ptr_eq(&a, &VoidDataType::data_type()));
        assert!(a.is_equivalent(&VoidDataType::new(None)));
        assert!(!a.is_equivalent(ByteDataType::instance().as_ref()));
    }
}
