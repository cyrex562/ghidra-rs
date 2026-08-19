use crate::format::dwarf::attribs::dwarf_attribute_def::DWARFAttributeDef;
use crate::format::seam_stubs::DWARFCompilationUnit;

/// Common methods for all DWARF attribute value implementations.
/// This trait is implemented by various DWARF attribute value types like
/// DWARFNumericAttribute, DWARFStringAttribute, DWARFBlobAttribute, etc.
pub trait DWARFAttributeValue: Send + Sync {
    /// Returns a human-readable string representation of this attribute's value.
    ///
    /// # Arguments
    /// * `cu` - The compilation unit context
    /// * `def` - The attribute definition providing form and metadata
    ///
    /// # Returns
    /// A string representation of the attribute value suitable for display
    fn get_value_string(&self, cu: &dyn DWARFCompilationUnit, def: &dyn DWARFAttributeDef) -> String;

    /// Exposes this value as [`std::any::Any`] so callers can downcast to the concrete
    /// implementation, mirroring the `instanceof` checks Java call sites use to recover a
    /// specific attribute value's typed accessors (e.g. `DWARFStringAttribute.getValue`).
    fn as_any(&self) -> &dyn std::any::Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAttributeValue;
    impl DWARFAttributeValue for MockAttributeValue {
        fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
            "test_value".to_string()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct MockCompilationUnit;
    impl DWARFCompilationUnit for MockCompilationUnit {
        fn get_dwarf_version(&self) -> i16 {
            4
        }
    }

    struct MockAttributeDef {
        form: crate::format::dwarf::attribs::dwarf_form::DWARFForm,
    }
    impl DWARFAttributeDef for MockAttributeDef {
        fn get_attribute_form(&self) -> crate::format::dwarf::attribs::dwarf_form::DWARFForm {
            self.form
        }
    }

    #[test]
    fn test_attribute_value_trait_can_return_string() {
        let attr = MockAttributeValue;
        let cu = MockCompilationUnit;
        let def =
            MockAttributeDef { form: crate::format::dwarf::attribs::dwarf_form::DWARFForm::DwFormData4 };

        let result = attr.get_value_string(&cu, &def);
        assert_eq!(result, "test_value");
    }

    #[test]
    fn test_mock_compilation_unit_dwarf_version() {
        let cu = MockCompilationUnit;
        assert_eq!(cu.get_dwarf_version(), 4);
    }
}
