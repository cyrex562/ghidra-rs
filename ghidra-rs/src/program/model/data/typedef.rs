use crate::program::seam_stubs::DataType;

/// Port of `ghidra.program.model.data.TypeDef`.
///
/// The typedef interface.
pub trait TypeDef: DataType {
    /// Determine if this datatype use auto-naming (e.g., see `PointerTypedef`). If true, any
    /// change to associated `TypeDefSettingsDefinition` settings or naming of the
    /// pointer-referenced datatype will cause an automatic renaming of this datatype.
    fn is_auto_named(&self) -> bool;

    /// Enable auto-naming for this typedef. This will force naming to reflect the name of the
    /// associated datatype plus an attribute list which corresponds to any
    /// `TypeDefSettingsDefinition` settings which may be set.
    fn enable_auto_naming(&mut self);

    /// Returns the dataType that this typedef is based on. This could be another typedef.
    fn get_data_type(&self) -> Box<dyn DataType>;

    /// Returns the non-typedef dataType that this typedef is based on, following chains of
    /// typedefs as necessary.
    fn get_base_data_type(&self) -> Box<dyn DataType>;

    /// Determine if this is a Pointer-TypeDef.
    fn is_pointer(&self) -> bool {
        self.get_base_data_type().is_pointer()
    }

    /// Compare the settings of two datatypes which correspond to a
    /// `TypeDefSettingsDefinition`.
    ///
    /// NOTE: It is required that both datatypes present their settings definitions in the same
    /// order (see `DataType::get_settings_definitions`) to be considered the same.
    ///
    /// Returns true if both datatypes have the same settings defined which correspond to
    /// `TypeDefSettingsDefinition` and have the same values, else false.
    fn has_same_type_def_settings(&self, dt: &dyn TypeDef) -> bool {
        let defs1 = self.get_settings_definitions();
        let defs2 = dt.get_settings_definitions();
        if defs1.len() != defs2.len() {
            return false;
        }

        let settings1 = self.get_default_settings();
        let settings2 = dt.get_default_settings();

        for (def, other_def) in defs1.iter().zip(defs2.iter()) {
            if !other_def.is_same_kind(def.as_ref()) {
                return false;
            }
            if def.is_type_def_settings_definition()
                && !def.has_same_value(settings1.as_ref(), settings2.as_ref())
            {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::seam_stubs::{Settings, SettingsDefinition};

    #[derive(Default)]
    struct MockDataType {
        pointer: bool,
    }
    impl DataType for MockDataType {
        fn is_pointer(&self) -> bool {
            self.pointer
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    struct MockSettingsDefinition {
        is_typedef_kind: bool,
    }
    impl SettingsDefinition for MockSettingsDefinition {
        fn is_same_kind(&self, _other: &dyn SettingsDefinition) -> bool {
            true
        }
        fn is_type_def_settings_definition(&self) -> bool {
            self.is_typedef_kind
        }
        fn has_same_value(&self, _settings1: &dyn Settings, _settings2: &dyn Settings) -> bool {
            true
        }
    }

    struct MockTypeDef {
        auto_named: bool,
        base_is_pointer: bool,
    }

    impl DataType for MockTypeDef {
        fn get_settings_definitions(&self) -> Vec<Box<dyn SettingsDefinition>> {
            vec![Box::new(MockSettingsDefinition {
                is_typedef_kind: true,
            })]
        }
        fn get_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
    }

    impl TypeDef for MockTypeDef {
        fn is_auto_named(&self) -> bool {
            self.auto_named
        }

        fn enable_auto_naming(&mut self) {
            self.auto_named = true;
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType::default())
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType {
                pointer: self.base_is_pointer,
            })
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut td = MockTypeDef {
            auto_named: false,
            base_is_pointer: true,
        };
        assert!(!td.is_auto_named());
        td.enable_auto_naming();
        assert!(td.is_auto_named());

        let dyn_td: &dyn TypeDef = &td;
        assert!(dyn_td.is_pointer());
    }

    #[test]
    fn has_same_type_def_settings_compares_defs() {
        let a = MockTypeDef {
            auto_named: false,
            base_is_pointer: false,
        };
        let b = MockTypeDef {
            auto_named: false,
            base_is_pointer: false,
        };
        assert!(a.has_same_type_def_settings(&b));
    }
}
