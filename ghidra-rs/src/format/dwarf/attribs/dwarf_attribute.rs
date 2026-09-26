//! Port of `ghidra.app.util.bin.format.dwarf.attribs.DWARFAttribute`.
//!
//! # Departures from the Java class
//!
//! * `DWARFCompilationUnit` isn't ported yet, so [`Self::get_cu`] returns
//!   `&dyn `[`DWARFCompilationUnit`](crate::format::seam_stubs::DWARFCompilationUnit), the stub
//!   trait from [`crate::format::seam_stubs`].
//! * Java's `getValue(Class<T>)` becomes [`Self::get_value_typed`], a generic method that
//!   downcasts through [`DWARFAttributeValue::as_any`] instead of taking a `Class` token.
//! * Java overrides `equals`/`hashCode`, hashing/comparing `def`, `die` and `value`. `def` and
//!   `die` are `PartialEq`/`Hash` already, but the `DWARFAttributeValue` implementations don't
//!   expose equality (there's no `PartialEq` bound on the trait, only `as_any`), so replicating
//!   those overrides here would require widening that trait for every implementer. This type
//!   doesn't derive `PartialEq`/`Hash`/`Eq` as a result.

use crate::format::dwarf::attribs::dwarf_attribute_id::AttrDef;
use crate::format::dwarf::attribs::dwarf_attribute_value::DWARFAttributeValue;
use crate::format::dwarf::attribs::dwarf_form::DWARFForm;
use crate::format::dwarf::debug_info_entry::DebugInfoEntry;
use crate::format::seam_stubs::DWARFCompilationUnit;

/// Represents an attribute contained in a DIE.
pub struct DWARFAttribute<'a> {
    pub die: &'a DebugInfoEntry,
    pub def: AttrDef,
    pub value: &'a dyn DWARFAttributeValue,
}

impl<'a> DWARFAttribute<'a> {
    /// Mirrors `DWARFAttribute(DebugInfoEntry, AttrDef, DWARFAttributeValue)`.
    pub fn new(die: &'a DebugInfoEntry, def: AttrDef, value: &'a dyn DWARFAttributeValue) -> Self {
        DWARFAttribute { die, def, value }
    }

    /// The DIE that contains this attribute. Mirrors `DWARFAttribute.getDIE()`.
    pub fn get_die(&self) -> &'a DebugInfoEntry {
        self.die
    }

    /// The compilation unit that contains the attribute's DIE. Mirrors `DWARFAttribute.getCU()`.
    pub fn get_cu(&self) -> &'a dyn DWARFCompilationUnit {
        self.die.get_compilation_unit()
    }

    /// The value of this attribute. Mirrors `DWARFAttribute.getValue()`.
    pub fn get_value(&self) -> &'a dyn DWARFAttributeValue {
        self.value
    }

    /// The value of this attribute, downcast to a specific implementation, or `None` if it isn't
    /// that type. Mirrors `DWARFAttribute.getValue(Class<T>)`.
    pub fn get_value_typed<T: DWARFAttributeValue + 'static>(&self) -> Option<&'a T> {
        self.value.as_any().downcast_ref::<T>()
    }

    /// String name of this attribute's identifier (eg. "DW_AT_high_pc"). Mirrors
    /// `DWARFAttribute.getAttributeName()`.
    pub fn get_attribute_name(&self) -> String {
        self.def.get_attribute_name()
    }

    /// The serialization format identifier of this attribute (eg. DW_FORM_ref4). Mirrors
    /// `DWARFAttribute.getAttributeForm()`.
    pub fn get_attribute_form(&self) -> DWARFForm {
        self.def.get_attribute_form()
    }

    /// The value of this attribute, as a formatted string. Mirrors
    /// `DWARFAttribute.getValueString()`.
    pub fn get_value_string(&self) -> String {
        self.value.get_value_string(self.die.get_compilation_unit(), &self.def)
    }
}

impl std::fmt::Display for DWARFAttribute<'_> {
    /// Mirrors `DWARFAttribute.toString()`: `"%s : %s = %s"`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} : {} = {}",
            self.get_attribute_name(),
            self.get_attribute_form().name(),
            self.get_value_string()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::dwarf::attribs::dwarf_attribute_def::DWARFAttributeDef;
    use crate::format::dwarf::attribs::dwarf_attribute_id::DWARFAttributeId;
    use std::sync::Arc;

    struct MockCompUnit;
    impl DWARFCompilationUnit for MockCompUnit {
        fn get_dwarf_version(&self) -> i16 {
            4
        }
    }

    struct MockValue(i64);
    impl DWARFAttributeValue for MockValue {
        fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
            self.0.to_string()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct OtherValue;
    impl DWARFAttributeValue for OtherValue {
        fn get_value_string(&self, _cu: &dyn DWARFCompilationUnit, _def: &dyn DWARFAttributeDef) -> String {
            String::new()
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn accessors_and_to_string_mirror_java() {
        let cu: Arc<dyn DWARFCompilationUnit> = Arc::new(MockCompUnit);
        let die = DebugInfoEntry::terminator(cu, 0x40);
        let def = AttrDef::new(Some(DWARFAttributeId::DwAtName), 0x3, DWARFForm::DwFormData4, 0);
        let value = MockValue(42);
        let attr = DWARFAttribute::new(&die, def, &value);

        assert_eq!(attr.get_die() as *const _, &die as *const _);
        assert_eq!(attr.get_attribute_name(), "DW_AT_name");
        assert_eq!(attr.get_attribute_form(), DWARFForm::DwFormData4);
        assert_eq!(attr.get_value_string(), "42");
        assert_eq!(attr.to_string(), "DW_AT_name : DW_FORM_data4 = 42");

        assert_eq!(attr.get_value_typed::<MockValue>().map(|v| v.0), Some(42));
        assert!(attr.get_value_typed::<OtherValue>().is_none());
    }
}
