//! Port of `ghidra.program.model.data.PointerTypedefBuilder`.

use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
use crate::docking::settings::string_settings_definition::StringSettingsDefinition;
use crate::program::model::address::AddressSpace;
use crate::program::model::data::address_space_settings_definition::AddressSpaceSettingsDefinition;
use crate::program::model::data::component_offset_settings_definition::ComponentOffsetSettingsDefinition;
use crate::program::model::data::data_type::{DataType, IntoDataTypeArc};
use crate::program::model::data::offset_mask_settings_definition::OffsetMaskSettingsDefinition;
use crate::program::model::data::offset_shift_settings_definition::OffsetShiftSettingsDefinition;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::pointer_type::PointerType;
use crate::program::model::data::pointer_type_settings_definition::PointerTypeSettingsDefinition;
use crate::program::model::data::pointer_typedef::PointerTypedef;
use crate::util::exception::InvalidNameException;

/// Builder for creating pointer [`TypeDef`](crate::program::model::data::typedef::TypeDef)s.
/// These special typedefs allow a modified-pointer datatype to be used for special situations
/// where a simple pointer will not suffice and special stored pointer interpretation/handling is
/// required.
///
/// Port of `ghidra.program.model.data.PointerTypedefBuilder`. Java's fluent setters return
/// `this`; here they take and return `&mut Self` so calls can still be chained.
pub struct PointerTypedefBuilder {
    typedef: PointerTypedef,
}

impl PointerTypedefBuilder {
    /// Port of `PointerTypedefBuilder(DataType, int, DataTypeManager)`: a pointer-typedef
    /// builder for a pointer to `base_data_type` (`None` for a default pointer) of `pointer_size`
    /// bytes (`<= 0` for the data organization's default size).
    ///
    /// # Errors
    /// Returns `Err` if the pointer cannot be constructed (e.g. a bitfield base type).
    pub fn new(base_data_type: Option<impl IntoDataTypeArc>, pointer_size: i32) -> Result<Self, String> {
        let base_data_type = base_data_type.map(IntoDataTypeArc::into_data_type_arc);
        Ok(PointerTypedefBuilder { typedef: PointerTypedef::new(None, base_data_type, pointer_size)? })
    }

    /// Port of `PointerTypedefBuilder(Pointer, DataTypeManager)`: a builder whose typedef wraps
    /// a copy of `pointer` (same referenced type and stored length).
    pub fn for_pointer(pointer: &dyn Pointer) -> Self {
        let pointer_size = if pointer.has_language_dependant_length() { -1 } else { pointer.get_length() };
        let typedef = PointerTypedef::new(None, pointer.get_data_type().map(std::sync::Arc::from), pointer_size)
            .expect("an existing pointer's referenced type is a valid pointer base");
        PointerTypedefBuilder { typedef }
    }

    /// Set pointer-typedef name. As in Java this sets the typedef's name without disabling
    /// auto-naming (a builder-created typedef is always auto-named, so the generated name still
    /// wins).
    ///
    /// # Errors
    /// Returns `Err` if `name` is not a valid data type name.
    pub fn name(&mut self, name: &str) -> Result<&mut Self, InvalidNameException> {
        self.typedef.set_typedef_name(name)?;
        Ok(self)
    }

    /// Update pointer type.
    pub fn set_type(&mut self, pointer_type: &dyn PointerType) -> &mut Self {
        let mut settings = self.typedef.get_default_settings();
        PointerTypeSettingsDefinition::DEF.set_type(settings.as_mut(), pointer_type);
        self
    }

    /// Update pointer offset bit-shift when translating to an absolute memory offset. If
    /// specified, bit-shift will be applied after applying any specified bit-mask.
    pub fn bit_shift(&mut self, shift: i32) -> &mut Self {
        let mut settings = self.typedef.get_default_settings();
        OffsetShiftSettingsDefinition::DEF.set_value(settings.as_mut(), shift as i64);
        self
    }

    /// Update pointer offset bit-mask when translating to an absolute memory offset. If
    /// specified, bit-mask will be AND-ed with stored offset prior to any specified bit-shift.
    pub fn bit_mask(&mut self, unsigned_mask: i64) -> &mut Self {
        let mut settings = self.typedef.get_default_settings();
        OffsetMaskSettingsDefinition::DEF.set_value(settings.as_mut(), unsigned_mask);
        self
    }

    /// Update pointer relative component-offset. The offset is relative to the start of the base
    /// datatype (e.g. a structure); it may refer to a component-offset within the base datatype
    /// or outside of it.
    pub fn component_offset(&mut self, offset: i64) -> &mut Self {
        let mut settings = self.typedef.get_default_settings();
        ComponentOffsetSettingsDefinition::DEF.set_value(settings.as_mut(), offset);
        self
    }

    /// Update pointer referenced address space when translating to an absolute memory offset.
    /// `None` selects the default space.
    pub fn address_space(&mut self, space: Option<&AddressSpace>) -> &mut Self {
        self.address_space_name(space.map(|s| s.name()))
    }

    /// Update pointer referenced address space by name. `None` selects the default space.
    pub fn address_space_name(&mut self, space_name: Option<&str>) -> &mut Self {
        let mut settings = self.typedef.get_default_settings();
        AddressSpaceSettingsDefinition::DEF.set_value(settings.as_mut(), space_name.unwrap_or(""));
        self
    }

    /// Build pointer-typedef with specified settings.
    pub fn build(self) -> PointerTypedef {
        self.typedef
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::number_settings_definition::NumberSettingsDefinition;
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::pointer_data_type::PointerDataType;
    use crate::program::model::data::pointer_type::ImageBaseRelativePointerType;
    use crate::program::model::data::typedef::TypeDef;

    #[test]
    fn settings_are_applied_to_the_built_typedef() {
        let mut builder = PointerTypedefBuilder::new(Some(ByteDataType::data_type()), 4).unwrap();
        builder.set_type(&ImageBaseRelativePointerType).bit_shift(2).bit_mask(0xFFFF);
        let td = builder.build();
        let settings = td.get_default_settings();
        assert_eq!(PointerTypeSettingsDefinition::DEF.get_type(Some(settings.as_ref())).value(), 1);
        assert_eq!(OffsetShiftSettingsDefinition::DEF.get_value(settings.as_ref()), 2);
        assert_eq!(OffsetMaskSettingsDefinition::DEF.get_value(settings.as_ref()), 0xFFFF);
        assert!(td.is_auto_named());
        assert_eq!(td.get_length(), 4);
        assert_eq!(td.get_name(), "byte *32 __((image-base-relative,mask(0xffff),shift(2)))");
    }

    #[test]
    fn for_pointer_copies_referenced_type_and_length() {
        let pointer = PointerDataType::to(ByteDataType::data_type(), 8).unwrap();
        let td = PointerTypedefBuilder::for_pointer(&pointer).build();
        assert_eq!(td.get_length(), 8);
        assert_eq!(td.get_referenced_data_type().unwrap().get_name(), "byte");
    }

    #[test]
    fn invalid_name_is_rejected() {
        let mut builder = PointerTypedefBuilder::new(None::<std::sync::Arc<dyn DataType>>, 4).unwrap();
        assert!(builder.name("").is_err());
        assert!(builder.name("myPtr").is_ok());
    }
}
