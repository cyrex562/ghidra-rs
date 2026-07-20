use crate::program::model::address::AddressSpace;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::typedef::TypeDef;
use crate::program::seam_stubs::PointerType;
use crate::util::exception::InvalidNameException;

/// Builder for creating [`Pointer`](crate::program::model::data::pointer::Pointer) -
/// [`TypeDef`]s. These special typedefs allow a modified-pointer datatype to be used for special
/// situations where a simple pointer will not suffice and special stored pointer
/// interpretation/handling is required.
///
/// Port of `ghidra.program.model.data.PointerTypedefBuilder`.
///
/// The Java class exposes a fluent API whose setters mutate an internal `PointerTypedef` and
/// return `this`. A trait method can't return `Self`, so each setter here mutates the builder in
/// place (`&mut self`) instead of chaining; callers issue one statement per setting rather than a
/// single fluent chain. Every setter carries a no-op default so a builder backed only by
/// placeholder state still satisfies the trait; the concrete implementation backed by a real
/// `PointerTypedef` (not yet ported) is expected to override each one to actually apply the
/// setting.
pub trait PointerTypedefBuilder {
    /// Set pointer-typedef name. If not specified a default name will be generated based upon
    /// the associated pointer type and the specified settings.
    fn name(&mut self, name: &str) -> Result<(), InvalidNameException> {
        let _ = name;
        Ok(())
    }

    /// Update pointer type.
    fn set_type(&mut self, pointer_type: PointerType) {
        let _ = pointer_type;
    }

    /// Update pointer offset bit-shift when translating to an absolute memory offset. If
    /// specified, bit-shift will be applied after applying any specified bit-mask.
    fn bit_shift(&mut self, shift: i32) {
        let _ = shift;
    }

    /// Update pointer offset bit-mask when translating to an absolute memory offset. If
    /// specified, bit-mask will be AND-ed with stored offset prior to any specified bit-shift.
    fn bit_mask(&mut self, unsigned_mask: i64) {
        let _ = unsigned_mask;
    }

    /// Update pointer relative component-offset. The offset is relative to the start of the base
    /// datatype (e.g. a structure); it may refer to a component-offset within the base datatype
    /// or outside of it.
    fn component_offset(&mut self, offset: i64) {
        let _ = offset;
    }

    /// Update pointer referenced address space when translating to an absolute memory offset.
    /// `None` selects the default space.
    fn address_space(&mut self, space: Option<&AddressSpace>) {
        let _ = space;
    }

    /// Update pointer referenced address space by name when translating to an absolute memory
    /// offset. `None` selects the default space.
    fn address_space_name(&mut self, space_name: Option<&str>) {
        let _ = space_name;
    }

    /// Build pointer-typedef with specified settings.
    fn build(&self) -> Box<dyn TypeDef> {
        Box::new(EmptyTypeDef)
    }
}

/// Trivial fallback [`TypeDef`] used by [`PointerTypedefBuilder::build`]'s default
/// implementation before a concrete builder is backed by a real `PointerTypedef`.
struct EmptyTypeDef;

impl DataType for EmptyTypeDef {}

impl TypeDef for EmptyTypeDef {
    fn is_auto_named(&self) -> bool {
        false
    }

    fn enable_auto_naming(&mut self) {}

    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(EmptyLeafDataType)
    }

    fn get_base_data_type(&self) -> Box<dyn DataType> {
        Box::new(EmptyLeafDataType)
    }
}

/// Trivial fallback [`DataType`] wrapped by [`EmptyTypeDef`].
struct EmptyLeafDataType;

impl DataType for EmptyLeafDataType {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockBuilder {
        auto_named: bool,
        pointer_type: PointerType,
        bit_shift: i32,
        bit_mask: i64,
        component_offset: i64,
        address_space_name: Option<String>,
    }

    impl MockBuilder {
        fn new() -> Self {
            MockBuilder {
                auto_named: true,
                ..Default::default()
            }
        }
    }

    struct MockTypeDef {
        auto_named: bool,
    }

    impl DataType for MockTypeDef {}

    impl TypeDef for MockTypeDef {
        fn is_auto_named(&self) -> bool {
            self.auto_named
        }

        fn enable_auto_naming(&mut self) {
            self.auto_named = true;
        }

        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(EmptyLeafDataType)
        }

        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(EmptyLeafDataType)
        }
    }

    impl PointerTypedefBuilder for MockBuilder {
        fn name(&mut self, name: &str) -> Result<(), InvalidNameException> {
            if name.is_empty() {
                return Err(InvalidNameException::with_message(
                    "pointer-typedef name must not be empty",
                ));
            }
            self.auto_named = false;
            Ok(())
        }

        fn set_type(&mut self, pointer_type: PointerType) {
            self.pointer_type = pointer_type;
        }

        fn bit_shift(&mut self, shift: i32) {
            self.bit_shift = shift;
        }

        fn bit_mask(&mut self, unsigned_mask: i64) {
            self.bit_mask = unsigned_mask;
        }

        fn component_offset(&mut self, offset: i64) {
            self.component_offset = offset;
        }

        fn address_space(&mut self, space: Option<&AddressSpace>) {
            self.address_space_name = space.map(|s| s.name().to_string());
        }

        fn address_space_name(&mut self, space_name: Option<&str>) {
            self.address_space_name = space_name.map(|s| s.to_string());
        }

        fn build(&self) -> Box<dyn TypeDef> {
            Box::new(MockTypeDef {
                auto_named: self.auto_named,
            })
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mut builder: Box<dyn PointerTypedefBuilder> = Box::new(MockBuilder::new());
        builder.set_type(PointerType::ImageBaseRelative);
        builder.bit_shift(2);
        builder.bit_mask(0xFFFF);
        builder.component_offset(8);
        builder.address_space_name(Some("ram"));

        let td = builder.build();
        assert!(td.is_auto_named());
    }

    #[test]
    fn setting_name_disables_auto_naming() {
        let mut builder = MockBuilder::new();
        builder.name("myPtr").unwrap();

        let td = builder.build();
        assert!(!td.is_auto_named());
    }

    #[test]
    fn empty_name_is_rejected() {
        let mut builder = MockBuilder::new();
        assert!(builder.name("").is_err());
    }

    #[test]
    fn address_space_setter_captures_name() {
        let mut builder = MockBuilder::new();
        let space = AddressSpace::new(
            "ram",
            32,
            1,
            crate::program::model::address::AddressSpaceType::Ram,
            0,
        );
        builder.address_space(Some(space.as_ref()));
        assert_eq!(builder.address_space_name.as_deref(), Some("ram"));
    }

    #[test]
    fn default_methods_are_no_ops_and_build_returns_non_auto_named_type_def() {
        struct DefaultBuilder;
        impl PointerTypedefBuilder for DefaultBuilder {}

        let mut builder = DefaultBuilder;
        assert!(builder.name("ignored").is_ok());
        builder.set_type(PointerType::Relative);
        builder.bit_shift(4);
        builder.bit_mask(1);
        builder.component_offset(1);
        builder.address_space(None);
        builder.address_space_name(None);

        let td = builder.build();
        assert!(!td.is_auto_named());
    }
}
