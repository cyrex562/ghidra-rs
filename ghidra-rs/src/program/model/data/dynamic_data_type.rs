use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::dynamic::Dynamic;
use crate::program::seam_stubs::MemBuffer;

/// Port of `ghidra.program.model.data.DynamicDataType`.
///
/// Interface for dataTypes that don't get applied, but instead generate dataTypes on the fly
/// based on the data.
///
/// The Java class is `abstract class DynamicDataType extends BuiltIn implements Dynamic`, so
/// this trait carries [`Dynamic`] as a supertrait. Rust has no inheritance, so the pieces that
/// came along for free via `BuiltIn`/`Dynamic` (name/category/settings plumbing) are already
/// covered by the [`DataType`]/[`BuiltInDataType`](super::built_in_data_type::BuiltInDataType)/
/// [`Dynamic`] supertrait chain and are not repeated here.
///
/// The Java class's private `SoftCacheMap<Address, DataTypeComponent[]>` memoizes
/// `getAllComponents(buf)` per `Address` purely as a performance optimization; it is not part of
/// the observable contract, so it is dropped here and every template method below simply
/// recomputes from [`get_all_components`](Self::get_all_components). A concrete implementation
/// that wants the caching behavior back is free to add it once it owns real fields.
///
/// Several of the Java class's `final` methods are concrete overrides of methods that are also
/// declared (abstract, with no default) on [`Dynamic`] or
/// [`DataType`](crate::program::model::data::data_type::DataType): `getLength(MemBuffer, int)`
/// overrides `Dynamic.getLength(..)` (ported as [`Dynamic::get_dynamic_length`]),
/// `getReplacementBaseType()` overrides `Dynamic.getReplacementBaseType()` (ported as
/// [`Dynamic::get_replacement_base_type`]), and `getLength()` overrides
/// `DataType.getLength()`. A Rust subtrait cannot redeclare a supertrait method of the same name
/// without making calls through `dyn DynamicDataType` ambiguous, so those template
/// implementations are exposed here under distinct names
/// ([`dynamic_length_from_components`](Self::dynamic_length_from_components),
/// [`default_replacement_base_type`](Self::default_replacement_base_type)); a concrete type that
/// implements both `Dynamic` and `DynamicDataType` should have its `Dynamic::get_dynamic_length`
/// and `Dynamic::get_replacement_base_type` (and `DataType::get_length`, returning `-1`) delegate
/// to them.
pub trait DynamicDataType: Dynamic {
    /// Get all dynamic components associated with the specified MemBuffer.
    ///
    /// Returns all components, or `None` if memory data is not valid for this data type. Each
    /// slot in the returned `Vec` may itself be `None`, mirroring the nullable elements Java's
    /// `DataTypeComponent[]` allows for gaps in the layout.
    fn get_all_components(
        &self,
        buf: &dyn MemBuffer,
    ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>>;

    /// Gets the number of component data types in this data type.
    ///
    /// `buf` is a memory buffer to be used by dataTypes that change depending on their data
    /// context.
    ///
    /// Returns the number of components that make up this data prototype:
    ///   - if this is an Array, the number of elements in the array.
    ///   - if this datatype is a subcomponent of another datatype and it won't fit in its
    ///     defined space, `-1`.
    fn get_num_components(&self, buf: &dyn MemBuffer) -> i32 {
        match self.get_all_components(buf) {
            Some(comps) if !comps.is_empty() => comps.len() as i32,
            _ => -1,
        }
    }

    /// Returns the immediate n'th component of this data type.
    ///
    /// `ordinal` is the component's ordinal (zero based); `buf` is a memory buffer to be used by
    /// dataTypes that change depending on their data context.
    ///
    /// Returns the component data type, or `None` if there is no component at the indicated
    /// index. Unlike the Java method, an out-of-range `ordinal` returns `None` rather than
    /// panicking.
    fn get_component(&self, ordinal: i32, buf: &dyn MemBuffer) -> Option<Box<dyn DataTypeComponent>> {
        if ordinal < 0 {
            return None;
        }
        self.get_all_components(buf)?
            .into_iter()
            .nth(ordinal as usize)
            .flatten()
    }

    /// Returns the components that make up this data type.
    ///
    /// Could return `None` if there are no subcomponents.
    fn get_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        self.get_all_components(buf)
    }

    /// Returns the first component containing the byte at the given offset.
    ///
    /// It is possible with zero-length components and bitfields for multiple components to
    /// share the same offset.
    ///
    /// Returns the first component containing the byte at `offset`, or `None` if no component is
    /// defined. A zero-length component may be returned.
    fn get_component_at(&self, offset: i32, buf: &dyn MemBuffer) -> Option<Box<dyn DataTypeComponent>> {
        let comps = self.get_all_components(buf)?;
        for comp in comps.into_iter().flatten() {
            if offset >= comp.get_offset() && offset <= comp.get_end_offset() {
                return Some(comp);
            }
        }
        None
    }

    /// Template implementation backing the Java class's concrete override of
    /// `Dynamic.getLength(MemBuffer, int)` (ported as [`Dynamic::get_dynamic_length`]).
    ///
    /// `max_length` is accepted only to match the overridden signature; like the Java
    /// implementation, it is not used in computing the result.
    ///
    /// Returns the data length, or `-1` if it could not be determined.
    fn dynamic_length_from_components(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
        let _ = max_length;
        match self.get_all_components(buf) {
            Some(comps) if !comps.is_empty() => match comps.last().and_then(|c| c.as_ref()) {
                Some(last) => last.get_offset() + last.get_length(),
                None => -1,
            },
            _ => -1,
        }
    }

    /// Template implementation backing the Java class's concrete override of
    /// `Dynamic.getReplacementBaseType()` (ported as [`Dynamic::get_replacement_base_type`]),
    /// which returns `ByteDataType.dataType`. `ByteDataType` is not yet ported, so this returns a
    /// minimal stand-in with the same 1-byte length.
    fn default_replacement_base_type(&self) -> Box<dyn DataType> {
        Box::new(BytePlaceholderDataType)
    }

    /// Clears any cached per-buffer component computation.
    ///
    /// The Java class's private component cache is not modeled on this trait (see the trait's
    /// documentation), so the default implementation is a no-op. A concrete implementation that
    /// reintroduces caching should override this to actually clear it.
    fn invalidate_cache(&mut self) {}
}

/// Minimal stand-in for `ghidra.program.model.data.ByteDataType.dataType`, used by
/// [`DynamicDataType::default_replacement_base_type`] until `ByteDataType` is ported.
struct BytePlaceholderDataType;

impl DataType for BytePlaceholderDataType {
    fn get_length(&self) -> i32 {
        1
    }

    fn get_name(&self) -> String {
        "byte".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::docking::settings::settings::Settings;

    struct MockMemBuffer;
    impl MemBuffer for MockMemBuffer {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
        }
    }

    struct MockSettings;
    impl Settings for MockSettings {}

    #[derive(Clone, Copy)]
    struct MockComponent {
        offset: i32,
        length: i32,
    }

    impl DataTypeComponent for MockComponent {
        fn get_offset(&self) -> i32 {
            self.offset
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockDynamicDataType;

    impl DataType for MockDynamicDataType {
        fn get_length(&self) -> i32 {
            -1
        }
    }

    impl BuiltInDataType for MockDynamicDataType {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&dyn DataOrganization>,
        ) -> Option<String> {
            None
        }

        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for MockDynamicDataType {
        fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
            self.dynamic_length_from_components(buf, max_length)
        }

        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            self.default_replacement_base_type()
        }
    }

    impl DynamicDataType for MockDynamicDataType {
        fn get_all_components(
            &self,
            _buf: &dyn MemBuffer,
        ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            Some(vec![
                Some(Box::new(MockComponent { offset: 0, length: 4 })),
                None,
                Some(Box::new(MockComponent { offset: 8, length: 2 })),
            ])
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let dt = MockDynamicDataType;
        let dyn_dt: &dyn DynamicDataType = &dt;

        assert_eq!(dyn_dt.get_num_components(&MockMemBuffer), 3);
        assert_eq!(dyn_dt.get_component(0, &MockMemBuffer).unwrap().get_length(), 4);
        assert!(dyn_dt.get_component(1, &MockMemBuffer).is_none());
        assert!(dyn_dt.get_component(99, &MockMemBuffer).is_none());
        assert_eq!(
            dyn_dt.get_component_at(9, &MockMemBuffer).unwrap().get_offset(),
            8
        );
        assert_eq!(dyn_dt.dynamic_length_from_components(&MockMemBuffer, -1), 10);
        assert_eq!(dyn_dt.default_replacement_base_type().get_length(), 1);
        assert!(!dyn_dt.can_specify_length());
    }

    #[test]
    fn empty_components_report_unknown_length() {
        struct EmptyDynamicDataType;
        impl DataType for EmptyDynamicDataType {}
        impl BuiltInDataType for EmptyDynamicDataType {
            fn get_c_type_declaration(
                &self,
                _data_organization: Option<&dyn DataOrganization>,
            ) -> Option<String> {
                None
            }
            fn set_default_settings(&mut self, _settings: &dyn Settings) {}
        }
        impl Dynamic for EmptyDynamicDataType {
            fn get_dynamic_length(&self, buf: &dyn MemBuffer, max_length: i32) -> i32 {
                self.dynamic_length_from_components(buf, max_length)
            }
            fn get_replacement_base_type(&self) -> Box<dyn DataType> {
                self.default_replacement_base_type()
            }
        }
        impl DynamicDataType for EmptyDynamicDataType {
            fn get_all_components(
                &self,
                _buf: &dyn MemBuffer,
            ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
                None
            }
        }

        let dt = EmptyDynamicDataType;
        assert_eq!(dt.get_num_components(&MockMemBuffer), -1);
        assert_eq!(dt.dynamic_length_from_components(&MockMemBuffer, -1), -1);
        assert!(dt.get_components(&MockMemBuffer).is_none());
    }
}
