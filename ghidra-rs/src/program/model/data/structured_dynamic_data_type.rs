//! Port of `ghidra.program.model.data.StructuredDynamicDataType`.
//!
//! Structured Dynamic Data type: a dynamic structure that is built by adding data types to it.
//!
//! NOTE: This is a special Dynamic data-type which can only appear as a component created by a
//! Dynamic data-type.
//!
//! The Java class is `abstract class StructuredDynamicDataType extends DynamicDataType`, so this
//! trait carries [`DynamicDataType`] (and transitively `Dynamic`/`BuiltInDataType`/[`DataType`])
//! as its supertrait chain -- the same shape
//! [`CountedDynamicDataType`](super::counted_dynamic_data_type::CountedDynamicDataType) already
//! uses for the same Java superclass. The Java constructor's fields (`description`, `components`,
//! `componentNames`, `componentDescs`) become the accessor methods below, which a concrete
//! implementation supplies from its own storage.
//!
//! `DynamicDataType::get_all_components` is the method Java's `getAllComponents(MemBuffer)`
//! overrides; since a Rust subtrait cannot redeclare a supertrait method of the same name (see
//! [`DynamicDataType`]'s docs for why, and
//! [`CountedDynamicDataType::counted_all_components`](super::counted_dynamic_data_type::CountedDynamicDataType::counted_all_components)
//! for the identical situation on the sibling class), the template implementation is exposed here
//! under [`structured_dynamic_all_components`](Self::structured_dynamic_all_components); a
//! concrete type implementing both traits should have its `DynamicDataType::get_all_components`
//! delegate to it.
//!
//! `getValue`/`getRepresentation` are not repeated here: Java's bodies (`null`/`""`) already match
//! [`DataType::get_value`]/[`DataType::get_representation`]'s existing defaults (`None`/
//! `String::new()`), matching [`CountedDynamicDataType`]'s identical precedent for the same two
//! methods. `getDescription()` and `getMnemonic(Settings)` *do* differ from their respective
//! [`DataType`] defaults (a stored field rather than an empty string / `get_name()`'s result), so
//! they are ported under distinct `structured_dynamic_*` names for the usual name-clash reason.
//!
//! The commented-out `clone(DataTypeManager)` override present in the Java source (entirely
//! `//`-commented, i.e. dead code even in Java) is not ported.
//!
//! ## `getAllComponents`'s dependencies
//!
//! Java's override builds a `MemoryBufferImpl` and calls the real, now-ported
//! `DataTypeInstance.getDataTypeInstance`/`ReadOnlyDataTypeComponent` classes. This port instead
//! uses [`seam_stubs::get_data_type_instance`]/[`seam_stubs::ReadOnlyDataTypeComponent`], exactly
//! mirroring [`CountedDynamicDataType::counted_all_components`](super::counted_dynamic_data_type::CountedDynamicDataType::counted_all_components)'s
//! own, already-established choice for the identical Java pattern: the *real*
//! [`ReadOnlyDataTypeComponent`](super::read_only_data_type_component::ReadOnlyDataTypeComponent)'s
//! constructor requires `parent: Arc<dyn DynamicDataType>`, but a trait default method only has
//! `&self`, from which an `Arc<Self>` handle back to the same object cannot be soundly recovered
//! in general -- the same problem the seam-stub version's own doc comment describes as its reason
//! for dropping the `parent` constructor argument entirely. Since the sibling class already
//! accepted this trade-off for the same reason, this port follows suit rather than introducing a
//! second, inconsistent answer to the identical problem.

use std::sync::Arc;

use crate::docking::settings::settings::Settings;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::dynamic_data_type::DynamicDataType;
use crate::program::model::mem::MemBuffer;
use crate::program::seam_stubs;

/// Structured Dynamic Data type: a dynamic structure built by adding data types to it.
///
/// Port of `ghidra.program.model.data.StructuredDynamicDataType`. See the module-level
/// documentation for the accessor convention standing in for private fields, and for what was
/// left identical to an existing default or exposed under a distinct name.
pub trait StructuredDynamicDataType: DynamicDataType {
    /// Backing storage for the protected `description` field.
    fn stored_description(&self) -> Option<String>;

    /// Mutator for the protected `description` field's backing storage.
    fn set_stored_description(&mut self, description: Option<String>);

    /// Backing storage for the protected `components` field.
    fn stored_components(&self) -> Vec<Arc<dyn DataType>>;

    /// Mutator for the protected `components` field's backing storage.
    fn set_stored_components(&mut self, components: Vec<Arc<dyn DataType>>);

    /// Backing storage for the protected `componentNames` field.
    fn stored_component_names(&self) -> Vec<String>;

    /// Mutator for the protected `componentNames` field's backing storage.
    fn set_stored_component_names(&mut self, component_names: Vec<String>);

    /// Backing storage for the protected `componentDescs` field.
    fn stored_component_descriptions(&self) -> Vec<String>;

    /// Mutator for the protected `componentDescs` field's backing storage.
    fn set_stored_component_descriptions(&mut self, component_descriptions: Vec<String>);

    /// Port of `StructuredDynamicDataType.add(DataType, String, String)`: adds a component data
    /// type onto the end of the dynamic structure.
    fn structured_dynamic_add(
        &mut self,
        data: Arc<dyn DataType>,
        component_name: String,
        component_description: String,
    ) {
        let mut components = self.stored_components();
        components.push(data);
        self.set_stored_components(components);

        let mut names = self.stored_component_names();
        names.push(component_name);
        self.set_stored_component_names(names);

        let mut descriptions = self.stored_component_descriptions();
        descriptions.push(component_description);
        self.set_stored_component_descriptions(descriptions);
    }

    /// Port of `StructuredDynamicDataType.setComponents(List, List, List)`: replaces all existing
    /// components at once (rather than appending, unlike
    /// [`structured_dynamic_add`](Self::structured_dynamic_add)).
    fn structured_dynamic_set_components(
        &mut self,
        components: Vec<Arc<dyn DataType>>,
        component_names: Vec<String>,
        component_descriptions: Vec<String>,
    ) {
        self.set_stored_components(components);
        self.set_stored_component_names(component_names);
        self.set_stored_component_descriptions(component_descriptions);
    }

    /// Port of `StructuredDynamicDataType.getDescription()`. Exposed under a distinct name since
    /// [`DataType::get_description`] already provides a (different, empty-string) default. A
    /// concrete `impl DataType for ...` should delegate `get_description` to this.
    fn structured_dynamic_description(&self) -> String {
        self.stored_description().unwrap_or_default()
    }

    /// Port of `StructuredDynamicDataType.getMnemonic(Settings)`. Exposed under a distinct name
    /// since [`DataType::get_mnemonic`] already provides a (different, but often equivalent)
    /// default. A concrete `impl DataType for ...` should delegate `get_mnemonic` to this.
    fn structured_dynamic_mnemonic(&self, settings: &dyn Settings) -> String {
        let _ = settings;
        self.get_name()
    }

    /// Template implementation backing the Java class's override of
    /// `DynamicDataType.getAllComponents(MemBuffer)`. See the module docs for why this is exposed
    /// under a distinct name, and for the `ReadOnlyDataTypeComponent`/`DataTypeInstance` seam-stub
    /// choice.
    ///
    /// Returns all components, or `None` if a data-type instance could not be determined for any
    /// component, or if the running offset overflows the address space (mirroring Java's
    /// `AddressOverflowException` catch, both of which return `null` in the original).
    fn structured_dynamic_all_components(
        &self,
        buf: &dyn MemBuffer,
    ) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
        let components = self.stored_components();
        let names = self.stored_component_names();

        let mut comps: Vec<Option<Box<dyn DataTypeComponent>>> = Vec::with_capacity(components.len());
        let mut offset: i32 = 0;
        let mut cur_addr = buf.get_address();
        for (i, data_type) in components.iter().enumerate() {
            let instance = seam_stubs::get_data_type_instance(Arc::clone(data_type), buf, false)?;
            let len = instance.get_length();
            let field_name = format!("{}_{}", names.get(i).cloned().unwrap_or_default(), cur_addr);
            comps.push(Some(Box::new(seam_stubs::ReadOnlyDataTypeComponent::new(
                instance.get_data_type(),
                len,
                i as i32,
                offset,
                field_name,
            ))));
            offset += len;
            cur_addr = cur_addr.add(len as i64).ok()?;
        }
        Some(comps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn ram_address(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }
    use crate::program::model::data::dynamic::Dynamic;
    use crate::program::model::mem::MemoryAccessException;

    #[derive(Clone)]
    struct MockLeaf {
        name: String,
        length: i32,
    }
    impl DataType for MockLeaf {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            self.length
        }
    }

    struct MockBuf {
        addr: Address,
    }
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> Address {
            self.addr.clone()
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            Ok(0)
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            0
        }
        fn is_big_endian(&self) -> bool {
            false
        }
    }

    #[derive(Default)]
    struct TestStructured {
        name: String,
        description: Option<String>,
        components: Vec<Arc<dyn DataType>>,
        component_names: Vec<String>,
        component_descriptions: Vec<String>,
    }

    impl DataType for TestStructured {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            -1 // required directly, per DynamicDataType's own doc comment
        }
        fn get_description(&self) -> String {
            self.structured_dynamic_description()
        }
        fn get_mnemonic(&self, settings: &dyn Settings) -> String {
            self.structured_dynamic_mnemonic(settings)
        }
    }

    impl crate::program::model::data::built_in_data_type::BuiltInDataType for TestStructured {
        fn get_c_type_declaration(
            &self,
            _data_organization: Option<&crate::program::model::data::data_organization_impl::DataOrganizationImpl>,
        ) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }

    impl Dynamic for TestStructured {
        fn get_dynamic_length(&self, _buf: &dyn MemBuffer, _max_length: i32) -> i32 {
            -1
        }
        fn get_replacement_base_type(&self) -> Box<dyn DataType> {
            Box::new(MockLeaf { name: "undefined".to_string(), length: 1 })
        }
    }

    impl DynamicDataType for TestStructured {
        fn get_all_components(&self, buf: &dyn MemBuffer) -> Option<Vec<Option<Box<dyn DataTypeComponent>>>> {
            self.structured_dynamic_all_components(buf)
        }
    }

    impl StructuredDynamicDataType for TestStructured {
        fn stored_description(&self) -> Option<String> {
            self.description.clone()
        }
        fn set_stored_description(&mut self, description: Option<String>) {
            self.description = description;
        }
        fn stored_components(&self) -> Vec<Arc<dyn DataType>> {
            self.components.clone()
        }
        fn set_stored_components(&mut self, components: Vec<Arc<dyn DataType>>) {
            self.components = components;
        }
        fn stored_component_names(&self) -> Vec<String> {
            self.component_names.clone()
        }
        fn set_stored_component_names(&mut self, component_names: Vec<String>) {
            self.component_names = component_names;
        }
        fn stored_component_descriptions(&self) -> Vec<String> {
            self.component_descriptions.clone()
        }
        fn set_stored_component_descriptions(&mut self, component_descriptions: Vec<String>) {
            self.component_descriptions = component_descriptions;
        }
    }

    fn leaf(name: &str, length: i32) -> Arc<dyn DataType> {
        Arc::new(MockLeaf { name: name.to_string(), length })
    }

    #[test]
    fn add_appends_component_name_and_description() {
        let mut s = TestStructured::default();
        s.structured_dynamic_add(leaf("byte", 1), "field0".to_string(), "first field".to_string());
        s.structured_dynamic_add(leaf("dword", 4), "field1".to_string(), "second field".to_string());
        assert_eq!(s.stored_components().len(), 2);
        assert_eq!(s.stored_component_names(), vec!["field0", "field1"]);
        assert_eq!(s.stored_component_descriptions(), vec!["first field", "second field"]);
    }

    #[test]
    fn set_components_replaces_rather_than_appends() {
        let mut s = TestStructured::default();
        s.structured_dynamic_add(leaf("byte", 1), "old".to_string(), "old desc".to_string());
        s.structured_dynamic_set_components(
            vec![leaf("word", 2)],
            vec!["new".to_string()],
            vec!["new desc".to_string()],
        );
        assert_eq!(s.stored_component_names(), vec!["new"]);
        assert_eq!(s.stored_components().len(), 1);
    }

    #[test]
    fn description_reflects_stored_field() {
        let mut s = TestStructured::default();
        assert_eq!(s.structured_dynamic_description(), "");
        s.set_stored_description(Some("a dynamic structure".to_string()));
        assert_eq!(DataType::get_description(&s), "a dynamic structure");
    }

    struct NoSettings;
    impl Settings for NoSettings {}

    #[test]
    fn mnemonic_returns_raw_name() {
        let s = TestStructured { name: "MyDynamic".to_string(), ..Default::default() };
        assert_eq!(DataType::get_mnemonic(&s, &NoSettings), "MyDynamic");
    }

    #[test]
    fn get_all_components_builds_offsets_and_field_names() {
        let mut s = TestStructured::default();
        s.structured_dynamic_add(leaf("byte", 1), "a".to_string(), String::new());
        s.structured_dynamic_add(leaf("dword", 4), "b".to_string(), String::new());
        let buf = MockBuf { addr: ram_address(0) };

        let comps = DynamicDataType::get_all_components(&s, &buf).expect("components expected");
        assert_eq!(comps.len(), 2);
        let first = comps[0].as_ref().unwrap();
        assert_eq!(first.get_ordinal(), 0);
        assert_eq!(first.get_offset(), 0);
        assert_eq!(first.get_length(), 1);
        assert!(first.get_field_name().unwrap().starts_with("a_"));

        let second = comps[1].as_ref().unwrap();
        assert_eq!(second.get_ordinal(), 1);
        assert_eq!(second.get_offset(), 1); // right after the 1-byte first component
        assert_eq!(second.get_length(), 4);
        assert!(second.get_field_name().unwrap().starts_with("b_"));
    }

    #[test]
    fn get_all_components_empty_when_no_components_added() {
        let s = TestStructured::default();
        let buf = MockBuf { addr: ram_address(0) };
        let comps = DynamicDataType::get_all_components(&s, &buf).expect("components expected");
        assert!(comps.is_empty());
    }

    #[test]
    fn get_num_components_reflects_component_count() {
        let mut s = TestStructured::default();
        s.structured_dynamic_add(leaf("byte", 1), "a".to_string(), String::new());
        let buf = MockBuf { addr: ram_address(0) };
        assert_eq!(DynamicDataType::get_num_components(&s, &buf), 1);
    }
}
