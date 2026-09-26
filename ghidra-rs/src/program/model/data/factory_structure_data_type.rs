//! Port of `ghidra.program.model.data.FactoryStructureDataType`.
//!
//! The Java class is `abstract class FactoryStructureDataType extends BuiltIn implements
//! FactoryDataType`, with one abstract method (`populateDynamicStructure`) that concrete
//! subclasses supply. Both supertraits ([`BuiltIn`] and [`FactoryDataType`]) are already ported,
//! so this trait extends them directly -- the same shape [`BooleanDataType`](super::boolean_data_type::BooleanDataType)
//! and this crate's other `abstract class extends X implements Y` cut-point traits already use.
//!
//! ## `get_data_type` is real, not a stub
//!
//! [`FactoryDataType::get_data_type`] (the method this whole class exists to implement) has no
//! default on its own supertrait, so this trait is free to declare its *own* `get_data_type` with
//! a real body (no ambiguous-override concern, since there is no existing default to collide
//! with). Note that -- exactly like
//! [`CountedDynamicDataType::counted_all_components`](super::counted_dynamic_data_type::CountedDynamicDataType::counted_all_components)'s
//! identical situation with `DynamicDataType::get_all_components` -- a subtrait method of the same
//! name as a supertrait's required (no-default) method is still a *distinct* trait item in Rust;
//! it does not automatically satisfy the supertrait's requirement. A concrete type implementing
//! both `FactoryDataType` and `FactoryStructureDataType` must still give its own
//! `FactoryDataType::get_data_type` a one-line body delegating to
//! `FactoryStructureDataType::get_data_type(self, buf)` (see this module's own tests for a
//! working example). The real logic lives here, built on
//! [`populate_dynamic_structure`](Self::populate_dynamic_structure) (required, mirroring the Java
//! `abstract` method) and [`new_empty_structure`](Self::new_empty_structure) (a second, new
//! required method -- see below).
//!
//! ## The one genuine blocker: constructing `new StructureDataType(getName(), 0)`
//!
//! Java's `getDataType(MemBuffer)` starts with `new StructureDataType(getName(), 0)`. The
//! concrete `StructureDataType` class has no constructible Rust port yet -- only a cut-point
//! *trait* skeleton exists (`structure_data_type.rs`, whose own module docs list its five public
//! constructors as one of the pieces "left to whatever concrete type eventually backs" it). Rather
//! than blocking this entire class on that gap, [`new_empty_structure`](Self::new_empty_structure)
//! is exposed as a required method with no default, standing in for exactly that constructor call
//! -- mirroring [`StructureFactory::new_structure`](super::structure_factory::StructureFactory::new_structure)'s
//! already-established, identical answer to the identical gap. Once a concrete `StructureDataType`
//! exists, an implementor's `new_empty_structure` becomes a one-line `StructureDataType::new(name,
//! 0)`, and [`get_data_type`](FactoryDataType::get_data_type)'s default here needs no further
//! changes.
//!
//! ## Ported faithfully
//!
//! - [`add_component`](Self::add_component)/[`add_component_with_length`](Self::add_component_with_length):
//!   `Structure.add(DataType, String)`-style helpers, built on the already-ported
//!   [`Composite::add_with_length_and_name`](super::composite::Composite::add_with_length_and_name).
//! - [`factory_structure_set_category_path`](Self::factory_structure_set_category_path)/the private
//!   free function [`set_category`]: the recursive category-path assignment walking
//!   Structure/Union/TypeDef/Pointer/Array component trees, matching the Java `instanceof` chain
//!   method-for-method via the already-ported [`DataType::as_structure`]/`as_union`/`as_typedef`/
//!   `as_pointer`/`as_array` downcasts.
//! - [`factory_structure_description`](Self::factory_structure_description): the literal
//!   `"Dynamic Data Type should not be instantiated directly"` string.
//!
//! ## Known fidelity limitation of the recursive descent
//!
//! [`set_category`]'s recursion into a component's data type calls
//! [`DataTypeComponent::get_data_type`](super::data_type_component::DataTypeComponent::get_data_type),
//! which for the crate's real, already-ported component implementation
//! ([`DataTypeComponentImpl`](super::data_type_component_impl::DataTypeComponentImpl)) returns a
//! [`share_data_type`](crate::program::seam_stubs::share_data_type) handle. That handle *does*
//! forward the `as_structure`/`as_union`/`as_typedef`/`as_pointer`/`as_array` downcasts (so the
//! recursive dispatch still visits every nested component correctly), but it does **not** forward
//! `set_category_path` (a `&mut self` method -- the handle only ever holds a shared, immutable
//! `Arc<dyn DataType>`), so the actual category-path mutation silently no-ops for any component
//! reached this way. This is a pre-existing limitation of `share_data_type` itself (see its own
//! and [`TypedefDataType`](super::typedef_data_type::TypedefDataType)'s module docs for the same
//! "detached/partially-forwarding handle" trade-off), not something new introduced here. Only the
//! outermost structure passed into [`factory_structure_set_category_path`](Self::factory_structure_set_category_path)
//! directly (by mutable reference, never through a `share_data_type` handle) is guaranteed to
//! actually have its category path updated.
//!
//! `getValue`/`getRepresentation` are not overridden: Java's bodies (`return null;`) are
//! close enough to the pre-existing [`DataType::get_value`]/[`DataType::get_representation`]
//! defaults (`None`/`String::new()`) that no override is needed, mirroring the "identical to an
//! existing default" convention documented throughout this crate's other cut-point traits.
//! [`DataType::get_length`] must still be implemented directly by any concrete type to return
//! `-1` -- this is [`FactoryDataType`]'s own pre-existing requirement, not new here.

use crate::program::model::data::category_path::{CategoryPath, ROOT};
use crate::program::model::data::composite::Composite;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_type_component::DataTypeComponent;
use crate::program::model::data::factory_data_type::FactoryDataType;
use crate::program::model::data::structure::Structure;
use crate::program::model::data::built_in::BuiltIn;
use crate::program::model::mem::MemBuffer;

/// Port of the private `FactoryStructureDataType.setCategory(DataType, CategoryPath)`.
///
/// Sets `dt`'s category path, then recurses into its nested component data types (for
/// Structure/Union) or wrapped data type (for TypeDef/Pointer/Array), matching the Java
/// `instanceof` chain exactly. See the module docs for the recursion's known fidelity limitation
/// when a component's data type is reached through a `share_data_type`-style handle.
fn set_category(dt: &mut dyn DataType, path: &CategoryPath) {
    // Mirrors `try { dt.setCategoryPath(path); } catch (DuplicateNameException e) {}`.
    let _ = dt.set_category_path(path.clone());

    if let Some(structure) = dt.as_structure() {
        let comps = structure.get_defined_components();
        for comp in comps {
            let mut inner = comp.get_data_type();
            set_category(inner.as_mut(), path);
        }
    } else if let Some(union) = dt.as_union() {
        let comps = Composite::get_components(union);
        for comp in comps {
            let mut inner = comp.get_data_type();
            set_category(inner.as_mut(), path);
        }
    } else if let Some(typedef) = dt.as_typedef() {
        let mut inner = typedef.get_data_type();
        set_category(inner.as_mut(), path);
    } else if let Some(pointer) = dt.as_pointer() {
        if let Some(mut inner) = pointer.get_data_type() {
            set_category(inner.as_mut(), path);
        }
    } else if let Some(array) = dt.as_array() {
        let mut inner = array.get_data_type();
        set_category(inner.as_mut(), path);
    }
}

/// Abstract class used to create specialized data structures that act like a Structure and
/// create a new Dynamic structure each time they are used.
///
/// Port of `ghidra.program.model.data.FactoryStructureDataType`. See the module-level
/// documentation for the one genuine blocker ([`new_empty_structure`](Self::new_empty_structure))
/// and for what was ported faithfully.
pub trait FactoryStructureDataType: BuiltIn + FactoryDataType {
    /// Constructs a fresh, empty [`Structure`] named after this factory type, standing in for `new
    /// StructureDataType(getName(), 0)`. See the module docs for why this is required (no default)
    /// rather than provided here directly.
    fn new_empty_structure(&self) -> Box<dyn Structure>;

    /// Port of the abstract `FactoryStructureDataType.populateDynamicStructure(MemBuffer,
    /// Structure)`.
    fn populate_dynamic_structure(&self, buf: &dyn MemBuffer, es: &mut dyn Structure);

    /// Port of `FactoryStructureDataType.getDescription()`.
    ///
    /// Exposed under a distinct name since [`DataType::get_description`] already provides a
    /// (different, empty-string) default.
    fn factory_structure_description(&self) -> String {
        "Dynamic Data Type should not be instantiated directly".to_string()
    }

    /// Port of `FactoryStructureDataType.getDataType(MemBuffer)`.
    ///
    /// See the module docs: a concrete type must still delegate its own
    /// `FactoryDataType::get_data_type` to this method by name (this trait method does not
    /// automatically satisfy that supertrait's requirement, even though the names match and the
    /// supertrait method has no default of its own). Unlike the Java original's `if (buf != null)`
    /// guard -- for which there is no null `MemBuffer` in this port's non-optional `&dyn MemBuffer`
    /// signature (a decision already made when [`FactoryDataType`] itself was ported) -- population
    /// and category assignment always run.
    fn get_data_type(&self, buf: &dyn MemBuffer) -> Box<dyn DataType> {
        let mut structure = self.new_empty_structure();
        self.populate_dynamic_structure(buf, structure.as_mut());
        self.factory_structure_set_category_path(structure.as_mut(), buf);
        structure as Box<dyn DataType>
    }

    /// Port of `FactoryStructureDataType.setCategoryPath(Structure, MemBuffer)`.
    ///
    /// Unlike the Java original (which returns a possibly-different `Structure` reference), this
    /// mutates `structure` in place -- Rust has no need for the Java version's "return the same
    /// object back" idiom since ordinary mutable-reference semantics already express it.
    fn factory_structure_set_category_path(&self, structure: &mut dyn Structure, buf: &dyn MemBuffer) {
        let mut path = ROOT.clone();
        if let Ok(name_path) = CategoryPath::new(ROOT.clone(), &[&self.get_name()]) {
            if let Ok(full_path) = CategoryPath::new(name_path, &[&buf.get_address().to_string()]) {
                path = full_path;
            }
        }
        set_category(structure, &path);
    }

    /// Port of `FactoryStructureDataType.addComponent(Structure, DataType, String)`: adds `dt` to
    /// the end of `es` using `dt`'s own length.
    fn add_component(
        &self,
        es: &mut dyn Structure,
        dt: Box<dyn DataType>,
        component_name: &str,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        let length = dt.get_length();
        self.add_component_with_length(es, dt, length, component_name)
    }

    /// Port of `FactoryStructureDataType.addComponent(Structure, DataType, int, String)`.
    fn add_component_with_length(
        &self,
        es: &mut dyn Structure,
        dt: Box<dyn DataType>,
        length: i32,
        component_name: &str,
    ) -> Result<Box<dyn DataTypeComponent>, String> {
        es.add_with_length_and_name(dt, length, Some(component_name.to_string()), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::category_path::CategoryPath;
    use crate::program::model::data::data_organization_impl::DataOrganizationImpl;
    use crate::program::model::data::data_type_component::DataTypeComponent;
    use crate::program::model::data::data_type_impl::DataTypeImpl;
    use crate::program::model::data::data_type_manager::DataTypeManager;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::data::source_archive::SourceArchive;
    use crate::program::model::data::typedef::TypeDef;
    use crate::program::model::data::union::Union;
    use crate::program::model::mem::MemoryAccessException;
    use std::sync::{Arc, Mutex, Weak};

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

    fn leaf(name: &str, length: i32) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: name.to_string(), length })
    }

    /// A single component: a name plus a fully-owned (not `share_data_type`-wrapped) data type
    /// clone factory, so recursive mutation through [`get_data_type`] is fully observable --
    /// see the module docs' note on `share_data_type`'s more limited real-world fidelity.
    struct MockComponent {
        make: Box<dyn Fn() -> Box<dyn DataType>>,
    }
    impl DataTypeComponent for MockComponent {
        fn get_data_type(&self) -> Box<dyn DataType> {
            (self.make)()
        }
    }

    struct MockStructure {
        name: String,
        category_path: CategoryPath,
        components: Vec<(String, i32)>, // (name, length) added via add_with_length_and_name
        nested: Vec<Arc<Mutex<CategoryPath>>>, // tracks nested structures' mutated category paths
    }
    impl Default for MockStructure {
        fn default() -> Self {
            MockStructure {
                name: String::new(),
                category_path: ROOT.clone(),
                components: Vec::new(),
                nested: Vec::new(),
            }
        }
    }
    impl DataType for MockStructure {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_category_path(&self) -> CategoryPath {
            self.category_path.clone()
        }
        fn set_category_path(&mut self, path: CategoryPath) -> Result<(), crate::util::exception::DuplicateNameException> {
            self.category_path = path;
            Ok(())
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for MockStructure {
        fn add_with_length_and_name(
            &mut self,
            data_type: Box<dyn DataType>,
            length: i32,
            component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            self.components.push((component_name.unwrap_or_default(), length));
            Ok(Box::new(MockComponent { make: Box::new(move || data_type_clone(data_type.as_ref())) }))
        }
        fn get_defined_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            self.nested
                .iter()
                .map(|shared| -> Box<dyn DataTypeComponent> {
                    let shared = Arc::clone(shared);
                    Box::new(MockComponent {
                        make: Box::new(move || {
                            Box::new(NestedStructure { category_path: Arc::clone(&shared) })
                        }),
                    })
                })
                .collect()
        }
    }
    impl Structure for MockStructure {}

    /// Cheap stand-in for "clone whatever concrete `DataType` this is" -- only ever called with a
    /// [`MockLeaf`] in these tests, so a trivial name/length copy suffices (the real crate-wide
    /// `clone_data_type` has its own, unrelated limitations already documented on [`DataType`]).
    fn data_type_clone(dt: &dyn DataType) -> Box<dyn DataType> {
        Box::new(MockLeaf { name: dt.get_name(), length: dt.get_length() })
    }

    /// A nested structure whose category path is backed by a shared `Arc<Mutex<...>>` so a test
    /// can observe mutations made through an owned, detached `Box<dyn DataType>` handle returned
    /// from [`DataTypeComponent::get_data_type`] -- otherwise unobservable once the box is
    /// dropped at the end of `set_category`'s recursive call.
    struct NestedStructure {
        category_path: Arc<Mutex<CategoryPath>>,
    }
    impl DataType for NestedStructure {
        fn get_category_path(&self) -> CategoryPath {
            self.category_path.lock().unwrap().clone()
        }
        fn set_category_path(&mut self, path: CategoryPath) -> Result<(), crate::util::exception::DuplicateNameException> {
            *self.category_path.lock().unwrap() = path;
            Ok(())
        }
        fn as_structure(&self) -> Option<&dyn Structure> {
            Some(self)
        }
    }
    impl Composite for NestedStructure {}
    impl Structure for NestedStructure {}

    struct MockUnion {
        nested: Arc<Mutex<CategoryPath>>,
    }
    impl DataType for MockUnion {
        fn as_union(&self) -> Option<&dyn Union> {
            Some(self)
        }
    }
    impl Composite for MockUnion {
        fn get_components(&self) -> Vec<Box<dyn DataTypeComponent>> {
            let shared = Arc::clone(&self.nested);
            vec![Box::new(MockComponent {
                make: Box::new(move || Box::new(NestedStructure { category_path: Arc::clone(&shared) })),
            })]
        }
    }
    impl Union for MockUnion {
        fn clone_union(&self, _dtm: &dyn DataTypeManager) -> Box<dyn Union> {
            unimplemented!("not exercised by these tests")
        }
        fn insert_bit_field(
            &mut self,
            _ordinal: i32,
            _base_data_type: Box<dyn DataType>,
            _bit_size: i32,
            _component_name: Option<String>,
            _comment: Option<String>,
        ) -> Result<Box<dyn DataTypeComponent>, String> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockTypeDef {
        nested: Arc<Mutex<CategoryPath>>,
    }
    impl DataType for MockTypeDef {
        fn as_typedef(&self) -> Option<&dyn TypeDef> {
            Some(self)
        }
    }
    impl TypeDef for MockTypeDef {
        fn is_auto_named(&self) -> bool {
            false
        }
        fn enable_auto_naming(&mut self) {}
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(NestedStructure { category_path: Arc::clone(&self.nested) })
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            self.get_data_type()
        }
    }

    struct MockPointer {
        nested: Arc<Mutex<CategoryPath>>,
    }
    impl DataType for MockPointer {
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(NestedStructure { category_path: Arc::clone(&self.nested) }))
        }
        fn new_pointer(&self, _data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            unimplemented!("not exercised by these tests")
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unimplemented!("not exercised by these tests")
        }
    }

    struct MockBuf;
    impl MemBuffer for MockBuf {
        fn get_address(&self) -> crate::program::model::address::Address {
            crate::program::model::address::SpecialAddress::no_address()
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

    struct MockSettings;
    impl Settings for MockSettings {}

    /// A real [`DataOrganizationImpl`] configured as this test expects.
    fn mock_data_organization() -> DataOrganizationImpl {
        let mut org = DataOrganizationImpl::get_default_organization(None);
        org.set_big_endian(false);
        org.set_pointer_size(8);
        org.set_pointer_shift(0);
        org.set_char_is_signed(true);
        org.set_char_size(1);
        org.set_wide_char_size(4);
        org.set_short_size(2);
        org.set_integer_size(4);
        org.set_long_size(8);
        org.set_long_long_size(8);
        org.set_float_size(4);
        org.set_double_size(8);
        org.set_long_double_size(8);
        org.set_absolute_max_alignment(0);
        org.set_machine_alignment(8);
        org.set_default_alignment(1);
        org.set_default_pointer_alignment(8);
        org.clear_size_alignment_map();
        org
    }

    /// Minimal concrete `FactoryStructureDataType` implementor exercising the whole trait.
    struct TestFactory {
        name: String,
        settings: Arc<Mutex<()>>,
        parents: Vec<Weak<dyn DataType>>,
    }

    impl TestFactory {
        fn new(name: &str) -> Self {
            TestFactory { name: name.to_string(), settings: Arc::new(Mutex::new(())), parents: Vec::new() }
        }
    }

    impl DataType for TestFactory {
        fn get_name(&self) -> String {
            self.name.clone()
        }
        fn get_length(&self) -> i32 {
            -1 // required directly per FactoryDataType's own doc comment
        }
        fn get_description(&self) -> String {
            self.factory_structure_description()
        }
        fn get_data_organization(&self) -> Arc<DataOrganizationImpl> {
            Arc::new(mock_data_organization())
        }
    }

    impl DataTypeImpl for TestFactory {
        fn stored_default_settings(&self) -> Box<dyn Settings> {
            Box::new(MockSettings)
        }
        fn set_stored_default_settings(&mut self, _settings: Box<dyn Settings>) {}
        fn stored_source_archive(&self) -> Option<Box<dyn SourceArchive>> {
            None
        }
        fn set_stored_source_archive(&mut self, _archive: Option<Box<dyn SourceArchive>>) {}
        fn stored_universal_id(&self) -> crate::util::UniversalID {
            crate::util::UniversalID::new(0)
        }
        fn stored_last_change_time(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time(&mut self, _v: i64) {}
        fn stored_last_change_time_in_source_archive(&self) -> i64 {
            0
        }
        fn set_stored_last_change_time_in_source_archive(&mut self, _v: i64) {}
        fn stored_parent_refs(&self) -> Vec<Weak<dyn DataType>> {
            self.parents.clone()
        }
        fn set_stored_parent_refs(&mut self, parents: Vec<Weak<dyn DataType>>) {
            self.parents = parents;
        }
    }

    impl BuiltInDataType for TestFactory {
        fn get_c_type_declaration(&self, _data_organization: Option<&DataOrganizationImpl>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {
            let _ = &self.settings;
        }
    }

    impl BuiltIn for TestFactory {
        fn built_in_is_equivalent(&self, dt: &dyn DataType) -> bool {
            dt.get_name() == self.get_name()
        }
    }

    impl FactoryDataType for TestFactory {
        fn get_data_type(&self, buf: &dyn MemBuffer) -> Box<dyn DataType> {
            FactoryStructureDataType::get_data_type(self, buf)
        }
    }

    impl FactoryStructureDataType for TestFactory {
        fn new_empty_structure(&self) -> Box<dyn Structure> {
            Box::new(MockStructure { name: self.get_name(), ..Default::default() })
        }

        fn populate_dynamic_structure(&self, _buf: &dyn MemBuffer, es: &mut dyn Structure) {
            self.add_component(es, leaf("byte", 1), "field0").unwrap();
            self.add_component_with_length(es, leaf("dword", 4), 4, "field1").unwrap();
        }
    }

    #[test]
    fn factory_structure_description_matches_java_literal() {
        let f = TestFactory::new("MyDynamic");
        assert_eq!(f.factory_structure_description(), "Dynamic Data Type should not be instantiated directly");
        assert_eq!(DataType::get_description(&f), "Dynamic Data Type should not be instantiated directly");
    }

    #[test]
    fn add_component_uses_data_types_own_length() {
        let mut s = MockStructure { name: "s".to_string(), ..Default::default() };
        let f = TestFactory::new("F");
        f.add_component(&mut s, leaf("dword", 4), "x").unwrap();
        assert_eq!(s.components, vec![("x".to_string(), 4)]);
    }

    #[test]
    fn add_component_with_length_uses_explicit_length() {
        let mut s = MockStructure { name: "s".to_string(), ..Default::default() };
        let f = TestFactory::new("F");
        f.add_component_with_length(&mut s, leaf("dword", 4), 8, "x").unwrap();
        assert_eq!(s.components, vec![("x".to_string(), 8)]);
    }

    #[test]
    fn get_data_type_populates_and_returns_structure() {
        let f = TestFactory::new("MyDynamic");
        let dt = FactoryDataType::get_data_type(&f, &MockBuf);
        // Real component population is verified directly against a `MockStructure` in
        // `populate_dynamic_structure_adds_both_components` (there is no `Any`-downcast available
        // here to inspect the returned `Box<dyn DataType>`'s concrete `MockStructure::components`
        // field). This test instead checks the shape `get_data_type` itself is responsible for:
        // a real `Structure`, with its category path set underneath `MyDynamic` (note: the
        // `-1` length FactoryDataType requires belongs to the *factory* type `f` itself, not to
        // the structure it produces -- see `factory_structure_description_matches_java_literal`'s
        // sibling assertions on `f` for that).
        let structure = dt.as_structure().expect("expected a Structure");
        let path = structure.get_category_path();
        let parent = path.get_parent().expect("path should have a parent");
        assert_eq!(parent.get_name(), "MyDynamic");
    }

    #[test]
    fn set_category_mutates_top_level_structure_directly() {
        let mut s = MockStructure { name: "s".to_string(), ..Default::default() };
        let path = CategoryPath::new(ROOT.clone(), &["MyDynamic"]).unwrap();
        set_category(&mut s, &path);
        assert_eq!(DataType::get_category_path(&s), path);
    }

    #[test]
    fn set_category_recurses_into_nested_structure_component() {
        let nested_path = Arc::new(Mutex::new(ROOT.clone()));
        let mut s = MockStructure { name: "s".to_string(), nested: vec![Arc::clone(&nested_path)], ..Default::default() };
        let path = CategoryPath::new(ROOT.clone(), &["Outer"]).unwrap();
        set_category(&mut s, &path);
        assert_eq!(DataType::get_category_path(&s), path);
        assert_eq!(*nested_path.lock().unwrap(), path); // recursion visited + mutated the nested structure
    }

    #[test]
    fn set_category_recurses_into_union_component() {
        let nested_path = Arc::new(Mutex::new(ROOT.clone()));
        let mut u = MockUnion { nested: Arc::clone(&nested_path) };
        let path = CategoryPath::new(ROOT.clone(), &["Outer"]).unwrap();
        set_category(&mut u, &path);
        assert_eq!(*nested_path.lock().unwrap(), path);
    }

    #[test]
    fn set_category_recurses_into_typedef_wrapped_type() {
        let nested_path = Arc::new(Mutex::new(ROOT.clone()));
        let mut td = MockTypeDef { nested: Arc::clone(&nested_path) };
        let path = CategoryPath::new(ROOT.clone(), &["Outer"]).unwrap();
        set_category(&mut td, &path);
        assert_eq!(*nested_path.lock().unwrap(), path);
    }

    #[test]
    fn set_category_recurses_into_pointer_target() {
        let nested_path = Arc::new(Mutex::new(ROOT.clone()));
        let mut p = MockPointer { nested: Arc::clone(&nested_path) };
        let path = CategoryPath::new(ROOT.clone(), &["Outer"]).unwrap();
        set_category(&mut p, &path);
        assert_eq!(*nested_path.lock().unwrap(), path);
    }

    #[test]
    fn factory_structure_set_category_path_builds_name_and_address_path() {
        let f = TestFactory::new("MyDynamic");
        let mut s = MockStructure { name: f.get_name(), ..Default::default() };
        f.factory_structure_set_category_path(&mut s, &MockBuf);
        let path = DataType::get_category_path(&s);
        let parent = path.get_parent().expect("path should have a parent");
        assert_eq!(parent.get_name(), "MyDynamic");
        assert_eq!(path.get_name(), crate::program::model::address::SpecialAddress::no_address().to_string());
    }

    #[test]
    fn populate_dynamic_structure_adds_both_components() {
        let f = TestFactory::new("MyDynamic");
        let mut s = MockStructure { name: f.get_name(), ..Default::default() };
        f.populate_dynamic_structure(&MockBuf, &mut s);
        assert_eq!(s.components, vec![("field0".to_string(), 1), ("field1".to_string(), 4)]);
    }
}
