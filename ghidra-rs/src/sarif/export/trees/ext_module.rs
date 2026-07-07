use crate::program::model::data::isf::IsfObject;
use crate::program::model::listing::group::Group;
use crate::program::model::listing::program_module::ProgramModule;

use super::ext_fragment::ExtFragment;

/// Represents an extended module for SARIF export.
///
/// Mirrors `ExtModule` from Ghidra's `sarif.export.trees` package. Stores the name
/// of a [`ProgramModule`] along with vectors of child modules and fragments.
pub struct ExtModule {
    pub name: String,
    pub value: String,
    pub modules: Vec<ExtModule>,
    pub fragments: Vec<ExtFragment>,
}

impl ExtModule {
    /// Creates a new `ExtModule` from a [`ProgramModule`].
    ///
    /// Recursively constructs the module hierarchy by iterating over the module's
    /// children. Child modules are converted to `ExtModule` instances, and child
    /// fragments are converted to `ExtFragment` instances. The module is added to
    /// the provided `visited` vector to track processing and avoid cycles.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the module.
    /// * `module` - The program module to extract data from.
    /// * `visited` - A mutable vector tracking visited module names (for cycle detection).
    pub fn new(name: &str, module: &dyn ProgramModule, visited: &mut Vec<String>) -> Self {
        let mut modules = Vec::new();
        let mut fragments = Vec::new();

        if !visited.contains(&name.to_string()) {
            visited.push(name.to_string());

            let children = module.get_children();
            for child in children {
                let child_name = child.get_name();

                if let Some(module_child) = downcast_to_program_module(&*child) {
                    let ext_module = ExtModule::new(&child_name, module_child, visited);
                    modules.push(ext_module);
                } else if let Some(fragment_child) = downcast_to_program_fragment(&*child) {
                    let ext_fragment = ExtFragment::new(fragment_child, visited);
                    fragments.push(ext_fragment);
                }
            }
        }

        Self {
            name: name.to_string(),
            value: String::new(),
            modules,
            fragments,
        }
    }
}

impl IsfObject for ExtModule {}

fn downcast_to_program_module(group: &dyn Group) -> Option<&dyn ProgramModule> {
    (group as &dyn std::any::Any)
        .downcast_ref::<&dyn ProgramModule>()
        .copied()
}

fn downcast_to_program_fragment(group: &dyn Group) -> Option<&dyn crate::program::model::listing::program_fragment::ProgramFragment> {
    (group as &dyn std::any::Any)
        .downcast_ref::<&dyn crate::program::model::listing::program_fragment::ProgramFragment>()
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressRange, AddressRangeIterator, AddressSpace, AddressSpaceType};
    use crate::program::model::address::AddressSet;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::code_unit_iterator::CodeUnitIterator;
    use crate::program::model::listing::program_fragment::ProgramFragment;
    use crate::util::exception::{DuplicateNameException, NotFoundException};
    use std::any::Any;

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockProgramFragment {
        name: String,
        addresses: AddressSet,
    }

    impl MockProgramFragment {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                addresses: AddressSet::new(),
            }
        }
    }

    impl Group for MockProgramFragment {
        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
            self.name = name.to_string();
            Ok(())
        }

        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            false
        }

        fn get_num_parents(&self) -> i32 {
            0
        }

        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }

        fn get_parent_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_tree_name(&self) -> String {
            "Program Tree".to_string()
        }

        fn is_deleted(&self) -> bool {
            false
        }

        fn get_min_address(&self) -> Option<Address> {
            None
        }

        fn get_max_address(&self) -> Option<Address> {
            None
        }
    }

    impl crate::program::model::address::AddressSetView for MockProgramFragment {
        fn contains(&self, address: &Address) -> bool {
            self.addresses.contains(address)
        }

        fn contains_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.contains_range(start, end)
        }

        fn contains_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.addresses.contains_set(set)
        }

        fn is_empty(&self) -> bool {
            self.addresses.is_empty()
        }

        fn min_address(&self) -> Option<Address> {
            self.addresses.min_address()
        }

        fn max_address(&self) -> Option<Address> {
            self.addresses.max_address()
        }

        fn num_address_ranges(&self) -> usize {
            self.addresses.num_address_ranges()
        }

        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            self.addresses.address_ranges()
        }

        fn address_ranges_ordered(&self, forward: bool) -> Box<dyn AddressRangeIterator> {
            self.addresses.address_ranges_ordered(forward)
        }

        fn address_ranges_from(&self, start: &Address, forward: bool) -> Box<dyn AddressRangeIterator> {
            self.addresses.address_ranges_from(start, forward)
        }

        fn num_addresses(&self) -> u64 {
            self.addresses.num_addresses()
        }

        fn addresses(&self, forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            crate::program::model::address::AddressSetView::addresses(&self.addresses, forward)
        }

        fn addresses_from(&self, start: &Address, forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            self.addresses.addresses_from(start, forward)
        }

        fn intersects_set(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.addresses.intersects_set(set)
        }

        fn intersects_range(&self, start: &Address, end: &Address) -> bool {
            self.addresses.intersects_range(start, end)
        }

        fn intersect(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.intersect(set)
        }

        fn intersect_range(&self, start: &Address, end: &Address) -> AddressSet {
            self.addresses.intersect_range(start, end)
        }

        fn union(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.union(set)
        }

        fn subtract(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.subtract(set)
        }

        fn xor(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            self.addresses.xor(set)
        }

        fn has_same_addresses(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            self.addresses.has_same_addresses(set)
        }

        fn first_range(&self) -> Option<AddressRange> {
            self.addresses.first_range()
        }

        fn last_range(&self) -> Option<AddressRange> {
            self.addresses.last_range()
        }

        fn range_containing(&self, address: &Address) -> Option<AddressRange> {
            self.addresses.range_containing(address)
        }

        fn find_first_address_in_common(&self, set: &dyn crate::program::model::address::AddressSetView) -> Option<Address> {
            self.addresses.find_first_address_in_common(set)
        }
    }

    impl ProgramFragment for MockProgramFragment {
        fn get_code_units(&self) -> Box<dyn CodeUnitIterator> {
            Box::new(crate::program::model::listing::code_unit_iterator::EmptyCodeUnitIterator)
        }

        fn move_code_units(&mut self, _min: &Address, _max: &Address) -> Result<(), NotFoundException> {
            Ok(())
        }
    }

    struct MockProgramModule {
        name: String,
        children: Vec<Box<dyn Group>>,
    }

    impl MockProgramModule {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                children: Vec::new(),
            }
        }

        fn add_child(&mut self, child: Box<dyn Group>) {
            self.children.push(child);
        }
    }

    impl Group for MockProgramModule {
        fn get_comment(&self) -> Option<String> {
            None
        }

        fn set_comment(&mut self, _comment: Option<&str>) {}

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) -> Result<(), DuplicateNameException> {
            self.name = name.to_string();
            Ok(())
        }

        fn contains(&self, _code_unit: &dyn CodeUnit) -> bool {
            false
        }

        fn get_num_parents(&self) -> i32 {
            0
        }

        fn get_parents(&self) -> Vec<Box<dyn Group>> {
            Vec::new()
        }

        fn get_parent_names(&self) -> Vec<String> {
            Vec::new()
        }

        fn get_tree_name(&self) -> String {
            "Program Tree".to_string()
        }

        fn is_deleted(&self) -> bool {
            false
        }

        fn get_min_address(&self) -> Option<Address> {
            None
        }

        fn get_max_address(&self) -> Option<Address> {
            None
        }
    }

    impl crate::program::model::address::AddressSetView for MockProgramModule {
        fn contains(&self, _address: &Address) -> bool {
            false
        }

        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }

        fn contains_set(&self, _set: &dyn crate::program::model::address::AddressSetView) -> bool {
            false
        }

        fn is_empty(&self) -> bool {
            true
        }

        fn min_address(&self) -> Option<Address> {
            None
        }

        fn max_address(&self) -> Option<Address> {
            None
        }

        fn num_address_ranges(&self) -> usize {
            0
        }

        fn address_ranges(&self) -> Box<dyn AddressRangeIterator> {
            use crate::program::model::address::EmptyAddressRangeIterator;
            Box::new(EmptyAddressRangeIterator)
        }

        fn address_ranges_ordered(&self, _forward: bool) -> Box<dyn AddressRangeIterator> {
            use crate::program::model::address::EmptyAddressRangeIterator;
            Box::new(EmptyAddressRangeIterator)
        }

        fn address_ranges_from(&self, _start: &Address, _forward: bool) -> Box<dyn AddressRangeIterator> {
            use crate::program::model::address::EmptyAddressRangeIterator;
            Box::new(EmptyAddressRangeIterator)
        }

        fn num_addresses(&self) -> u64 {
            0
        }

        fn addresses(&self, _forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            use crate::program::model::address::EmptyAddressIterator;
            Box::new(EmptyAddressIterator)
        }

        fn addresses_from(&self, _start: &Address, _forward: bool) -> Box<dyn crate::program::model::address::AddressIterator> {
            use crate::program::model::address::EmptyAddressIterator;
            Box::new(EmptyAddressIterator)
        }

        fn intersects_set(&self, _set: &dyn crate::program::model::address::AddressSetView) -> bool {
            false
        }

        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            false
        }

        fn intersect(&self, _set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            AddressSet::new()
        }

        fn intersect_range(&self, _start: &Address, _end: &Address) -> AddressSet {
            AddressSet::new()
        }

        fn union(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            set.union(&AddressSet::new())
        }

        fn subtract(&self, _set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            AddressSet::new()
        }

        fn xor(&self, set: &dyn crate::program::model::address::AddressSetView) -> AddressSet {
            set.xor(&AddressSet::new())
        }

        fn has_same_addresses(&self, set: &dyn crate::program::model::address::AddressSetView) -> bool {
            set.is_empty()
        }

        fn first_range(&self) -> Option<AddressRange> {
            None
        }

        fn last_range(&self) -> Option<AddressRange> {
            None
        }

        fn range_containing(&self, _address: &Address) -> Option<AddressRange> {
            None
        }

        fn find_first_address_in_common(&self, _set: &dyn crate::program::model::address::AddressSetView) -> Option<Address> {
            None
        }
    }

    impl ProgramModule for MockProgramModule {
        fn contains_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            false
        }

        fn contains_module(&self, _module: &dyn ProgramModule) -> bool {
            false
        }

        fn get_num_children(&self) -> i32 {
            self.children.len() as i32
        }

        fn get_children(&self) -> Vec<Box<dyn Group>> {
            self.children.iter().map(|c| {
                if let Some(module) = downcast_to_program_module(c.as_ref()) {
                    let name = c.get_name();
                    let mock = MockProgramModule::new(&name);
                    Box::new(mock) as Box<dyn Group>
                } else if let Some(_fragment) = downcast_to_program_fragment(c.as_ref()) {
                    c.clone_box()
                } else {
                    c.clone_box()
                }
            }).collect()
        }

        fn get_index(&self, name: &str) -> i32 {
            self.children
                .iter()
                .position(|c| c.get_name() == name)
                .map(|i| i as i32)
                .unwrap_or(-1)
        }

        fn add_module(&mut self, _module: Box<dyn ProgramModule>) -> Result<(), crate::program::model::listing::program_module::AddModuleError> {
            Ok(())
        }

        fn add_fragment(&mut self, _fragment: Box<dyn ProgramFragment>) -> Result<(), crate::program::model::listing::DuplicateGroupException> {
            Ok(())
        }

        fn create_module(&mut self, _module_name: &str) -> Result<Box<dyn ProgramModule>, DuplicateNameException> {
            Err(DuplicateNameException::default())
        }

        fn create_fragment(&mut self, _fragment_name: &str) -> Result<Box<dyn ProgramFragment>, DuplicateNameException> {
            Err(DuplicateNameException::default())
        }

        fn reparent(&mut self, _name: &str, _old_parent: &mut dyn ProgramModule) -> Result<(), NotFoundException> {
            Ok(())
        }

        fn move_child(&mut self, _name: &str, _index: i32) -> Result<(), NotFoundException> {
            Ok(())
        }

        fn remove_child(&mut self, _name: &str) -> Result<bool, crate::util::exception::NotEmptyException> {
            Ok(false)
        }

        fn is_descendant_module(&self, _module: &dyn ProgramModule) -> bool {
            false
        }

        fn is_descendant_fragment(&self, _fragment: &dyn ProgramFragment) -> bool {
            false
        }

        fn get_first_address(&self) -> Option<Address> {
            None
        }

        fn get_last_address(&self) -> Option<Address> {
            None
        }

        fn get_address_set(&self) -> &dyn crate::program::model::address::AddressSetView {
            static EMPTY: std::sync::OnceLock<AddressSet> = std::sync::OnceLock::new();
            EMPTY.get_or_init(AddressSet::new)
        }

        fn get_version_tag(&self) -> Box<dyn Any> {
            Box::new(0i64)
        }

        fn get_modification_number(&self) -> i64 {
            0
        }

        fn get_tree_id(&self) -> i64 {
            0
        }
    }

    #[test]
    fn creates_module_with_name() {
        let module = MockProgramModule::new("TestModule");
        let mut visited = Vec::new();

        let ext = ExtModule::new("TestModule", &module, &mut visited);

        assert_eq!(ext.name, "TestModule");
    }

    #[test]
    fn adds_module_to_visited() {
        let module = MockProgramModule::new("MyModule");
        let mut visited = Vec::new();

        ExtModule::new("MyModule", &module, &mut visited);

        assert_eq!(visited.len(), 1);
        assert_eq!(visited[0], "MyModule");
    }

    #[test]
    fn does_not_process_already_visited_module() {
        let module = MockProgramModule::new("MyModule");
        let mut visited = vec!["MyModule".to_string()];

        let ext = ExtModule::new("MyModule", &module, &mut visited);

        assert_eq!(ext.modules.is_empty(), true);
        assert_eq!(ext.fragments.is_empty(), true);
        assert_eq!(visited.len(), 1);
    }

    #[test]
    fn creates_child_fragments() {
        let mut module = MockProgramModule::new("ParentModule");
        let fragment = MockProgramFragment::new("ChildFragment");
        module.add_child(Box::new(fragment));

        let mut visited = Vec::new();
        let ext = ExtModule::new("ParentModule", &module, &mut visited);

        assert_eq!(ext.fragments.len(), 1);
        assert_eq!(ext.fragments[0].name, "ChildFragment");
    }

    #[test]
    fn initializes_value_field_as_empty_string() {
        let module = MockProgramModule::new("TestModule");
        let mut visited = Vec::new();

        let ext = ExtModule::new("TestModule", &module, &mut visited);

        assert_eq!(ext.value, "");
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let module = MockProgramModule::new("TestModule");
        let mut visited = Vec::new();
        let ext = ExtModule::new("TestModule", &module, &mut visited);

        accepts_isf_object(&ext);
    }

    #[test]
    fn handles_multiple_child_types() {
        let mut module = MockProgramModule::new("ParentModule");
        let fragment = MockProgramFragment::new("Fragment1");
        module.add_child(Box::new(fragment));

        let mut visited = Vec::new();
        let ext = ExtModule::new("ParentModule", &module, &mut visited);

        assert_eq!(ext.fragments.len(), 1);
        assert_eq!(ext.modules.is_empty(), true);
    }

    #[test]
    fn preserves_module_name_exactly() {
        let names = vec!["a", "Module_With_Underscore", "123", "MixedCASE"];
        for name in names {
            let module = MockProgramModule::new(name);
            let mut visited = Vec::new();

            let ext = ExtModule::new(name, &module, &mut visited);

            assert_eq!(ext.name, name);
        }
    }
}
