use super::{Address, AddressSet, AddressSetView, AddressSpace, AddressSpaceType};
use std::collections::HashMap;
use std::sync::Arc;

pub trait AddressFactory: Send + Sync {
    fn get_address(&self, addr_string: &str) -> Option<Address>;
    fn get_all_addresses(&self, addr_string: &str) -> Vec<Address> {
        self.get_all_addresses_case(addr_string, true)
    }
    fn get_all_addresses_case(&self, addr_string: &str, case_sensitive: bool) -> Vec<Address>;
    fn get_default_address_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>>;
    fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>>;
    fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>>;
    fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>>;
    fn get_num_address_spaces(&self) -> usize;
    fn is_valid_address(&self, address: &Address) -> bool;
    fn get_index(&self, address: &Address) -> i64;
    fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace>;
    fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>>;
    fn address(&self, space_id: i32, offset: i64) -> Option<Address>;
    fn get_stack_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_constant_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_unique_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_register_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_constant_address(&self, offset: i64) -> Option<Address>;
    fn get_address_set_range(&self, min: &Address, max: &Address) -> AddressSet;
    fn get_address_set(&self) -> AddressSet;
    fn old_get_address_from_long(&self, value: i64) -> Option<Address>;
    fn has_multiple_memory_spaces(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultAddressFactory {
    spaces_by_name: HashMap<String, Arc<AddressSpace>>,
    spaces_by_id: HashMap<i32, Arc<AddressSpace>>,
    all_spaces: Vec<Arc<AddressSpace>>,
    default_space: Option<Arc<AddressSpace>>,
    memory_address_set: AddressSet,
    register_space: Option<Arc<AddressSpace>>,
}

impl DefaultAddressFactory {
    pub fn new(spaces: Vec<Arc<AddressSpace>>) -> Self {
        let default_space = spaces.first().cloned();
        Self::with_default_space(spaces, default_space)
    }

    pub fn with_default_space(
        spaces: Vec<Arc<AddressSpace>>,
        default_space: Option<Arc<AddressSpace>>,
    ) -> Self {
        let mut spaces_by_name = HashMap::new();
        let mut spaces_by_id = HashMap::new();
        let mut memory_address_set = AddressSet::new();
        let mut register_space = None;
        for space in &spaces {
            validate_space(space);
            spaces_by_name.insert(space.name().to_string(), space.clone());
            spaces_by_id.insert(space.space_id(), space.clone());
            if space.is_memory_space() {
                memory_address_set.add_range(&space.min_address(), &space.max_address());
            }
            if space.space_type() == AddressSpaceType::Register {
                register_space = Some(space.clone());
            }
        }

        if let Some(default_space) = &default_space {
            if !spaces.iter().any(|space| space == default_space) {
                panic!("Specified default space not in array");
            }
        }

        let register_space = register_space.or_else(|| {
            Some(AddressSpace::new(
                "REGISTER",
                32,
                1,
                AddressSpaceType::Register,
                0,
            ))
        });

        Self {
            spaces_by_name,
            spaces_by_id,
            all_spaces: spaces,
            default_space,
            memory_address_set,
            register_space,
        }
    }
}

impl AddressFactory for DefaultAddressFactory {
    fn get_address(&self, addr_string: &str) -> Option<Address> {
        if let Some(default_space) = &self.default_space {
            match default_space.parse_address(addr_string, true) {
                Ok(Some(address)) => return Some(address),
                Ok(None) | Err(_) => {}
            }
        }

        for space in &self.all_spaces {
            if self
                .default_space
                .as_ref()
                .map(|default_space| default_space == space)
                .unwrap_or(false)
            {
                continue;
            }
            match space.parse_address(addr_string, true) {
                Ok(Some(address)) => return Some(address),
                Ok(None) | Err(_) => {}
            }
        }
        None
    }

    fn get_all_addresses_case(&self, addr_string: &str, case_sensitive: bool) -> Vec<Address> {
        let mut loaded_memory = Vec::new();
        let mut other_memory = Vec::new();

        for space in self
            .all_spaces
            .iter()
            .filter(|space| space.is_memory_space())
        {
            let Ok(Some(address)) = space.parse_address(addr_string, case_sensitive) else {
                continue;
            };
            if !space.is_loaded_memory_space() {
                other_memory.push(address);
            } else if self
                .default_space
                .as_ref()
                .map(|default_space| default_space == space)
                .unwrap_or(false)
            {
                loaded_memory.insert(0, address);
            } else {
                loaded_memory.push(address);
            }
        }

        if loaded_memory.is_empty() && other_memory.len() == 1 {
            return other_memory;
        }
        loaded_memory
    }

    fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
        self.default_space.clone()
    }

    fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
        self.get_physical_spaces()
    }

    fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
        self.spaces_by_name.get(name).cloned()
    }

    fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
        self.spaces_by_id.get(&id).cloned()
    }

    fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
        self.all_spaces.clone()
    }

    fn get_num_address_spaces(&self) -> usize {
        self.get_physical_spaces().len()
    }

    fn is_valid_address(&self, address: &Address) -> bool {
        self.all_spaces.iter().any(|space| space == address.space())
    }

    fn get_index(&self, address: &Address) -> i64 {
        ((address.space().space_id() as i64) << 48).wrapping_add(address.offset())
    }

    fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
        space.clone()
    }

    fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
        self.all_spaces
            .iter()
            .filter(|space| space.is_memory_space())
            .cloned()
            .collect()
    }

    fn address(&self, space_id: i32, offset: i64) -> Option<Address> {
        self.get_address_space_by_id(space_id)
            .map(|space| space.address(offset))
    }

    fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
        self.all_spaces
            .iter()
            .find(|s| s.space_type() == AddressSpaceType::Stack)
            .cloned()
    }

    fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
        self.all_spaces
            .iter()
            .find(|s| s.space_type() == AddressSpaceType::Constant)
            .cloned()
    }

    fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
        self.all_spaces
            .iter()
            .find(|s| s.space_type() == AddressSpaceType::Unique)
            .cloned()
    }

    fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
        self.register_space.clone()
    }

    fn get_constant_address(&self, offset: i64) -> Option<Address> {
        self.get_constant_space().map(|space| space.address(offset))
    }

    fn get_address_set_range(&self, min: &Address, max: &Address) -> AddressSet {
        if min.space() == max.space() {
            return AddressSet::from_start_end(min.clone(), max.clone());
        }
        let mut set = AddressSet::new();
        let mut ranges = self.memory_address_set.address_ranges();
        while let Some(range) = ranges.next_range() {
            if range.max_address() < min || range.min_address() > max {
                continue;
            }
            let start = if range.space() == min.space() && min > range.min_address() {
                min.clone()
            } else {
                range.min_address().clone()
            };
            let end = if range.space() == max.space() && max < range.max_address() {
                max.clone()
            } else {
                range.max_address().clone()
            };
            set.add_range(&start, &end);
        }
        set
    }

    fn get_address_set(&self) -> AddressSet {
        AddressSet::from_set(&self.memory_address_set)
    }

    fn old_get_address_from_long(&self, value: i64) -> Option<Address> {
        let space_id = (value >> 48) as i32;
        let offset = value & 0xffff_ffff;
        self.address(space_id, offset)
    }

    fn has_multiple_memory_spaces(&self) -> bool {
        self.get_physical_spaces().len() > 1
    }
}

fn validate_space(space: &AddressSpace) {
    match space.space_type() {
        AddressSpaceType::Variable => panic!("Variable space should not be specified"),
        AddressSpaceType::Join => panic!("Join space should not be specified"),
        AddressSpaceType::External => panic!("External space should not be specified"),
        AddressSpaceType::Stack => panic!("Stack space should not be specified"),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_space_parses_bare_addresses_before_other_spaces() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let code = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 2);
        let factory = DefaultAddressFactory::with_default_space(
            vec![code.clone(), ram.clone()],
            Some(ram.clone()),
        );

        assert_eq!(factory.get_address("1000"), Some(ram.address(0x1000)));
        assert_eq!(factory.get_address("code:1000"), Some(code.address(0x1000)));
        assert_eq!(factory.get_default_address_space(), Some(ram));
    }

    #[test]
    fn all_addresses_prefers_loaded_memory_and_default_first() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let code = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 2);
        let other = AddressSpace::new("OTHER", 32, 1, AddressSpaceType::Other, 3);
        let factory = DefaultAddressFactory::with_default_space(
            vec![code.clone(), other.clone(), ram.clone()],
            Some(ram.clone()),
        );

        let addresses = factory.get_all_addresses("1000");
        assert_eq!(addresses, vec![ram.address(0x1000), code.address(0x1000)]);

        let other_only = DefaultAddressFactory::new(vec![other.clone()]);
        assert_eq!(
            other_only.get_all_addresses("1000"),
            vec![other.address(0x1000)]
        );
    }

    #[test]
    fn lookup_and_space_lists_match_java_factory_contract() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let constant = AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 2);
        let unique = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 3);
        let register = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 4);
        let factory = DefaultAddressFactory::new(vec![
            ram.clone(),
            constant.clone(),
            unique.clone(),
            register.clone(),
        ]);

        assert_eq!(factory.get_address_space_by_name("ram"), Some(ram.clone()));
        assert_eq!(
            factory.get_address_space_by_id(ram.space_id()),
            Some(ram.clone())
        );
        assert_eq!(factory.get_address_spaces(), vec![ram.clone()]);
        assert_eq!(factory.get_num_address_spaces(), 1);
        assert_eq!(factory.get_all_address_spaces().len(), 4);
        assert_eq!(factory.get_constant_space(), Some(constant.clone()));
        assert_eq!(factory.get_unique_space(), Some(unique));
        assert_eq!(factory.get_register_space(), Some(register));
        assert_eq!(factory.get_constant_address(-1), Some(constant.address(-1)));
    }

    #[test]
    fn index_encoding_and_decoding_round_trip() {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let factory = DefaultAddressFactory::new(vec![ram.clone()]);
        let address = ram.address(0x1234);
        let index = factory.get_index(&address);

        assert_eq!(factory.old_get_address_from_long(index), Some(address));
        assert_eq!(
            factory.address(ram.space_id(), 0x20),
            Some(ram.address(0x20))
        );
        assert!(factory.is_valid_address(&ram.address(0)));
    }

    #[test]
    fn memory_address_set_spans_physical_spaces() {
        let ram = AddressSpace::new("ram", 8, 1, AddressSpaceType::Ram, 1);
        let code = AddressSpace::new("code", 8, 1, AddressSpaceType::Code, 2);
        let factory = DefaultAddressFactory::new(vec![ram.clone(), code.clone()]);

        let set = factory.get_address_set();
        assert_eq!(set.num_address_ranges(), 2);
        assert!(set.contains_range(&ram.address(0), &ram.address(0xff)));
        assert!(set.contains_range(&code.address(0), &code.address(0xff)));
        assert!(factory.has_multiple_memory_spaces());

        let range = factory.get_address_set_range(&ram.address(0x80), &code.address(0x7f));
        assert!(range.contains_range(&ram.address(0x80), &ram.address(0xff)));
        assert!(range.contains_range(&code.address(0), &code.address(0x7f)));
    }

    #[test]
    #[should_panic(expected = "Stack space should not be specified")]
    fn constructor_rejects_reserved_stack_space() {
        let stack = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1);
        let _ = DefaultAddressFactory::new(vec![stack]);
    }
}
