use super::{AddressSpace, AddressSpaceType};
use std::collections::HashMap;
use std::sync::Arc;

pub trait AddressFactory: Send + Sync {
    fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>>;
    fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>>;
    fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>>;
    fn get_stack_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_constant_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_unique_space(&self) -> Option<Arc<AddressSpace>>;
    fn get_register_space(&self) -> Option<Arc<AddressSpace>>;
}

pub struct DefaultAddressFactory {
    spaces_by_name: HashMap<String, Arc<AddressSpace>>,
    spaces_by_id: HashMap<i32, Arc<AddressSpace>>,
    all_spaces: Vec<Arc<AddressSpace>>,
}

impl DefaultAddressFactory {
    pub fn new(spaces: Vec<Arc<AddressSpace>>) -> Self {
        let mut spaces_by_name = HashMap::new();
        let mut spaces_by_id = HashMap::new();
        for space in &spaces {
            spaces_by_name.insert(space.name().to_string(), space.clone());
            spaces_by_id.insert(space.space_id(), space.clone());
        }
        Self {
            spaces_by_name,
            spaces_by_id,
            all_spaces: spaces,
        }
    }
}

impl AddressFactory for DefaultAddressFactory {
    fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
        self.spaces_by_name.get(name).cloned()
    }

    fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
        self.spaces_by_id.get(&id).cloned()
    }

    fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
        self.all_spaces.clone()
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
        self.all_spaces
            .iter()
            .find(|s| s.space_type() == AddressSpaceType::Register)
            .cloned()
    }
}
