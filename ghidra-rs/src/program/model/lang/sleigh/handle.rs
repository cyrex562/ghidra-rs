use crate::program::model::address::AddressSpace;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct FixedHandle {
    pub space: Option<Arc<AddressSpace>>,
    pub size: i32,
    pub offset_space: Option<Arc<AddressSpace>>,
    pub offset_offset: u64,
    pub offset_size: i32,
    pub temp_space: Option<Arc<AddressSpace>>,
    pub temp_offset: u64,
    pub fixable: bool,
}

impl FixedHandle {
    pub fn new() -> Self {
        Self {
            space: None,
            size: 0,
            offset_space: None,
            offset_offset: 0,
            offset_size: 0,
            temp_space: None,
            temp_offset: 0,
            fixable: true,
        }
    }

    pub fn is_invalid(&self) -> bool {
        self.space.is_none()
    }

    pub fn set_invalid(&mut self) {
        self.space = None;
    }

    pub fn is_dynamic(&self) -> bool {
        self.offset_space.is_some()
    }
}

impl PartialEq for FixedHandle {
    fn eq(&self, other: &Self) -> bool {
        self.space == other.space
            && self.size == other.size
            && self.offset_space == other.offset_space
            && self.offset_offset == other.offset_offset
            && self.offset_size == other.offset_size
            && self.temp_space == other.temp_space
            && self.temp_offset == other.temp_offset
    }
}

impl Eq for FixedHandle {}
