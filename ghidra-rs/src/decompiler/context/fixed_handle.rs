use crate::decompiler::space::AddrSpace;
use std::sync::Arc;

/// A fixed handle to a location in memory or registers.
///
/// A `FixedHandle` describes a varnode location using address space fields. It can represent
/// either a static location (when `offset_space` is `None`) or a dynamic location where the
/// actual offset is stored in memory (when `offset_space` is `Some`). A temporary location
/// (`temp_space`, `temp_offset`) may be associated with dynamic cases for storing intermediate values.
///
/// Corresponds to `ghidra.pcodeCPort.context.FixedHandle`.
#[derive(Clone)]
pub struct FixedHandle {
    pub space: Option<Arc<dyn AddrSpace>>,
    pub size: i32,
    pub offset_space: Option<Arc<dyn AddrSpace>>,
    pub offset_offset: i64,
    pub offset_size: i32,
    pub temp_space: Option<Arc<dyn AddrSpace>>,
    pub temp_offset: i64,
}

impl FixedHandle {
    /// Creates a new `FixedHandle` with all optional spaces set to `None`.
    pub fn new() -> Self {
        Self {
            space: None,
            size: 0,
            offset_space: None,
            offset_offset: 0,
            offset_size: 0,
            temp_space: None,
            temp_offset: 0,
        }
    }
}

impl Default for FixedHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FixedHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedHandle")
            .field("space", &self.space.as_ref().map(|s| s.name()))
            .field("size", &self.size)
            .field("offset_space", &self.offset_space.as_ref().map(|s| s.name()))
            .field("offset_offset", &self.offset_offset)
            .field("offset_size", &self.offset_size)
            .field("temp_space", &self.temp_space.as_ref().map(|s| s.name()))
            .field("temp_offset", &self.temp_offset)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_initializes_defaults() {
        let handle = FixedHandle::new();
        assert!(handle.space.is_none());
        assert_eq!(handle.size, 0);
        assert!(handle.offset_space.is_none());
        assert_eq!(handle.offset_offset, 0);
        assert_eq!(handle.offset_size, 0);
        assert!(handle.temp_space.is_none());
        assert_eq!(handle.temp_offset, 0);
    }

    #[test]
    fn default_initializes_same_as_new() {
        let handle = FixedHandle::default();
        let new_handle = FixedHandle::new();
        assert!(handle.space.is_none());
        assert_eq!(handle.size, new_handle.size);
        assert_eq!(handle.offset_offset, new_handle.offset_offset);
    }

    #[test]
    fn can_set_fields() {
        let mut handle = FixedHandle::new();
        handle.size = 8;
        handle.offset_offset = 0x1000;
        handle.offset_size = 4;
        handle.temp_offset = 0x2000;

        assert_eq!(handle.size, 8);
        assert_eq!(handle.offset_offset, 0x1000);
        assert_eq!(handle.offset_size, 4);
        assert_eq!(handle.temp_offset, 0x2000);
    }

    #[test]
    fn clone_creates_independent_copy() {
        let mut handle1 = FixedHandle::new();
        handle1.size = 5;
        handle1.offset_offset = 0x500;

        let mut handle2 = handle1.clone();
        handle2.size = 10;

        assert_eq!(handle1.size, 5);
        assert_eq!(handle2.size, 10);
        assert_eq!(handle1.offset_offset, handle2.offset_offset);
    }
}
