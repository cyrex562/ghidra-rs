//! Models `ghidra.pcodeCPort.utils.AddrSpaceToIdSymmetryMap`.

use crate::decompiler::space::AddrSpace;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

/// Wrapper for Arc<dyn AddrSpace> that compares and hashes by pointer identity.
#[derive(Clone)]
struct AddrSpacePtr {
    ptr: *const dyn AddrSpace,
}

// Safety: The pointer is only used for identity checking; it never dereferences
// and is always associated with an Arc<dyn AddrSpace> held elsewhere.
unsafe impl Send for AddrSpacePtr {}
unsafe impl Sync for AddrSpacePtr {}

impl AddrSpacePtr {
    fn new(space: &Arc<dyn AddrSpace>) -> Self {
        Self {
            ptr: Arc::as_ptr(space),
        }
    }
}

impl PartialEq for AddrSpacePtr {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::addr_eq(self.ptr, other.ptr)
    }
}

impl Eq for AddrSpacePtr {}

impl std::hash::Hash for AddrSpacePtr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let addr = self.ptr as *const () as usize;
        addr.hash(state);
    }
}

/// A bidirectional map between address spaces and unique IDs.
///
/// Maintains a 1-to-1 correspondence between `Arc<dyn AddrSpace>` objects
/// and `u64` IDs, using weak references to allow spaces to be garbage
/// collected when no external references remain. Thread-safe; operations
/// block on a `Mutex`.
struct IdSymmetryMapInner {
    id_to_space: HashMap<u64, Weak<dyn AddrSpace>>,
    space_to_id: HashMap<AddrSpacePtr, u64>,
    id_generator: u64,
}

impl IdSymmetryMapInner {
    fn new() -> Self {
        Self {
            id_to_space: HashMap::new(),
            space_to_id: HashMap::new(),
            id_generator: 10000,
        }
    }

    fn get_id(&mut self, space: Arc<dyn AddrSpace>) -> u64 {
        let ptr = AddrSpacePtr::new(&space);
        if let Some(&id) = self.space_to_id.get(&ptr) {
            return id;
        }

        let id = self.id_generator;
        self.id_generator += 1;

        self.id_to_space.insert(id, Arc::downgrade(&space));
        self.space_to_id.insert(ptr, id);

        id
    }

    fn get_space(&mut self, id: u64) -> Option<Arc<dyn AddrSpace>> {
        if let Some(weak) = self.id_to_space.get(&id) {
            if let Some(arc) = weak.upgrade() {
                return Some(arc);
            }
        }
        None
    }
}

static MAP: Lazy<Mutex<IdSymmetryMapInner>> =
    Lazy::new(|| Mutex::new(IdSymmetryMapInner::new()));

/// Returns a unique ID for the given address space, assigning one if needed.
///
/// Thread-safe. If the space has already been assigned an ID, returns that
/// same ID. If not, generates a new ID (starting from 10000), stores the
/// mapping, and returns it.
pub fn get_id(space: Arc<dyn AddrSpace>) -> u64 {
    let mut map = MAP.lock().unwrap();
    map.get_id(space)
}

/// Returns the address space for a given ID, or `None` if not found.
///
/// Thread-safe. Returns `None` if the ID was never assigned, or if the
/// space with that ID has been dropped (weak reference went away).
pub fn get_space(id: u64) -> Option<Arc<dyn AddrSpace>> {
    let mut map = MAP.lock().unwrap();
    map.get_space(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn get_id_returns_consistent_id() {
        let dummy_space = create_test_space("test1");
        let id1 = get_id(dummy_space.clone());
        let id2 = get_id(dummy_space.clone());
        assert_eq!(id1, id2);
    }

    #[test]
    fn get_id_assigns_different_ids_to_different_spaces() {
        let space1 = create_test_space("space1");
        let space2 = create_test_space("space2");
        let id1 = get_id(space1);
        let id2 = get_id(space2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn get_space_returns_none_for_unknown_id() {
        let result = get_space(99999);
        assert!(result.is_none());
    }

    #[test]
    fn get_space_returns_assigned_space() {
        let dummy_space = create_test_space("test_space");
        let id = get_id(dummy_space.clone());
        let retrieved = get_space(id).unwrap();
        assert_eq!(Arc::as_ptr(&dummy_space), Arc::as_ptr(&retrieved));
    }

    #[test]
    fn id_starts_at_10000() {
        let space1 = create_test_space("s1");
        let space2 = create_test_space("s2");
        let space3 = create_test_space("s3");

        let id1 = get_id(space1);
        let id2 = get_id(space2);
        let id3 = get_id(space3);

        assert!(id1 >= 10000);
        assert!(id2 >= 10000);
        assert!(id3 >= 10000);
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn get_space_after_drop_returns_none() {
        let id = {
            let space = create_test_space("transient");
            get_id(space.clone())
        };

        assert!(get_space(id).is_none());
    }

    fn create_test_space(name: &str) -> Arc<dyn AddrSpace> {
        Arc::new(TestSpace {
            name: name.to_string(),
        })
    }

    struct TestSpace {
        name: String,
    }

    impl AddrSpace for TestSpace {
        fn name(&self) -> &str {
            &self.name
        }

        fn get_trans(&self) -> &dyn crate::decompiler::translate::Translate {
            panic!("Not implemented for test")
        }

        fn get_type(&self) -> crate::decompiler::space::SpaceType {
            crate::decompiler::space::SpaceType::IptrInternal
        }

        fn get_delay(&self) -> i32 {
            0
        }

        fn get_index(&self) -> i32 {
            0
        }

        fn get_word_size(&self) -> i32 {
            1
        }

        fn get_scale(&self) -> i32 {
            0
        }

        fn get_addr_size(&self) -> i32 {
            8
        }

        fn get_mask(&self) -> i64 {
            i64::MAX
        }

        fn get_short_cut(&self) -> char {
            'T'
        }

        fn flags(&self) -> i32 {
            0
        }
    }
}
