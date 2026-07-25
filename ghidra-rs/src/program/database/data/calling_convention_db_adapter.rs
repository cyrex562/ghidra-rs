//! Port of `ghidra.program.database.data.CallingConventionDBAdapter`.
//!
//! The Java type is an abstract class whose static factory method (`getAdapter`) selects and
//! upgrades between concrete version-specific implementations (`CallingConventionDBAdapterV0`,
//! `CallingConventionDBAdapterNoTable`). Those concrete adapters have not been ported yet, so
//! this port only models the abstract instance API each version implements, as an object-safe
//! trait; the version-selection/upgrade logic belongs with whichever type ends up owning the
//! concrete adapters. This trait was itself selected as a dependency-cycle cut-point.

use std::collections::HashSet;
use std::io;

/// Calling convention ID reserved for an unknown/unrecorded calling convention.
pub const UNKNOWN_CALLING_CONVENTION_ID: u8 = 0;

/// Calling convention ID reserved for the "default" calling convention.
pub const DEFAULT_CALLING_CONVENTION_ID: u8 = 1;

/// First calling convention ID available for an actual stored calling convention name.
pub const FIRST_CALLING_CONVENTION_ID: u8 = 2;

/// Adapter to access the Function Calling Conventions tables.
///
/// Port of `ghidra.program.database.data.CallingConventionDBAdapter`.
pub trait CallingConventionDBAdapter {
    /// Get (and assign if needed, thus requiring an open transaction) the ID associated with the
    /// specified calling convention name. If `name` is a new convention and the number of stored
    /// convention names exceeds 127 the returned ID will correspond to the unknown calling
    /// convention.
    ///
    /// `name` is `None` if unknown. `convention_added` is called back when a new calling
    /// convention is added.
    fn get_calling_convention_id(
        &mut self,
        name: Option<&str>,
        convention_added: &mut dyn FnMut(&str),
    ) -> io::Result<u8>;

    /// Get calling convention name which corresponds to the specified id, or `None` if unknown
    /// calling convention.
    fn get_calling_convention_name(&self, id: u8) -> io::Result<Option<String>>;

    /// Clear calling convention cached lookup maps.
    fn invalidate_cache(&mut self);

    /// Get all stored calling convention names. The "default" and "unknown" names are excluded
    /// from this set.
    fn get_calling_convention_names(&self) -> io::Result<HashSet<String>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct MockCallingConventionDBAdapter {
        names_by_id: RefCell<HashMap<u8, String>>,
        ids_by_name: RefCell<HashMap<String, u8>>,
        next_id: RefCell<u8>,
        invalidated: RefCell<bool>,
    }

    impl MockCallingConventionDBAdapter {
        fn new() -> Self {
            MockCallingConventionDBAdapter {
                names_by_id: RefCell::new(HashMap::new()),
                ids_by_name: RefCell::new(HashMap::new()),
                next_id: RefCell::new(FIRST_CALLING_CONVENTION_ID),
                invalidated: RefCell::new(false),
            }
        }
    }

    impl CallingConventionDBAdapter for MockCallingConventionDBAdapter {
        fn get_calling_convention_id(
            &mut self,
            name: Option<&str>,
            convention_added: &mut dyn FnMut(&str),
        ) -> io::Result<u8> {
            let name = match name {
                None => return Ok(UNKNOWN_CALLING_CONVENTION_ID),
                Some(n) => n,
            };
            if let Some(id) = self.ids_by_name.borrow().get(name) {
                return Ok(*id);
            }
            let mut next_id = self.next_id.borrow_mut();
            if *next_id == u8::MAX {
                return Ok(UNKNOWN_CALLING_CONVENTION_ID);
            }
            let id = *next_id;
            *next_id += 1;
            self.ids_by_name.borrow_mut().insert(name.to_string(), id);
            self.names_by_id.borrow_mut().insert(id, name.to_string());
            convention_added(name);
            Ok(id)
        }

        fn get_calling_convention_name(&self, id: u8) -> io::Result<Option<String>> {
            Ok(self.names_by_id.borrow().get(&id).cloned())
        }

        fn invalidate_cache(&mut self) {
            *self.invalidated.borrow_mut() = true;
        }

        fn get_calling_convention_names(&self) -> io::Result<HashSet<String>> {
            Ok(self.ids_by_name.borrow().keys().cloned().collect())
        }
    }

    #[test]
    fn mock_adapter_is_object_safe_and_assigns_ids() {
        let mut adapter: Box<dyn CallingConventionDBAdapter> =
            Box::new(MockCallingConventionDBAdapter::new());

        let mut added = Vec::new();
        let id = adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |n| added.push(n.to_string()))
            .unwrap();
        assert_eq!(id, FIRST_CALLING_CONVENTION_ID);
        assert_eq!(added, vec!["__stdcall".to_string()]);

        // Re-requesting the same name returns the same id, with no further callback.
        let same_id = adapter
            .get_calling_convention_id(Some("__stdcall"), &mut |n| added.push(n.to_string()))
            .unwrap();
        assert_eq!(same_id, id);
        assert_eq!(added.len(), 1);

        assert_eq!(
            adapter.get_calling_convention_name(id).unwrap(),
            Some("__stdcall".to_string())
        );

        let unknown_id = adapter
            .get_calling_convention_id(None, &mut |_| panic!("should not be called"))
            .unwrap();
        assert_eq!(unknown_id, UNKNOWN_CALLING_CONVENTION_ID);

        let names = adapter.get_calling_convention_names().unwrap();
        assert!(names.contains("__stdcall"));
        assert_eq!(names.len(), 1);

        adapter.invalidate_cache();
    }
}
