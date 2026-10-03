//! Port of `ghidra.program.database.ProgramAddressFactory`.
//!
//! Augments the address spaces supplied by a `Language`/`CompilerSpec` pair with the extra
//! spaces a `Program` needs (`OTHER`, `EXTERNAL`, a stack space, `HASH`, and a join space), and
//! adds support for `ProgramOverlayAddressSpace` bookkeeping (creation, removal, renaming, and
//! staleness tracking).
//!
//! This was selected as a dependency-cycle cut point: in the original Java, the
//! `ProgramOverlayAddressSpace` constructor takes a `ProgramAddressFactory` and calls back into
//! it (`factory.generateOrderedKey(...)`, `factory.addOverlaySpace(this)`), while
//! `ProgramAddressFactory` in turn constructs and manages `ProgramOverlayAddressSpace` instances.
//! Expressing this type as a trait -- with `ProgramOverlayAddressSpace` itself represented by a
//! minimal placeholder trait in `seam_stubs` -- breaks that cycle.
//!
//! The Java class's private construction-time helpers (`initOtherSpace`, `initExternalSpace`,
//! `initStackSpace`, `initHashSpace`, `initJoinSpace`, `getNextUniqueID`) are implementation
//! details of a concrete constructor and are not part of the public/protected/package-private API
//! surface, so they are not modeled as trait methods here.

use crate::program::model::address::{Address, AddressFactory, AddressSpace};
use crate::program::seam_stubs::ProgramOverlayAddressSpace;
use crate::util::exception::{DuplicateNameException, InvalidNameException};
use std::sync::Arc;
use thiserror::Error;

/// Combines the checked exceptions declared on `ProgramAddressFactory.checkValidOverlaySpaceName`.
#[derive(Error, Debug)]
pub enum CheckOverlayNameError {
    #[error(transparent)]
    Invalid(#[from] InvalidNameException),
    #[error(transparent)]
    Duplicate(#[from] DuplicateNameException),
}

/// A `Program`-specific `AddressFactory` which augments a language's address spaces with
/// program-level spaces and manages overlay address spaces.
///
/// Port of `ghidra.program.database.ProgramAddressFactory`.
pub trait ProgramAddressFactory {
    /// Invalidate the cached defined-region data for every overlay address space managed by this
    /// factory, forcing it to be recomputed (via `OverlayRegionSupplier`) on next access.
    fn invalidate_overlay_cache(&self);

    /// Get the stack address space associated with this factory's compiler spec. Unlike the
    /// general `AddressFactory::get_stack_space` this is guaranteed to be defined once the
    /// factory is constructed.
    fn get_stack_space(&self) -> Arc<AddressSpace>;

    /// Get the original (language-supplied) address factory this factory was built from, before
    /// program-specific spaces were added.
    fn get_original_address_factory(&self) -> Box<dyn AddressFactory>;

    /// Determine whether the given space can have an overlay created on top of it.
    fn is_valid_overlay_base_space(&self, base_space: &Arc<AddressSpace>) -> bool;

    /// Add an already-constructed overlay address space to this factory.
    ///
    /// # Errors
    /// Returns [`DuplicateNameException`] if the name of the overlay space already exists in
    /// this factory.
    fn add_overlay_space(
        &mut self,
        ov_space: Arc<dyn ProgramOverlayAddressSpace>,
    ) -> Result<(), DuplicateNameException>;

    /// Create a new overlay address space based upon the given overlay name and base address
    /// space, and add it to this factory.
    ///
    /// # Errors
    /// Returns [`DuplicateNameException`] if `overlay_name` duplicates another address space
    /// name.
    ///
    /// # Panics
    /// Implementations should panic (mirroring the Java `IllegalArgumentException`) if
    /// `base_space` is not a valid overlay base space, or is not the same instance already known
    /// to this factory.
    fn create_overlay_space(
        &mut self,
        key: i64,
        overlay_name: &str,
        base_space: Arc<AddressSpace>,
    ) -> Result<Arc<dyn ProgramOverlayAddressSpace>, DuplicateNameException>;

    /// Validate that `name` is usable as a new overlay address space name.
    ///
    /// # Errors
    /// Returns [`CheckOverlayNameError::Invalid`] if `name` is not a valid address space name, or
    /// [`CheckOverlayNameError::Duplicate`] if an address space with that name already exists.
    fn check_valid_overlay_space_name(&self, name: &str) -> Result<(), CheckOverlayNameError>;

    /// Get the address with the given space ID and offset, falling back to the stack space if no
    /// address space with that ID is otherwise known.
    fn address(&self, space_id: i32, offset: i64) -> Option<Address>;

    /// Parse `addr_string` into an address, recognizing the special `Stack[...]` textual form in
    /// addition to the forms understood by the base address factory.
    fn get_address(&self, addr_string: &str) -> Option<Address>;

    /// Remove the named overlay space from this factory.
    ///
    /// # Panics
    /// Implementations should panic (mirroring the Java `IllegalArgumentException`) if no overlay
    /// space with that name is found.
    fn remove_overlay_space(&mut self, name: &str);

    /// Update bookkeeping after an overlay space has been renamed from `old_overlay_space_name`
    /// to `new_name`. When `refresh_status_if_needed` is `true` and this rename may have resolved
    /// a stale-overlay condition, the stale status is fully recomputed.
    fn overlay_space_renamed(
        &mut self,
        old_overlay_space_name: &str,
        new_name: &str,
        refresh_status_if_needed: bool,
    );

    /// Re-examine all overlay spaces and update the stale-overlay status indicator.
    fn refresh_stale_overlay_status(&mut self);

    /// Returns `true` if one or more overlay spaces have a name which does not match their
    /// ordered key (e.g., due to a rename that has not been fully reconciled).
    fn has_stale_overlay_condition(&self) -> bool;

    /// Generate an ordered, unique, name-based key for use with a new overlay space. This will
    /// generally be `overlay_name` unless that value has already been used by another overlay.
    fn generate_ordered_key(&mut self, overlay_name: &str) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use std::cell::{Cell, RefCell};

    struct MockOverlaySpace {
        ordered_key: String,
        name: String,
        invalidated: Cell<bool>,
    }

    impl ProgramOverlayAddressSpace for MockOverlaySpace {
        fn get_ordered_key(&self) -> &str {
            &self.ordered_key
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn invalidate(&self) {
            self.invalidated.set(true);
        }
    }

    struct MockProgramAddressFactory {
        stack_space: Arc<AddressSpace>,
        overlays: RefCell<Vec<Arc<dyn ProgramOverlayAddressSpace>>>,
        has_stale_overlays: Cell<bool>,
        next_tmp_id: Cell<u64>,
    }

    impl MockProgramAddressFactory {
        fn new(stack_space: Arc<AddressSpace>) -> Self {
            MockProgramAddressFactory {
                stack_space,
                overlays: RefCell::new(Vec::new()),
                has_stale_overlays: Cell::new(false),
                next_tmp_id: Cell::new(1),
            }
        }
    }

    impl ProgramAddressFactory for MockProgramAddressFactory {
        fn invalidate_overlay_cache(&self) {
            for ov in self.overlays.borrow().iter() {
                ov.invalidate();
            }
        }

        fn get_stack_space(&self) -> Arc<AddressSpace> {
            self.stack_space.clone()
        }

        fn get_original_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }

        fn is_valid_overlay_base_space(&self, base_space: &Arc<AddressSpace>) -> bool {
            base_space.is_memory_space()
        }

        fn add_overlay_space(
            &mut self,
            ov_space: Arc<dyn ProgramOverlayAddressSpace>,
        ) -> Result<(), DuplicateNameException> {
            if self
                .overlays
                .borrow()
                .iter()
                .any(|ov| ov.get_name() == ov_space.get_name())
            {
                return Err(DuplicateNameException::with_message(format!(
                    "duplicate overlay name: {}",
                    ov_space.get_name()
                )));
            }
            self.overlays.borrow_mut().push(ov_space);
            Ok(())
        }

        fn create_overlay_space(
            &mut self,
            _key: i64,
            overlay_name: &str,
            base_space: Arc<AddressSpace>,
        ) -> Result<Arc<dyn ProgramOverlayAddressSpace>, DuplicateNameException> {
            assert!(self.is_valid_overlay_base_space(&base_space));
            let ordered_key = self.generate_ordered_key(overlay_name);
            let mock: Arc<MockOverlaySpace> = Arc::new(MockOverlaySpace {
                ordered_key,
                name: overlay_name.to_string(),
                invalidated: Cell::new(false),
            });
            self.add_overlay_space(mock.clone())?;
            Ok(mock)
        }

        fn check_valid_overlay_space_name(&self, name: &str) -> Result<(), CheckOverlayNameError> {
            if name.is_empty() {
                return Err(CheckOverlayNameError::Invalid(InvalidNameException::new()));
            }
            if self.overlays.borrow().iter().any(|ov| ov.get_name() == name) {
                return Err(CheckOverlayNameError::Duplicate(
                    DuplicateNameException::new(),
                ));
            }
            Ok(())
        }

        fn address(&self, space_id: i32, offset: i64) -> Option<Address> {
            if space_id == self.stack_space.space_id() {
                Some(self.stack_space.address(offset))
            } else {
                None
            }
        }

        fn get_address(&self, addr_string: &str) -> Option<Address> {
            let inner = addr_string.strip_prefix("Stack[")?.strip_suffix(']')?;
            let offset = i64::from_str_radix(inner.trim_start_matches("0x"), 16).ok()?;
            Some(self.stack_space.address(offset))
        }

        fn remove_overlay_space(&mut self, name: &str) {
            let mut overlays = self.overlays.borrow_mut();
            let before = overlays.len();
            overlays.retain(|ov| ov.get_name() != name);
            assert_ne!(before, overlays.len(), "Overlay {name} not found");
        }

        fn overlay_space_renamed(
            &mut self,
            old_overlay_space_name: &str,
            new_name: &str,
            refresh_status_if_needed: bool,
        ) {
            let mut went_stale = false;
            {
                let mut overlays = self.overlays.borrow_mut();
                if let Some(idx) = overlays
                    .iter()
                    .position(|ov| ov.get_name() == old_overlay_space_name)
                {
                    let ordered_key = overlays[idx].get_ordered_key().to_string();
                    went_stale = ordered_key != new_name;
                    overlays[idx] = Arc::new(MockOverlaySpace {
                        ordered_key,
                        name: new_name.to_string(),
                        invalidated: Cell::new(false),
                    });
                }
            }
            if went_stale {
                self.has_stale_overlays.set(true);
            } else if self.has_stale_overlays.get() && refresh_status_if_needed {
                self.refresh_stale_overlay_status();
            }
        }

        fn refresh_stale_overlay_status(&mut self) {
            let stale = self
                .overlays
                .borrow()
                .iter()
                .any(|ov| ov.get_name() != ov.get_ordered_key());
            self.has_stale_overlays.set(stale);
        }

        fn has_stale_overlay_condition(&self) -> bool {
            self.has_stale_overlays.get()
        }

        fn generate_ordered_key(&mut self, overlay_name: &str) -> String {
            let in_use = self
                .overlays
                .borrow()
                .iter()
                .any(|ov| ov.get_ordered_key() == overlay_name);
            if in_use {
                let id = self.next_tmp_id.get();
                self.next_tmp_id.set(id + 1);
                format!("{overlay_name}_{id}")
            } else {
                overlay_name.to_string()
            }
        }
    }

    fn make_stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    #[test]
    fn add_overlay_space_rejects_duplicate_names_and_invalidate_cache_notifies_all() {
        let mut factory = MockProgramAddressFactory::new(make_stack_space());
        let mock = Arc::new(MockOverlaySpace {
            ordered_key: "OV".to_string(),
            name: "OV".to_string(),
            invalidated: Cell::new(false),
        });
        factory
            .add_overlay_space(mock.clone())
            .expect("first add should succeed");

        let duplicate = Arc::new(MockOverlaySpace {
            ordered_key: "OV2".to_string(),
            name: "OV".to_string(),
            invalidated: Cell::new(false),
        });
        assert!(factory.add_overlay_space(duplicate).is_err());

        assert!(!mock.invalidated.get());
        factory.invalidate_overlay_cache();
        assert!(mock.invalidated.get());
    }

    #[test]
    fn create_overlay_space_dedupes_ordered_keys_and_tracks_staleness_through_rename() {
        let mut factory = MockProgramAddressFactory::new(make_stack_space());
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);

        let first = factory
            .create_overlay_space(1, "OV", ram.clone())
            .expect("first overlay should succeed");
        assert_eq!(first.get_ordered_key(), "OV");
        assert!(!factory.has_stale_overlay_condition());

        // Renaming the first overlay leaves its ordered key ("OV") stuck on the old name, which
        // is a stale condition until the space is removed or refreshed away.
        factory.overlay_space_renamed("OV", "OV_renamed", true);
        assert!(factory.has_stale_overlay_condition());

        // A second overlay newly requesting the name "OV" collides with the first overlay's
        // still-reserved ordered key, so it gets a disambiguated one.
        let second = factory
            .create_overlay_space(2, "OV", ram)
            .expect("second overlay should succeed");
        assert_eq!(second.get_ordered_key(), "OV_1");
        assert_ne!(second.get_ordered_key(), first.get_ordered_key());

        factory.remove_overlay_space("OV_renamed");
        factory.remove_overlay_space("OV");
        factory.refresh_stale_overlay_status();
        assert!(!factory.has_stale_overlay_condition());
    }

    #[test]
    fn check_valid_overlay_space_name_rejects_blank_and_duplicate_names() {
        let mut factory = MockProgramAddressFactory::new(make_stack_space());
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);

        assert!(matches!(
            factory.check_valid_overlay_space_name(""),
            Err(CheckOverlayNameError::Invalid(_))
        ));

        factory
            .create_overlay_space(1, "OV", ram)
            .expect("overlay creation should succeed");
        assert!(matches!(
            factory.check_valid_overlay_space_name("OV"),
            Err(CheckOverlayNameError::Duplicate(_))
        ));
        assert!(factory.check_valid_overlay_space_name("OV2").is_ok());
    }

    // Exercise the trait object surface to confirm object-safety.
    #[test]
    fn program_address_factory_is_object_safe() {
        let factory: Box<dyn ProgramAddressFactory> =
            Box::new(MockProgramAddressFactory::new(make_stack_space()));

        assert_eq!(factory.get_stack_space().name(), "stack");
        assert_eq!(
            factory.address(factory.get_stack_space().space_id(), 4),
            Some(factory.get_stack_space().address(4))
        );
        assert_eq!(
            factory.get_address("Stack[0x10]"),
            Some(factory.get_stack_space().address(0x10))
        );
        assert!(factory.get_address("bogus").is_none());
    }
}
