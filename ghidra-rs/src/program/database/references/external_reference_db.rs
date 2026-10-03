//! Port of `ghidra.program.database.references.ExternalReferenceDB`.
//!
//! **Not stored: the owning `Program`.** Java's `ExternalReferenceDB` keeps a `Program` field
//! purely to resolve `getExternalLocation()` via
//! `((ExternalManagerDB) program.getExternalManager()).getExtLocation(toAddr)` on every call. This
//! port replaces that with a caller-supplied `location_factory` closure (the caller -- typically
//! whichever code already has `ProgramDB`/`ExternalManagerDb` access when constructing this
//! reference -- captures the lookup), matching this project's preference for trait/closure seams
//! over pervasive concrete `Program` coupling for a leaf value type.

use std::sync::Arc;

use crate::program::database::references::reference_db::ReferenceDbCore;
use crate::program::model::address::Address;
use crate::program::model::symbol::{ExternalLocation, ExternalReference, RefType, Reference, SourceType};

/// A reference to an external location (a symbol in another program/library).
///
/// Port of `ghidra.program.database.references.ExternalReferenceDB`. Composes a
/// [`ReferenceDbCore`] (Java: `extends ReferenceDB`) rather than inheriting from it. See the
/// module docs for the `location_factory` simplification.
#[derive(Clone)]
pub struct ExternalReferenceDb {
    core: ReferenceDbCore,
    location_factory: Arc<dyn Fn() -> Box<dyn ExternalLocation> + Send + Sync>,
}

impl std::fmt::Debug for ExternalReferenceDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalReferenceDb")
            .field("core", &self.core)
            .finish_non_exhaustive()
    }
}

impl ExternalReferenceDb {
    /// Stands in for `ExternalReferenceDB`'s constructor. `isPrimary`/`symbolID` are fixed at
    /// `true`/`-1` respectively, matching the Java constructor's hardcoded `super(..., true, -1)`
    /// call. `location_factory` stands in for `program.getExternalManager()`-based resolution --
    /// see the module docs.
    pub fn new(
        from_addr: Address,
        to_addr: Address,
        ref_type: RefType,
        op_index: i32,
        source_type: SourceType,
        location_factory: Arc<dyn Fn() -> Box<dyn ExternalLocation> + Send + Sync>,
    ) -> Self {
        ExternalReferenceDb {
            core: ReferenceDbCore::new(
                from_addr, to_addr, ref_type, op_index, source_type, true, -1,
            ),
            location_factory,
        }
    }

    /// Stands in for `ExternalReferenceDB.toString()`. Java's version defers to
    /// `ExternalLocation.toString()`, which this port's [`ExternalLocation`] trait does not
    /// define (no `Display` impl for the generic trait object); this approximates it using the
    /// location's label instead.
    pub fn to_display_string(&self) -> String {
        format!("->{}", self.get_external_location().get_label())
    }

    /// Stands in for `ExternalReferenceDB.equals(Object)`.
    pub fn equals(&self, other: &dyn Reference) -> bool {
        if !other.is_external_reference() {
            return false;
        }
        if self.from_address() != other.from_address()
            || self.operand_index() != other.operand_index()
            || self.source() != other.source()
            || self.reference_type() != other.reference_type()
        {
            return false;
        }
        let Some(other_ext) = other.as_external_reference() else {
            return false;
        };
        self.get_external_location()
            .is_equivalent(other_ext.get_external_location().as_ref())
    }
}

impl Reference for ExternalReferenceDb {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn to_external_reference(
        &self,
    ) -> Option<std::sync::Arc<dyn crate::program::model::symbol::ExternalReference>> {
        Some(std::sync::Arc::new(self.clone()))
    }

    fn from_address(&self) -> Address {
        self.core.from_address()
    }

    fn to_address(&self) -> Address {
        self.core.to_address()
    }

    fn is_primary(&self) -> bool {
        self.core.is_primary()
    }

    fn symbol_id(&self) -> i64 {
        self.core.symbol_id()
    }

    fn reference_type(&self) -> RefType {
        self.core.reference_type()
    }

    fn operand_index(&self) -> i32 {
        self.core.operand_index()
    }

    fn is_mnemonic_reference(&self) -> bool {
        self.core.is_mnemonic_reference()
    }

    fn is_operand_reference(&self) -> bool {
        self.core.is_operand_reference()
    }

    fn is_stack_reference(&self) -> bool {
        false
    }

    /// Stands in for `ExternalReferenceDB.isExternalReference()`.
    fn is_external_reference(&self) -> bool {
        true
    }

    fn is_entry_point_reference(&self) -> bool {
        false
    }

    fn is_memory_reference(&self) -> bool {
        self.core.is_memory_reference()
    }

    fn is_register_reference(&self) -> bool {
        self.core.is_register_reference()
    }

    fn is_offset_reference(&self) -> bool {
        false
    }

    fn is_shifted_reference(&self) -> bool {
        false
    }

    fn source(&self) -> SourceType {
        self.core.source()
    }

    fn as_external_reference(&self) -> Option<&dyn ExternalReference> {
        Some(self)
    }
}

impl ExternalReference for ExternalReferenceDb {
    /// Stands in for `ExternalReferenceDB.getExternalLocation()`.
    fn get_external_location(&self) -> Box<dyn ExternalLocation> {
        (self.location_factory)()
    }

    /// Stands in for `ExternalReferenceDB.getLibraryName()`.
    fn get_library_name(&self) -> String {
        self.get_external_location().get_library_name()
    }

    /// Stands in for `ExternalReferenceDB.getLabel()`.
    fn get_label(&self) -> Option<String> {
        let label = self.get_external_location().get_label();
        if label.is_empty() {
            None
        } else {
            Some(label)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockExternalLocation {
        library: String,
        label: String,
    }

    impl ExternalLocation for MockExternalLocation {
        fn get_library_name(&self) -> String {
            self.library.clone()
        }

        fn get_label(&self) -> String {
            self.label.clone()
        }
    }

    fn factory(library: &str, label: &str) -> Arc<dyn Fn() -> Box<dyn ExternalLocation> + Send + Sync> {
        let library = library.to_string();
        let label = label.to_string();
        Arc::new(move || {
            Box::new(MockExternalLocation {
                library: library.clone(),
                label: label.clone(),
            }) as Box<dyn ExternalLocation>
        })
    }

    fn external_ref(library: &str, label: &str) -> ExternalReferenceDb {
        ExternalReferenceDb::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            0,
            SourceType::Imported,
            factory(library, label),
        )
    }

    #[test]
    fn constructor_hardcodes_primary_true_and_symbol_id_negative_one() {
        let r = external_ref("MyLib", "entry");
        assert!(r.is_primary());
        assert_eq!(r.symbol_id(), -1);
        assert!(r.is_external_reference());
    }

    #[test]
    fn library_name_and_label_delegate_to_resolved_location() {
        let r = external_ref("MyLib", "entry");
        assert_eq!(r.get_library_name(), "MyLib");
        assert_eq!(r.get_label(), Some("entry".to_string()));
    }

    #[test]
    fn empty_label_reports_none() {
        let r = external_ref("MyLib", "");
        assert_eq!(r.get_label(), None);
    }

    #[test]
    fn to_display_string_uses_label() {
        let r = external_ref("MyLib", "entry");
        assert_eq!(r.to_display_string(), "->entry");
    }

    #[test]
    fn as_external_reference_downcast_works() {
        let r = external_ref("MyLib", "entry");
        let dynref: &dyn Reference = &r;
        let downcast = dynref.as_external_reference().expect("should downcast");
        assert_eq!(downcast.get_library_name(), "MyLib");
    }

    #[test]
    fn equals_compares_location_equivalence_and_core_fields() {
        let a = external_ref("MyLib", "entry");
        let b = external_ref("MyLib", "entry");
        assert!(a.equals(&b));

        let different_label = external_ref("MyLib", "other");
        assert!(!a.equals(&different_label));
    }

    #[test]
    fn equals_rejects_non_external_references() {
        use crate::program::database::references::MemReferenceDb;
        let a = external_ref("MyLib", "entry");
        let plain = MemReferenceDb::new(
            addr(0x1000),
            addr(0x2000),
            RefType::Data,
            0,
            SourceType::Imported,
            true,
            -1,
        );
        assert!(!a.equals(&plain));
    }
}
