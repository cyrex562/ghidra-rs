//! Port of `ghidra.program.model.lang.DynamicVariableStorage`.
//!
//! Storage for a variable (typically a parameter or return value) whose location was computed
//! dynamically by a [`PrototypeModel`](crate::program::model::lang::prototype_model::PrototypeModel)
//! rather than read back from a fixed storage record, and which may also record that the variable
//! was forced to pass indirectly (as a pointer) or is an auto-parameter injected by the calling
//! convention.
//!
//! This was selected as a dependency-cycle cut-point: `HighSymbol.getStorage()` and
//! `ParameterPieces` (both already ported as [`VariableStorage`]-returning surfaces in
//! `seam_stubs.rs`) as well as `ReturnParameterDB` reference `DynamicVariableStorage` long before
//! its own dependents (`ProgramArchitecture`-backed storage construction, `Varnode`) are fully
//! wired together, so it is modeled as a trait -- a supertrait of [`VariableStorage`] adding just
//! the four `@Override` accessors this subclass introduces -- rather than a concrete struct.
//!
//! All four (`isForcedIndirect()`/`isAutoStorage()`/`isUnassignedStorage()`/`isVoidStorage()`)
//! have since been promoted onto the real [`VariableStorage`] port itself (see
//! [`VariableStorage::is_forced_indirect`]/[`is_auto_storage`](VariableStorage::is_auto_storage)/
//! [`is_unassigned_storage`](VariableStorage::is_unassigned_storage)/
//! [`is_void_storage`](VariableStorage::is_void_storage)). Since a subtrait cannot supply a new
//! default body under a supertrait method's exact name (the same limitation documented on
//! [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl)), this trait no
//! longer redeclares any of them; implementors instead override those `VariableStorage` methods
//! directly, optionally delegating to
//! [`dynamic_variable_storage_is_auto_storage`](DynamicVariableStorage::dynamic_variable_storage_is_auto_storage)
//! for the `autoParamType != null` default this class's real Java override provides.
//!
//! The private/public constructors and the `getUnassignedDynamicStorage`/`INDIRECT_VOID_STORAGE`
//! static factories are construction-time plumbing tied to a concrete backing representation
//! (varnode list validation against a `ProgramArchitecture`, raising `InvalidInputException`) and
//! have no Rust trait equivalent, following the same precedent set by
//! [`HighVariable`](crate::program::model::pcode::high_variable::HighVariable) for the Java
//! constructors it does not model.
//!
//! `toString()`'s `" (ptr)"`/`" (auto)"` suffix logic is ported as
//! [`dynamic_storage_suffix`](DynamicVariableStorage::dynamic_storage_suffix); the base
//! `VariableStorage.toString()` description itself is not modeled by [`VariableStorage`], so
//! implementors are expected to append this suffix to their own base description.

use crate::program::model::listing::AutoParameterType;
use crate::program::model::listing::variable_storage::VariableStorage;

/// Port of `ghidra.program.model.lang.DynamicVariableStorage`.
pub trait DynamicVariableStorage: VariableStorage {
    /// Default body an implementor's own `VariableStorage::is_auto_storage` override can delegate
    /// to: `true` if this storage carries an auto-parameter type, matching
    /// `DynamicVariableStorage.isAutoStorage()`'s `autoParamType != null` check (as opposed to the
    /// base `VariableStorage.isAutoStorage()`, which always returns `false`).
    fn dynamic_variable_storage_is_auto_storage(&self) -> bool {
        self.get_auto_parameter_type().is_some()
    }

    /// Port of the `" (ptr)"`/`" (auto)"` suffix appended by `DynamicVariableStorage.toString()`.
    /// See the module docs for why the base description itself is not modeled here.
    fn dynamic_storage_suffix(&self) -> String {
        let mut suffix = String::new();
        if self.is_forced_indirect() && !self.get_varnodes().is_empty() {
            suffix.push_str(" (ptr)");
        }
        if self.is_auto_storage() {
            suffix.push_str(" (auto)");
        }
        suffix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::Varnode;
    /// Mock backing a forced-indirect, non-auto parameter storage -- proves object-safety and
    /// exercises the real `is_auto_storage`/`dynamic_storage_suffix` default logic.
    struct MockForcedIndirectStorage {
        varnodes: Vec<Varnode>,
    }

    impl VariableStorage for MockForcedIndirectStorage {
        fn get_first_varnode(&self) -> Option<Varnode> {
            self.varnodes.first().cloned()
        }

        fn get_varnodes(&self) -> Vec<Varnode> {
            self.varnodes.clone()
        }

        fn is_forced_indirect(&self) -> bool {
            true
        }
    }

    impl DynamicVariableStorage for MockForcedIndirectStorage {}

    /// Mock backing unassigned storage carrying an auto-parameter type -- proves the
    /// `get_auto_parameter_type` override drives `is_auto_storage` through the supertrait.
    struct MockAutoParamStorage;

    impl VariableStorage for MockAutoParamStorage {
        fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
            Some(AutoParameterType::This)
        }

        fn is_auto_storage(&self) -> bool {
            self.dynamic_variable_storage_is_auto_storage()
        }

        fn is_unassigned_storage(&self) -> bool {
            true
        }
    }

    impl DynamicVariableStorage for MockAutoParamStorage {}

    fn ram_varnode() -> Varnode {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Varnode::new(Address::new(space, 0x1000), 4)
    }

    #[test]
    fn object_safe_as_trait_object() {
        let storage: Box<dyn DynamicVariableStorage> = Box::new(MockForcedIndirectStorage {
            varnodes: vec![ram_varnode()],
        });
        assert!(storage.is_forced_indirect());
        assert!(!storage.is_unassigned_storage());
        assert!(!storage.is_void_storage());
        assert!(!storage.is_auto_storage());
    }

    #[test]
    fn suffix_reports_ptr_when_forced_indirect_with_varnodes() {
        let storage = MockForcedIndirectStorage {
            varnodes: vec![ram_varnode()],
        };
        assert_eq!(storage.dynamic_storage_suffix(), " (ptr)");
    }

    #[test]
    fn suffix_omits_ptr_when_no_varnodes() {
        let storage = MockForcedIndirectStorage { varnodes: vec![] };
        assert_eq!(storage.dynamic_storage_suffix(), "");
    }

    #[test]
    fn auto_storage_follows_auto_parameter_type() {
        let storage = MockAutoParamStorage;
        assert!(storage.is_auto_storage());
        assert!(storage.is_unassigned_storage());
        assert_eq!(storage.dynamic_storage_suffix(), " (auto)");
    }
}
