//! Port of `ghidra.program.database.symbol.EquateDB` as a trait (cycle cut-point).
//!
//! The Java class extends `DbObject` and implements `Equate`, but every public method (except the
//! package-private constructor) forwards to an `EquateManager` field captured at construction time
//! (`new EquateDB(this, record)`, called from `EquateManager` itself), and the record/manager pair
//! is exactly what let `EquateManager` construct `EquateDB` while `EquateDB` called back into
//! `EquateManager` (e.g. `addReference` forwards to `EquateManager.addReference(long, Address, int,
//! long)`, `renameEquate` forwards to `EquateManager.getEquateDatabaseAdapter()` and
//! `equateNameChanged`). That mutual construction/call-back wiring is what makes this class a cycle
//! cut-point, exactly as documented on
//! [`EquateManager`](crate::program::database::symbol::EquateManager)'s own port.
//!
//! Left out, matching the same convention `EquateManager`'s port already established: the
//! constructor (`EquateManager`/`DBRecord` wiring), and the private helpers that exist purely to
//! support it (`findOpIndex`/`findScalarOpIndex`, which resolve a dynamic hash back to an operand
//! index using `Instruction`/`DynamicHash`/`Scalar`, and `updateRecord`). None of those appear in
//! this trait's public signatures, so no placeholder stubs for `Instruction`/`DynamicHash`/`Scalar`/
//! `DataTypeManager`/`Enum` are needed here -- they stay entirely inside whichever concrete,
//! adapter-backed implementation is added later (the same reasoning `EquateDBAdapter`'s port used to
//! leave out its table-layout constants).
//!
//! `addReference`/`removeReference` (both overloads of each) are `void` in Java and swallow any
//! `IOException` via `EquateManager.dbError`, which this crate's `ManagerDB` deliberately does not
//! model (see `EquateManager`'s port docs); this trait mirrors that by making all four infallible
//! (no `Result`), matching the public signature Java actually exposes.
//!
//! `renameEquate` is the one method that can fail *without* going through `dbError` (Java declares
//! `throws DuplicateNameException, InvalidInputException`), so it keeps a typed [`RenameEquateError`]
//! matching [`EquateManager::create_equate`](crate::program::database::symbol::EquateManager::create_equate)'s
//! own [`CreateEquateError`](crate::program::database::symbol::CreateEquateError) convention.
//!
//! Query methods that hand back another equate/reference use trait objects rather than concrete
//! types, per this crate's general cut-point convention: [`references`](EquateDb::references) and
//! [`references_at`](EquateDb::references_at) return `Box<dyn` [`EquateReference`]`>`, mirroring
//! [`EquateManager`](crate::program::database::symbol::EquateManager)'s own `Arc<dyn Equate>`
//! convention for its query methods.
//!
//! Unlike the already-ported, in-memory [`Equate`](crate::program::model::symbol::Equate) model
//! trait (backed by `SimpleEquate`, whose methods take `&mut self`), this trait's methods all take
//! `&self`, matching [`DbObject`]'s convention of exposing interior-mutability-guarded state on a
//! shared (typically `Arc`-held) object -- the same reasoning that kept this trait independent of
//! `Equate` rather than built on top of it, mirroring how `EquateManager`'s port declined to build on
//! the separately-ported `EquateTable` model trait for the analogous representation mismatch.
//!
//! `equals(Object)` is modeled as a default method ([`EquateDb::equate_equals`]) since it only reads
//! other trait methods (`name`/`value`); `toString()` is modeled via a blanket `Display` impl for
//! `dyn EquateDb` delegating to `display_name()`. `hashCode()` is omitted as internal bookkeeping
//! with no behaviorally significant public contract beyond what `equate_equals` already covers.

use std::fmt;

use crate::program::database::DbObject;
use crate::program::model::address::Address;
use crate::program::model::symbol::EquateReference;
use crate::util::exception::{DuplicateNameException, InvalidInputException};
use crate::util::UniversalID;

/// Error produced by [`EquateDb::rename_equate`], mirroring the Java method's
/// `throws DuplicateNameException, InvalidInputException`.
#[derive(Debug, thiserror::Error)]
pub enum RenameEquateError {
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Database object for an Equate.
///
/// Port of `ghidra.program.database.symbol.EquateDB`. See the module docs for what was
/// intentionally left out (the constructor and its private helpers).
pub trait EquateDb: DbObject {
    /// Returns the actual equate name. Stands in for `EquateDB.getName()`.
    fn name(&self) -> String;

    /// Returns the user-facing display name: the enum member name when this equate is enum-based
    /// and the enum/member can still be resolved, an error-tagged formatted value when it cannot,
    /// or just the equate name otherwise. Stands in for `EquateDB.getDisplayName()`.
    fn display_name(&self) -> String;

    /// Returns the scalar value associated with this equate. Stands in for `EquateDB.getValue()`.
    fn value(&self) -> i64;

    /// Returns the signed hexadecimal display value. Stands in for `EquateDB.getDisplayValue()`.
    fn display_value(&self) -> String;

    /// Returns the enum data type's universal id if this equate is enum-based and valid, or `None`
    /// otherwise. Stands in for `EquateDB.getEnumUUID()`.
    fn enum_uuid(&self) -> Option<UniversalID>;

    /// Returns true if this equate is either not enum-based or has a valid, resolvable enum id.
    /// Stands in for `EquateDB.isValidUUID()`.
    fn is_valid_uuid(&self) -> bool;

    /// Returns true if this equate is backed by an enum data type id. Stands in for
    /// `EquateDB.isEnumBased()`.
    fn is_enum_based(&self) -> bool;

    /// Returns the number of references to this equate, or 0 if the count could not be
    /// determined. Stands in for `EquateDB.getReferenceCount()`.
    fn reference_count(&self) -> i32;

    /// Returns all references to this equate. Stands in for `EquateDB.getReferences()`.
    fn references(&self) -> Vec<Box<dyn EquateReference>>;

    /// Returns references to this equate at the given address. Stands in for
    /// `EquateDB.getReferences(Address)`.
    fn references_at(&self, ref_addr: &Address) -> Vec<Box<dyn EquateReference>>;

    /// Adds or replaces a reference at the given address and operand position. Stands in for
    /// `EquateDB.addReference(Address, int)`.
    fn add_reference(&self, ref_addr: Address, op_index: i32);

    /// Adds or replaces a dynamic-hash reference at the given address. Stands in for
    /// `EquateDB.addReference(long, Address)`.
    fn add_dynamic_reference(&self, dynamic_hash: i64, ref_addr: Address);

    /// Removes the reference at the given address and operand position. Stands in for
    /// `EquateDB.removeReference(Address, int)`.
    fn remove_reference(&self, ref_addr: &Address, op_index: i32);

    /// Removes the reference at the given address and dynamic hash. Stands in for
    /// `EquateDB.removeReference(long, Address)`.
    fn remove_dynamic_reference(&self, dynamic_hash: i64, ref_addr: &Address);

    /// Renames this equate. Stands in for `EquateDB.renameEquate(String)`.
    ///
    /// # Errors
    /// Returns [`RenameEquateError::DuplicateName`] if `new_name` is already in use as an equate,
    /// or [`RenameEquateError::InvalidInput`] if `new_name` is blank.
    fn rename_equate(&self, new_name: &str) -> Result<(), RenameEquateError>;

    /// Returns true if `other` has the same value and name as this equate. Stands in for
    /// `EquateDB.equals(Object)`.
    fn equate_equals(&self, other: &dyn EquateDb) -> bool {
        self.value() == other.value() && self.name() == other.name()
    }
}

impl fmt::Display for dyn EquateDb + '_ {
    /// Stands in for `EquateDB.toString()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::DbObjectState;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    struct MockEquateReference {
        address: Address,
        op_index: i16,
        dynamic_hash_value: i64,
    }

    impl EquateReference for MockEquateReference {
        fn address(&self) -> &Address {
            &self.address
        }

        fn op_index(&self) -> i16 {
            self.op_index
        }

        fn dynamic_hash_value(&self) -> i64 {
            self.dynamic_hash_value
        }
    }

    /// Minimal mock exercising the record-plus-manager-callback shape `EquateDB` actually has,
    /// without depending on a concrete `EquateManager`/`DBRecord` -- just enough state to prove the
    /// trait is object-safe and that its methods behave like the Java class.
    struct MockEquateDb {
        state: DbObjectState,
        name: Mutex<String>,
        value: i64,
        refs: Mutex<Vec<(Address, i32, i64)>>,
        rename_calls: AtomicI32,
    }

    impl MockEquateDb {
        fn new(key: i64, name: &str, value: i64) -> Self {
            MockEquateDb {
                state: DbObjectState::new(key),
                name: Mutex::new(name.to_string()),
                value,
                refs: Mutex::new(Vec::new()),
                rename_calls: AtomicI32::new(0),
            }
        }
    }

    impl DbObject for MockEquateDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&crate::framework::db::DBRecord>) -> bool {
            true
        }
    }

    impl EquateDb for MockEquateDb {
        fn name(&self) -> String {
            self.name.lock().unwrap().clone()
        }

        fn display_name(&self) -> String {
            self.name()
        }

        fn value(&self) -> i64 {
            self.value
        }

        fn display_value(&self) -> String {
            if self.value < 0 {
                format!("-0x{:x}", self.value.unsigned_abs())
            } else {
                format!("0x{:x}", self.value)
            }
        }

        fn enum_uuid(&self) -> Option<UniversalID> {
            None
        }

        fn is_valid_uuid(&self) -> bool {
            true
        }

        fn is_enum_based(&self) -> bool {
            false
        }

        fn reference_count(&self) -> i32 {
            self.refs.lock().unwrap().len() as i32
        }

        fn references(&self) -> Vec<Box<dyn EquateReference>> {
            self.refs
                .lock()
                .unwrap()
                .iter()
                .map(|(address, op_index, dynamic_hash_value)| {
                    Box::new(MockEquateReference {
                        address: address.clone(),
                        op_index: *op_index as i16,
                        dynamic_hash_value: *dynamic_hash_value,
                    }) as Box<dyn EquateReference>
                })
                .collect()
        }

        fn references_at(&self, ref_addr: &Address) -> Vec<Box<dyn EquateReference>> {
            self.references()
                .into_iter()
                .filter(|r| r.address() == ref_addr)
                .collect()
        }

        fn add_reference(&self, ref_addr: Address, op_index: i32) {
            let mut refs = self.refs.lock().unwrap();
            refs.retain(|(a, o, _)| !(*a == ref_addr && *o == op_index));
            refs.push((ref_addr, op_index, 0));
        }

        fn add_dynamic_reference(&self, dynamic_hash: i64, ref_addr: Address) {
            let mut refs = self.refs.lock().unwrap();
            refs.retain(|(a, _, h)| !(*a == ref_addr && *h == dynamic_hash));
            refs.push((ref_addr, -1, dynamic_hash));
        }

        fn remove_reference(&self, ref_addr: &Address, op_index: i32) {
            self.refs
                .lock()
                .unwrap()
                .retain(|(a, o, _)| !(a == ref_addr && *o == op_index));
        }

        fn remove_dynamic_reference(&self, dynamic_hash: i64, ref_addr: &Address) {
            self.refs
                .lock()
                .unwrap()
                .retain(|(a, _, h)| !(a == ref_addr && *h == dynamic_hash));
        }

        fn rename_equate(&self, new_name: &str) -> Result<(), RenameEquateError> {
            self.rename_calls.fetch_add(1, Ordering::SeqCst);
            if new_name.trim().is_empty() {
                return Err(InvalidInputException::with_message("Name is empty string.").into());
            }
            if new_name == "TAKEN" {
                return Err(DuplicateNameException::with_message(format!(
                    "Equate named {new_name} already exists"
                ))
                .into());
            }
            *self.name.lock().unwrap() = new_name.to_string();
            Ok(())
        }
    }

    #[test]
    fn object_safety_and_reference_round_trip() {
        let equate: Box<dyn EquateDb> = Box::new(MockEquateDb::new(1, "FLAG", 0x80));

        assert_eq!(equate.name(), "FLAG");
        assert_eq!(equate.display_name(), "FLAG");
        assert_eq!(equate.value(), 0x80);
        assert_eq!(equate.display_value(), "0x80");
        assert_eq!(equate.to_string(), "FLAG");
        assert_eq!(equate.reference_count(), 0);

        let a = addr(0x1000);
        let b = addr(0x2000);
        equate.add_reference(a.clone(), 1);
        equate.add_reference(a.clone(), 1); // replaces, not duplicates
        equate.add_dynamic_reference(0x55, b.clone());

        assert_eq!(equate.reference_count(), 2);
        assert_eq!(equate.references_at(&a).len(), 1);
        assert_eq!(equate.references_at(&a)[0].op_index(), 1);
        assert_eq!(equate.references_at(&b)[0].dynamic_hash_value(), 0x55);

        equate.remove_reference(&a, 1);
        assert_eq!(equate.reference_count(), 1);
        equate.remove_dynamic_reference(0x55, &b);
        assert_eq!(equate.reference_count(), 0);
    }

    #[test]
    fn rename_equate_rejects_blank_and_duplicate_names() {
        let equate: Box<dyn EquateDb> = Box::new(MockEquateDb::new(2, "GOOD", 1));

        assert!(matches!(
            equate.rename_equate("   "),
            Err(RenameEquateError::InvalidInput(_))
        ));
        assert!(matches!(
            equate.rename_equate("TAKEN"),
            Err(RenameEquateError::DuplicateName(_))
        ));

        equate.rename_equate("BETTER").unwrap();
        assert_eq!(equate.name(), "BETTER");
    }

    #[test]
    fn equate_equals_compares_value_and_name() {
        let a: Box<dyn EquateDb> = Box::new(MockEquateDb::new(1, "FIVE", 5));
        let b: Box<dyn EquateDb> = Box::new(MockEquateDb::new(2, "FIVE", 5));
        let c: Box<dyn EquateDb> = Box::new(MockEquateDb::new(3, "SIX", 6));

        assert!(a.equate_equals(&*b));
        assert!(!a.equate_equals(&*c));
    }

    #[test]
    fn db_object_supertrait_is_usable() {
        let equate = MockEquateDb::new(42, "KEY", 1);
        assert_eq!(equate.get_key(), 42);
        assert!(equate.refresh_if_needed());
    }
}
