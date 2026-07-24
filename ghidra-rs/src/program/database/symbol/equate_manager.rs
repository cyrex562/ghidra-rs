//! Port of `ghidra.program.database.symbol.EquateManager` as a trait (cycle cut-point).
//!
//! The Java class is a concrete `EquateTable`/`ErrorHandler`/`ManagerDB` implementation that owns
//! the `EquateDBAdapter`/`EquateRefDBAdapter` tables and hands itself to every `EquateDB`/
//! `EquateRefDB` it creates (`new EquateDB(this, record)`) so those record wrappers can call back
//! into it (e.g. `Equate.addReference` on `EquateDB` forwards to
//! `EquateManager.addReference(long, Address, int, long)`). `EquateDB`/`EquateRefDB` are not
//! ported yet, so that mutual construction-time wiring -- plus `EquateManager`'s own dependency on
//! [`EquateDBAdapter`](crate::program::database::symbol::EquateDBAdapter) and
//! [`EquateRefDBAdapter`](crate::program::database::symbol::EquateRefDBAdapter), themselves earlier
//! cycle cut-points -- is what makes `EquateManager` a cut-point in turn.
//!
//! This port keeps the genuinely callable API: the public `EquateTable` methods it implements
//! (`ManagerDB`'s `invalidateCache`/`deleteAddressRange`/`moveAddressRange` and `ErrorHandler`'s
//! `dbError` are covered abstractly by the already-ported [`ManagerDB`] supertrait, exactly as
//! [`CodeManager`](crate::program::database::code::CodeManager)'s port does -- this crate's
//! `ManagerDB` never modeled `setProgram`/`programReady`/`dbError`/`dispose` in the first place),
//! plus `addReference(long, Address, int, long)`. That last one is package-private in Java, but is
//! kept here (identified by equate *name* rather than the DB row id `EquateDB`/`EquateRefDB` would
//! use, since this trait has no row-id concept of its own) because it is the only way a concrete
//! implementor can ever populate the address-indexed queries (`getEquate(Address, int, long)`,
//! `getEquates(Address, int)`, `getEquates(Address)`, `getEquateAddresses*`) -- the same reasoning
//! that kept `symbolAdded`/`symbolRemoved` on
//! [`ReferenceDbManager`](crate::program::database::references::ReferenceDbManager).
//!
//! Left out: the constructor (`DBHandle`/`AddressMap`/`OpenMode`/`Lock`/`TaskMonitor` wiring and
//! adapter selection), and package-private accessors used only by sibling `symbol` classes not yet
//! ported (`getAddressMap()`, `getEquateDatabaseAdapter()`, `getRefDatabaseAdapter()`, `getLock()`,
//! `getProgram()`, the two `removeReference` overloads, `getReferences`/`getReferenceCount`,
//! `getEquateRecord`/`getEquateRefRecord`, `equateNameChanged`) -- these are `EquateDB`/`EquateRefDB`
//! implementation plumbing, not part of the callable surface other managers depend on, and belong
//! with whichever concrete type is added later (matching the precedent set by
//! [`CodeManager`](crate::program::database::code::CodeManager) for its own such accessors).
//!
//! `EquateTable` was already ported separately as a model-level, in-memory contract
//! ([`program::model::symbol::EquateTable`](crate::program::model::symbol::EquateTable), backed by
//! `SimpleEquate`); this trait is *not* built on top of it, since that contract's methods return
//! `&(mut) SimpleEquate` by reference into owned storage, which a DB-backed manager producing
//! independent [`Equate`] trait objects per lookup cannot satisfy. Instead, query methods here
//! return `Arc<dyn Equate>`, following the same trait-object convention already used by
//! [`ReferenceManager`](crate::program::model::symbol::ReferenceManager)'s `Arc<dyn Reference>`.
//!
//! Method names mirror the corresponding Java methods (`snake_case`d), splitting overloads into
//! distinctly-named methods since Rust does not support overloading on parameter type, following
//! the same convention `CodeManager`'s and `ReferenceDbManager`'s ports already established.
//!
//! The four static formatting helpers (`formatNameForEquate`, `formatNameForEquateError`,
//! `getDataTypeUUID`, `getEquateValueFromFormattedName`) and the `DATATYPE_TAG`/`ERROR_TAG`/
//! `FORMAT_DELIMITER` constants don't depend on instance state, so they are ported as free
//! functions/constants in this module rather than trait methods.

use std::io;
use std::sync::Arc;

use thiserror::Error;

use crate::program::database::ManagerDB;
use crate::program::model::address::{Address, AddressIterator, AddressSetView};
use crate::program::model::symbol::Equate;
use crate::util::exception::{DuplicateNameException, InvalidInputException};
use crate::util::UniversalID;

/// Error produced by [`EquateManager::create_equate`], mirroring the Java method's
/// `throws DuplicateNameException, InvalidInputException` (plus the `IOException` a real
/// adapter-backed implementation may hit, which Java's version swallows via `ErrorHandler`).
#[derive(Debug, Error)]
pub enum CreateEquateError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    DuplicateName(#[from] DuplicateNameException),
    #[error(transparent)]
    InvalidInput(#[from] InvalidInputException),
}

/// Tag prefixed to equate names formatted from an enum data type id. Stands in for
/// `EquateManager.DATATYPE_TAG`.
pub const DATATYPE_TAG: &str = "dtID";
/// Suffix appended to equate names formatted from a value with no backing data type. Stands in
/// for `EquateManager.ERROR_TAG`.
pub const ERROR_TAG: &str = "<BAD EQUATE>";
/// Delimiter separating the fields of a formatted equate name. Stands in for
/// `EquateManager.FORMAT_DELIMITER`.
pub const FORMAT_DELIMITER: &str = ":";

/// Validates a candidate equate name, mirroring `EquateManager.validateName(String)` -- which,
/// unlike the general symbol-name validator, only rejects a name that is blank once trimmed.
pub fn validate_equate_name(name: &str) -> Result<(), InvalidInputException> {
    if name.trim().is_empty() {
        return Err(InvalidInputException::with_message("Name is empty string."));
    }
    Ok(())
}

fn signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-{:x}", value.unsigned_abs())
    } else {
        format!("{:x}", value)
    }
}

/// Formats a name for an equate driven by an enum data type, encoding the enum's universal id and
/// the equate's value so both can be recovered later via [`get_data_type_uuid`] and
/// [`get_equate_value_from_formatted_name`]. Stands in for
/// `EquateManager.formatNameForEquate(UniversalID, long)`.
pub fn format_name_for_equate(dt_id: UniversalID, equate_value: i64) -> String {
    format!("{DATATYPE_TAG}{FORMAT_DELIMITER}{}{FORMAT_DELIMITER}{equate_value}", dt_id.value())
}

/// Formats an error name for a value with no backing data type. Stands in for
/// `EquateManager.formatNameForEquateError(long)`.
pub fn format_name_for_equate_error(equate_value: i64) -> String {
    format!("0x{} {ERROR_TAG}", signed_hex(equate_value))
}

/// Recovers the enum data type's universal id from a formatted equate name, or `None` if the name
/// is not formatted. Stands in for `EquateManager.getDataTypeUUID(String)`.
pub fn get_data_type_uuid(formatted_equate_name: &str) -> Option<UniversalID> {
    if !formatted_equate_name.starts_with(DATATYPE_TAG) {
        return None;
    }
    let id: i64 = formatted_equate_name.split(FORMAT_DELIMITER).nth(1)?.parse().ok()?;
    Some(UniversalID::new(id))
}

/// Recovers the scalar value from a formatted equate name, or `-1` if the name is not formatted.
/// Stands in for `EquateManager.getEquateValueFromFormattedName(String)`.
pub fn get_equate_value_from_formatted_name(formatted_equate_name: &str) -> i64 {
    if !formatted_equate_name.starts_with(DATATYPE_TAG) {
        return -1;
    }
    formatted_equate_name
        .split(FORMAT_DELIMITER)
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(-1)
}

/// Implementation of the Equate Table.
///
/// Port of `ghidra.program.database.symbol.EquateManager`. See the module docs for what was
/// intentionally left out (the constructor and `EquateDB`/`EquateRefDB`-only accessors).
pub trait EquateManager: ManagerDB {
    /// Creates a new equate. Stands in for `EquateManager.createEquate(String, long)`.
    ///
    /// # Errors
    /// Returns [`CreateEquateError::DuplicateName`] if `name` is already in use as an equate, or
    /// [`CreateEquateError::InvalidInput`] if `name` is blank.
    fn create_equate(&mut self, name: &str, value: i64) -> Result<Arc<dyn Equate>, CreateEquateError>;

    /// Removes the named equate, along with all of its references. Returns `true` if the equate
    /// existed. Stands in for `EquateManager.removeEquate(String)`.
    fn remove_equate(&mut self, name: &str) -> bool;

    /// Returns the equate with the given name, if any. Stands in for
    /// `EquateManager.getEquate(String)`.
    fn get_equate(&self, name: &str) -> Option<Arc<dyn Equate>>;

    /// Returns the first equate associated with `scalar_value` at `reference`/`op_index`. Stands
    /// in for `EquateManager.getEquate(Address, int, long)`.
    fn get_equate_at(
        &self,
        reference: &Address,
        op_index: i32,
        scalar_value: i64,
    ) -> Option<Arc<dyn Equate>>;

    /// Returns the equates (one per scalar) at `reference`/`op_index`. Stands in for
    /// `EquateManager.getEquates(Address, int)`.
    fn get_equates_at_operand(&self, reference: &Address, op_index: i32) -> Vec<Arc<dyn Equate>>;

    /// Returns the equates (one per scalar and operand index) at `reference`. Stands in for
    /// `EquateManager.getEquates(Address)`.
    fn get_equates_at(&self, reference: &Address) -> Vec<Arc<dyn Equate>>;

    /// Returns an address iterator over every address with an equate reference. Stands in for
    /// `EquateManager.getEquateAddresses()`.
    fn get_equate_addresses(&self) -> Box<dyn AddressIterator>;

    /// Returns an address iterator over addresses with an equate reference at or after `start`.
    /// Stands in for `EquateManager.getEquateAddresses(Address)`.
    fn get_equate_addresses_from(&self, start: &Address) -> Box<dyn AddressIterator>;

    /// Returns an address iterator over addresses with an equate reference that lie in `set`.
    /// Stands in for `EquateManager.getEquateAddresses(AddressSetView)`.
    fn get_equate_addresses_in(&self, set: &dyn AddressSetView) -> Box<dyn AddressIterator>;

    /// Returns an iterator over all equates. Stands in for `EquateManager.getEquates()`.
    fn get_equates(&self) -> Box<dyn Iterator<Item = Arc<dyn Equate>> + '_>;

    /// Returns all equates with the given scalar value. Stands in for
    /// `EquateManager.getEquates(long)`.
    fn get_equates_for_value(&self, value: i64) -> Vec<Arc<dyn Equate>>;

    /// Adds a reference from `address`/`op_index` to the named equate, first removing any
    /// existing reference for the same address (and, when `dynamic_hash` is non-zero, the same
    /// dynamic hash; otherwise the same operand index). Stands in for
    /// `EquateManager.addReference(long, Address, int, long)`, keyed by equate name rather than
    /// database row id (see the module docs).
    ///
    /// # Errors
    /// Returns an error if there is no equate named `name`, or if there was a problem accessing
    /// the database.
    fn add_reference(
        &mut self,
        name: &str,
        address: &Address,
        op_index: i32,
        dynamic_hash: i64,
    ) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressIteratorAdapter, AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{SimpleEquateReference, UniversalId};
    use std::collections::HashMap;
    use std::io::ErrorKind;

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
    }

    /// Minimal `Equate` implementation the mock manager hands out; unrelated `Equate` methods
    /// (renaming, per-address filtering) are left inert, mirroring how `MockRefDbManager` in
    /// `reference_db_manager.rs`'s tests leaves unrelated `ReferenceManager` methods unimplemented.
    #[derive(Clone)]
    struct MockEquate {
        name: String,
        value: i64,
        reference_count: usize,
    }

    impl Equate for MockEquate {
        fn name(&self) -> &str {
            &self.name
        }

        fn display_name(&self) -> String {
            self.name.clone()
        }

        fn value(&self) -> i64 {
            self.value
        }

        fn display_value(&self) -> String {
            signed_hex(self.value)
        }

        fn reference_count(&self) -> usize {
            self.reference_count
        }

        fn add_reference(&mut self, _ref_addr: Address, _opnd_position: i16) {
            self.reference_count += 1;
        }

        fn add_dynamic_reference(&mut self, _dynamic_hash: i64, _ref_addr: Address) {
            self.reference_count += 1;
        }

        fn rename_equate(&mut self, new_name: &str) -> Result<(), String> {
            self.name = new_name.to_string();
            Ok(())
        }

        fn references(&self) -> Vec<SimpleEquateReference> {
            Vec::new()
        }

        fn references_at(&self, _ref_addr: &Address) -> Vec<SimpleEquateReference> {
            Vec::new()
        }

        fn remove_reference(&mut self, _ref_addr: &Address, _opnd_position: i16) -> bool {
            false
        }

        fn remove_dynamic_reference(&mut self, _dynamic_hash: i64, _ref_addr: &Address) -> bool {
            false
        }

        fn is_valid_uuid(&self) -> bool {
            true
        }

        fn is_enum_based(&self) -> bool {
            false
        }

        fn enum_uuid(&self) -> Option<UniversalId> {
            None
        }
    }

    struct RefEntry {
        name: String,
        address: Address,
        op_index: i32,
        dynamic_hash: i64,
    }

    /// Mock backing the address index off a flat `Vec` instead of `EquateRefDBAdapter`, exercising
    /// real create/lookup/reference/delete-range behavior.
    struct MockEquateManager {
        equates: HashMap<String, MockEquate>,
        refs: Vec<RefEntry>,
    }

    impl MockEquateManager {
        fn new() -> Self {
            MockEquateManager {
                equates: HashMap::new(),
                refs: Vec::new(),
            }
        }

        fn to_arc(equate: &MockEquate) -> Arc<dyn Equate> {
            Arc::new(equate.clone())
        }
    }

    impl ManagerDB for MockEquateManager {
        fn invalidate_cache(&mut self, _all: bool) -> io::Result<()> {
            Ok(())
        }

        fn delete_address_range(&mut self, start_addr: &Address, end_addr: &Address) -> io::Result<()> {
            self.refs.retain(|r| !(r.address >= *start_addr && r.address <= *end_addr));
            let live_names: std::collections::HashSet<&str> =
                self.refs.iter().map(|r| r.name.as_str()).collect();
            self.equates.retain(|name, _| live_names.contains(name.as_str()));
            Ok(())
        }

        fn move_address_range(
            &mut self,
            _from_addr: &Address,
            _to_addr: &Address,
            _length: u64,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl EquateManager for MockEquateManager {
        fn create_equate(&mut self, name: &str, value: i64) -> Result<Arc<dyn Equate>, CreateEquateError> {
            if self.equates.contains_key(name) {
                return Err(DuplicateNameException::with_message(format!(
                    "{name} already exists for an equate."
                ))
                .into());
            }
            validate_equate_name(name)?;
            let equate = MockEquate {
                name: name.to_string(),
                value,
                reference_count: 0,
            };
            let handle = Self::to_arc(&equate);
            self.equates.insert(name.to_string(), equate);
            Ok(handle)
        }

        fn remove_equate(&mut self, name: &str) -> bool {
            if self.equates.remove(name).is_none() {
                return false;
            }
            self.refs.retain(|r| r.name != name);
            true
        }

        fn get_equate(&self, name: &str) -> Option<Arc<dyn Equate>> {
            self.equates.get(name).map(Self::to_arc)
        }

        fn get_equate_at(
            &self,
            reference: &Address,
            op_index: i32,
            scalar_value: i64,
        ) -> Option<Arc<dyn Equate>> {
            self.refs
                .iter()
                .filter(|r| &r.address == reference && r.op_index == op_index)
                .find_map(|r| {
                    let equate = self.equates.get(&r.name)?;
                    (equate.value == scalar_value).then(|| Self::to_arc(equate))
                })
        }

        fn get_equates_at_operand(&self, reference: &Address, op_index: i32) -> Vec<Arc<dyn Equate>> {
            self.refs
                .iter()
                .filter(|r| &r.address == reference && r.op_index == op_index)
                .filter_map(|r| self.equates.get(&r.name).map(Self::to_arc))
                .collect()
        }

        fn get_equates_at(&self, reference: &Address) -> Vec<Arc<dyn Equate>> {
            self.refs
                .iter()
                .filter(|r| &r.address == reference)
                .filter_map(|r| self.equates.get(&r.name).map(Self::to_arc))
                .collect()
        }

        fn get_equate_addresses(&self) -> Box<dyn AddressIterator> {
            let mut addrs: Vec<Address> = self.refs.iter().map(|r| r.address.clone()).collect();
            addrs.sort();
            addrs.dedup();
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_equate_addresses_from(&self, start: &Address) -> Box<dyn AddressIterator> {
            let mut addrs: Vec<Address> = self
                .refs
                .iter()
                .map(|r| r.address.clone())
                .filter(|a| a >= start)
                .collect();
            addrs.sort();
            addrs.dedup();
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_equate_addresses_in(&self, set: &dyn AddressSetView) -> Box<dyn AddressIterator> {
            let mut addrs: Vec<Address> = self
                .refs
                .iter()
                .map(|r| r.address.clone())
                .filter(|a| set.contains(a))
                .collect();
            addrs.sort();
            addrs.dedup();
            Box::new(AddressIteratorAdapter::from_vec(addrs))
        }

        fn get_equates(&self) -> Box<dyn Iterator<Item = Arc<dyn Equate>> + '_> {
            Box::new(self.equates.values().map(Self::to_arc))
        }

        fn get_equates_for_value(&self, value: i64) -> Vec<Arc<dyn Equate>> {
            self.equates
                .values()
                .filter(|e| e.value == value)
                .map(Self::to_arc)
                .collect()
        }

        fn add_reference(
            &mut self,
            name: &str,
            address: &Address,
            op_index: i32,
            dynamic_hash: i64,
        ) -> io::Result<()> {
            let equate = self
                .equates
                .get_mut(name)
                .ok_or_else(|| io::Error::new(ErrorKind::NotFound, format!("no equate named {name}")))?;

            self.refs.retain(|r| {
                !(r.address == *address
                    && if dynamic_hash != 0 {
                        r.dynamic_hash == dynamic_hash
                    } else {
                        r.dynamic_hash == 0 && r.op_index == op_index
                    })
            });
            self.refs.push(RefEntry {
                name: name.to_string(),
                address: address.clone(),
                op_index,
                dynamic_hash,
            });
            if dynamic_hash != 0 {
                equate.add_dynamic_reference(dynamic_hash, address.clone());
            } else {
                equate.add_reference(address.clone(), op_index as i16);
            }
            Ok(())
        }
    }

    #[test]
    fn format_helpers_round_trip() {
        let uid = UniversalID::new(0x2a);
        let formatted = format_name_for_equate(uid, 7);
        assert_eq!(formatted, "dtID:42:7");
        assert_eq!(get_data_type_uuid(&formatted), Some(uid));
        assert_eq!(get_equate_value_from_formatted_name(&formatted), 7);

        assert_eq!(get_data_type_uuid("FOO"), None);
        assert_eq!(get_equate_value_from_formatted_name("FOO"), -1);

        assert_eq!(format_name_for_equate_error(-1), "0x-1 <BAD EQUATE>");
        assert_eq!(format_name_for_equate_error(255), "0xff <BAD EQUATE>");
    }

    #[test]
    fn validate_equate_name_rejects_blank() {
        assert!(validate_equate_name("  ").is_err());
        assert!(validate_equate_name("").is_err());
        assert!(validate_equate_name("ok").is_ok());
    }

    #[test]
    fn object_safety_and_create_lookup_remove_round_trip() {
        let mut mgr: Box<dyn EquateManager> = Box::new(MockEquateManager::new());

        let created = mgr.create_equate("FLAG", 0x80).unwrap();
        assert_eq!(created.value(), 0x80);

        assert!(matches!(
            mgr.create_equate("FLAG", 1),
            Err(CreateEquateError::DuplicateName(_))
        ));
        assert!(matches!(
            mgr.create_equate("   ", 1),
            Err(CreateEquateError::InvalidInput(_))
        ));

        assert_eq!(mgr.get_equate("FLAG").unwrap().value(), 0x80);
        assert!(mgr.get_equate("MISSING").is_none());

        assert!(mgr.remove_equate("FLAG"));
        assert!(!mgr.remove_equate("FLAG"));
        assert!(mgr.get_equate("FLAG").is_none());
    }

    #[test]
    fn address_indexed_queries_reflect_added_references() {
        let mut mgr: Box<dyn EquateManager> = Box::new(MockEquateManager::new());
        mgr.create_equate("FIVE", 5).unwrap();
        mgr.create_equate("ALSO_FIVE", 5).unwrap();
        mgr.create_equate("SIX", 6).unwrap();

        mgr.add_reference("FIVE", &addr(0x1000), 1, 0).unwrap();
        mgr.add_reference("ALSO_FIVE", &addr(0x1000), 2, 0).unwrap();
        // A given (address, opIndex) can only ever host one equate reference, mirroring
        // `EquateManager.addReference`'s scan-and-replace over *all* refs at the address
        // (not just the target equate's own), so SIX gets a distinct operand index.
        mgr.add_reference("SIX", &addr(0x1000), 3, 0).unwrap();
        mgr.add_reference("FIVE", &addr(0x2000), 0, 0x44).unwrap();

        assert!(matches!(
            mgr.add_reference("NOPE", &addr(0x3000), 0, 0),
            Err(e) if e.kind() == ErrorKind::NotFound
        ));

        assert_eq!(
            mgr.get_equate_at(&addr(0x1000), 1, 5).unwrap().name(),
            "FIVE"
        );
        assert!(mgr.get_equate_at(&addr(0x1000), 1, 999).is_none());
        assert_eq!(mgr.get_equates_at_operand(&addr(0x1000), 1).len(), 1);
        assert_eq!(mgr.get_equates_at(&addr(0x1000)).len(), 3);
        assert_eq!(mgr.get_equates_for_value(5).len(), 2);
        assert_eq!(mgr.get_equates().count(), 3);

        let mut all_addrs = Vec::new();
        let mut it = mgr.get_equate_addresses();
        while let Some(a) = it.next_address() {
            all_addrs.push(a);
        }
        assert_eq!(all_addrs, vec![addr(0x1000), addr(0x2000)]);

        let mut from = mgr.get_equate_addresses_from(&addr(0x1500));
        assert_eq!(from.next_address(), Some(addr(0x2000)));
        assert_eq!(from.next_address(), None);

        let set = AddressSet::from_start_end(addr(0x1000), addr(0x1fff));
        let mut in_set = mgr.get_equate_addresses_in(&set);
        assert_eq!(in_set.next_address(), Some(addr(0x1000)));
        assert_eq!(in_set.next_address(), None);

        // Re-adding the same equate at the same address/op-index replaces the prior reference
        // rather than duplicating it.
        mgr.add_reference("SIX", &addr(0x1000), 3, 0).unwrap();
        assert_eq!(mgr.get_equates_at_operand(&addr(0x1000), 3).len(), 1);

        mgr.delete_address_range(&addr(0x1000), &addr(0x1fff)).unwrap();
        assert!(mgr.get_equate("SIX").is_none());
        assert!(mgr.get_equate("ALSO_FIVE").is_none());
        assert!(mgr.get_equate("FIVE").is_some());
        assert_eq!(mgr.get_equates_at(&addr(0x1000)).len(), 0);
        assert_eq!(mgr.get_equates_at(&addr(0x2000)).len(), 1);
    }
}
