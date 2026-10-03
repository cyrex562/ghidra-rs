//! Port of `ghidra.program.database.symbol.MemorySymbol` as a trait (cycle cut-point).
//!
//! `MemorySymbol` is Java's `abstract class MemorySymbol extends SymbolDB` -- the shared base for
//! every symbol whose address is a real memory address or a "fake" external address
//! ([`CodeSymbol`](crate::program::database::symbol::CodeSymbol),
//! [`FunctionSymbol`](crate::program::database::symbol::FunctionSymbol),
//! [`ClassSymbol`](crate::program::database::symbol::ClassSymbol),
//! [`LibraryDb`](crate::program::database::symbol::LibraryDb),
//! [`NamespaceSymbol`](crate::program::database::symbol::NamespaceSymbol)). Every one of those
//! concrete Java leaf classes has already been ported in this crate as its own object-safe trait
//! extending [`Symbol`] directly, with a doc comment explaining that it "keeps only its overridden
//! `Symbol`/`MemorySymbol` contract ... rather than modeling the `MemorySymbol`/`SymbolDB`
//! superclass chain" -- i.e. none of them compose a concrete `MemorySymbol` base the way
//! `InstructionDB`/`DataDB` compose
//! [`CodeUnitDbBase`](crate::program::database::code::code_unit_db::CodeUnitDbBase). Building a
//! `MemorySymbolBase` analogous to `CodeUnitDbBase` here would therefore produce an orphan type
//! nothing in this package actually uses (unlike `CodeUnitDbBase`, which real, already-shipped
//! `InstructionDB`/`DataDB` ports genuinely hold as a field) -- so this port follows the
//! convention already established by every sibling class in this exact package instead: an
//! object-safe trait extending [`Symbol`] directly, with `MemorySymbol`'s substantial `final`
//! (non-overridable) Java logic ported as real default methods, and everything that reaches into
//! `SymbolManager`/the backing `DBRecord` modeled as required accessor methods a concrete
//! implementor supplies (mirroring the `base_*`/accessor convention `CodeSymbol`/`FunctionSymbol`
//! already use).
//!
//! `MemorySymbol`'s constructor validation (`addr.isMemoryAddress() || isExternal()`) has no
//! `&self`-callable home in a trait; [`validate_memory_symbol_address`] is provided as a free
//! function a concrete implementor's own constructor can call instead.
//!
//! Left out, as package-private low-level machinery not exercised outside `SymbolManager`'s own
//! (unported) memory-block-move / image-base-change code paths: `moveLowLevel(Address, String,
//! Namespace, SourceType, boolean)`. Porting it faithfully would require re-encoding an address
//! through `SymbolManager.getAddressMap()` and writing four independent record fields
//! (address/primary/name/namespace) plus the source-flag bits, none of which this trait's
//! `&self`-only accessor surface can express as a single atomic operation without inventing
//! plumbing no current caller needs.
//!
//! `hasExactlyOneSymbolAtAddress(Address)` (private, used only by
//! [`get_reference_count`](MemorySymbol::get_reference_count)) is modeled as the required
//! [`has_exactly_one_symbol_at_address`](MemorySymbol::has_exactly_one_symbol_at_address) accessor
//! rather than iterating `symbolMgr.getSymbolsAsIterator(Address)` directly, since `SymbolManager`
//! itself is a cut-point not reachable from this trait.

use std::sync::Arc;

use crate::framework::db::DBRecord;
use crate::program::model::address::Address;
use crate::program::model::symbol::{Reference, Symbol};
use crate::util::task::TaskMonitor;

/// Validates the constructor precondition `MemorySymbol(SymbolManager, Address, DBRecord, long)`
/// enforces: `addr.isMemoryAddress() || isExternal()`. Stands in for the Java constructor's
/// `if (!addr.isMemoryAddress() && !isExternal()) throw new IllegalArgumentException(...)`.
///
/// # Errors
/// Returns an error message mirroring the Java `IllegalArgumentException` text if `addr` is
/// neither a memory address nor an external address.
pub fn validate_memory_symbol_address(addr: &Address) -> Result<(), String> {
    if !addr.is_memory_address() && !addr.is_external_address() {
        return Err("memory or external address required".to_string());
    }
    Ok(())
}

/// Sets the sparse `SYMBOL_EXTERNAL_PROG_ADDR_COL`/`SYMBOL_ORIGINAL_IMPORTED_NAME_COL` fields on a
/// freshly-created symbol record. Stands in for the package-private static
/// `MemorySymbol.setExternalFields(DBRecord, String, Address)`, called by `CodeSymbol`/
/// `FunctionSymbol`'s (unported) construction helpers when creating an external label/function
/// symbol.
pub fn set_external_fields(
    record: &mut DBRecord,
    original_import_name: Option<&str>,
    external_program_address: Option<&Address>,
) {
    let addr_str = external_program_address.map(|a| a.to_string());
    record.set_string(
        crate::program::database::symbol::symbol_database_adapter_v5::SYMBOL_EXTERNAL_PROG_ADDR_COL,
        addr_str,
    );
    record.set_string(
        crate::program::database::symbol::symbol_database_adapter_v5::SYMBOL_ORIGINAL_IMPORTED_NAME_COL,
        original_import_name.map(str::to_string),
    );
}

/// Any symbol that resides at a memory location (or a fake external address).
///
/// Port of `ghidra.program.database.symbol.MemorySymbol` as a trait (cycle cut-point). See the
/// module docs for why this mirrors the sibling `CodeSymbol`/`FunctionSymbol` convention rather
/// than the `CodeUnitDb`/`CodeUnitDbBase` composition pattern, and for what was intentionally left
/// out.
pub trait MemorySymbol: Symbol {
    // -----------------------------------------------------------------------------------------
    // isExternalEntryPoint / isExternal
    // -----------------------------------------------------------------------------------------

    /// Accessor standing in for `symbolMgr.isExternalEntryPoint(address)`, used by
    /// [`is_external_entry_point`](Self::is_external_entry_point). Required because
    /// `SymbolManager` is a cut-point not reachable from this trait.
    fn is_external_entry_point_lookup(&self) -> bool;

    /// Stands in for the `final` `MemorySymbol.isExternalEntryPoint()`.
    fn is_external_entry_point(&self) -> bool {
        self.is_external_entry_point_lookup()
    }

    /// Stands in for the `final` `MemorySymbol.isExternal()`: `address.isExternalAddress()`.
    /// Named distinctly from [`Symbol::is_external`] (which this trait does not override, since a
    /// default trait method cannot override a supertrait's default without the implementing type
    /// doing so explicitly) -- concrete implementors should forward their `Symbol::is_external`
    /// to this method, mirroring how `CodeSymbol`/`FunctionSymbol` handle the analogous
    /// `is_primary` naming overlap.
    fn is_external(&self) -> bool {
        self.get_address().is_external_address()
    }

    // -----------------------------------------------------------------------------------------
    // isPinned / setPinned
    // -----------------------------------------------------------------------------------------

    /// Accessor standing in for reading the `SYMBOL_PINNED_FLAG` bit of `SYMBOL_FLAGS_COL` on the
    /// backing record (the private `MemorySymbol.doIsPinned()`), used by
    /// [`is_pinned`](Self::is_pinned). Should return `false` when there is no backing record
    /// (dynamic symbol), matching Java's `if (record == null) return false;`.
    fn pinned_flag(&self) -> bool;

    /// Accessor standing in for `MemorySymbol.updatePinnedFlag(boolean)` +
    /// `updateRecord()` + `symbolMgr.symbolAnchoredFlagChanged(this)` -- the full body of the
    /// private `doSetPinned(boolean)` once the "value actually changed" and "record present"
    /// guards have passed. Required because writing the record and notifying the symbol manager
    /// both need state/collaborators not modeled by this trait.
    fn write_pinned_flag(&self, pinned: bool);

    /// Stands in for the `final` `MemorySymbol.isPinned()`: external symbols are never pinned.
    fn is_pinned(&self) -> bool {
        if MemorySymbol::is_external(self) {
            return false;
        }
        self.pinned_flag()
    }

    /// Stands in for the `final` `MemorySymbol.setPinned(boolean)`, including `doSetPinned`'s
    /// "no-op if already at the requested state" guard.
    fn set_pinned(&self, pinned: bool) {
        if MemorySymbol::is_external(self) {
            return;
        }
        if pinned == MemorySymbol::is_pinned(self) {
            return;
        }
        self.write_pinned_flag(pinned);
    }

    // -----------------------------------------------------------------------------------------
    // getReferenceCount / hasReferences / getReferences
    // -----------------------------------------------------------------------------------------

    /// Accessor standing in for `symbolMgr.getReferenceManager().getReferenceCountTo(address)`,
    /// used by [`get_reference_count`](Self::get_reference_count)'s fast paths.
    fn reference_count_to_address(&self) -> i32;

    /// Accessor standing in for the private `hasExactlyOneSymbolAtAddress(Address)`: whether
    /// exactly one symbol (of any type) exists at this symbol's address. Used by
    /// [`get_reference_count`](Self::get_reference_count) to decide whether every reference to the
    /// address unambiguously belongs to this symbol.
    fn has_exactly_one_symbol_at_address(&self) -> bool;

    /// Accessor standing in for `symbolMgr.getReferenceManager().getReferencesTo(address)`,
    /// collected eagerly (Java iterates a `ReferenceIterator` lazily; this port's default methods
    /// need to inspect and count/filter the same sequence more than once).
    fn references_to_address(&self) -> Vec<Arc<dyn Reference>>;

    /// Stands in for `MemorySymbol.getReferenceCount()`. If this symbol is external or the only
    /// symbol at its address, every reference to the address counts; otherwise only references
    /// that name this symbol's ID (or, when this is the primary symbol, references that name no
    /// specific symbol) are counted.
    fn get_reference_count(&self) -> i32 {
        if MemorySymbol::is_external(self) || self.has_exactly_one_symbol_at_address() {
            return self.reference_count_to_address();
        }
        let key = self.get_id();
        let is_primary = self.is_primary();
        self.references_to_address()
            .iter()
            .filter(|r| r.symbol_id() == key || (is_primary && r.symbol_id() < 0))
            .count() as i32
    }

    /// Stands in for `MemorySymbol.hasReferences()`.
    fn has_references(&self) -> bool {
        let key = self.get_id();
        let is_primary = self.is_primary();
        self.references_to_address()
            .iter()
            .any(|r| r.symbol_id() == key || (is_primary && r.symbol_id() < 0))
    }

    /// Stands in for `MemorySymbol.getReferences(TaskMonitor)`. The Java method's progress-bar
    /// initialization dance (`UnknownProgressWrappingTaskMonitor`) is a rendering-only concern and
    /// is not modeled; cancellation is still honored.
    fn get_references(&self, monitor: &dyn TaskMonitor) -> Vec<Arc<dyn Reference>> {
        let key = self.get_id();
        let is_primary = self.is_primary();
        let mut list = Vec::new();
        for r in self.references_to_address() {
            if monitor.is_cancelled() {
                break;
            }
            if r.symbol_id() == key || (is_primary && r.symbol_id() < 0) {
                list.push(r);
            }
        }
        list
    }

    // -----------------------------------------------------------------------------------------
    // External original imported name / external program address
    // -----------------------------------------------------------------------------------------

    /// Accessor standing in for reading `SYMBOL_ORIGINAL_IMPORTED_NAME_COL` off the backing
    /// record, used by [`get_external_original_imported_name`](Self::get_external_original_imported_name).
    /// Should return `None` when there is no backing record, matching Java's
    /// `if (record == null) return null;`.
    fn external_original_imported_name(&self) -> Option<String>;

    /// Accessor standing in for the body of `setExternalOriginalImportedName` once the type guard
    /// (see [`set_external_original_imported_name`](Self::set_external_original_imported_name))
    /// has passed: the old-vs-new comparison, record write, `updateRecord()`, and conditional
    /// `symbolMgr.symbolDataChanged(this)` notification. Should no-op when there is no backing
    /// record, matching Java's `if (record == null) return;`.
    fn write_external_original_imported_name(&self, name: Option<&str>, notify: bool);

    /// Stands in for the `final` `MemorySymbol.getExternalOriginalImportedName()`.
    fn get_external_original_imported_name(&self) -> Option<String> {
        self.external_original_imported_name()
    }

    /// Stands in for the `final` `MemorySymbol.setExternalOriginalImportedName(String, boolean)`,
    /// including its type-guard precondition.
    ///
    /// # Panics
    /// Panics (mirroring Java's `UnsupportedOperationException`) unless this symbol is an
    /// external [`SymbolType::Label`](crate::program::model::symbol::SymbolType::Label) or
    /// [`SymbolType::Function`](crate::program::model::symbol::SymbolType::Function).
    fn set_external_original_imported_name(&self, original_imported_name: Option<&str>, notify: bool) {
        use crate::program::model::symbol::SymbolType;
        let ty = self.get_symbol_type();
        if !self.get_address().is_external_address()
            || (ty != SymbolType::Label && ty != SymbolType::Function)
        {
            panic!("Symbol does not support: originalImportedName");
        }
        self.write_external_original_imported_name(original_imported_name, notify);
    }

    /// Accessor standing in for reading and parsing `SYMBOL_EXTERNAL_PROG_ADDR_COL` off the
    /// backing record via `symbolMgr.getAddressMap().getAddressFactory().getAddress(String)`, used
    /// by [`get_external_program_address`](Self::get_external_program_address). Should return
    /// `None` when there is no backing record or no stored address, matching Java's `null` return.
    fn external_program_address(&self) -> Option<Address>;

    /// Accessor standing in for the body of `setExternalProgramAddress` once the type/address-kind
    /// guards (see [`set_external_program_address`](Self::set_external_program_address)) have
    /// passed: the old-vs-new comparison, record write, `updateRecord()`, and conditional
    /// `symbolMgr.symbolDataChanged(this)` notification. Should no-op when there is no backing
    /// record, matching Java's `if (record == null) return;`.
    fn write_external_program_address(&self, external_program_address: Option<&Address>, notify: bool);

    /// Stands in for the `final` `MemorySymbol.getExternalProgramAddress()`.
    fn get_external_program_address(&self) -> Option<Address> {
        self.external_program_address()
    }

    /// Stands in for the `final` `MemorySymbol.setExternalProgramAddress(Address, boolean)`,
    /// including its type-guard and memory-address-kind preconditions.
    ///
    /// # Panics
    /// Panics (mirroring Java's `UnsupportedOperationException`) unless this symbol is an
    /// external [`SymbolType::Label`](crate::program::model::symbol::SymbolType::Label) or
    /// [`SymbolType::Function`](crate::program::model::symbol::SymbolType::Function), and
    /// (mirroring Java's `IllegalArgumentException`) if a non-`None` address is not a loaded
    /// memory address.
    fn set_external_program_address(&self, external_program_address: Option<&Address>, notify: bool) {
        use crate::program::model::symbol::SymbolType;
        let ty = self.get_symbol_type();
        if !self.get_address().is_external_address()
            || (ty != SymbolType::Label && ty != SymbolType::Function)
        {
            panic!("Symbol does not support: external program address");
        }
        if let Some(addr) = external_program_address {
            if !addr.is_loaded_memory_address() {
                panic!("Memory address required for external program");
            }
        }
        self.write_external_program_address(external_program_address, notify);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::symbol::{RefType, SourceType, SymbolType};
    use std::any::Any;
    use std::sync::Mutex;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn external_space() -> Arc<AddressSpace> {
        AddressSpace::new("EXTERNAL", 32, 1, AddressSpaceType::External, 2)
    }

    fn ram_addr(offset: i64) -> Address {
        Address::new(ram_space(), offset)
    }

    struct MockRef {
        symbol_id: i64,
    }

    impl Reference for MockRef {
        fn from_address(&self) -> Address {
            ram_addr(0)
        }
        fn to_address(&self) -> Address {
            ram_addr(0x1000)
        }
        fn is_primary(&self) -> bool {
            true
        }
        fn symbol_id(&self) -> i64 {
            self.symbol_id
        }
        fn reference_type(&self) -> RefType {
            RefType::Data
        }
        fn operand_index(&self) -> i32 {
            0
        }
        fn is_mnemonic_reference(&self) -> bool {
            false
        }
        fn is_operand_reference(&self) -> bool {
            true
        }
        fn is_stack_reference(&self) -> bool {
            false
        }
        fn is_external_reference(&self) -> bool {
            false
        }
        fn is_entry_point_reference(&self) -> bool {
            false
        }
        fn is_memory_reference(&self) -> bool {
            true
        }
        fn is_register_reference(&self) -> bool {
            false
        }
        fn is_offset_reference(&self) -> bool {
            false
        }
        fn is_shifted_reference(&self) -> bool {
            false
        }
        fn source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    struct MockMemorySymbol {
        address: Address,
        primary: bool,
        id: i64,
        pinned: Mutex<bool>,
        entry_point: bool,
        one_symbol_at_address: bool,
        ref_count: i32,
        refs: Vec<Arc<dyn Reference>>,
        orig_import_name: Mutex<Option<String>>,
        ext_prog_addr: Mutex<Option<Address>>,
        symbol_type: SymbolType,
    }

    impl Symbol for MockMemorySymbol {
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_name(&self) -> &str {
            "mock"
        }
        fn get_symbol_type(&self) -> SymbolType {
            self.symbol_type
        }
        fn get_source(&self) -> SourceType {
            SourceType::UserDefined
        }
        fn is_primary(&self) -> bool {
            self.primary
        }
        fn get_id(&self) -> i64 {
            self.id
        }
        fn get_parent_id(&self) -> i64 {
            0
        }
    }

    impl MemorySymbol for MockMemorySymbol {
        fn is_external_entry_point_lookup(&self) -> bool {
            self.entry_point
        }

        fn pinned_flag(&self) -> bool {
            *self.pinned.lock().unwrap()
        }

        fn write_pinned_flag(&self, pinned: bool) {
            *self.pinned.lock().unwrap() = pinned;
        }

        fn reference_count_to_address(&self) -> i32 {
            self.ref_count
        }

        fn has_exactly_one_symbol_at_address(&self) -> bool {
            self.one_symbol_at_address
        }

        fn references_to_address(&self) -> Vec<Arc<dyn Reference>> {
            self.refs.clone()
        }

        fn external_original_imported_name(&self) -> Option<String> {
            self.orig_import_name.lock().unwrap().clone()
        }

        fn write_external_original_imported_name(&self, name: Option<&str>, _notify: bool) {
            *self.orig_import_name.lock().unwrap() = name.map(str::to_string);
        }

        fn external_program_address(&self) -> Option<Address> {
            self.ext_prog_addr.lock().unwrap().clone()
        }

        fn write_external_program_address(&self, addr: Option<&Address>, _notify: bool) {
            *self.ext_prog_addr.lock().unwrap() = addr.cloned();
        }
    }

    fn mock(address: Address, symbol_type: SymbolType) -> MockMemorySymbol {
        MockMemorySymbol {
            address,
            primary: true,
            id: 7,
            pinned: Mutex::new(false),
            entry_point: false,
            one_symbol_at_address: false,
            ref_count: 0,
            refs: Vec::new(),
            orig_import_name: Mutex::new(None),
            ext_prog_addr: Mutex::new(None),
            symbol_type,
        }
    }

    #[test]
    fn is_external_reflects_address_space() {
        let mem_sym = mock(ram_addr(0x1000), SymbolType::Label);
        assert!(!MemorySymbol::is_external(&mem_sym));

        let ext_sym = mock(Address::new(external_space(), 0), SymbolType::Label);
        assert!(MemorySymbol::is_external(&ext_sym));
    }

    #[test]
    fn pinned_state_round_trips_and_external_symbols_are_never_pinned() {
        let sym = mock(ram_addr(0x1000), SymbolType::Label);
        assert!(!MemorySymbol::is_pinned(&sym));
        sym.set_pinned(true);
        assert!(MemorySymbol::is_pinned(&sym));
        sym.set_pinned(false);
        assert!(!MemorySymbol::is_pinned(&sym));

        let ext_sym = mock(Address::new(external_space(), 0), SymbolType::Label);
        ext_sym.set_pinned(true);
        assert!(!MemorySymbol::is_pinned(&ext_sym), "external symbols cannot be pinned");
    }

    #[test]
    fn set_pinned_is_a_no_op_when_state_is_unchanged() {
        let sym = mock(ram_addr(0x1000), SymbolType::Label);
        sym.set_pinned(false);
        assert!(!MemorySymbol::is_pinned(&sym));
    }

    #[test]
    fn reference_count_uses_fast_path_for_external_or_sole_symbol() {
        let mut sym = mock(ram_addr(0x1000), SymbolType::Label);
        sym.ref_count = 5;
        sym.one_symbol_at_address = true;
        assert_eq!(sym.get_reference_count(), 5);

        let mut ext_sym = mock(Address::new(external_space(), 0), SymbolType::Label);
        ext_sym.ref_count = 3;
        assert_eq!(ext_sym.get_reference_count(), 3);
    }

    #[test]
    fn reference_count_filters_by_symbol_id_when_multiple_symbols_share_address() {
        let mut sym = mock(ram_addr(0x1000), SymbolType::Label);
        sym.id = 7;
        sym.primary = false;
        sym.one_symbol_at_address = false;
        sym.refs = vec![
            Arc::new(MockRef { symbol_id: 7 }),
            Arc::new(MockRef { symbol_id: 99 }),
            Arc::new(MockRef { symbol_id: -1 }),
        ];
        // Not primary, so the symbol_id == -1 reference does not count.
        assert_eq!(sym.get_reference_count(), 1);
        assert!(sym.has_references());

        let refs = sym.get_references(&crate::util::task::DummyMonitor);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].symbol_id(), 7);
    }

    #[test]
    fn primary_symbol_also_claims_unattributed_references() {
        let mut sym = mock(ram_addr(0x1000), SymbolType::Label);
        sym.id = 7;
        sym.primary = true;
        sym.refs = vec![Arc::new(MockRef { symbol_id: -1 })];
        assert!(sym.has_references());
        assert_eq!(sym.get_reference_count(), 1);
    }

    #[test]
    fn get_references_honors_cancellation() {
        let mut sym = mock(ram_addr(0x1000), SymbolType::Label);
        sym.id = 7;
        sym.refs = vec![Arc::new(MockRef { symbol_id: 7 }), Arc::new(MockRef { symbol_id: 7 })];
        struct CancelledMonitor;
        impl crate::util::task::TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), crate::util::exception::CancelledException> {
                Ok(())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }
        let refs = sym.get_references(&CancelledMonitor);
        assert!(refs.is_empty());
    }

    #[test]
    fn external_original_imported_name_requires_external_label_or_function() {
        let sym = mock(ram_addr(0x1000), SymbolType::Label);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sym.set_external_original_imported_name(Some("_foo"), false);
        }));
        assert!(result.is_err(), "non-external symbol must reject the setter");

        let ext_sym = mock(Address::new(external_space(), 0), SymbolType::Label);
        ext_sym.set_external_original_imported_name(Some("_foo"), false);
        assert_eq!(
            ext_sym.get_external_original_imported_name(),
            Some("_foo".to_string())
        );
    }

    #[test]
    fn external_original_imported_name_rejects_non_label_function_types() {
        let ext_sym = mock(Address::new(external_space(), 0), SymbolType::Class);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ext_sym.set_external_original_imported_name(Some("_foo"), false);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn external_program_address_requires_loaded_memory_address() {
        let ext_sym = mock(Address::new(external_space(), 0), SymbolType::Function);
        ext_sym.set_external_program_address(Some(&ram_addr(0x2000)), false);
        assert_eq!(ext_sym.get_external_program_address(), Some(ram_addr(0x2000)));

        let non_memory = Address::new(external_space(), 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ext_sym.set_external_program_address(Some(&non_memory), false);
        }));
        assert!(result.is_err(), "a non-loaded-memory address must be rejected");
    }

    #[test]
    fn is_external_entry_point_delegates_to_accessor() {
        let mut sym = mock(ram_addr(0x1000), SymbolType::Label);
        sym.entry_point = true;
        assert!(MemorySymbol::is_external_entry_point(&sym));
    }

    #[test]
    fn set_external_fields_writes_both_sparse_columns() {
        use crate::framework::db::{DBRecord, Field};
        let record_schema = crate::program::database::symbol::symbol_database_adapter_v5::schema();
        let mut record = DBRecord::new(record_schema, Field::Long(Some(1)));
        set_external_fields(&mut record, Some("_orig"), Some(&ram_addr(0x3000)));
        assert_eq!(
            record.get_string(
                crate::program::database::symbol::symbol_database_adapter_v5::SYMBOL_ORIGINAL_IMPORTED_NAME_COL
            ),
            Some("_orig")
        );
        assert_eq!(
            record.get_string(
                crate::program::database::symbol::symbol_database_adapter_v5::SYMBOL_EXTERNAL_PROG_ADDR_COL
            ),
            Some(ram_addr(0x3000).to_string().as_str())
        );
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let sym: Box<dyn MemorySymbol> = Box::new(mock(ram_addr(0x1000), SymbolType::Label));
        assert!(!MemorySymbol::is_external(sym.as_ref()));
    }
}
