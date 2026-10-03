//! Port of `ghidra.program.database.code.CodeUnitDB` as a trait (cycle cut-point).
//!
//! The Java class is a package-private `abstract class CodeUnitDB extends DbObject implements
//! CodeUnit, ProcessorContext`. `DataDB` and `InstructionDB` both extend it, and `CodeUnitDB`
//! itself is constructed from (and calls back into) `CodeManager`/`ProgramDB`/`ReferenceDBManager`
//! -- the not-yet-ported `CodeManager` in particular sits at the center of that dependency web, so
//! porting `CodeUnitDB` as a concrete struct would pull in the whole `code` package at once. That
//! is the cycle this port cuts.
//!
//! Nearly all of `CodeUnitDB`'s `@Override` methods simply implement the already-ported
//! [`CodeUnit`] and [`ProcessorContext`] interfaces (see
//! [`DataDb`](crate::program::database::code::data_db::DataDb) for the same observation about
//! `DataDB`), so they are not repeated here. What `CodeUnitDb` adds on top of those two supertraits
//! (plus [`DbObject`], for the `key`/`cache`/`refresh` bookkeeping) is the class's own novel
//! contract -- the methods `DataDB`/`InstructionDB`/`DataComponent` each override with independent
//! logic:
//!
//! - `hasBeenDeleted(DBRecord)`: `protected abstract`, so every concrete subclass must supply its
//!   own "is this code unit still present" check.
//! - `getPreferredCacheLength()`: `protected`, overridden by `InstructionDB` (and `DataComponent`)
//!   to account for instruction length overrides / component sizing; `CodeUnitDB`'s own body is
//!   just `getLength()`, kept here as the default.
//! - `toString()`: `public abstract`, overridden by each subclass to render its own mnemonic and
//!   operands.
//!
//! Left out as implementation detail of a concrete DB-backed type (mirroring how
//! [`ReferenceDbManager`](crate::program::database::references::ReferenceDbManager) left out its
//! constructor): the constructor's `CodeManager`/`Address`/cache-key wiring, `DbObject.refresh`'s
//! address-map-decode-and-reset-caches body (needs `CodeManager.getAddressMap()`), and the private
//! comment/byte-cache helpers (`getCommentRecord`, `populateByteArray`, `readComments`,
//! `updateCommentRecord`) -- none of which are referenced outside this file in the original source.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, RwLock};

use crate::framework::db::DBRecord;
use crate::program::database::code::code_unit_owner::CodeUnitOwner;
use crate::program::database::code::comments_db_adapter::COMMENT_COL_COUNT;
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::address::Address;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::code_unit::{CodeUnit, MNEMONIC};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{Memory, MemoryAccessException};
use crate::program::model::symbol::{
    ExternalReference, Reference, ReferenceIterator, RefType, SourceType, Symbol,
};
use crate::program::model::lang::register_value::RegisterValue;
use crate::util::exception::NoValueException;
use crate::util::lock::ReentrantLock;
use crate::util::saveable::Saveable;
use crate::util::string_utilities::StringUtilities;

/// Database implementation of [`CodeUnit`] (and [`ProcessorContext`]).
///
/// Port of `ghidra.program.database.code.CodeUnitDB`. See the module docs for what was
/// intentionally left out.
pub trait CodeUnitDb: CodeUnit + ProcessorContext + DbObject {
    /// Determines whether this code unit has been deleted. If a record has been provided, it may
    /// be used to facilitate a refresh without performing a record query from the database.
    /// `record` mirrors the Java method's `DBRecord` parameter, which may be absent when the
    /// caller expects the implementor to look its own record up as needed.
    ///
    /// Stands in for the abstract `CodeUnitDB.hasBeenDeleted(DBRecord)`.
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool;

    /// The number of bytes that should be cached for fast [`CodeUnit::get_byte`]/`get_bytes`
    /// access. Stands in for `CodeUnitDB.getPreferredCacheLength()`, whose default body is just
    /// `getLength()`; `InstructionDB` overrides this to account for an instruction length
    /// override.
    fn get_preferred_cache_length(&self) -> i32 {
        self.get_length()
    }

    /// Returns a string that represents this code unit with default markup. Only the mnemonic
    /// and operands are included. Stands in for the abstract `CodeUnitDB.toString()`.
    fn code_unit_string(&self) -> String;
}

// ===========================================================================================
// Concrete shared state: the `CodeUnitDB` abstract base class itself.
// ===========================================================================================

/// The concrete state and behaviour of the abstract Java class `CodeUnitDB`, factored out so that
/// the code-unit implementations can *compose* it rather than inherit from it.
///
/// Java's `CodeUnitDB` is an abstract class carrying both a large body of shared implementation
/// (comment caching, byte caching, property access, reference access, processor context) and three
/// hooks its subclasses override (`hasBeenDeleted`, `getPreferredCacheLength`, `toString`). Rust
/// has no implementation inheritance, so the split is made explicit:
///
/// * the *shared implementation* lives here, in `CodeUnitDbBase`, as inherent methods;
/// * the *overridable hooks* live on the [`CodeUnitDb`] trait, which each concrete code unit
///   implements;
/// * each concrete code unit (`InstructionDB`, `DataDB`, `DataComponent`) holds a
///   `CodeUnitDbBase` in a `base` field and forwards its trait methods to it.
///
/// Where a shared method calls one of the overridable hooks in Java (`populateByteArray()` calls
/// the virtual `getPreferredCacheLength()`; `validateOpIndex()` calls the virtual
/// `getNumOperands()`; `getMaxAddress()` calls the virtual `getLength()`), the Rust method takes
/// that value as an explicit parameter instead. This keeps `CodeUnitDbBase` free of any back
/// reference to its owner-of-record, so no `Weak`/`Rc` cycle is needed to model the virtual call.
///
/// # Interior mutability
///
/// Every method takes `&self`. The Java fields that mutate after construction (`address`,
/// `endAddr`, `length`, `commentRec`, `checkedComments`, `bytes`) are held behind locks/atomics.
/// This mirrors [`DbObjectState`], which already does exactly this for the `DbObject` bookkeeping
/// fields, and it is what allows a code unit to be handed out as a shared `Arc<dyn CodeUnit>`
/// while still supporting `refresh` and the cache invalidation `DbObject` requires.
pub struct CodeUnitDbBase {
    /// The manager that created this code unit. Stands in for `CodeUnitDB.codeMgr`, narrowed to
    /// the callbacks actually used -- see [`CodeUnitOwner`].
    owner: Arc<dyn CodeUnitOwner>,
    /// `DbObject` bookkeeping. Stands in for the fields of the Java `DbObject` superclass.
    state: DbObjectState,
    /// Stands in for `CodeUnitDB.address`; re-decoded from [`Self::addr`] on refresh.
    address: RwLock<Address>,
    /// Stands in for `CodeUnitDB.addr`, the address map index for [`Self::address`]. Never
    /// changes, so it needs no lock.
    addr: i64,
    /// Lazily computed `address + length - 1`. Stands in for `CodeUnitDB.endAddr`.
    end_addr: RwLock<Option<Address>>,
    /// Stands in for `CodeUnitDB.length`. Mutable because `DataDB.refresh` recomputes it for
    /// dynamically-sized data types.
    length: AtomicI32,
    /// Cached comment record. Stands in for `CodeUnitDB.commentRec`.
    comment_rec: RwLock<Option<DBRecord>>,
    /// Whether [`Self::comment_rec`] has been read from the database yet -- `None` is a valid
    /// cached answer, so a separate flag is needed. Stands in for `CodeUnitDB.checkedComments`.
    checked_comments: AtomicBool,
    /// Cached bytes for fast `getByte`/`getBytes`. Stands in for `CodeUnitDB.bytes`.
    bytes: RwLock<Option<Vec<u8>>>,
    /// Cached `codeMgr.getLock()`, as the Java constructor does.
    lock: Arc<ReentrantLock>,
}

impl CodeUnitDbBase {
    /// Constructs the shared state for a new code unit.
    ///
    /// Stands in for `CodeUnitDB(CodeManager codeMgr, long cacheKey, Address address, long addr,
    /// int length)`. `cache_key` is separate from `addr` because a `DataComponent`'s key is only
    /// unique within its parent, so it cannot be the address index (see the note on the Java
    /// class).
    pub fn new(
        owner: Arc<dyn CodeUnitOwner>,
        cache_key: i64,
        address: Address,
        addr: i64,
        length: i32,
    ) -> Self {
        let lock = owner.get_lock();
        CodeUnitDbBase {
            owner,
            state: DbObjectState::new(cache_key),
            address: RwLock::new(address),
            addr,
            end_addr: RwLock::new(None),
            length: AtomicI32::new(length),
            comment_rec: RwLock::new(None),
            checked_comments: AtomicBool::new(false),
            bytes: RwLock::new(None),
            lock,
        }
    }

    /// The manager that created this code unit.
    pub fn owner(&self) -> &Arc<dyn CodeUnitOwner> {
        &self.owner
    }

    /// The `DbObject` bookkeeping state, for the composing type's [`DbObject::state`] impl.
    pub fn state(&self) -> &DbObjectState {
        &self.state
    }

    /// The lock guarding code-unit access, cached from the owner at construction.
    pub fn lock(&self) -> &Arc<ReentrantLock> {
        &self.lock
    }

    /// The address map index of this code unit's minimum address. Stands in for `CodeUnitDB.addr`.
    pub fn addr(&self) -> i64 {
        self.addr
    }

    /// This code unit's minimum address. Stands in for reading the `CodeUnitDB.address` field.
    pub fn address(&self) -> Address {
        self.address.read().unwrap().clone()
    }

    /// Stands in for reading the `CodeUnitDB.length` field, which `CodeUnitDB.getLength()`
    /// returns directly.
    pub fn length(&self) -> i32 {
        self.length.load(Ordering::SeqCst)
    }

    /// Overwrites the cached length and invalidates the derived end address. Stands in for
    /// `DataDB.refresh`'s `length = codeMgr.getLength(address)` assignment.
    pub fn set_length(&self, length: i32) {
        self.length.store(length, Ordering::SeqCst);
        *self.end_addr.write().unwrap() = None;
    }

    /// Re-decodes the address and drops every cached value, returning nothing.
    ///
    /// Stands in for the body of `CodeUnitDB.refresh(DBRecord)` *up to* its
    /// `return !hasBeenDeleted(record)` -- the deletion check itself is the subclass's
    /// [`CodeUnitDb::has_been_deleted`] hook, so the composing type calls this and then its own
    /// check, exactly as the Java method does.
    pub fn refresh_base(&self) {
        *self.address.write().unwrap() = self.owner.get_address_map().decode_address(self.addr);
        *self.end_addr.write().unwrap() = None;
        *self.comment_rec.write().unwrap() = None;
        self.checked_comments.store(false, Ordering::SeqCst);
        *self.bytes.write().unwrap() = None;
    }

    // -- CodeUnit: addresses ----------------------------------------------------------------

    /// Stands in for `CodeUnitDB.contains(Address)`. `length` is the caller's (possibly
    /// overridden) `getLength()`.
    pub fn contains(&self, test_addr: &Address, length: i32) -> bool {
        let address = self.address();
        address <= *test_addr && *test_addr <= self.get_max_address(length)
    }

    /// Stands in for `CodeUnitDB.compareTo(Address)`.
    pub fn compare_to(&self, addr: &Address, length: i32) -> i32 {
        if self.contains(addr, length) {
            return 0;
        }
        match self.address().cmp(addr) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }

    /// Stands in for `CodeUnitDB.getMaxAddress()`, including its `endAddr` memoization.
    pub fn get_max_address(&self, length: i32) -> Address {
        if let Some(end) = self.end_addr.read().unwrap().as_ref() {
            return end.clone();
        }
        let address = self.address();
        let end = if length == 0 {
            address
        } else {
            address
                .add(i64::from(length - 1))
                .unwrap_or_else(|_| self.address())
        };
        *self.end_addr.write().unwrap() = Some(end.clone());
        end
    }

    /// Stands in for `CodeUnitDB.getAddressString(boolean, boolean)`.
    pub fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        let cu_address = self.address();
        // Java: `cuAddress.toString(false, pad)`. `Address::format` clamps `min_num_digits` to
        // the address space's own digit count, so an oversized request means "pad fully".
        let address_string = cu_address.format(false, if pad { 64 } else { 1 });
        if show_block_name {
            if let Some(memory) = self.owner.get_memory() {
                if let Some(block) = memory.get_block(&cu_address) {
                    return format!("{}:{}", block.get_name(), address_string);
                }
            }
        }
        address_string
    }

    // -- CodeUnit: comments -----------------------------------------------------------------

    /// Reads the comment record from the database if it has not been read yet. Stands in for the
    /// private `CodeUnitDB.readComments()`.
    fn read_comments(&self) {
        match self.owner.get_comment_record(self.addr) {
            Ok(record) => {
                *self.comment_rec.write().unwrap() = record;
                self.checked_comments.store(true, Ordering::SeqCst);
            }
            Err(e) => self.owner.db_error(e),
        }
    }

    /// The cached comment record, if this code unit has one. Stands in for the package-private
    /// `CodeUnitDB.getCommentRecord()`.
    pub fn get_comment_record(&self) -> Option<DBRecord> {
        self.comment_rec.read().unwrap().clone()
    }

    /// Stands in for `CodeUnitDB.getComment(CommentType)`.
    pub fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        let _guard = self.lock.read();
        if !self.checked_comments.load(Ordering::SeqCst) {
            self.read_comments();
        }
        let comment_rec = self.comment_rec.read().unwrap();
        comment_rec
            .as_ref()?
            .get_string(comment_type.ordinal() as usize)
            .map(str::to_owned)
    }

    /// Stands in for `CodeUnitDB.getCommentAsArray(CommentType)`.
    pub fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        match self.get_comment(comment_type) {
            Some(comment) => comment.to_lines_default(),
            None => Vec::new(),
        }
    }

    /// Stands in for `CodeUnitDB.setComment(CommentType, String)`, including its
    /// "delete the record once every column is empty" behaviour.
    pub fn set_comment(&self, comment_type: CommentType, comment: Option<String>) {
        let _guard = self.lock.write();
        if !self.checked_comments.load(Ordering::SeqCst) {
            self.read_comments();
        }

        let column = comment_type.ordinal() as usize;
        let existing = self.comment_rec.read().unwrap().clone();

        let Some(mut record) = existing else {
            // No record yet: nothing to do unless a comment is actually being set.
            let Some(comment) = comment else {
                return;
            };
            match self
                .owner
                .create_comment_record(self.addr, comment_type.ordinal(), &comment)
            {
                Ok(record) => *self.comment_rec.write().unwrap() = Some(record),
                Err(e) => self.owner.db_error(e),
            }
            self.owner
                .send_comment_notification(&self.address(), comment_type, None, Some(&comment));
            return;
        };

        let old_value = record.get_string(column).map(str::to_owned);
        record.set_string(column, comment.clone());
        self.owner.send_comment_notification(
            &self.address(),
            comment_type,
            old_value.as_deref(),
            comment.as_deref(),
        );

        let still_has_a_comment =
            (0..COMMENT_COL_COUNT).any(|i| record.get_string(i).is_some());
        let key = record.get_key().get_long_value();
        *self.comment_rec.write().unwrap() = Some(record);

        if still_has_a_comment {
            self.update_comment_record();
            return;
        }
        if let Err(e) = self.owner.delete_comment_record(key) {
            self.owner.db_error(e);
        }
    }

    /// Stands in for `CodeUnitDB.setCommentAsArray(CommentType, String[])`.
    pub fn set_comment_as_array(&self, comment_type: CommentType, comment: &[String]) {
        self.set_comment(comment_type, Some(comment.join("\n")));
    }

    /// Writes the cached comment record back to the database. Stands in for the private
    /// `CodeUnitDB.updateCommentRecord()`.
    fn update_comment_record(&self) {
        let record = self.comment_rec.read().unwrap().clone();
        if let Some(record) = record {
            if let Err(e) = self.owner.update_comment_record(&record) {
                self.owner.db_error(e);
            }
        }
    }

    // -- CodeUnit: symbols ------------------------------------------------------------------

    /// Stands in for `CodeUnitDB.getLabel()`.
    pub fn get_label(&self) -> Option<String> {
        let address = self.address();
        self.owner
            .get_symbol_table()
            .get_primary_symbol(&address)
            .ok()
            .flatten()
            .map(|symbol| symbol.get_name().to_owned())
    }

    /// Stands in for `CodeUnitDB.getPrimarySymbol()`.
    pub fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        let address = self.address();
        self.owner
            .get_symbol_table()
            .get_primary_symbol(&address)
            .ok()
            .flatten()
    }

    /// Stands in for `CodeUnitDB.getSymbols()`.
    pub fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        let address = self.address();
        self.owner
            .get_symbol_table()
            .get_symbols(&address)
            .unwrap_or_default()
    }

    // -- CodeUnit: references ---------------------------------------------------------------

    /// Stands in for `CodeUnitDB.getReferencesFrom()`.
    pub fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .get_references_from(address)
    }

    /// Stands in for `CodeUnitDB.getMnemonicReferences()`.
    pub fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        self.get_operand_references(MNEMONIC)
    }

    /// Stands in for `CodeUnitDB.getOperandReferences(int)`.
    pub fn get_operand_references(&self, op_index: i32) -> Vec<Arc<dyn Reference>> {
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .get_references_from_operand(address, op_index)
    }

    /// Stands in for `CodeUnitDB.getPrimaryReference(int)`.
    pub fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn Reference>> {
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .get_primary_reference_from(address, index)
    }

    /// Stands in for `CodeUnitDB.getReferenceIteratorTo()`.
    pub fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .get_references_to(address)
    }

    /// Stands in for `CodeUnitDB.getExternalReference(int)`.
    pub fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        self.get_operand_references(op_index)
            .into_iter()
            .find(|r| r.is_external_reference())
            .and_then(|r| r.to_external_reference())
    }

    /// Stands in for `CodeUnitDB.removeExternalReference(int)`.
    pub fn remove_external_reference(&self, op_index: i32) {
        let address = self.address();
        let ref_mgr = self.owner.get_reference_manager();
        let mut ref_mgr = ref_mgr.lock().unwrap();
        if let Some(reference) = ref_mgr
            .get_references_from_operand(address, op_index)
            .into_iter()
            .find(|r| r.is_external_reference())
        {
            ref_mgr.delete(reference);
        }
    }

    /// Stands in for `CodeUnitDB.removeMnemonicReference(Address)`.
    pub fn remove_mnemonic_reference(&self, ref_addr: &Address) {
        self.remove_operand_reference(MNEMONIC, ref_addr);
    }

    /// Stands in for `CodeUnitDB.removeOperandReference(int, Address)`.
    pub fn remove_operand_reference(&self, op_index: i32, ref_addr: &Address) {
        let address = self.address();
        let ref_mgr = self.owner.get_reference_manager();
        let mut ref_mgr = ref_mgr.lock().unwrap();
        if let Some(reference) = ref_mgr.get_reference(address, ref_addr.clone(), op_index) {
            ref_mgr.delete(reference);
        }
    }

    /// Stands in for `CodeUnitDB.setPrimaryMemoryReference(Reference)`.
    pub fn set_primary_memory_reference(&self, reference: Arc<dyn Reference>) {
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .set_primary(reference, true);
    }

    /// Stands in for `CodeUnitDB.addMnemonicReference(Address, RefType, SourceType)`.
    pub fn add_mnemonic_reference(
        &self,
        ref_addr: &Address,
        ref_type: RefType,
        source_type: SourceType,
    ) {
        self.add_operand_reference(MNEMONIC, ref_addr, ref_type, source_type);
    }

    /// Stands in for `CodeUnitDB.addOperandReference(int, Address, RefType, SourceType)`.
    pub fn add_operand_reference(
        &self,
        op_index: i32,
        ref_addr: &Address,
        ref_type: RefType,
        source_type: SourceType,
    ) {
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .add_memory_reference(address, ref_addr.clone(), ref_type, source_type, op_index);
    }

    /// Stands in for `CodeUnitDB.setStackReference(int, int, SourceType, RefType)`, including its
    /// `validateOpIndex` precondition. `num_operands` is the caller's (overridden)
    /// `getNumOperands()`.
    ///
    /// # Panics
    /// Panics if `op_index >= num_operands`, mirroring the Java method's
    /// `IllegalArgumentException`.
    pub fn set_stack_reference(
        &self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: RefType,
        num_operands: i32,
    ) {
        validate_op_index(op_index, num_operands);
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .add_stack_reference(address, op_index, offset, ref_type, source_type);
    }

    /// Stands in for `CodeUnitDB.setRegisterReference(int, Register, SourceType, RefType)`.
    ///
    /// # Panics
    /// Panics if `op_index >= num_operands`, mirroring the Java method's
    /// `IllegalArgumentException`.
    pub fn set_register_reference(
        &self,
        op_index: i32,
        register: RegisterRef,
        source_type: SourceType,
        ref_type: RefType,
        num_operands: i32,
    ) {
        validate_op_index(op_index, num_operands);
        let address = self.address();
        self.owner
            .get_reference_manager()
            .lock()
            .unwrap()
            .add_register_reference(address, op_index, &register, ref_type, source_type);
    }

    // -- PropertySet ------------------------------------------------------------------------

    /// Stands in for `CodeUnitDB.getIntProperty(String)`.
    pub fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        let manager = self.owner.get_property_map_manager();
        let manager = manager.lock().unwrap();
        let address = self.address();
        manager
            .get_int_property_map(name)
            .and_then(|pm| pm.get_int(&address).ok())
            .ok_or_else(|| {
                NoValueException::with_message(format!("no int property named '{name}'"))
            })
    }

    /// Stands in for `CodeUnitDB.getStringProperty(String)`.
    pub fn get_string_property(&self, name: &str) -> Option<String> {
        let manager = self.owner.get_property_map_manager();
        let manager = manager.lock().unwrap();
        let address = self.address();
        manager
            .get_string_property_map(name)
            .and_then(|pm| pm.get_string(&address).ok())
    }

    /// Stands in for `CodeUnitDB.getObjectProperty(String)`.
    pub fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        let manager = self.owner.get_property_map_manager();
        let manager = manager.lock().unwrap();
        let address = self.address();
        manager
            .get_object_property_map(name)
            .and_then(|pm| pm.get_object(&address).ok())
    }

    /// Stands in for `CodeUnitDB.getVoidProperty(String)`.
    pub fn get_void_property(&self, name: &str) -> bool {
        let manager = self.owner.get_property_map_manager();
        let manager = manager.lock().unwrap();
        let address = self.address();
        manager
            .get_void_property_map(name)
            .is_some_and(|pm| pm.has_property(&address))
    }

    /// Stands in for `CodeUnitDB.hasProperty(String)`, which -- unlike the typed getters above --
    /// works for any property map type.
    pub fn has_property(&self, name: &str) -> bool {
        let manager = self.owner.get_property_map_manager();
        let manager = manager.lock().unwrap();
        let address = self.address();
        manager
            .get_property_map(name)
            .is_some_and(|pm| pm.has_property(&address))
    }

    /// Stands in for `CodeUnitDB.propertyNames()`.
    pub fn property_names(&self) -> Vec<String> {
        let manager = self.owner.get_property_map_manager();
        let manager = manager.lock().unwrap();
        manager.property_managers().collect()
    }

    /// Stands in for `CodeUnitDB.removeProperty(String)`.
    pub fn remove_property(&self, name: &str) {
        let manager = self.owner.get_property_map_manager();
        let mut manager = manager.lock().unwrap();
        let address = self.address();
        if let Some(mut pm) = manager.get_property_map(name) {
            pm.remove(&address);
        }
        let _ = &mut manager;
    }

    /// Stands in for `CodeUnitDB.setProperty(String, int)`, creating the map if it is absent.
    pub fn set_int_property(&self, name: &str, value: i32) {
        let manager = self.owner.get_property_map_manager();
        let mut manager = manager.lock().unwrap();
        let address = self.address();
        let mut pm = match manager.get_int_property_map(name) {
            Some(pm) => pm,
            None => match manager.create_int_property_map(name) {
                Ok(pm) => pm,
                Err(_) => return,
            },
        };
        pm.add_int(&address, value);
    }

    /// Stands in for `CodeUnitDB.setProperty(String, String)`, creating the map if it is absent.
    pub fn set_string_property(&self, name: &str, value: &str) {
        let manager = self.owner.get_property_map_manager();
        let mut manager = manager.lock().unwrap();
        let address = self.address();
        let mut pm = match manager.get_string_property_map(name) {
            Some(pm) => pm,
            None => match manager.create_string_property_map(name) {
                Ok(pm) => pm,
                Err(_) => return,
            },
        };
        pm.add_string(&address, value.to_owned());
    }

    /// Stands in for `CodeUnitDB.setProperty(String)` (the void-property overload), creating the
    /// map if it is absent.
    pub fn set_void_property(&self, name: &str) {
        let manager = self.owner.get_property_map_manager();
        let mut manager = manager.lock().unwrap();
        let address = self.address();
        let mut pm = match manager.get_void_property_map(name) {
            Some(pm) => pm,
            None => match manager.create_void_property_map(name) {
                Ok(pm) => pm,
                Err(_) => return,
            },
        };
        pm.add_void(&address);
    }

    // -- MemBuffer / byte access ------------------------------------------------------------

    /// Fills (and returns) the byte cache. Stands in for the private
    /// `CodeUnitDB.populateByteArray()`; `preferred_cache_length` is the caller's (overridden)
    /// `getPreferredCacheLength()`.
    fn populate_byte_array(&self, preferred_cache_length: i32) -> Vec<u8> {
        if let Some(cached) = self.bytes.read().unwrap().as_ref() {
            return cached.clone();
        }
        let cache_length = preferred_cache_length.max(0) as usize;
        let mut local_bytes = vec![0u8; cache_length];
        if cache_length != 0 {
            let address = self.address();
            let n = self
                .owner
                .get_memory()
                .map_or(0, |memory| memory.get_bytes(&address, &mut local_bytes));
            if n != local_bytes.len() {
                local_bytes = Vec::new();
            }
        }
        *self.bytes.write().unwrap() = Some(local_bytes.clone());
        local_bytes
    }

    /// Stands in for `CodeUnitDB.getByte(int)`.
    pub fn get_byte(
        &self,
        offset: i32,
        preferred_cache_length: i32,
    ) -> Result<u8, MemoryAccessException> {
        let local_bytes = self.populate_byte_array(preferred_cache_length);
        if offset >= 0 && (offset as usize) < local_bytes.len() {
            return Ok(local_bytes[offset as usize]);
        }
        let address = self
            .address()
            .add(i64::from(offset))
            .map_err(|e| MemoryAccessException::new(e.to_string()))?;
        self.owner
            .get_memory()
            .ok_or_else(|| MemoryAccessException::new("no memory"))?
            .get_byte(&address)
    }

    /// Stands in for `CodeUnitDB.getBytes(byte[], int)`, returning the number of bytes copied.
    pub fn get_bytes_at(&self, buf: &mut [u8], offset: i32, preferred_cache_length: i32) -> usize {
        let local_bytes = self.populate_byte_array(preferred_cache_length);
        if offset >= 0 && (offset as usize).saturating_add(buf.len()) <= local_bytes.len() {
            let start = offset as usize;
            buf.copy_from_slice(&local_bytes[start..start + buf.len()]);
            return buf.len();
        }
        let Ok(address) = self.address().add(i64::from(offset)) else {
            return 0;
        };
        self.owner
            .get_memory()
            .map_or(0, |memory| memory.get_bytes(&address, buf))
    }

    /// Stands in for `CodeUnitDB.getBytes()`; `length` is the caller's (overridden)
    /// `getLength()`.
    pub fn get_bytes(
        &self,
        length: i32,
        preferred_cache_length: i32,
    ) -> Result<Vec<u8>, MemoryAccessException> {
        let local_bytes = self.populate_byte_array(preferred_cache_length);
        let len = length.max(0) as usize;
        if local_bytes.len() >= len {
            return Ok(local_bytes[..len].to_vec());
        }
        let mut buf = vec![0u8; len];
        let address = self.address();
        let n = self
            .owner
            .get_memory()
            .map_or(0, |memory| memory.get_bytes(&address, &mut buf));
        if n != len {
            return Err(MemoryAccessException::new(
                "Couldn't get all bytes for CodeUnit",
            ));
        }
        Ok(buf)
    }

    /// Stands in for `CodeUnitDB.getBytesInCodeUnit(byte[], int)`.
    pub fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
        length: i32,
        preferred_cache_length: i32,
    ) -> Result<(), MemoryAccessException> {
        let code_unit_bytes = self.get_bytes(length, preferred_cache_length)?;
        let start = buffer_offset.max(0) as usize;
        let n = buffer
            .len()
            .min(length.max(0) as usize)
            .min(code_unit_bytes.len())
            .min(buffer.len().saturating_sub(start));
        buffer[start..start + n].copy_from_slice(&code_unit_bytes[..n]);
        Ok(())
    }

    /// Stands in for `CodeUnitDB.isBigEndian()`.
    pub fn is_big_endian(&self) -> bool {
        self.owner
            .get_memory()
            .is_some_and(|memory| memory.is_big_endian())
    }

    /// Stands in for `CodeUnitDB.getMemory()`.
    pub fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.owner.get_memory()
    }

    /// Stands in for `CodeUnitDB.getProgram()`.
    pub fn get_program(&self) -> Arc<dyn Program> {
        self.owner.get_program()
    }

    // -- ProcessorContext -------------------------------------------------------------------

    /// Stands in for `CodeUnitDB.getValue(Register, boolean)`.
    pub fn get_register_bigint_value(&self, register: &Register, signed: bool) -> Option<i128> {
        let address = self.address();
        self.owner
            .get_program_context()
            .lock()
            .unwrap()
            .get_value(register, &address, signed)
    }

    /// Stands in for `CodeUnitDB.hasValue(Register)`.
    pub fn has_value(&self, register: &Register) -> bool {
        self.get_register_bigint_value(register, false).is_some()
    }

    /// Stands in for `CodeUnitDB.getRegisterValue(Register)`.
    pub fn get_register_value(&self, register: &Register) -> Option<RegisterValue> {
        let address = self.address();
        self.owner
            .get_program_context()
            .lock()
            .unwrap()
            .get_register_value(register, &address)
    }

    /// Stands in for `CodeUnitDB.setValue(Register, BigInteger)`.
    pub fn set_register_bigint_value(
        &self,
        register: &Register,
        value: i128,
    ) -> Result<(), ContextChangeException> {
        let address = self.address();
        self.owner
            .get_program_context()
            .lock()
            .unwrap()
            .set_value(register, &address, &address, Some(value))
    }

    /// Stands in for `CodeUnitDB.clearRegister(Register)`, which is `setValue(reg, addr, addr,
    /// null)`.
    pub fn clear_register(&self, register: &Register) -> Result<(), ContextChangeException> {
        let address = self.address();
        self.owner
            .get_program_context()
            .lock()
            .unwrap()
            .set_value(register, &address, &address, None)
    }

    /// Stands in for `CodeUnitDB.setRegisterValue(RegisterValue)`.
    pub fn set_register_value(
        &self,
        value: RegisterValue,
    ) -> Result<(), ContextChangeException> {
        let address = self.address();
        self.owner
            .get_program_context()
            .lock()
            .unwrap()
            .set_register_value(&address, &address, value)
    }

    /// Stands in for `CodeUnitDB.getRegister(String)`.
    pub fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.owner.get_program_context().lock().unwrap().get_register(name)
    }

    /// Stands in for `CodeUnitDB.getBaseContextRegister()`.
    pub fn get_base_context_register(&self) -> RegisterRef {
        self.owner
            .get_program_context()
            .lock()
            .unwrap()
            .get_base_context_register()
    }

    /// Stands in for `CodeUnitDB.getRegisters()`.
    pub fn get_registers(&self) -> Vec<RegisterRef> {
        self.owner.get_program_context().lock().unwrap().get_registers()
    }

    /// Stands in for `CodeUnitDB.equals(Object)`'s field comparison: two code units are equal when
    /// they share an address index *and* the same owning manager. The concrete-type check that
    /// Java performs with `getClass() != obj.getClass()` is the caller's responsibility, since in
    /// Rust it is the implementing type's `PartialEq` that decides which types may be compared.
    pub fn same_code_unit(&self, other: &CodeUnitDbBase) -> bool {
        self.addr == other.addr && Arc::ptr_eq(&self.owner, &other.owner)
    }
}

/// Mirrors `CodeUnitDB.validateOpIndex(int)`.
///
/// # Panics
/// Panics if `op_index >= num_operands`, mirroring Java's `IllegalArgumentException`.
fn validate_op_index(op_index: i32, num_operands: i32) {
    assert!(
        op_index < num_operands,
        "Invalid operand index [{op_index}] specified"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::db_object::DbObjectState;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::processor_context_view::ProcessorContextView;
    use crate::program::model::lang::register::{Register, RegisterRef};
    use crate::program::model::listing::context_change_exception::ContextChangeException;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
    use std::sync::Arc;

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn mock_register() -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 1);
        Register::new(
            "context",
            "Processor context register",
            Address::new(space, 0),
            4,
            false,
            0,
        )
    }

    /// A minimal object-safe `CodeUnitDb`: a fixed-length, unnamed code unit with a length-based
    /// preferred cache length override and a record-presence-based deletion check, mirroring (in
    /// miniature) how `InstructionDB` overrides `getPreferredCacheLength` and how any `CodeUnitDB`
    /// subclass implements `hasBeenDeleted`.
    struct MockCodeUnitDb {
        state: DbObjectState,
        min_address: Address,
        length: i32,
        cache_length_override: Option<i32>,
        present: bool,
    }

    impl MemBuffer for MockCodeUnitDb {
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockCodeUnitDb {}

    impl DbObject for MockCodeUnitDb {
        fn state(&self) -> &DbObjectState {
            &self.state
        }

        fn refresh(&self, _record: Option<&DBRecord>) -> bool {
            self.present
        }
    }

    impl CodeUnit for MockCodeUnitDb {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }
        fn get_mnemonic_string(&self) -> String {
            "??".to_string()
        }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            self.length
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0; self.length as usize])
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }
        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl crate::program::model::listing::Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock.bin".to_string()
                }
                fn get_language_id(&self) -> String {
                    "test:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl ProcessorContextView for MockCodeUnitDb {
        fn get_base_context_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> {
            None
        }
        fn get_register_value(&self, _register: &Register) -> Option<RegisterValue> {
            None
        }
        fn has_value(&self, _register: &Register) -> bool {
            false
        }
    }

    impl ProcessorContext for MockCodeUnitDb {
        fn set_value(
            &mut self,
            _register: &Register,
            _value: i128,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn set_register_value(
            &mut self,
            _value: RegisterValue,
        ) -> Result<(), ContextChangeException> {
            Ok(())
        }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> {
            Ok(())
        }
    }

    impl CodeUnitDb for MockCodeUnitDb {
        fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
            record.is_none() && !self.present
        }

        fn get_preferred_cache_length(&self) -> i32 {
            self.cache_length_override.unwrap_or_else(|| self.get_length())
        }

        fn code_unit_string(&self) -> String {
            self.get_mnemonic_string()
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let plain = MockCodeUnitDb {
            state: DbObjectState::new(1),
            min_address: mock_address(0x100),
            length: 4,
            cache_length_override: None,
            present: true,
        };
        let dyn_plain: &dyn CodeUnitDb = &plain;
        assert_eq!(dyn_plain.get_preferred_cache_length(), 4);
        assert!(!dyn_plain.has_been_deleted(None));
        assert_eq!(dyn_plain.code_unit_string(), "??");

        // Mirrors InstructionDB overriding getPreferredCacheLength() to diverge from getLength().
        let overridden = MockCodeUnitDb {
            state: DbObjectState::new(2),
            min_address: mock_address(0x200),
            length: 4,
            cache_length_override: Some(1),
            present: false,
        };
        let dyn_overridden: &dyn CodeUnitDb = &overridden;
        assert_eq!(dyn_overridden.get_preferred_cache_length(), 1);
        assert_ne!(dyn_overridden.get_preferred_cache_length(), dyn_overridden.get_length());
        assert!(dyn_overridden.has_been_deleted(None));
        assert!(dyn_overridden.refresh(None) == false);

        assert!(mock_register().name() == "context");
    }

    // =======================================================================================
    // `CodeUnitDbBase` -- the shared implementation of the Java abstract class.
    //
    // These exercise the real thing against the in-memory owner in
    // [`test_support`](crate::program::database::code::test_support): real bytes, real comment
    // records, real property maps.
    // =======================================================================================

    use crate::program::database::code::comments_db_adapter::{
        EOL_COMMENT_COL, PLATE_COMMENT_COL, PRE_COMMENT_COL,
    };
    use crate::program::database::code::test_support::{CommentNotification, TestCodeUnitOwner};

    /// The eight bytes every byte-access test below reads from, laid down at 0x1000.
    const MEM: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    /// Builds an owner plus the `Arc<dyn CodeUnitOwner>` handed to each code unit. Both point at
    /// the same allocation, so code units built from the returned `dyn` handle compare equal
    /// under [`CodeUnitDbBase::same_code_unit`].
    fn test_owner() -> (Arc<TestCodeUnitOwner>, Arc<dyn CodeUnitOwner>) {
        let owner = Arc::new(TestCodeUnitOwner::new(
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
            0x1000,
            MEM.to_vec(),
        ));
        let dynamic: Arc<dyn CodeUnitOwner> = owner.clone();
        (owner, dynamic)
    }

    /// A `CodeUnitDbBase` at `offset` whose cache key and address index are both `offset`, the
    /// arrangement `InstructionDB`/`DataDB` use (only `DataComponent` differs).
    fn cu(owner: &Arc<dyn CodeUnitOwner>, offset: i64, length: i32) -> CodeUnitDbBase {
        CodeUnitDbBase::new(
            owner.clone(),
            offset,
            mock_address(offset),
            offset,
            length,
        )
    }

    #[test]
    fn get_max_address_spans_the_length_and_is_memoized() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        assert_eq!(base.get_max_address(4), mock_address(0x1003));

        // Java caches into `endAddr` and never recomputes until something clears it, so a
        // subsequent call with a *different* length still reports the memoized answer.
        assert_eq!(base.get_max_address(8), mock_address(0x1003));

        // `set_length` is the one thing that invalidates it (DataDB.refresh's resize).
        base.set_length(8);
        assert_eq!(base.get_max_address(8), mock_address(0x1007));
    }

    #[test]
    fn get_max_address_of_zero_length_code_unit_is_its_own_address() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 0);
        // Java: `endAddr = getLength() == 0 ? address : address.add(getLength() - 1)`.
        assert_eq!(base.get_max_address(0), mock_address(0x1000));
    }

    #[test]
    fn contains_and_compare_to_at_the_boundaries() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        assert!(!base.contains(&mock_address(0x0fff), 4));
        assert!(base.contains(&mock_address(0x1000), 4));
        assert!(base.contains(&mock_address(0x1003), 4));
        assert!(!base.contains(&mock_address(0x1004), 4));

        // compareTo returns 0 for anything contained, and otherwise compares min addresses.
        assert_eq!(base.compare_to(&mock_address(0x0fff), 4), 1);
        assert_eq!(base.compare_to(&mock_address(0x1000), 4), 0);
        assert_eq!(base.compare_to(&mock_address(0x1003), 4), 0);
        assert_eq!(base.compare_to(&mock_address(0x1004), 4), -1);
    }

    #[test]
    fn get_byte_reads_the_cache_then_falls_through_to_memory() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        // Inside the 4-byte cache window.
        assert_eq!(base.get_byte(0, 4).unwrap(), 0x11);
        assert_eq!(base.get_byte(3, 4).unwrap(), 0x44);
        // Outside it: read straight from memory at address + offset.
        assert_eq!(base.get_byte(5, 4).unwrap(), 0x66);
        // Past the end of memory entirely.
        assert!(base.get_byte(100, 4).is_err());

        // Changing memory behind the cache proves the first read really was cached and the
        // out-of-window read really was not.
        owner.memory().poke(0, 0xee);
        owner.memory().poke(5, 0xee);
        assert_eq!(base.get_byte(0, 4).unwrap(), 0x11);
        assert_eq!(base.get_byte(5, 4).unwrap(), 0xee);
    }

    #[test]
    fn get_bytes_uses_the_cache_window_then_falls_through_to_memory() {
        let (owner, dynamic) = test_owner();
        // A preferred cache length smaller than the code unit's length, as DataComponent has.
        let base = cu(&dynamic, 0x1000, 4);

        // Cache holds 2 bytes, and a 2-byte request is served from it.
        assert_eq!(base.get_bytes(2, 2).unwrap(), vec![0x11, 0x22]);
        owner.memory().poke(0, 0xee);
        assert_eq!(base.get_bytes(2, 2).unwrap(), vec![0x11, 0x22]);

        // A 4-byte request cannot be served from the 2-byte cache, so it re-reads memory --
        // and therefore sees the poked byte.
        assert_eq!(
            base.get_bytes(4, 2).unwrap(),
            vec![0xee, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn get_bytes_errors_when_memory_comes_up_short() {
        let (_owner, dynamic) = test_owner();
        // Only two bytes (0x1006, 0x1007) exist, but the code unit claims four.
        let base = cu(&dynamic, 0x1006, 4);

        let error = base.get_bytes(4, 4).unwrap_err();
        assert!(
            error.to_string().contains("Couldn't get all bytes"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn populate_byte_array_caches_an_empty_array_after_a_short_read() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1006, 4);

        // Fills (and therefore caches) the byte array; the underlying read returns 2 of 4 bytes.
        assert!(base.get_bytes(4, 4).is_err());

        // Java replaces the partially-filled array with `new byte[0]`, so nothing is cached and
        // every later access goes back to memory. Poking memory makes the difference visible: a
        // partially-filled cache would have answered with the stale 0x77.
        owner.memory().poke(6, 0xee);
        assert_eq!(base.get_byte(0, 4).unwrap(), 0xee);
    }

    #[test]
    fn get_bytes_at_copies_from_the_cache_window_or_from_memory() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        // offset + buf.len() fits inside the 4-byte cache.
        let mut buf = [0u8; 2];
        assert_eq!(base.get_bytes_at(&mut buf, 1, 4), 2);
        assert_eq!(buf, [0x22, 0x33]);

        owner.memory().poke(1, 0xee);
        let mut cached = [0u8; 2];
        assert_eq!(base.get_bytes_at(&mut cached, 1, 4), 2);
        assert_eq!(cached, [0x22, 0x33], "should still be served from the cache");

        // offset + buf.len() runs past the cache, so this reads memory at address + offset.
        let mut spilled = [0u8; 4];
        assert_eq!(base.get_bytes_at(&mut spilled, 2, 4), 4);
        assert_eq!(spilled, [0x33, 0x44, 0x55, 0x66]);

        // A memory read that comes up short reports how much it actually copied.
        let mut short = [0u8; 4];
        assert_eq!(base.get_bytes_at(&mut short, 6, 4), 2);
        assert_eq!(short, [0x77, 0x88, 0x00, 0x00]);
    }

    #[test]
    fn get_bytes_in_code_unit_copies_at_the_buffer_offset() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        let mut buffer = [0u8; 8];
        base.get_bytes_in_code_unit(&mut buffer, 2, 4, 4).unwrap();
        assert_eq!(buffer, [0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00]);

        // It propagates getBytes()'s short-read failure.
        let short_base = cu(&dynamic, 0x1006, 4);
        let mut buffer = [0u8; 8];
        assert!(short_base
            .get_bytes_in_code_unit(&mut buffer, 0, 4, 4)
            .is_err());
    }

    #[test]
    fn comments_round_trip_through_the_owner() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        assert_eq!(base.get_comment(CommentType::Eol), None);
        assert!(base.get_comment_as_array(CommentType::Eol).is_empty());

        // Clearing a comment when no record exists is a no-op: no record, no notification.
        base.set_comment(CommentType::Eol, None);
        assert_eq!(owner.comment_record_count(), 0);
        assert!(owner.comment_notifications().is_empty());

        base.set_comment(CommentType::Eol, Some("end of line".to_string()));
        assert_eq!(
            base.get_comment(CommentType::Eol).as_deref(),
            Some("end of line")
        );
        assert_eq!(owner.comment_record_count(), 1);

        // A second comment type shares the one record keyed by this address.
        base.set_comment(CommentType::Plate, Some("line one\nline two".to_string()));
        assert_eq!(owner.comment_record_count(), 1);
        assert_eq!(
            base.get_comment_as_array(CommentType::Plate),
            vec!["line one".to_string(), "line two".to_string()]
        );
        assert_eq!(
            base.get_comment(CommentType::Eol).as_deref(),
            Some("end of line"),
            "writing one column must not disturb another"
        );

        // setCommentAsArray joins with '\n'.
        base.set_comment_as_array(CommentType::Pre, &["a".to_string(), "b".to_string()]);
        assert_eq!(base.get_comment(CommentType::Pre).as_deref(), Some("a\nb"));

        let record = owner.comment_record_directly(0x1000).unwrap();
        assert_eq!(record.get_string(EOL_COMMENT_COL), Some("end of line"));
        assert_eq!(record.get_string(PLATE_COMMENT_COL), Some("line one\nline two"));
        assert_eq!(record.get_string(PRE_COMMENT_COL), Some("a\nb"));
    }

    #[test]
    fn clearing_the_last_comment_column_deletes_the_record() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        base.set_comment(CommentType::Eol, Some("eol".to_string()));
        base.set_comment(CommentType::Plate, Some("plate".to_string()));
        assert_eq!(owner.comment_record_count(), 1);

        // With another column still populated the record is merely updated.
        base.set_comment(CommentType::Plate, None);
        assert_eq!(owner.comment_record_count(), 1);
        let record = owner.comment_record_directly(0x1000).unwrap();
        assert_eq!(record.get_string(EOL_COMMENT_COL), Some("eol"));
        assert_eq!(record.get_string(PLATE_COMMENT_COL), None);
        assert!((0..COMMENT_COL_COUNT).any(|i| record.get_string(i).is_some()));

        // Clearing the last populated column deletes it outright.
        base.set_comment(CommentType::Eol, None);
        assert_eq!(owner.comment_record_count(), 0);
        assert!(owner.comment_record_directly(0x1000).is_none());
        assert_eq!(base.get_comment(CommentType::Eol), None);
    }

    #[test]
    fn comment_notifications_carry_the_old_and_new_values() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        base.set_comment(CommentType::Eol, Some("first".to_string()));
        base.set_comment(CommentType::Eol, Some("second".to_string()));
        base.set_comment(CommentType::Eol, None);

        let notifications = owner.comment_notifications();
        assert_eq!(notifications.len(), 3);
        // Create path: `codeMgr.sendNotification(address, commentType, null, comment)`.
        assert_eq!(
            notifications[0],
            CommentNotification {
                address: owner.address(0x1000),
                comment_type: CommentType::Eol,
                old_value: None,
                new_value: Some("first".to_string()),
            }
        );
        // Update path: the old column value is reported alongside the new one.
        assert_eq!(
            notifications[1],
            CommentNotification {
                address: owner.address(0x1000),
                comment_type: CommentType::Eol,
                old_value: Some("first".to_string()),
                new_value: Some("second".to_string()),
            }
        );
        // Clear path: still an update, with a null new value.
        assert_eq!(
            notifications[2],
            CommentNotification {
                address: owner.address(0x1000),
                comment_type: CommentType::Eol,
                old_value: Some("second".to_string()),
                new_value: None,
            }
        );
    }

    #[test]
    fn properties_round_trip_and_can_be_removed() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        assert!(base.get_int_property("count").is_err());
        assert_eq!(base.get_string_property("label"), None);
        assert!(!base.get_void_property("marked"));
        assert!(!base.has_property("count"));
        assert!(base.property_names().is_empty());

        base.set_int_property("count", 42);
        base.set_string_property("label", "hello");
        base.set_void_property("marked");

        assert_eq!(base.get_int_property("count").unwrap(), 42);
        assert_eq!(base.get_string_property("label").as_deref(), Some("hello"));
        assert!(base.get_void_property("marked"));
        assert!(base.has_property("count"));
        assert!(base.has_property("label"));
        assert!(base.has_property("marked"));
        assert!(!base.has_property("absent"));
        assert_eq!(
            base.property_names(),
            vec![
                "count".to_string(),
                "label".to_string(),
                "marked".to_string()
            ]
        );

        // Overwriting goes through the same (already existing) map.
        base.set_int_property("count", 7);
        assert_eq!(base.get_int_property("count").unwrap(), 7);

        // A property at a *different* address is unaffected by this code unit's removal.
        let neighbour = cu(&dynamic, 0x1004, 4);
        neighbour.set_int_property("count", 99);

        // removeProperty clears the value at this address, not the map itself.
        base.remove_property("count");
        assert!(base.get_int_property("count").is_err());
        assert!(!base.has_property("count"));
        assert_eq!(neighbour.get_int_property("count").unwrap(), 99);
        assert!(base.property_names().contains(&"count".to_string()));
    }

    #[test]
    fn refresh_base_drops_the_comment_and_byte_caches() {
        let (owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        base.set_comment(CommentType::Eol, Some("cached".to_string()));
        assert_eq!(base.get_byte(0, 4).unwrap(), 0x11);

        // Change both backing stores behind the code unit's back.
        owner.put_comment_record_directly(0x1000, EOL_COMMENT_COL, "refreshed");
        owner.memory().poke(0, 0xee);

        assert_eq!(base.get_comment(CommentType::Eol).as_deref(), Some("cached"));
        assert_eq!(base.get_byte(0, 4).unwrap(), 0x11);

        base.refresh_base();

        assert_eq!(
            base.get_comment(CommentType::Eol).as_deref(),
            Some("refreshed")
        );
        assert_eq!(base.get_byte(0, 4).unwrap(), 0xee);
        // The address is re-decoded from the address map, and the end address recomputed.
        assert_eq!(base.address(), mock_address(0x1000));
        assert_eq!(base.get_max_address(2), mock_address(0x1001));
    }

    #[test]
    fn same_code_unit_compares_address_index_and_owner() {
        let (_owner_a, dynamic_a) = test_owner();
        let (_owner_b, dynamic_b) = test_owner();

        let a = cu(&dynamic_a, 0x1000, 4);
        let same = cu(&dynamic_a, 0x1000, 4);
        let elsewhere = cu(&dynamic_a, 0x2000, 4);
        let other_owner = cu(&dynamic_b, 0x1000, 4);

        assert!(a.same_code_unit(&same));
        assert!(!a.same_code_unit(&elsewhere));
        assert!(!a.same_code_unit(&other_owner));
    }

    #[test]
    fn get_address_string_honours_the_block_name_and_padding() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);

        assert_eq!(base.get_address_string(false, false), "1000");
        assert_eq!(base.get_address_string(false, true), "00001000");
        assert_eq!(base.get_address_string(true, false), "text:1000");
        assert_eq!(base.get_address_string(true, true), "text:00001000");
        assert!(!base.is_big_endian());

        // A memory with no block falls back to the bare address string even when asked for the
        // block name -- Java's `if (block != null)` guard.
        let blockless = Arc::new(TestCodeUnitOwner::new_big_endian_without_block(
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
            0x1000,
            MEM.to_vec(),
        ));
        let blockless_dyn: Arc<dyn CodeUnitOwner> = blockless.clone();
        let base = cu(&blockless_dyn, 0x1000, 4);
        assert_eq!(base.get_address_string(true, true), "00001000");
        assert!(base.is_big_endian());
    }

    #[test]
    #[should_panic(expected = "Invalid operand index [2] specified")]
    fn set_stack_reference_rejects_an_out_of_range_operand_index() {
        let (_owner, dynamic) = test_owner();
        let base = cu(&dynamic, 0x1000, 4);
        // Java's validateOpIndex throws IllegalArgumentException when opIndex >= getNumOperands().
        base.set_stack_reference(2, 4, SourceType::UserDefined, SymRefType::Flow, 1);
    }

    #[test]
    fn owner_records_flag_and_error_callbacks() {
        let (owner, dynamic) = test_owner();

        // `setFlags` and `dbError` are the two owner callbacks InstructionDB drives; the shared
        // test owner records them so those tests can assert on them.
        dynamic.set_flags(0x1000, 0x03);
        dynamic.set_flags(0x1004, 0x01);
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x03), (0x1004, 0x01)]);

        dynamic.db_error(std::io::Error::other("table is gone"));
        assert_eq!(owner.db_errors(), vec!["table is gone".to_string()]);
    }
}
