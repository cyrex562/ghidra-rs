//! The callback surface a concrete code unit needs from the `CodeManager` that created it.
//!
//! This trait has no single Java counterpart: it is the seam that makes concrete
//! [`CodeUnitDbBase`](super::code_unit_db::CodeUnitDbBase)-derived types portable at all.
//!
//! In Java, `CodeUnitDB` holds a `CodeManager codeMgr` field and reaches back through it for
//! everything it cannot answer from its own fields -- the address map, the comment adapter, the
//! property map manager, the symbol table, prototype lookup, neighbouring-code-unit queries, and
//! error reporting. Almost all of those are *package-private* members of `CodeManager`
//! (`getCommentAdapter()`, `getLock()`, `setFlags(...)`, `sendNotification(...)`,
//! `getInstructionRecord(...)`, ...), deliberately invisible outside `ghidra.program.database.code`.
//! The already-ported [`CodeManager`](super::code_manager::CodeManager) trait therefore -- correctly
//! -- exposes only the class's genuinely `public` API, and none of those internal callbacks.
//!
//! Rather than widen the public `CodeManager` trait with methods Java keeps package-private (which
//! would leak database internals into the crate's public surface), the internal callbacks live here
//! in their own trait. A future concrete `CodeManagerDB` implements *both*: `CodeManager` for the
//! public listing API, and `CodeUnitOwner` for the code units it hands out. Everything in
//! `program::database::code` that constructs a code unit takes an `Arc<dyn CodeUnitOwner>`, so no
//! concrete manager type is named anywhere in this package -- which is what keeps the
//! `CodeManager` <-> `CodeUnitDB` <-> `InstructionDB`/`DataDB` construction cycle cut.
//!
//! # Method grouping
//!
//! The methods below are grouped by which Java call site they stand in for, and each carries the
//! `codeMgr.xxx(...)` expression it replaces. Only callbacks that the four code-unit classes
//! actually make are present -- this is a demand-driven trait, not a mirror of `CodeManager`.
//!
//! # `&self` throughout
//!
//! Every method takes `&self`, including the mutating ones (`set_flags`, `create_comment_record`,
//! ...). This matches how the rest of the database layer already works: code units are handed out
//! as `Arc<dyn CodeUnit>`/`Arc<dyn Instruction>` and
//! [`DbObject`](crate::program::database::db_object::DbObject) already performs its `refresh`
//! bookkeeping through `&self` plus interior mutability. An implementor is expected to hold its own
//! interior mutability (as `CodeManager` does in Java, under the lock returned by [`get_lock`]).
//!
//! [`get_lock`]: CodeUnitOwner::get_lock

use std::io;
use std::sync::{Arc, Mutex};

use crate::framework::db::DBRecord;
use crate::program::database::map::address_map::AddressMap;
use crate::program::model::address::Address;
use crate::program::model::data::data_type::DataType;
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::register::RegisterRef;
use crate::program::model::lang::ProcessorContextView;
use crate::program::model::listing::instruction::Instruction;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::Memory;
use crate::program::model::symbol::{ReferenceManager, SymbolTable};
use crate::program::model::util::property_map_manager::PropertyMapManager;
use crate::util::lock::ReentrantLock;

/// The set of `CodeManager` callbacks a concrete code unit depends on.
///
/// See the module documentation for why this is separate from the public
/// [`CodeManager`](super::code_manager::CodeManager) trait.
pub trait CodeUnitOwner {
    // ---------------------------------------------------------------------------------------
    // Construction-time accessors.
    //
    // `CodeUnitDB`'s constructor caches each of these in a field:
    //   this.lock   = codeMgr.getLock();
    //   program     = (ProgramDB) codeMgr.getProgram();
    //   refMgr      = program.getReferenceManager();
    //   programContext = program.getProgramContext();
    //
    // `refMgr`/`programContext` are reached *through* the program in Java, but the ported
    // `Program` trait exposes them only via `&mut self` accessors, which an `Arc<dyn Program>`
    // cannot call. They are therefore requested from the owner directly -- the owner is the one
    // component that genuinely has mutable access to the program it belongs to.
    // ---------------------------------------------------------------------------------------

    /// The lock guarding all code-unit access. Stands in for `codeMgr.getLock()`.
    fn get_lock(&self) -> Arc<ReentrantLock>;

    /// The program these code units belong to. Stands in for `codeMgr.getProgram()`.
    fn get_program(&self) -> Arc<dyn Program>;

    /// Stands in for the constructor's `program.getReferenceManager()`.
    fn get_reference_manager(&self) -> Arc<dyn ReferenceManager>;

    /// Stands in for the constructor's `program.getProgramContext()`.
    fn get_program_context(&self) -> Arc<dyn ProgramContext>;

    /// Stands in for `program.getMemory()`, used for every byte read and for
    /// `getAddressString(showBlockName, ..)`'s block lookup.
    fn get_memory(&self) -> Option<Arc<dyn Memory>>;

    /// Stands in for `codeMgr.getSymbolTable()`, used by `getLabel`/`getPrimarySymbol`/`getSymbols`.
    fn get_symbol_table(&self) -> Arc<dyn SymbolTable>;

    /// Stands in for `codeMgr.getAddressMap()`, used by `refresh` to re-decode this code unit's
    /// address from its stored index.
    fn get_address_map(&self) -> Arc<dyn AddressMap>;

    /// Stands in for `codeMgr.getPropertyMapManager()`, the backing store for every
    /// [`PropertySet`](crate::program::model::util::PropertySet) method.
    ///
    /// Returned behind a [`Mutex`] because the ported `PropertyMapManager` trait needs `&mut self`
    /// for its `create_*`/`remove_*` methods, which the `&self` callbacks here must still be able
    /// to reach.
    fn get_property_map_manager(&self) -> Arc<Mutex<dyn PropertyMapManager>>;

    // ---------------------------------------------------------------------------------------
    // Comment storage.
    //
    // Java reaches the raw adapter (`codeMgr.getCommentAdapter().getRecord(addr)` and friends)
    // and reports failures via `codeMgr.dbError(e)`. Exposing the adapter itself here would put a
    // `CommentsDBAdapter` in the seam and make every implementor own one; instead the three
    // record operations `CodeUnitDB` actually performs are named directly, each already having
    // absorbed the `try { ... } catch (IOException e) { codeMgr.dbError(e); }` wrapper that
    // surrounds it at the Java call site.
    // ---------------------------------------------------------------------------------------

    /// Fetches this code unit's comment record, if any. Stands in for
    /// `codeMgr.getCommentAdapter().getRecord(addr)` inside `readComments()`.
    fn get_comment_record(&self, addr: i64) -> io::Result<Option<DBRecord>>;

    /// Creates a comment record holding `comment` in column `comment_col`. Stands in for
    /// `codeMgr.getCommentAdapter().createRecord(addr, commentType.ordinal(), comment)`.
    fn create_comment_record(
        &self,
        addr: i64,
        comment_col: i32,
        comment: &str,
    ) -> io::Result<DBRecord>;

    /// Writes back a modified comment record. Stands in for
    /// `codeMgr.getCommentAdapter().updateRecord(commentRec)` inside `updateCommentRecord()`.
    fn update_comment_record(&self, record: &DBRecord) -> io::Result<()>;

    /// Deletes a comment record that no longer holds any comment. Stands in for
    /// `codeMgr.getCommentAdapter().deleteRecord(commentRec.getKey())`.
    fn delete_comment_record(&self, key: i64) -> io::Result<bool>;

    /// Fires the program change notification for a comment edit. Stands in for
    /// `codeMgr.sendNotification(address, commentType, oldValue, comment)`.
    fn send_comment_notification(
        &self,
        address: &Address,
        comment_type: CommentType,
        old_value: Option<&str>,
        new_value: Option<&str>,
    );

    /// Reports a database failure. Stands in for `codeMgr.dbError(e)`, which in Java converts the
    /// `IOException` into an unchecked error via the manager's `ErrorHandler` contract.
    fn db_error(&self, error: io::Error);

    // ---------------------------------------------------------------------------------------
    // Code-unit queries used by `DataDB` and `InstructionDB` during refresh and navigation.
    // ---------------------------------------------------------------------------------------

    /// Whether the given address holds *undefined* data. Stands in for
    /// `codeMgr.isUndefined(address, addr)` in `DataDB.hasBeenDeleted`.
    fn is_undefined(&self, address: &Address, addr: i64) -> bool;

    /// Resolves the data type described by a data record. Stands in for
    /// `codeMgr.getDataType(rec)` in `DataDB.refresh`.
    fn get_data_type_for_record(&self, record: &DBRecord) -> Option<Box<dyn DataType>>;

    /// Resolves the data type defined at an address index. Stands in for
    /// `codeMgr.getDataType(addr)` in `DataDB.refresh`.
    fn get_data_type_at(&self, addr: i64) -> Option<Box<dyn DataType>>;

    /// The length of the code unit starting at `address`. Stands in for
    /// `codeMgr.getLength(address)`, used by `DataDB` to size dynamic data types.
    fn get_length_at(&self, address: &Address) -> i32;

    /// The next address at or after `address` holding a *defined* code unit. Stands in for
    /// `codeMgr.getDefinedAddressAfter(address)`, used to bound a dynamic data type's length and
    /// to validate an instruction length override.
    fn get_defined_address_after(&self, address: &Address) -> Option<Address>;

    /// Updates the flag byte stored alongside an instruction record. Stands in for
    /// `codeMgr.setFlags(addr, flags)`, used by the fall-through / flow / length overrides.
    fn set_flags(&self, addr: i64, flags: u8);

    // ---------------------------------------------------------------------------------------
    // Instruction-specific callbacks.
    // ---------------------------------------------------------------------------------------

    /// Re-reads an instruction's own record. Stands in for `codeMgr.getInstructionRecord(addr)`
    /// in `InstructionDB.refresh`.
    fn get_instruction_record(&self, addr: i64) -> Option<DBRecord>;

    /// Resolves a prototype by its stored id. Stands in for
    /// `codeMgr.getInstructionPrototype(newProtoID)`.
    fn get_instruction_prototype(&self, proto_id: i32) -> Option<Arc<dyn InstructionPrototype>>;

    /// Recovers the processor context an instruction was originally parsed under. Stands in for
    /// `codeMgr.getOriginalPrototypeContext(proto, baseContextReg)`.
    fn get_original_prototype_context(
        &self,
        prototype: &dyn InstructionPrototype,
        base_context_register: Option<RegisterRef>,
    ) -> Option<Arc<dyn ProcessorContextView>>;

    /// Stands in for `codeMgr.getInstructionAt(address)`.
    fn get_instruction_at(&self, address: &Address) -> Option<Arc<dyn Instruction>>;

    /// Stands in for `codeMgr.getInstructionAfter(address)`.
    fn get_instruction_after(&self, address: &Address) -> Option<Arc<dyn Instruction>>;

    /// Stands in for `codeMgr.getInstructionBefore(address)`.
    fn get_instruction_before(&self, address: &Address) -> Option<Arc<dyn Instruction>>;
}
