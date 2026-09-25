//! Port of `ghidra.program.database.code.InstructionDB`.
//!
//! The first concrete, database-backed [`CodeUnit`]/[`Instruction`] implementation in this crate.
//! Java's `InstructionDB extends CodeUnitDB implements Instruction, InstructionContext`; since
//! Rust has no implementation inheritance, the shared `CodeUnitDB` state and behaviour live in
//! [`CodeUnitDbBase`], which this type *composes* through its `base` field and forwards to
//! wherever Java inherits. The three `CodeUnitDB` hooks the Java class overrides
//! (`hasBeenDeleted`, `getPreferredCacheLength`, `toString`) are supplied through the
//! [`CodeUnitDb`] trait, and the calls Java makes on its package-private `codeMgr` field go
//! through the [`CodeUnitOwner`] seam.
//!
//!
//! # Known gaps
//!
//! This is a real implementation, not a stub, but a few methods are blocked on crate
//! infrastructure that does not exist yet. Each is marked with a `TODO(port):` comment at its
//! site; they are collected here so the incompleteness is visible without reading 3000 lines:
//!
//! - `get_fall_from`: needs `Listing::get_instruction_containing` plus a `SymbolTable::has_symbol`
//!   that is not ported, and the ported `Program` exposes its listing and symbol table only
//!   through `&mut self` accessors an `Arc<dyn Program>` cannot reach. Returns `None`.
//! - `do_set_flow_override`'s reference-retyping loop: `RefTypeFactory` is ported as the ref-type
//!   tables only, without `get_default_memory_ref_type`, which is the whole loop body. The flag
//!   bits and the `set_flags` callback *are* applied.
//! - `program.setChanged(...)` (3 sites): `Program` has no `set_changed` and `ProgramEvent` is
//!   not ported.
//! - `PropertySet::set_object_property`: no object-property setter exists on `ObjectPropertyMap`.
//! - `InstructionContext::get_parser_context_at` for a *foreign* address: needs a downcast to
//!   `InstructionDB` plus Java's `proto.getClass()` comparison. The same-address case works.
//! # Interior mutability, and why construction returns an `Arc`
//!
//! Every Java field that mutates after construction (`flags`, `flowOverride`, `lengthOverride`,
//! `clearingFallThroughs`, `mnemonicString`) is held behind an atomic or an `RwLock`, so all of
//! this type's real work happens through `&self` even where the ported trait method is declared
//! `&mut self` (a pre-existing crate-wide tension: instances are handed out as
//! `Arc<dyn Instruction>`).
//!
//! [`InstructionDB::new`] returns an `Arc<InstructionDB>` built with [`Arc::new_cyclic`] because
//! `getInstructionContext()` returns `this` as a *different* interface, and the ported
//! [`Instruction::get_instruction_context`] returns an `Arc<dyn InstructionContext>`. A `&self`
//! method cannot manufacture an `Arc` of itself, so the object keeps a `Weak` back-reference to
//! itself, set at construction. (`new InstructionPcodeOverride(this)` used to need it too; the
//! override now borrows its instruction. See `OWNERSHIP_MIGRATION.md`, "Instruction/CodeUnit
//! arena", for how the remaining use goes away.)

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::{Arc, RwLock, Weak};

use crate::framework::db::DBRecord;
use crate::program::database::code::code_unit_db::{CodeUnitDb, CodeUnitDbBase};
use crate::program::database::code::code_unit_owner::CodeUnitOwner;
use crate::program::database::code::inst_db_adapter::{self, FLAGS_COL, PROTO_ID_COL};
use crate::program::database::db_object::{DbObject, DbObjectState};
use crate::program::model::address::Address;
use crate::program::model::lang::instruction_context::{
    InstructionContext as LangInstructionContext, InstructionContextError,
};
use crate::program::model::lang::instruction_prototype::InstructionPrototype;
use crate::program::model::lang::operand_type::OperandType;
use crate::program::model::lang::parser_context::ParserContext as LangParserContext;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::UnknownContextException;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::instruction::{Instruction, OperandValue, MAX_LENGTH_OVERRIDE};
use crate::program::model::listing::instruction_pcode_override::InstructionPcodeOverrideImpl;
use crate::program::model::listing::instruction_record::modified_flow_type;
use crate::program::model::listing::program::Program;
use crate::program::model::listing::CommentType;
use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException};
use crate::program::model::pcode::PcodeOp;
use crate::program::model::scalar::Scalar;
use crate::program::model::symbol::{
    ExternalReference, Reference, ReferenceIterator, RefType, SourceType, Symbol,
};
use crate::program::model::util::PropertySet;
use crate::program::seam_stubs::{
    FlowOverride, InstructionContext as SeamInstructionContext,
    ParserContext as SeamParserContext, RegisterValue,
};
use crate::program::util::CodeUnitInsertionException;
use crate::util::exception::NoValueException;
use crate::util::saveable::Saveable;

/// Stands in for `InstructionDB.FALLTHROUGH_SET_MASK`.
const FALLTHROUGH_SET_MASK: u8 = 0x01;
/// Stands in for `InstructionDB.FALLTHROUGH_CLEAR_MASK`.
const FALLTHROUGH_CLEAR_MASK: u8 = !FALLTHROUGH_SET_MASK;

/// Stands in for `InstructionDB.FLOW_OVERRIDE_SET_MASK`.
const FLOW_OVERRIDE_SET_MASK: u8 = 0x0e;
/// Stands in for `InstructionDB.FLOW_OVERRIDE_CLEAR_MASK`.
const FLOW_OVERRIDE_CLEAR_MASK: u8 = !FLOW_OVERRIDE_SET_MASK;
/// Stands in for `InstructionDB.FLOW_OVERRIDE_SHIFT`.
const FLOW_OVERRIDE_SHIFT: u32 = 1;

/// Stands in for `InstructionDB.LENGTH_OVERRIDE_SET_MASK`.
const LENGTH_OVERRIDE_SET_MASK: u8 = 0x70;
/// Stands in for `InstructionDB.LENGTH_OVERRIDE_CLEAR_MASK`.
const LENGTH_OVERRIDE_CLEAR_MASK: u8 = !LENGTH_OVERRIDE_SET_MASK;
/// Stands in for `InstructionDB.LENGTH_OVERRIDE_SHIFT`.
const LENGTH_OVERRIDE_SHIFT: u32 = 4;

// ===========================================================================================
// `FlowOverride` helpers.
//
// Java's `FlowOverride` is a real enum carrying `getFlowOverride(int)`, `ordinal()` and
// `getModifiedFlowType(FlowType, FlowOverride)`. The ported `FlowOverride` in `seam_stubs` is a
// bare placeholder enum with none of those, so `InstructionDB`'s three uses of them are supplied
// here. They are faithful ports of the Java statics and belong on `FlowOverride` itself once
// that placeholder is replaced by a real port of `FlowOverride.java`.
// ===========================================================================================

/// Port of `FlowOverride.values()` order, which the persisted flag bits index into.
const FLOW_OVERRIDE_VALUES: [FlowOverride; 5] = [
    FlowOverride::None,
    FlowOverride::Branch,
    FlowOverride::Call,
    FlowOverride::CallReturn,
    FlowOverride::Return,
];

/// Port of `FlowOverride.getFlowOverride(int)`: `NONE` for an unknown ordinal.
fn flow_override_from_ordinal(ordinal: i32) -> FlowOverride {
    match usize::try_from(ordinal) {
        Ok(index) if index < FLOW_OVERRIDE_VALUES.len() => FLOW_OVERRIDE_VALUES[index],
        _ => FlowOverride::None,
    }
}

/// Port of `FlowOverride.ordinal()`.
fn flow_override_ordinal(flow_override: FlowOverride) -> u8 {
    FLOW_OVERRIDE_VALUES
        .iter()
        .position(|candidate| *candidate == flow_override)
        .unwrap_or(0) as u8
}

/// Bridges the [`SeamParserContext`] an [`InstructionPrototype`] returns onto the
/// [`LangParserContext`] the [`LangInstructionContext`] trait requires.
///
/// The crate currently carries two same-named `ParserContext` traits with identical single
/// methods -- the real port at `program::model::lang::parser_context` and an older placeholder in
/// `program::seam_stubs` -- and `InstructionPrototype::get_parser_context` is declared against the
/// placeholder while `InstructionContext::get_parser_context` is declared against the port. This
/// wrapper forwards the one method between them.
///
/// NOTE: Java documents that the returned `ParserContext` "may be cast to the prototype's
/// implementation without checking". Wrapping defeats such a cast; nothing in the ported traits
/// performs one (neither trait exposes an `Any` downcast), but it is a real divergence that
/// disappears once the duplicate placeholder trait is removed.
struct ParserContextBridge(Box<dyn SeamParserContext>);

impl LangParserContext for ParserContextBridge {
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        self.0.get_prototype()
    }

    /// Forwards the wrapped context, so the prototype's cast to its own context type works
    /// through the bridge.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        self.0.as_any()
    }
}

/// Database implementation for an [`Instruction`].
///
/// Port of `ghidra.program.database.code.InstructionDB`.
pub struct InstructionDB {
    /// The shared `CodeUnitDB` state Java inherits. See the module docs.
    base: CodeUnitDbBase,
    /// Stands in for `InstructionDB.proto`. Never reassigned: Java's `hasBeenDeleted` reports a
    /// changed prototype as a *deletion* rather than swapping it in place.
    proto: Arc<dyn InstructionPrototype>,
    /// Stands in for `InstructionDB.flags`.
    flags: AtomicU8,
    /// Stands in for `InstructionDB.flowOverride`, derived from [`Self::flags`].
    flow_override: RwLock<FlowOverride>,
    /// Stands in for `InstructionDB.lengthOverride`, derived from [`Self::flags`].
    length_override: AtomicI32,
    /// Stands in for the `volatile boolean InstructionDB.clearingFallThroughs`.
    clearing_fall_throughs: AtomicBool,
    /// Stands in for the lazily initialized `InstructionDB.mnemonicString`.
    mnemonic_string: RwLock<Option<String>>,
    /// Back-reference to this object's own `Arc`. See the module docs.
    self_ref: Weak<InstructionDB>,
}

impl InstructionDB {
    /// Construct a new `InstructionDB`.
    ///
    /// Stands in for the package-private
    /// `InstructionDB(CodeManager, Address, long, InstructionPrototype, byte)`. Returns an `Arc`
    /// so the object can hand itself back out as an `Arc<dyn Instruction>` -- see the module docs.
    ///
    /// # Arguments
    /// * `owner` - the creating code manager, narrowed to the callbacks a code unit makes
    /// * `address` - min address of this instruction
    /// * `addr` - database key (address index)
    /// * `proto` - instruction prototype
    /// * `flags` - flow override flags
    pub fn new(
        owner: Arc<dyn CodeUnitOwner>,
        address: Address,
        addr: i64,
        proto: Arc<dyn InstructionPrototype>,
        flags: u8,
    ) -> Arc<Self> {
        let instruction = Arc::new_cyclic(|weak| {
            let length = proto.get_length();
            InstructionDB {
                base: CodeUnitDbBase::new(owner, addr, address, addr, length),
                proto,
                flags: AtomicU8::new(flags),
                flow_override: RwLock::new(flow_override_from_ordinal(i32::from(
                    (flags & FLOW_OVERRIDE_SET_MASK) >> FLOW_OVERRIDE_SHIFT,
                ))),
                length_override: AtomicI32::new(0),
                clearing_fall_throughs: AtomicBool::new(false),
                mnemonic_string: RwLock::new(None),
                self_ref: weak.clone(),
            }
        });
        instruction.refresh_length();
        instruction
    }

    /// The shared `CodeUnitDB` state, for callers that need to reach the base directly.
    pub fn base(&self) -> &CodeUnitDbBase {
        &self.base
    }

    /// This instruction as a shared handle, for the Java methods that pass or return `this` as
    /// some other interface.
    ///
    /// # Panics
    /// Panics if the object was not created through [`InstructionDB::new`], which is the only
    /// constructor.
    fn arc_self(&self) -> Arc<InstructionDB> {
        self.self_ref
            .upgrade()
            .expect("InstructionDB must be constructed through InstructionDB::new")
    }

    /// Reads the current `flags` byte. Stands in for reading the Java field.
    pub fn flags(&self) -> u8 {
        self.flags.load(Ordering::SeqCst)
    }

    /// Stands in for the private `InstructionDB.refreshLength()`.
    fn refresh_length(&self) {
        let mut length = self.proto.get_length();
        let mut length_override =
            i32::from((self.flags() & LENGTH_OVERRIDE_SET_MASK) >> LENGTH_OVERRIDE_SHIFT);
        if length_override != 0 && length_override < length {
            length = length_override;
        } else {
            length_override = 0;
        }
        self.length_override.store(length_override, Ordering::SeqCst);
        // Java assigns the `length` field directly; `set_length` additionally drops the memoized
        // `endAddr`, which is exactly what `doSetLengthOverride` does by hand right before calling
        // `refreshLength()`, and is a no-op on the constructor/refresh paths where it is already
        // cleared.
        self.base.set_length(length);
    }

    /// Get the instruction code unit length based upon its prototype and flags, which will be
    /// used to check for a length-override condition.
    ///
    /// Stands in for the package-private static `InstructionDB.getLength(InstructionPrototype,
    /// byte)`.
    pub fn length_of(proto: &dyn InstructionPrototype, flags: u8) -> i32 {
        let length = proto.get_length();
        let length_override =
            i32::from((flags & LENGTH_OVERRIDE_SET_MASK) >> LENGTH_OVERRIDE_SHIFT);
        if length_override != 0 && length_override < length {
            length_override
        } else {
            length
        }
    }

    /// Get the original context used to establish the shared prototype.
    ///
    /// Stands in for `InstructionDB.getOriginalPrototypeContext(Register)`. Java returns a
    /// `RegisterValue`; the [`CodeUnitOwner`] seam answers with the read-only processor context
    /// the prototype was parsed under, so that is what is returned here. Java's
    /// `catch (NoValueException)` -> `Msg.error` -> `return null` becomes the `None` the seam
    /// already reports.
    pub fn get_original_prototype_context(
        &self,
        base_context_register: Option<RegisterRef>,
    ) -> Option<Arc<dyn ProcessorContextView>> {
        self.base
            .owner()
            .get_original_prototype_context(&*self.proto, base_context_register)
    }

    /// Stands in for the private `InstructionDB.getFallThroughReference()`.
    fn get_fall_through_reference(&self) -> Option<Address> {
        self.base
            .get_references_from()
            .into_iter()
            .find(|reference| {
                reference.reference_type().is_fallthrough()
                    && reference.to_address().is_memory_address()
            })
            .map(|reference| reference.to_address())
    }

    /// Clear all existing fall-through references from this instruction's address.
    ///
    /// Stands in for the private `InstructionDB.clearFallThroughRefs(Address)`.
    ///
    /// # Arguments
    /// * `keep_fall_through_addr` - if not `None`, the corresponding fall-through reference will
    ///   be preserved.
    fn clear_fall_through_refs(&self, keep_fall_through_addr: Option<&Address>) {
        if self.clearing_fall_throughs.load(Ordering::SeqCst) {
            return;
        }
        self.validate(self.base.lock());
        self.clearing_fall_throughs.store(true, Ordering::SeqCst);

        let mut fall_through_preserved = false;
        let mut doomed: Vec<Arc<dyn Reference>> = Vec::new();
        for reference in self.base.get_references_from() {
            if reference.reference_type() != RefType::FallThrough {
                continue;
            }
            if !fall_through_preserved
                && keep_fall_through_addr.is_some_and(|keep| reference.to_address() == *keep)
            {
                fall_through_preserved = true; // only preserve one
            } else {
                doomed.push(reference);
            }
        }
        if !doomed.is_empty() {
            let reference_manager = self.base.owner().get_reference_manager();
            let mut reference_manager = reference_manager.lock().unwrap();
            for reference in doomed {
                reference_manager.delete(reference);
            }
        }

        self.clearing_fall_throughs.store(false, Ordering::SeqCst);
    }

    /// Notification that this instruction's fall-through reference changed.
    ///
    /// Stands in for the package-private `InstructionDB.fallThroughChanged(Reference)`, which the
    /// reference manager calls back on a fall-through reference being added or removed.
    pub fn fall_through_changed(&self, fall_through_ref: Option<&dyn Reference>) {
        if self.clearing_fall_throughs.load(Ordering::SeqCst) {
            return;
        }
        let fall_through_addr = fall_through_ref.map(|reference| reference.to_address());
        // ensure there is only one fallthrough ref
        self.clear_fall_through_refs(fall_through_addr.as_ref());
        match fall_through_addr {
            None => {
                // fallthrough ref removed
                self.set_fallthrough_override(false);
                // restore length-override fallthrough if needed
                self.add_length_override_fallthrough_ref();
            }
            Some(fall_through_addr) => {
                // enable fallthrough-override if fallThroughRef does not match the length-override
                // fallthrough
                self.set_fallthrough_override(
                    self.get_length_override_fall_through().as_ref() != Some(&fall_through_addr),
                );
            }
        }
    }

    /// Stands in for the private `InstructionDB.setFallthroughOverride(boolean)`.
    fn set_fallthrough_override(&self, state: bool) {
        if state == self.is_fall_through_overridden() {
            return;
        }
        let flags = if state {
            self.flags() | FALLTHROUGH_SET_MASK
        } else {
            self.flags() & FALLTHROUGH_CLEAR_MASK
        };
        self.flags.store(flags, Ordering::SeqCst);
        self.base.owner().set_flags(self.base.addr(), flags);
        // TODO(port): Java follows this with
        // `program.setChanged(ProgramEvent.FALLTHROUGH_CHANGED, address, address, null, null)`.
        // The ported `Program` trait exposes no `setChanged`, and `ProgramEvent` is not ported.
    }

    /// Stands in for the private `InstructionDB.addLengthOverrideFallthroughRef()`.
    fn add_length_override_fallthrough_ref(&self) {
        if !self.is_length_overridden() || self.is_fall_through_overridden() {
            return;
        }
        // length-override always uses default fall-through address
        if let Some(default_fall_through) = self.get_default_fall_through() {
            let address = self.base.address();
            self.base
                .owner()
                .get_reference_manager()
                .lock()
                .unwrap()
                .add_memory_reference(
                    address,
                    default_fall_through,
                    RefType::FallThrough,
                    SourceType::UserDefined,
                    crate::program::model::listing::code_unit::MNEMONIC,
                );
        }
    }

    /// Stands in for the private `InstructionDB.getLengthOverrideFallThrough()`.
    fn get_length_override_fall_through(&self) -> Option<Address> {
        if self.is_length_overridden() {
            self.get_default_fall_through()
        } else {
            None
        }
    }

    /// Check and revise a specified `length` to arrive at a suitable length-override value.
    ///
    /// Stands in for the public static `InstructionDB.checkLengthOverride(int,
    /// InstructionPrototype)`. A return of 0 disables the length override.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if `length` is not a multiple of the language's
    /// instruction alignment or exceeds [`MAX_LENGTH_OVERRIDE`].
    ///
    /// # Panics
    /// Panics on a negative `length`, mirroring Java's `IllegalArgumentException`.
    pub fn check_length_override(
        length: i32,
        prototype: &dyn InstructionPrototype,
    ) -> Result<i32, CodeUnitInsertionException> {
        assert!(length >= 0, "Negative length not permitted");
        let instr_proto_length = prototype.get_length();
        if length == 0 || length == instr_proto_length {
            return Ok(0);
        }
        if length > instr_proto_length {
            return Ok(0);
        }

        let align = prototype.get_language().get_instruction_alignment();
        if align == 0 || length % align != 0 {
            return Err(CodeUnitInsertionException::new(format!(
                "Length({length}) override must be a multiple of {align} bytes"
            )));
        }

        if length > MAX_LENGTH_OVERRIDE {
            return Err(CodeUnitInsertionException::new(format!(
                "Unsupported length override: {length}"
            )));
        }
        Ok(length)
    }

    /// Stands in for the package-private `InstructionDB.doSetLengthOverride(int)`, returning
    /// whether the override actually changed.
    ///
    /// # Errors
    /// Returns [`CodeUnitInsertionException`] if the (grown) instruction would collide with the
    /// next defined code unit, or if `len` is not a supported override value.
    pub fn do_set_length_override(&self, len: i32) -> Result<bool, CodeUnitInsertionException> {
        let proto_length = self.proto.get_length();
        let len = Self::check_length_override(len, &*self.proto)?;
        if len == self.length_override.load(Ordering::SeqCst) {
            return Ok(false); // no change
        }

        let instr_length = if len != 0 { len } else { proto_length };
        if instr_length > self.get_length() {
            let address = self.base.address();
            let new_end_addr = address
                .add(i64::from(instr_length - 1))
                .map_err(|e| CodeUnitInsertionException::new(e.to_string()))?;
            let next_code_unit_addr = self.base.owner().get_defined_address_after(&address);
            if let Some(next_code_unit_addr) = next_code_unit_addr {
                if next_code_unit_addr <= new_end_addr {
                    return Err(CodeUnitInsertionException::new(format!(
                        "Length override of {instr_length} conflicts with code unit at \
                         {next_code_unit_addr}"
                    )));
                }
            }
        }

        let flags =
            (self.flags() & LENGTH_OVERRIDE_CLEAR_MASK) | ((len as u8) << LENGTH_OVERRIDE_SHIFT);
        self.flags.store(flags, Ordering::SeqCst);
        self.base.owner().set_flags(self.base.addr(), flags);

        // Java clears `endAddr` here and then calls `refreshLength()`; `refresh_length` clears it
        // as part of writing the new length (see the note there).
        self.refresh_length();

        self.add_length_override_fallthrough_ref();

        Ok(true)
    }

    /// Stands in for `InstructionDB.setFlowOverride(FlowOverride)`, taking `&self` so it is
    /// reachable through a shared handle; [`Instruction::set_flow_override`] delegates here.
    pub fn do_set_flow_override(&self, flow: FlowOverride) {
        let _guard = self.base.lock().write();
        if self.check_deleted().is_err() {
            return;
        }
        if flow == *self.flow_override.read().unwrap() {
            return;
        }
        let _orig_flow_type = self.get_flow_type();

        let flags = (self.flags() & FLOW_OVERRIDE_CLEAR_MASK)
            | (flow_override_ordinal(flow) << FLOW_OVERRIDE_SHIFT);
        self.flags.store(flags, Ordering::SeqCst);
        self.base.owner().set_flags(self.base.addr(), flags);
        *self.flow_override.write().unwrap() = flow;

        // TODO(port): Java then walks `refMgr.getFlowReferencesFrom(getAddress())` and retypes
        // every flow reference whose type still matches `origFlowType`, using
        // `RefTypeFactory.getDefaultMemoryRefType(this, opIndex, toAddr, true)` to pick the
        // replacement (deleting the old reference, adding the new one, and restoring its primary
        // flag). `ghidra.program.model.symbol.RefTypeFactory` is ported only as the reference-type
        // *tables* (`RefTypeFactory::memory_ref_types` and friends) -- it has no
        // `get_default_memory_ref_type`, which is the whole content of the loop body -- so the
        // reference fix-up is omitted rather than approximated. The private helper
        // `isSameFlowType(FlowType, RefType)` exists only to filter that loop and is likewise
        // omitted.
        //
        // TODO(port): Java also ends with
        // `program.setChanged(ProgramEvent.FLOW_OVERRIDE_CHANGED, address, address, null, null)`.
        // The ported `Program` trait exposes no `setChanged`, and `ProgramEvent` is not ported.
    }

    /// Stands in for `InstructionDB.setLengthOverride(int)`, taking `&self`;
    /// [`Instruction::set_length_override`] delegates here.
    ///
    /// # Errors
    /// See [`InstructionDB::do_set_length_override`].
    pub fn do_set_length_override_checked(
        &self,
        len: i32,
    ) -> Result<(), CodeUnitInsertionException> {
        let _guard = self.base.lock().write();
        self.check_deleted()
            .map_err(CodeUnitInsertionException::new)?;
        if self.do_set_length_override(len)? {
            // TODO(port): Java fires
            // `program.setChanged(ProgramEvent.LENGTH_OVERRIDE_CHANGED, address, address, null,
            // null)` here; the ported `Program` trait exposes no `setChanged`.
        }
        Ok(())
    }

    /// Stands in for `InstructionDB.clearFallThroughOverride()`, taking `&self`;
    /// [`Instruction::clear_fall_through_override`] delegates here.
    pub fn do_clear_fall_through_override(&self) {
        let _guard = self.base.lock().write();
        if self.check_deleted().is_err() {
            return;
        }
        if !self.is_fall_through_overridden() {
            return;
        }
        // clear fall-through override
        self.clear_fall_through_refs(None);
        self.set_fallthrough_override(false);
        // restore length-override fallthrough if needed
        self.add_length_override_fallthrough_ref();
    }

    /// Stands in for `InstructionDB.setFallThrough(Address)`, taking `&self`;
    /// [`Instruction::set_fall_through`] delegates here.
    pub fn do_set_fall_through(&self, fall_through_addr: Option<Address>) {
        let _guard = self.base.lock().write();
        if self.check_deleted().is_err() {
            return;
        }
        let default_fall_through = self.proto.get_fall_through(self);
        if fall_through_addr == default_fall_through {
            self.do_clear_fall_through_override();
            return;
        }
        match fall_through_addr {
            None => {
                // Fall-through eliminated (i.e., terminal flow) - no reference added
                self.clear_fall_through_refs(None);
                self.set_fallthrough_override(true);
            }
            Some(fall_through_addr) => {
                // Adding a fallthrough ref will trigger the override flag on the
                // `fall_through_changed` callback.
                let address = self.base.address();
                self.base
                    .owner()
                    .get_reference_manager()
                    .lock()
                    .unwrap()
                    .add_memory_reference(
                        address,
                        fall_through_addr,
                        RefType::FallThrough,
                        SourceType::UserDefined,
                        crate::program::model::listing::code_unit::MNEMONIC,
                    );
            }
        }
    }

    /// Whether `record`'s shape matches the instruction table's.
    ///
    /// Stands in for `rec.hasSameSchema(InstDBAdapter.INSTRUCTION_SCHEMA)`. The ported `DBRecord`
    /// exposes neither its `Schema` nor a `has_same_schema`, and `Schema` has no equality, so the
    /// check is made on what `hasSameSchema` compares: the key type and the column types.
    fn has_instruction_schema(record: &DBRecord) -> bool {
        let schema = inst_db_adapter::schema();
        if record.get_key().get_type() != schema.get_key_type() {
            return false;
        }
        if record.get_field_count() != schema.get_field_count() {
            return false;
        }
        (0..schema.get_field_count())
            .all(|i| record.get_field(i).get_type() == schema.get_field_type(i))
    }
}

// ===========================================================================================
// MemBuffer -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl MemBuffer for InstructionDB {
    fn get_address(&self) -> Address {
        self.base.address()
    }

    fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
        self.base.get_byte(offset, self.get_preferred_cache_length())
    }

    fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
        self.base
            .get_bytes_at(buf, offset, self.get_preferred_cache_length())
    }

    fn is_big_endian(&self) -> bool {
        self.base.is_big_endian()
    }

    fn get_memory(&self) -> Option<Arc<dyn Memory>> {
        self.base.get_memory()
    }
}

// ===========================================================================================
// PropertySet -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl PropertySet for InstructionDB {
    fn set_object_property(&mut self, name: &str, value: Box<dyn Saveable>) {
        // TODO(port): `CodeUnitDbBase` has no object-property setter -- the ported
        // `PropertyMapManager`/`ObjectPropertyMap` pair carries no `add_object`, so
        // `CodeUnitDB.setProperty(String, Saveable)` has no shared implementation to forward to.
        let _ = (name, value);
    }

    fn set_string_property(&mut self, name: &str, value: &str) {
        self.base.set_string_property(name, value);
    }

    fn set_int_property(&mut self, name: &str, value: i32) {
        self.base.set_int_property(name, value);
    }

    fn set_void_property(&mut self, name: &str) {
        self.base.set_void_property(name);
    }

    fn get_object_property(&self, name: &str) -> Option<Box<dyn Saveable>> {
        self.base.get_object_property(name)
    }

    fn get_string_property(&self, name: &str) -> Option<String> {
        self.base.get_string_property(name)
    }

    fn get_int_property(&self, name: &str) -> Result<i32, NoValueException> {
        self.base.get_int_property(name)
    }

    fn has_property(&self, name: &str) -> bool {
        self.base.has_property(name)
    }

    fn get_void_property(&self, name: &str) -> bool {
        self.base.get_void_property(name)
    }

    fn property_names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.base.property_names().into_iter())
    }

    fn remove_property(&mut self, name: &str) {
        self.base.remove_property(name);
    }
}

// ===========================================================================================
// CodeUnit -- inherited from `CodeUnitDB` except where `InstructionDB` overrides.
// ===========================================================================================

impl CodeUnit for InstructionDB {
    fn get_address_string(&self, show_block_name: bool, pad: bool) -> String {
        self.base.get_address_string(show_block_name, pad)
    }

    fn get_label(&self) -> Option<String> {
        self.base.get_label()
    }

    fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
        self.base.get_symbols()
    }

    fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
        self.base.get_primary_symbol()
    }

    fn get_min_address(&self) -> Address {
        self.base.address()
    }

    fn get_max_address(&self) -> Address {
        self.base.get_max_address(self.get_length())
    }

    /// Port of `InstructionDB.getMnemonicString()`, including its lazy `mnemonicString` cache.
    fn get_mnemonic_string(&self) -> String {
        self.validate(self.base.lock());
        if let Some(cached) = self.mnemonic_string.read().unwrap().as_ref() {
            return cached.clone();
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let mnemonic = self.proto.get_mnemonic(self);
        *self.mnemonic_string.write().unwrap() = Some(mnemonic.clone());
        mnemonic
    }

    fn get_comment(&self, comment_type: CommentType) -> Option<String> {
        self.base.get_comment(comment_type)
    }

    fn get_comment_as_array(&self, comment_type: CommentType) -> Vec<String> {
        self.base.get_comment_as_array(comment_type)
    }

    fn set_comment(&mut self, comment_type: CommentType, comment: Option<String>) {
        self.base.set_comment(comment_type, comment);
    }

    fn set_comment_as_array(&mut self, comment_type: CommentType, comment: &[String]) {
        self.base.set_comment_as_array(comment_type, comment);
    }

    fn get_length(&self) -> i32 {
        self.base.length()
    }

    fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        self.base
            .get_bytes(self.get_length(), self.get_preferred_cache_length())
    }

    fn get_bytes_in_code_unit(
        &self,
        buffer: &mut [u8],
        buffer_offset: i32,
    ) -> Result<(), MemoryAccessException> {
        self.base.get_bytes_in_code_unit(
            buffer,
            buffer_offset,
            self.get_length(),
            self.get_preferred_cache_length(),
        )
    }

    fn contains(&self, test_addr: &Address) -> bool {
        self.base.contains(test_addr, self.get_length())
    }

    fn compare_to(&self, addr: &Address) -> i32 {
        self.base.compare_to(addr, self.get_length())
    }

    fn add_mnemonic_reference(
        &mut self,
        ref_addr: Address,
        ref_type: RefType,
        source_type: SourceType,
    ) {
        self.base
            .add_mnemonic_reference(&ref_addr, ref_type, source_type);
    }

    fn remove_mnemonic_reference(&mut self, ref_addr: &Address) {
        self.base.remove_mnemonic_reference(ref_addr);
    }

    fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
        self.base.get_mnemonic_references()
    }

    fn get_operand_references(&self, index: i32) -> Vec<Arc<dyn Reference>> {
        self.base.get_operand_references(index)
    }

    fn get_primary_reference(&self, index: i32) -> Option<Arc<dyn Reference>> {
        self.base.get_primary_reference(index)
    }

    fn add_operand_reference(
        &mut self,
        index: i32,
        ref_addr: Address,
        ref_type: RefType,
        source_type: SourceType,
    ) {
        self.base
            .add_operand_reference(index, &ref_addr, ref_type, source_type);
    }

    fn remove_operand_reference(&mut self, index: i32, ref_addr: &Address) {
        self.base.remove_operand_reference(index, ref_addr);
    }

    fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
        self.base.get_references_from()
    }

    fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
        self.base.get_reference_iterator_to()
    }

    fn get_program(&self) -> Arc<dyn Program> {
        self.base.get_program()
    }

    fn get_external_reference(&self, op_index: i32) -> Option<Arc<dyn ExternalReference>> {
        self.base.get_external_reference(op_index)
    }

    fn remove_external_reference(&mut self, op_index: i32) {
        self.base.remove_external_reference(op_index);
    }

    fn set_primary_memory_reference(&mut self, reference: Arc<dyn Reference>) {
        self.base.set_primary_memory_reference(reference);
    }

    fn set_stack_reference(
        &mut self,
        op_index: i32,
        offset: i32,
        source_type: SourceType,
        ref_type: RefType,
    ) {
        let num_operands = self.get_num_operands();
        self.base
            .set_stack_reference(op_index, offset, source_type, ref_type, num_operands);
    }

    fn set_register_reference(
        &mut self,
        op_index: i32,
        reg: &Register,
        source_type: SourceType,
        ref_type: RefType,
    ) {
        let num_operands = self.get_num_operands();
        self.base.set_register_reference(
            op_index,
            Register::from_register(reg),
            source_type,
            ref_type,
            num_operands,
        );
    }

    /// Port of `InstructionDB.getNumOperands()`.
    fn get_num_operands(&self) -> i32 {
        self.proto.get_num_operands()
    }

    /// Port of `InstructionDB.getAddress(int)`.
    fn get_address(&self, op_index: i32) -> Option<Address> {
        if op_index < 0 || op_index >= self.get_num_operands() {
            return None;
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let address = self.base.address();
        let reference = self
            .base
            .owner()
            .get_reference_manager()
            .lock()
            .unwrap()
            .get_primary_reference_from(address, op_index);
        if let Some(reference) = reference {
            return Some(reference.to_address());
        }

        let op_type = self.proto.get_op_type(op_index, self);
        if OperandType::is_address(op_type as u32) {
            return self.proto.get_address(op_index, self);
        }
        None
    }

    /// Port of `InstructionDB.getScalar(int)`.
    fn get_scalar(&self, op_index: i32) -> Option<Scalar> {
        if op_index < 0 || op_index >= self.get_num_operands() {
            return None;
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_scalar(op_index, self)
    }

    fn as_instruction(&self) -> Option<&dyn Instruction> {
        Some(self)
    }
}

// ===========================================================================================
// ProcessorContext / ProcessorContextView -- inherited from `CodeUnitDB` in Java.
// ===========================================================================================

impl ProcessorContextView for InstructionDB {
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        Some(self.base.get_base_context_register())
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.base.get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.base.get_register(name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        self.base.get_register_bigint_value(register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValue>> {
        self.base.get_register_value(register)
    }

    fn has_value(&self, register: &Register) -> bool {
        self.base.has_value(register)
    }
}

impl ProcessorContext for InstructionDB {
    fn set_value(&mut self, register: &Register, value: i128) -> Result<(), ContextChangeException> {
        self.base.set_register_bigint_value(register, value)
    }

    fn set_register_value(
        &mut self,
        value: Box<dyn RegisterValue>,
    ) -> Result<(), ContextChangeException> {
        self.base.set_register_value(value)
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        self.base.clear_register(register)
    }
}

// ===========================================================================================
// Instruction.
// ===========================================================================================

impl Instruction for InstructionDB {
    /// Port of `InstructionDB.getPrototype()`.
    fn get_prototype(&self) -> Arc<dyn InstructionPrototype> {
        self.proto.clone()
    }

    /// Port of `InstructionDB.getRegister(int)`.
    fn get_register(&self, operand_index: i32) -> Option<RegisterRef> {
        if operand_index < 0 || operand_index >= self.get_num_operands() {
            return None;
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_register(operand_index, self)
    }

    /// Port of `InstructionDB.getOpObjects(int)`.
    fn get_op_objects(&self, operand_index: i32) -> Vec<OperandValue> {
        if operand_index < 0 || operand_index >= self.get_num_operands() {
            return Vec::new();
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_op_objects(operand_index, self)
    }

    /// Port of `InstructionDB.getInputObjects()`.
    fn get_input_objects(&self) -> Vec<OperandValue> {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_input_objects(self)
    }

    /// Port of `InstructionDB.getResultObjects()`.
    fn get_result_objects(&self) -> Vec<OperandValue> {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_result_objects(self)
    }

    /// Port of `InstructionDB.getDefaultOperandRepresentation(int)`.
    fn get_default_operand_representation(&self, operand_index: i32) -> String {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let Some(op_list) = self.get_default_operand_representation_list(operand_index) else {
            return "<UNSUPPORTED>".to_string();
        };
        let mut buffer = String::new();
        for op_elem in op_list {
            match op_elem {
                // Java: `strBuf.append("0x"); strBuf.append(opAddr.toString(false));`
                OperandValue::Address(op_addr) => {
                    buffer.push_str("0x");
                    buffer.push_str(&op_addr.format(false, 1));
                }
                // Everything else is Java's `opElem.toString()`.
                OperandValue::Register(register) => buffer.push_str(register.name()),
                OperandValue::Scalar(scalar) => buffer.push_str(&scalar.to_string()),
                OperandValue::Character(c) => buffer.push(c),
                OperandValue::Text(text) => buffer.push_str(&text),
            }
        }
        buffer
    }

    /// Port of `InstructionDB.getDefaultOperandRepresentationList(int)`.
    fn get_default_operand_representation_list(
        &self,
        operand_index: i32,
    ) -> Option<Vec<OperandValue>> {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_op_representation_list(operand_index, self)
    }

    /// Port of `InstructionDB.getSeparator(int)`.
    fn get_separator(&self, operand_index: i32) -> Option<String> {
        self.proto.get_separator(operand_index)
    }

    /// Port of `InstructionDB.getOperandType(int)`.
    fn get_operand_type(&self, operand_index: i32) -> i32 {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let mut optype = self.proto.get_op_type(operand_index, self);

        let Some(reference) = self.get_primary_reference(operand_index) else {
            return optype;
        };
        if reference.is_stack_reference() {
            optype |= OperandType::ADDRESS as i32;
            return optype;
        }
        if reference.is_external_reference() || reference.to_address().is_memory_address() {
            optype |= OperandType::ADDRESS as i32;
        }
        optype
    }

    /// Port of `InstructionDB.getOperandRefType(int)`.
    ///
    /// Java returns `null` for an out-of-range operand index; the ported trait's return type is
    /// not optional, so that becomes [`RefType::Invalid`].
    fn get_operand_ref_type(&self, operand_index: i32) -> RefType {
        if operand_index < 0 || operand_index >= self.get_num_operands() {
            return RefType::Invalid;
        }
        // always reflects current flowOverride
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let pcode_override = InstructionPcodeOverrideImpl::new(self);
        self.proto
            .get_operand_ref_type(operand_index, self, Some(&pcode_override))
    }

    /// Port of `InstructionDB.getDefaultFallThroughOffset()`.
    fn get_default_fall_through_offset(&self) -> i32 {
        if self.proto.get_delay_slot_byte_count() <= 0 {
            return self.proto.get_length();
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        self.proto.get_fall_through_offset(self)
    }

    /// Port of `InstructionDB.getDefaultFallThrough()`.
    fn get_default_fall_through(&self) -> Option<Address> {
        let my_flow_type = self.get_flow_type(); // getFlowType will validate
        if my_flow_type.has_fallthrough() {
            // Java swallows the AddressOverflowException and returns null.
            return self
                .base
                .address()
                .add_no_wrap(i64::from(self.get_default_fall_through_offset()))
                .ok();
        }
        None
    }

    /// Port of `InstructionDB.getFallThrough()`.
    fn get_fall_through(&self) -> Option<Address> {
        if self.is_fall_through_overridden() {
            return self.get_fall_through_reference();
        }
        self.get_default_fall_through()
    }

    /// Port of `InstructionDB.getFallFrom()`.
    fn get_fall_from(&self) -> Option<Address> {
        // TODO(port): the Java body walks backwards over delay-slot instructions using
        // `program.getLanguage().getInstructionAlignment()`,
        // `program.getListing().getInstructionContaining(..)` and
        // `program.getSymbolTable().hasSymbol(..)`. The ported `Program` trait reaches its listing
        // and symbol table only through `&mut self` accessors (`get_listing(&mut self)`,
        // `get_symbol_table(&mut self)`), which an `Arc<dyn Program>` -- the only handle a code
        // unit has -- cannot call; and `SymbolTable` has no `has_symbol`. There is no
        // `CodeUnitOwner` callback for either, and adding one would not help: the walk needs
        // `getInstructionContaining`, not the `getInstructionAt/After/Before` the seam offers.
        None
    }

    /// Port of `InstructionDB.getFlows()`.
    ///
    /// Java's empty `Address[]` becomes `None`, per the ported trait's documented convention.
    fn get_flows(&self) -> Option<Vec<Address>> {
        self.validate(self.base.lock());
        let address = self.base.address();
        let refs = self
            .base
            .owner()
            .get_reference_manager()
            .lock()
            .unwrap()
            .get_flow_references_from(address);
        if refs.is_empty() {
            return None;
        }

        let mut list: Vec<Address> = Vec::new();
        for reference in refs {
            if !reference.reference_type().is_indirect() {
                let to_address = reference.to_address();
                if !list.contains(&to_address) {
                    list.push(to_address);
                }
            }
        }

        if *self.flow_override.read().unwrap() == FlowOverride::Return && list.len() == 1 {
            return None;
        }
        if list.is_empty() {
            return None;
        }
        Some(list)
    }

    /// Port of `InstructionDB.getDefaultFlows()`.
    fn get_default_flows(&self) -> Option<Vec<Address>> {
        self.validate(self.base.lock());
        let flows = self.proto.get_flows(self).unwrap_or_default();
        if *self.flow_override.read().unwrap() == FlowOverride::Return && flows.len() == 1 {
            return None;
        }
        if flows.is_empty() {
            return None;
        }
        Some(flows)
    }

    /// Port of `InstructionDB.getFlowType()`.
    fn get_flow_type(&self) -> RefType {
        self.validate(self.base.lock());
        modified_flow_type(
            self.proto.get_flow_type(self),
            *self.flow_override.read().unwrap(),
        )
    }

    /// Port of `InstructionDB.isFallthrough()`.
    fn is_fallthrough(&self) -> bool {
        if !self.get_flow_type().is_fallthrough() {
            return false;
        }
        self.has_fallthrough()
    }

    /// Port of `InstructionDB.hasFallthrough()`.
    fn has_fallthrough(&self) -> bool {
        if self.is_fall_through_overridden() {
            // fall-through destination stored as reference
            return self.get_fall_through().is_some();
        }
        self.get_flow_type().has_fallthrough()
    }

    /// Port of `InstructionDB.getFlowOverride()`.
    fn get_flow_override(&self) -> FlowOverride {
        *self.flow_override.read().unwrap()
    }

    /// Port of `InstructionDB.setFlowOverride(FlowOverride)`. See
    /// [`InstructionDB::do_set_flow_override`], which holds the real body so that it is reachable
    /// through a shared `&self` handle too.
    fn set_flow_override(&mut self, flow_override: FlowOverride) {
        self.do_set_flow_override(flow_override);
    }

    /// Port of `InstructionDB.setLengthOverride(int)`. See
    /// [`InstructionDB::do_set_length_override_checked`].
    fn set_length_override(&mut self, length: i32) -> Result<(), CodeUnitInsertionException> {
        self.do_set_length_override_checked(length)
    }

    /// Port of `InstructionDB.isLengthOverridden()`.
    fn is_length_overridden(&self) -> bool {
        self.validate(self.base.lock());
        self.length_override.load(Ordering::SeqCst) != 0
    }

    /// Port of `InstructionDB.getParsedLength()`.
    fn get_parsed_length(&self) -> i32 {
        if self.is_length_overridden() {
            self.proto.get_length()
        } else {
            self.get_length()
        }
    }

    /// Port of `InstructionDB.getParsedBytes()`.
    fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
        if !self.is_length_overridden() {
            return CodeUnit::get_bytes(self);
        }
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let len = self.proto.get_length().max(0) as usize;
        let mut b = vec![0u8; len];
        let address = self.base.address();
        let read = self
            .base
            .get_memory()
            .map_or(0, |memory| memory.get_bytes(&address, &mut b));
        if read != len {
            return Err(MemoryAccessException::new(format!(
                "Failed to read {len} bytes at {address}"
            )));
        }
        Ok(b)
    }

    /// Port of `InstructionDB.getPcode()`.
    fn get_pcode(&self) -> Vec<PcodeOp> {
        self.get_pcode_with_overrides(false)
    }

    /// Port of `InstructionDB.getPcode(boolean)`.
    fn get_pcode_with_overrides(&self, include_overrides: bool) -> Vec<PcodeOp> {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        if !include_overrides {
            return self.proto.get_pcode(self, None);
        }
        let pcode_override = InstructionPcodeOverrideImpl::new(self);
        self.proto.get_pcode(self, Some(&pcode_override))
    }

    /// Port of `InstructionDB.getPcode(int)`.
    fn get_pcode_for_operand(&self, operand_index: i32) -> Vec<PcodeOp> {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        // assumes operand pcode not affected by flow override
        self.proto.get_pcode_for_operand(self, operand_index)
    }

    /// Port of `InstructionDB.getDelaySlotDepth()`.
    fn get_delay_slot_depth(&self) -> i32 {
        if !self.proto.has_delay_slots() {
            return 0;
        }
        let _guard = self.base.lock().read();
        self.proto.get_delay_slot_depth(self)
    }

    /// Port of `InstructionDB.isInDelaySlot()`.
    fn is_in_delay_slot(&self) -> bool {
        self.proto.is_in_delay_slot()
    }

    /// Port of `InstructionDB.getNext()`.
    fn get_next(&self) -> Option<Arc<dyn Instruction>> {
        self.validate(self.base.lock());
        let address = self.base.address();
        self.base.owner().get_instruction_after(&address)
    }

    /// Port of `InstructionDB.getPrevious()`.
    fn get_previous(&self) -> Option<Arc<dyn Instruction>> {
        self.validate(self.base.lock());
        let address = self.base.address();
        self.base.owner().get_instruction_before(&address)
    }

    /// Port of `InstructionDB.setFallThrough(Address)`. See
    /// [`InstructionDB::do_set_fall_through`].
    fn set_fall_through(&mut self, addr: Option<Address>) {
        self.do_set_fall_through(addr);
    }

    /// Port of `InstructionDB.clearFallThroughOverride()`. See
    /// [`InstructionDB::do_clear_fall_through_override`].
    fn clear_fall_through_override(&mut self) {
        self.do_clear_fall_through_override();
    }

    /// Port of `InstructionDB.isFallThroughOverridden()`.
    fn is_fall_through_overridden(&self) -> bool {
        self.validate(self.base.lock());
        (self.flags() & FALLTHROUGH_SET_MASK) != 0
    }

    /// Port of `InstructionDB.getInstructionContext()`, which returns `this`.
    fn get_instruction_context(&self) -> Arc<dyn SeamInstructionContext> {
        self.arc_self()
    }
}

// ===========================================================================================
// InstructionContext -- Java's `implements InstructionContext`.
// ===========================================================================================

/// The placeholder `InstructionContext` the [`Instruction`] trait passes around declares no
/// members; the real contract is [`LangInstructionContext`], implemented just below.
impl SeamInstructionContext for InstructionDB {}

impl LangInstructionContext for InstructionDB {
    fn get_address(&self) -> Address {
        self.base.address()
    }

    /// Port of `InstructionDB.getProcessorContext()`, which returns `this`.
    fn get_processor_context(&self) -> &dyn ProcessorContextView {
        self
    }

    /// Port of `InstructionDB.getMemBuffer()`, which returns `this`.
    fn get_mem_buffer(&self) -> &dyn MemBuffer {
        self
    }

    /// Port of `InstructionDB.getParserContext()`.
    ///
    /// Java memoizes the result in its `parserContext` field (cleared on refresh). The ported
    /// signature returns an owned `Box<dyn ParserContext>`, which cannot be handed out repeatedly
    /// from a cache, so the context is rebuilt per call -- the same value, recomputed. See
    /// [`ParserContextBridge`] for why the result needs wrapping.
    fn get_parser_context(&self) -> Result<Box<dyn LangParserContext>, MemoryAccessException> {
        // NOTE: It is assumed this is invoked and used within a locked block
        let parser_context = self.proto.get_parser_context(self, self)?;
        Ok(Box::new(ParserContextBridge(parser_context)))
    }

    /// Port of `InstructionDB.getParserContext(Address)`.
    fn get_parser_context_at(
        &self,
        instruction_address: Address,
    ) -> Result<Box<dyn LangParserContext>, InstructionContextError> {
        if self.base.address() == instruction_address {
            return Ok(self.get_parser_context()?);
        }
        let Some(_instr) = self
            .base
            .owner()
            .get_instruction_at(&instruction_address)
        else {
            return Err(UnknownContextException::with_message(format!(
                "Program does not contain referenced instruction: {instruction_address}"
            ))
            .into());
        };
        // TODO(port): Java casts the neighbouring instruction to `InstructionDB`, compares
        // `otherProto.getClass()` with `proto.getClass()`, and returns `instr.getParserContext()`.
        // Neither step is expressible here: `CodeUnitOwner::get_instruction_at` yields an
        // `Arc<dyn Instruction>` with no downcast hook, the `Instruction` trait has no
        // `get_parser_context`, and `InstructionPrototype` exposes no run-time type identity to
        // compare. Reported as an incompatible prototype, which is the failure Java raises when
        // the prototypes do not match.
        Err(UnknownContextException::with_message(format!(
            "Instruction has incompatible prototype at: {instruction_address}"
        ))
        .into())
    }
}

// ===========================================================================================
// DbObject / CodeUnitDb.
// ===========================================================================================

impl DbObject for InstructionDB {
    fn state(&self) -> &DbObjectState {
        self.base.state()
    }

    /// Port of `InstructionDB.refresh(DBRecord)` composed with `CodeUnitDB.refresh(DBRecord)`:
    /// the subclass clears its lazy caches, the superclass re-decodes the address and drops its
    /// own caches, and the result is `!hasBeenDeleted(record)`.
    fn refresh(&self, record: Option<&DBRecord>) -> bool {
        *self.mnemonic_string.write().unwrap() = None;
        // (Java also nulls its cached `parserContext` here; this port holds no such cache -- see
        // `get_parser_context`.)
        self.base.refresh_base();
        !self.has_been_deleted(record)
    }
}

impl CodeUnitDb for InstructionDB {
    /// Port of `InstructionDB.hasBeenDeleted(DBRecord)`.
    fn has_been_deleted(&self, record: Option<&DBRecord>) -> bool {
        let owned;
        let rec = match record {
            None => {
                owned = self.base.owner().get_instruction_record(self.base.addr());
                match owned.as_ref() {
                    None => return true,
                    Some(rec) => rec,
                }
            }
            Some(rec) => {
                // ensure that record provided corresponds to an InstructionDB record since
                // following an undo/redo the record could correspond to a different type of code
                // unit (hopefully with a different record schema)
                if !Self::has_instruction_schema(rec) {
                    return true;
                }
                rec
            }
        };

        let Some(new_proto_id) = rec.get_int(PROTO_ID_COL) else {
            return true;
        };
        let Some(new_proto) = self.base.owner().get_instruction_prototype(new_proto_id) else {
            // Java: Msg.error(this, "Instruction found but prototype missing at " + address)
            return true;
        };
        // Java compares with `newProto.equals(proto)`. `InstructionPrototype` has no ported
        // equality, and prototypes are interned by the prototype manager the owner looks them up
        // in, so identity of the shared handle stands in for it.
        if !Arc::ptr_eq(&new_proto, &self.proto) {
            return true;
        }

        let flags = rec.get_byte(FLAGS_COL).unwrap_or(0) as u8;
        self.flags.store(flags, Ordering::SeqCst);
        *self.flow_override.write().unwrap() = flow_override_from_ordinal(i32::from(
            (flags & FLOW_OVERRIDE_SET_MASK) >> FLOW_OVERRIDE_SHIFT,
        ));
        self.refresh_length();
        false
    }

    /// Port of `InstructionDB.getPreferredCacheLength()`: cache the first delay slot if present.
    /// `length` is the (possibly length-overridden) code unit length.
    fn get_preferred_cache_length(&self) -> i32 {
        let length = self.base.length();
        if self.proto.has_delay_slots() {
            length * 2
        } else {
            length
        }
    }

    /// Port of `InstructionDB.toString()`.
    fn code_unit_string(&self) -> String {
        let _guard = self.base.lock().read();
        self.refresh_if_needed();
        let mut buffer = String::new();
        buffer.push_str(&self.get_mnemonic_string());

        let n = self.get_num_operands();
        let mut sep = Instruction::get_separator(self, 0);
        if sep.is_some() || n != 0 {
            buffer.push(' ');
        }
        if let Some(sep) = &sep {
            buffer.push_str(sep);
        }

        for i in 0..n {
            buffer.push_str(&self.get_default_operand_representation(i));
            sep = Instruction::get_separator(self, i + 1);
            if let Some(sep) = &sep {
                buffer.push_str(sep);
            }
        }
        buffer
    }
}

impl std::fmt::Display for InstructionDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code_unit_string())
    }
}

/// Port of `InstructionDB.equals(Object)`: `CodeUnitDB.equals` (same address index and same
/// owning manager, for two objects of the same class) plus the prototype comparison.
impl PartialEq for InstructionDB {
    fn eq(&self, other: &Self) -> bool {
        self.base.same_code_unit(&other.base) && Arc::ptr_eq(&self.proto, &other.proto)
    }
}

impl Eq for InstructionDB {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;
    use crate::program::database::code::comments_db_adapter;
    use crate::program::database::code::test_support::TestCodeUnitOwner;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::Mask;
    use crate::program::model::listing::instruction::tests::mock_instruction;
    use crate::program::model::pcode::{PatchEncoder, PcodeOverride};
    use std::io;

    const UNEXERCISED: &str = "not exercised by these tests";

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    // -- Test doubles -----------------------------------------------------------------------

    /// A [`Language`] whose only meaningful answer is its instruction alignment, which is all
    /// `InstructionDB.checkLengthOverride` asks a language for.
    struct TestLanguage {
        instruction_alignment: i32,
    }

    impl Language for TestLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<
            Box<
                dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper,
            >,
        > {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_version(&self) -> i32 {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_minor_version(&self) -> i32 {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            unimplemented!("{UNEXERCISED}")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_instruction_alignment(&self) -> i32 {
            self.instruction_alignment
        }
        fn supports_pcode(&self) -> bool {
            unimplemented!("{UNEXERCISED}")
        }
        fn is_volatile(&self, _addr: &crate::program::model::address::Address) -> bool {
            unimplemented!("{UNEXERCISED}")
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::model::mem::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            // `PcodeProgram::new` always calls this while resolving userop names, even for an
            // empty userop map, so it must not panic.
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_registers_at(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_register_names(&self) -> Vec<String> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_register_by_name(
            &self,
            _name: &str,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_register_at(
            &self,
            _addr: &crate::program::model::address::Address,
            _size: i32,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_program_counter(&self) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_context_base_register(
            &self,
        ) -> Option<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_context_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_segmented_space(&self) -> String {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_volatile_addresses(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("{UNEXERCISED}")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
            unimplemented!("{UNEXERCISED}")
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("{UNEXERCISED}")
        }
        fn has_property(&self, _key: &str) -> bool {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("{UNEXERCISED}")
        }
        fn has_manual(&self) -> bool {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_sorted_vector_registers(&self) -> Vec<crate::program::model::lang::register::RegisterRef> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("{UNEXERCISED}")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            unimplemented!("{UNEXERCISED}")
        }
    }

    /// A configurable [`InstructionPrototype`]: length, flow type, operand count, delay-slot
    /// behaviour and language alignment are all the prototype facts `InstructionDB` consults.
    struct TestPrototype {
        length: i32,
        flow_type: RefType,
        num_operands: i32,
        mnemonic: String,
        delay_slots: bool,
        delay_slot_byte_count: i32,
        flows: Vec<Address>,
        language: Arc<dyn Language>,
    }

    impl TestPrototype {
        fn new(length: i32) -> Self {
            TestPrototype {
                length,
                flow_type: RefType::FallThrough,
                num_operands: 2,
                mnemonic: "MOV".to_string(),
                delay_slots: false,
                delay_slot_byte_count: 0,
                flows: Vec::new(),
                language: Arc::new(TestLanguage {
                    instruction_alignment: 1,
                }),
            }
        }

        fn with_flow_type(mut self, flow_type: RefType) -> Self {
            self.flow_type = flow_type;
            self
        }

        fn with_alignment(mut self, alignment: i32) -> Self {
            self.language = Arc::new(TestLanguage {
                instruction_alignment: alignment,
            });
            self
        }

        fn with_delay_slots(mut self) -> Self {
            self.delay_slots = true;
            self
        }

        fn with_flows(mut self, flows: Vec<Address>) -> Self {
            self.flows = flows;
            self
        }
    }

    impl InstructionPrototype for TestPrototype {
        fn get_parser_context(
            &self,
            _buf: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<Box<dyn SeamParserContext>, MemoryAccessException> {
            unimplemented!("{UNEXERCISED}")
        }

        fn get_pseudo_parser_context(
            &self,
            _address: &Address,
            _buffer: &dyn MemBuffer,
            _processor_context: &dyn ProcessorContextView,
        ) -> Result<
            Box<dyn SeamParserContext>,
            crate::program::model::lang::instruction_prototype::GetPseudoParserContextError,
        > {
            unimplemented!("{UNEXERCISED}")
        }

        fn has_delay_slots(&self) -> bool {
            self.delay_slots
        }

        fn has_cross_build_dependency(&self) -> bool {
            false
        }

        fn has_next2_dependency(&self) -> bool {
            false
        }

        fn get_mnemonic(&self, _context: &dyn LangInstructionContext) -> String {
            self.mnemonic.clone()
        }

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_instruction_mask(&self) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_operand_value_mask(&self, _operand_index: i32) -> Option<Box<dyn Mask>> {
            None
        }

        fn get_flow_type(&self, _context: &dyn LangInstructionContext) -> RefType {
            self.flow_type
        }

        fn get_delay_slot_depth(&self, _context: &dyn LangInstructionContext) -> i32 {
            if self.delay_slots {
                1
            } else {
                0
            }
        }

        fn get_delay_slot_byte_count(&self) -> i32 {
            self.delay_slot_byte_count
        }

        fn is_in_delay_slot(&self) -> bool {
            false
        }

        fn get_num_operands(&self) -> i32 {
            self.num_operands
        }

        fn get_op_type(&self, _operand_index: i32, _context: &dyn LangInstructionContext) -> i32 {
            0
        }

        fn get_fall_through(&self, context: &dyn LangInstructionContext) -> Option<Address> {
            if !self.flow_type.has_fallthrough() {
                return None;
            }
            context.get_address().add_no_wrap(i64::from(self.length)).ok()
        }

        fn get_fall_through_offset(&self, _context: &dyn LangInstructionContext) -> i32 {
            self.length
        }

        fn get_flows(&self, _context: &dyn LangInstructionContext) -> Option<Vec<Address>> {
            if self.flows.is_empty() {
                None
            } else {
                Some(self.flows.clone())
            }
        }

        fn get_separator(&self, operand_index: i32) -> Option<String> {
            if operand_index > 0 && operand_index < self.num_operands {
                Some(",".to_string())
            } else {
                None
            }
        }

        fn get_op_representation_list(
            &self,
            operand_index: i32,
            _context: &dyn LangInstructionContext,
        ) -> Option<Vec<OperandValue>> {
            if operand_index < 0 || operand_index >= self.num_operands {
                return None;
            }
            Some(vec![OperandValue::Text(format!("op{operand_index}"))])
        }

        fn get_address(
            &self,
            _operand_index: i32,
            _context: &dyn LangInstructionContext,
        ) -> Option<Address> {
            None
        }

        fn get_register(
            &self,
            _operand_index: i32,
            _context: &dyn LangInstructionContext,
        ) -> Option<RegisterRef> {
            None
        }

        fn get_scalar(
            &self,
            operand_index: i32,
            _context: &dyn LangInstructionContext,
        ) -> Option<Scalar> {
            Some(Scalar::new(32, i64::from(operand_index)))
        }

        fn get_op_objects(
            &self,
            operand_index: i32,
            _context: &dyn LangInstructionContext,
        ) -> Vec<OperandValue> {
            vec![OperandValue::Text(format!("obj{operand_index}"))]
        }

        fn get_operand_ref_type(
            &self,
            _operand_index: i32,
            _context: &dyn LangInstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> RefType {
            RefType::Data
        }

        fn has_delimeter(&self, _operand_index: i32) -> bool {
            false
        }

        fn get_input_objects(&self, _context: &dyn LangInstructionContext) -> Vec<OperandValue> {
            vec![OperandValue::Text("in".to_string())]
        }

        fn get_result_objects(&self, _context: &dyn LangInstructionContext) -> Vec<OperandValue> {
            vec![OperandValue::Text("out".to_string())]
        }

        fn get_pcode(
            &self,
            _context: &dyn LangInstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_pcode_packed(
            &self,
            _encoder: &mut dyn PatchEncoder,
            _context: &dyn LangInstructionContext,
            _override_: Option<&dyn PcodeOverride>,
        ) -> io::Result<()> {
            unimplemented!("{UNEXERCISED}")
        }

        fn get_pcode_for_operand(
            &self,
            _context: &dyn LangInstructionContext,
            _operand_index: i32,
        ) -> Vec<PcodeOp> {
            Vec::new()
        }

        fn get_language(&self) -> Arc<dyn Language> {
            self.language.clone()
        }
    }

    // -- Fixtures ---------------------------------------------------------------------------

    /// Sixteen bytes of memory starting at 0x1000.
    const MEM: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];

    fn test_owner() -> (Arc<TestCodeUnitOwner>, Arc<dyn CodeUnitOwner>) {
        let owner = Arc::new(TestCodeUnitOwner::new(
            AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1),
            0x1000,
            MEM.to_vec(),
        ));
        let dynamic: Arc<dyn CodeUnitOwner> = owner.clone();
        (owner, dynamic)
    }

    /// An instruction at 0x1000 built from `proto`, with no flags set.
    fn instruction_with(
        owner: &Arc<dyn CodeUnitOwner>,
        proto: TestPrototype,
    ) -> Arc<InstructionDB> {
        InstructionDB::new(
            owner.clone(),
            mock_address(0x1000),
            0x1000,
            Arc::new(proto),
            0,
        )
    }

    /// The default fixture: a 4-byte, 2-operand, falls-through instruction at 0x1000.
    fn instruction(owner: &Arc<dyn CodeUnitOwner>) -> Arc<InstructionDB> {
        instruction_with(owner, TestPrototype::new(4))
    }

    // -- Construction and geometry ----------------------------------------------------------

    #[test]
    fn construction_reports_its_prototype_length_and_address_range() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        assert_eq!(instr.get_length(), 4);
        assert_eq!(instr.get_min_address(), mock_address(0x1000));
        assert_eq!(instr.get_max_address(), mock_address(0x1003));
        assert!(instr.contains(&mock_address(0x1003)));
        assert!(!instr.contains(&mock_address(0x1004)));
        assert_eq!(instr.get_num_operands(), 2);
        assert_eq!(instr.get_mnemonic_string(), "MOV");
        assert!(!instr.is_length_overridden());
        assert!(!instr.is_fall_through_overridden());
        assert_eq!(instr.get_flow_override(), FlowOverride::None);
        assert_eq!(instr.get_key(), 0x1000);

        // The byte window comes from real memory, through CodeUnitDbBase.
        assert_eq!(CodeUnit::get_bytes(&*instr).unwrap(), vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(MemBuffer::get_byte(&*instr, 1).unwrap(), 0x22);
        assert_eq!(MemBuffer::get_address(&*instr), mock_address(0x1000));

        // ... and it is usable through every trait it implements.
        let as_instruction: Arc<dyn Instruction> = instr.clone();
        assert_eq!(as_instruction.get_length(), 4);
        assert!(as_instruction.as_instruction().is_some());
    }

    #[test]
    fn mnemonic_string_is_cached_until_a_refresh_clears_it() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        assert_eq!(instr.get_mnemonic_string(), "MOV");
        // Second call is served from the `mnemonicString` field.
        assert_eq!(instr.get_mnemonic_string(), "MOV");
    }

    // -- Length override --------------------------------------------------------------------

    #[test]
    fn length_override_shrinks_the_code_unit_and_writes_the_flag_byte() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        // Memoize the end address first, to prove the override invalidates it.
        assert_eq!(instr.get_max_address(), mock_address(0x1003));

        instr.do_set_length_override_checked(2).unwrap();

        assert!(instr.is_length_overridden());
        assert_eq!(instr.get_length(), 2);
        assert_eq!(instr.get_max_address(), mock_address(0x1001));
        // The parsed length/bytes still describe the whole prototype.
        assert_eq!(instr.get_parsed_length(), 4);
        assert_eq!(
            instr.get_parsed_bytes().unwrap(),
            vec![0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(CodeUnit::get_bytes(&*instr).unwrap(), vec![0x11, 0x22]);

        // Java: `flags |= (len << LENGTH_OVERRIDE_SHIFT); codeMgr.setFlags(addr, flags);`
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x20)]);
        assert_eq!(instr.flags(), 0x20);
    }

    #[test]
    fn length_override_makes_the_preferred_cache_length_diverge_from_the_length() {
        let (_owner, dynamic) = test_owner();

        // Without delay slots the cache length is just the (overridden) length.
        let plain = instruction(&dynamic);
        assert_eq!(plain.get_preferred_cache_length(), 4);
        plain.do_set_length_override_checked(2).unwrap();
        assert_eq!(plain.get_preferred_cache_length(), 2);

        // With delay slots Java caches the first delay slot too: `length * 2`.
        let delayed = instruction_with(&dynamic, TestPrototype::new(4).with_delay_slots());
        assert_eq!(delayed.get_length(), 4);
        assert_eq!(delayed.get_preferred_cache_length(), 8);
        assert_ne!(delayed.get_preferred_cache_length(), delayed.get_length());

        delayed.do_set_length_override_checked(2).unwrap();
        assert_eq!(delayed.get_length(), 2);
        assert_eq!(delayed.get_preferred_cache_length(), 4);
        assert_ne!(delayed.get_preferred_cache_length(), delayed.get_length());
        assert_eq!(delayed.get_delay_slot_depth(), 1);
    }

    #[test]
    fn length_override_of_zero_or_the_full_length_imposes_no_override() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_length_override_checked(0).unwrap();
        assert!(!instr.is_length_overridden());
        instr.do_set_length_override_checked(4).unwrap();
        assert!(!instr.is_length_overridden());
        // Java's checkLengthOverride also ignores a length larger than the prototype's.
        instr.do_set_length_override_checked(6).unwrap();
        assert!(!instr.is_length_overridden());
        assert_eq!(instr.get_length(), 4);
        // None of those changed anything, so no flag write was made.
        assert!(owner.flag_calls().is_empty());
    }

    #[test]
    fn length_override_must_be_a_multiple_of_the_instruction_alignment() {
        let (owner, dynamic) = test_owner();
        let instr = instruction_with(&dynamic, TestPrototype::new(4).with_alignment(2));

        let error = instr.do_set_length_override_checked(3).unwrap_err();
        assert_eq!(
            error.message(),
            "Length(3) override must be a multiple of 2 bytes"
        );
        assert!(!instr.is_length_overridden());
        assert!(owner.flag_calls().is_empty());

        // An aligned value of the same magnitude is accepted.
        instr.do_set_length_override_checked(2).unwrap();
        assert_eq!(instr.get_length(), 2);
    }

    #[test]
    fn length_override_beyond_the_maximum_is_rejected() {
        let (_owner, dynamic) = test_owner();
        // A prototype long enough that 8 is a *shrink*, so only MAX_LENGTH_OVERRIDE rejects it.
        let instr = instruction_with(&dynamic, TestPrototype::new(12));

        let error = instr
            .do_set_length_override_checked(MAX_LENGTH_OVERRIDE + 1)
            .unwrap_err();
        assert_eq!(error.message(), "Unsupported length override: 8");
        assert!(!instr.is_length_overridden());

        // The largest supported value is accepted.
        instr
            .do_set_length_override_checked(MAX_LENGTH_OVERRIDE)
            .unwrap();
        assert_eq!(instr.get_length(), MAX_LENGTH_OVERRIDE);
    }

    #[test]
    #[should_panic(expected = "Negative length not permitted")]
    fn a_negative_length_override_panics() {
        let proto = TestPrototype::new(4);
        // Java throws IllegalArgumentException from the static checkLengthOverride.
        let _ = InstructionDB::check_length_override(-1, &proto);
    }

    #[test]
    fn growing_a_length_override_that_collides_with_the_next_code_unit_is_rejected() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_length_override_checked(2).unwrap();
        assert_eq!(instr.get_length(), 2);

        // A code unit now sits at 0x1002, inside the range restoring the full length would need.
        owner.set_defined_address_after(Some(mock_address(0x1002)));
        let error = instr.do_set_length_override_checked(0).unwrap_err();
        assert_eq!(
            error.message(),
            "Length override of 4 conflicts with code unit at ram:0x1002"
        );
        assert_eq!(instr.get_length(), 2, "the override must be left in place");

        // Moving that code unit out of the way lets the restore succeed.
        owner.set_defined_address_after(Some(mock_address(0x1004)));
        instr.do_set_length_override_checked(0).unwrap();
        assert!(!instr.is_length_overridden());
        assert_eq!(instr.get_length(), 4);
    }

    #[test]
    fn a_length_override_adds_a_fall_through_reference_to_the_default_target() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        assert!(instr.get_references_from().is_empty());

        instr.do_set_length_override_checked(2).unwrap();

        // Java: length-override always uses the *default* fall-through address, i.e. the
        // prototype length past the start, not the shortened length.
        let refs = instr.get_references_from();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].reference_type(), RefType::FallThrough);
        assert_eq!(refs[0].to_address(), mock_address(0x1004));
        assert_eq!(instr.get_default_fall_through(), Some(mock_address(0x1004)));
    }

    #[test]
    fn static_length_helpers_mirror_the_flag_encoding() {
        let proto = TestPrototype::new(4);
        assert_eq!(InstructionDB::length_of(&proto, 0), 4);
        // 2 << LENGTH_OVERRIDE_SHIFT
        assert_eq!(InstructionDB::length_of(&proto, 0x20), 2);
        // An override that is not smaller than the prototype length is ignored.
        assert_eq!(InstructionDB::length_of(&proto, 0x40), 4);
        assert_eq!(InstructionDB::length_of(&proto, 0x70), 4);
        // Other flag bits do not disturb it.
        assert_eq!(InstructionDB::length_of(&proto, 0x21), 2);
    }

    // -- Fall-through override --------------------------------------------------------------

    #[test]
    fn clearing_a_fall_through_that_is_not_overridden_does_nothing() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_clear_fall_through_override();

        assert!(!instr.is_fall_through_overridden());
        assert!(owner.flag_calls().is_empty());
    }

    #[test]
    fn setting_a_null_fall_through_marks_the_override_and_drops_the_fall_through() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        assert_eq!(instr.get_fall_through(), Some(mock_address(0x1004)));
        assert!(instr.has_fallthrough());
        assert!(instr.is_fallthrough());

        // Java: fall-through eliminated (terminal flow) - no reference added.
        instr.do_set_fall_through(None);

        assert!(instr.is_fall_through_overridden());
        assert_eq!(instr.get_fall_through(), None);
        assert!(!instr.has_fallthrough());
        assert!(!instr.is_fallthrough());
        assert!(instr.get_references_from().is_empty());
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x01)]);
        // The default fall-through is untouched by the override.
        assert_eq!(instr.get_default_fall_through(), Some(mock_address(0x1004)));
    }

    #[test]
    fn setting_the_fall_through_back_to_the_default_clears_the_override() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_fall_through(None);
        assert!(instr.is_fall_through_overridden());

        // Java short-circuits to clearFallThroughOverride() when the address matches the
        // prototype's own fall-through.
        instr.do_set_fall_through(Some(mock_address(0x1004)));

        assert!(!instr.is_fall_through_overridden());
        assert_eq!(instr.get_fall_through(), Some(mock_address(0x1004)));
        assert!(instr.has_fallthrough());
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x01), (0x1000, 0x00)]);
    }

    #[test]
    fn setting_a_non_default_fall_through_adds_the_reference_the_callback_keys_off() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_fall_through(Some(mock_address(0x2000)));

        // Java adds the reference and lets the reference manager call back into
        // fallThroughChanged; the test reference manager makes no such callback, so only the
        // reference is present at this point.
        let refs = instr.get_references_from();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_address(), mock_address(0x2000));
        assert_eq!(refs[0].reference_type(), RefType::FallThrough);
    }

    #[test]
    fn the_fall_through_changed_callback_drives_the_override_flag() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        // Stand in for ReferenceDBManager adding a user fall-through reference and calling back.
        instr.do_set_fall_through(Some(mock_address(0x2000)));
        let added = instr.get_references_from()[0].clone();
        instr.fall_through_changed(Some(&*added));

        assert!(instr.is_fall_through_overridden());
        assert_eq!(instr.get_fall_through(), Some(mock_address(0x2000)));
        assert!(instr.has_fallthrough());
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x01)]);

        // Removing the reference clears the override again.
        instr.fall_through_changed(None);
        assert!(!instr.is_fall_through_overridden());
        assert_eq!(instr.get_fall_through(), Some(mock_address(0x1004)));
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x01), (0x1000, 0x00)]);
    }

    #[test]
    fn the_callback_keeps_only_one_fall_through_reference() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_fall_through(Some(mock_address(0x2000)));
        instr.do_set_fall_through(Some(mock_address(0x3000)));
        assert_eq!(instr.get_references_from().len(), 2);

        // clearFallThroughRefs preserves exactly the one matching the new target.
        let kept = mock_address(0x3000);
        let reference = instr
            .get_references_from()
            .into_iter()
            .find(|r| r.to_address() == kept)
            .unwrap();
        instr.fall_through_changed(Some(&*reference));

        let refs = instr.get_references_from();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_address(), kept);
        assert!(instr.is_fall_through_overridden());
    }

    #[test]
    fn clearing_the_override_deletes_the_fall_through_references() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_fall_through(Some(mock_address(0x2000)));
        let added = instr.get_references_from()[0].clone();
        instr.fall_through_changed(Some(&*added));
        assert!(instr.is_fall_through_overridden());

        instr.do_clear_fall_through_override();

        assert!(!instr.is_fall_through_overridden());
        assert!(instr.get_references_from().is_empty());
        assert_eq!(instr.get_fall_through(), Some(mock_address(0x1004)));
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x01), (0x1000, 0x00)]);
    }

    #[test]
    fn a_length_overridden_instruction_restores_its_fall_through_ref_when_the_override_clears() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        instr.do_set_length_override_checked(2).unwrap();
        let length_override_ref = instr.get_references_from()[0].clone();
        assert_eq!(length_override_ref.to_address(), mock_address(0x1004));

        // A user fall-through elsewhere takes over ...
        instr.do_set_fall_through(Some(mock_address(0x2000)));
        let user_ref = instr
            .get_references_from()
            .into_iter()
            .find(|r| r.to_address() == mock_address(0x2000))
            .unwrap();
        instr.fall_through_changed(Some(&*user_ref));
        assert!(instr.is_fall_through_overridden());
        assert_eq!(instr.get_references_from().len(), 1);

        // ... and clearing it restores the length-override fall-through, per Java's
        // addLengthOverrideFallthroughRef.
        instr.do_clear_fall_through_override();
        let refs = instr.get_references_from();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].to_address(), mock_address(0x1004));
        assert!(!instr.is_fall_through_overridden());
        assert!(instr.is_length_overridden());
    }

    #[test]
    fn has_fallthrough_follows_the_flow_type_when_not_overridden() {
        let (_owner, dynamic) = test_owner();

        let falls = instruction_with(&dynamic, TestPrototype::new(4));
        assert!(falls.has_fallthrough());
        assert!(falls.is_fallthrough());

        // UNCONDITIONAL_JUMP does not fall through at all.
        let jumps = instruction_with(
            &dynamic,
            TestPrototype::new(4).with_flow_type(RefType::UnconditionalJump),
        );
        assert!(!jumps.has_fallthrough());
        assert!(!jumps.is_fallthrough());
        assert_eq!(jumps.get_default_fall_through(), None);
        assert_eq!(jumps.get_fall_through(), None);

        // UNCONDITIONAL_CALL falls through, but is not itself a fall-through flow.
        let calls = instruction_with(
            &dynamic,
            TestPrototype::new(4).with_flow_type(RefType::UnconditionalCall),
        );
        assert!(calls.has_fallthrough());
        assert!(!calls.is_fallthrough());
    }

    // -- Flow override ----------------------------------------------------------------------

    #[test]
    fn setting_a_flow_override_rewrites_the_flow_type_and_the_flag_byte() {
        let (owner, dynamic) = test_owner();
        let instr = instruction_with(
            &dynamic,
            TestPrototype::new(4).with_flow_type(RefType::UnconditionalCall),
        );
        assert_eq!(instr.get_flow_type(), RefType::UnconditionalCall);

        instr.do_set_flow_override(FlowOverride::Branch);

        assert_eq!(instr.get_flow_override(), FlowOverride::Branch);
        assert_eq!(instr.get_flow_type(), RefType::UnconditionalJump);
        // Branch is ordinal 1, shifted left by FLOW_OVERRIDE_SHIFT.
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x02)]);
        assert_eq!(instr.flags(), 0x02);

        // Setting the same override again is a no-op.
        instr.do_set_flow_override(FlowOverride::Branch);
        assert_eq!(owner.flag_calls().len(), 1);

        // RETURN is ordinal 4 -> 0x08.
        instr.do_set_flow_override(FlowOverride::Return);
        assert_eq!(instr.get_flow_type(), RefType::Terminator);
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x02), (0x1000, 0x08)]);

        // ... and clearing it restores the prototype's own flow type.
        instr.do_set_flow_override(FlowOverride::None);
        assert_eq!(instr.get_flow_type(), RefType::UnconditionalCall);
        assert_eq!(instr.flags(), 0x00);
    }

    #[test]
    fn a_flow_override_does_not_disturb_the_other_flag_bits() {
        let (owner, dynamic) = test_owner();
        let instr = instruction_with(
            &dynamic,
            TestPrototype::new(4).with_flow_type(RefType::UnconditionalCall),
        );

        instr.do_set_length_override_checked(2).unwrap();
        instr.do_set_flow_override(FlowOverride::Return);

        assert_eq!(instr.flags(), 0x28, "length override bits must survive");
        assert!(instr.is_length_overridden());
        assert_eq!(instr.get_length(), 2);
        assert_eq!(owner.flag_calls(), vec![(0x1000, 0x20), (0x1000, 0x28)]);
    }

    #[test]
    fn a_return_override_hides_a_lone_flow() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction_with(
            &dynamic,
            TestPrototype::new(4)
                .with_flow_type(RefType::UnconditionalCall)
                .with_flows(vec![mock_address(0x2000)]),
        );

        assert_eq!(instr.get_default_flows(), Some(vec![mock_address(0x2000)]));

        instr.do_set_flow_override(FlowOverride::Return);
        // Java: `if (flowOverride == RETURN && flows.length == 1) return EMPTY_ADDR_ARRAY;`
        assert_eq!(instr.get_default_flows(), None);
    }

    #[test]
    fn get_flows_reads_the_non_indirect_flow_references() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction_with(
            &dynamic,
            TestPrototype::new(4).with_flow_type(RefType::UnconditionalCall),
        );
        assert_eq!(instr.get_flows(), None);

        {
            let reference_manager = dynamic.get_reference_manager();
            let mut reference_manager = reference_manager.lock().unwrap();
            reference_manager.add_memory_reference(
                mock_address(0x1000),
                mock_address(0x2000),
                RefType::UnconditionalCall,
                SourceType::UserDefined,
                0,
            );
            reference_manager.add_memory_reference(
                mock_address(0x1000),
                mock_address(0x3000),
                RefType::Indirection,
                SourceType::UserDefined,
                1,
            );
        }

        // The INDIRECTION reference is filtered out; the call reference is kept.
        assert_eq!(instr.get_flows(), Some(vec![mock_address(0x2000)]));

        // With a RETURN override a lone flow disappears, as in getDefaultFlows.
        instr.do_set_flow_override(FlowOverride::Return);
        assert_eq!(instr.get_flows(), None);
    }

    #[test]
    fn modified_flow_type_is_a_faithful_port_of_the_java_table() {
        // A flow that is neither jump, terminal nor call is never modified.
        assert_eq!(
            modified_flow_type(RefType::FallThrough, FlowOverride::Branch),
            RefType::FallThrough
        );
        // NONE never modifies anything.
        assert_eq!(
            modified_flow_type(RefType::UnconditionalCall, FlowOverride::None),
            RefType::UnconditionalCall
        );
        // BRANCH.
        assert_eq!(
            modified_flow_type(RefType::UnconditionalJump, FlowOverride::Branch),
            RefType::UnconditionalJump
        );
        assert_eq!(
            modified_flow_type(RefType::ConditionalCall, FlowOverride::Branch),
            RefType::ConditionalJump
        );
        assert_eq!(
            modified_flow_type(RefType::ComputedCall, FlowOverride::Branch),
            RefType::ComputedJump
        );
        assert_eq!(
            modified_flow_type(RefType::Terminator, FlowOverride::Branch),
            RefType::ComputedJump
        );
        // CALL.
        assert_eq!(
            modified_flow_type(RefType::UnconditionalJump, FlowOverride::Call),
            RefType::UnconditionalCall
        );
        assert_eq!(
            modified_flow_type(RefType::ConditionalJump, FlowOverride::Call),
            RefType::ConditionalCall
        );
        assert_eq!(
            modified_flow_type(RefType::JumpTerminator, FlowOverride::Call),
            RefType::CallTerminator
        );
        assert_eq!(
            modified_flow_type(RefType::Terminator, FlowOverride::Call),
            RefType::ComputedCall
        );
        // CALL_RETURN.
        assert_eq!(
            modified_flow_type(RefType::UnconditionalCall, FlowOverride::CallReturn),
            RefType::CallTerminator
        );
        assert_eq!(
            modified_flow_type(RefType::ComputedJump, FlowOverride::CallReturn),
            RefType::ComputedCallTerminator
        );
        assert_eq!(
            modified_flow_type(RefType::ConditionalCall, FlowOverride::CallReturn),
            RefType::ConditionalCall
        );
        // RETURN.
        assert_eq!(
            modified_flow_type(RefType::UnconditionalCall, FlowOverride::Return),
            RefType::Terminator
        );
        assert_eq!(
            modified_flow_type(RefType::ConditionalJump, FlowOverride::Return),
            RefType::ConditionalTerminator
        );
    }

    #[test]
    fn flow_override_ordinals_round_trip_through_the_flag_bits() {
        for expected in FLOW_OVERRIDE_VALUES {
            let ordinal = flow_override_ordinal(expected);
            assert_eq!(flow_override_from_ordinal(i32::from(ordinal)), expected);
        }
        // Java's getFlowOverride answers NONE for an unknown ordinal.
        assert_eq!(flow_override_from_ordinal(7), FlowOverride::None);
        assert_eq!(flow_override_from_ordinal(-1), FlowOverride::None);
    }

    #[test]
    fn construction_decodes_the_flow_and_length_overrides_from_the_flag_byte() {
        let (_owner, dynamic) = test_owner();
        // CALL_RETURN (ordinal 3 -> 0x06) plus a length override of 2 (0x20) plus fall-through.
        let instr = InstructionDB::new(
            dynamic.clone(),
            mock_address(0x1000),
            0x1000,
            Arc::new(TestPrototype::new(4).with_flow_type(RefType::UnconditionalCall)),
            0x27,
        );

        assert_eq!(instr.get_flow_override(), FlowOverride::CallReturn);
        assert!(instr.is_length_overridden());
        assert_eq!(instr.get_length(), 2);
        assert!(instr.is_fall_through_overridden());
        assert_eq!(instr.get_flow_type(), RefType::CallTerminator);
    }

    // -- Navigation -------------------------------------------------------------------------

    #[test]
    fn get_next_and_get_previous_ask_the_owner() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        assert!(instr.get_next().is_none());
        assert!(instr.get_previous().is_none());

        owner.put_instruction(
            0x1004,
            mock_instruction(mock_address(0x1004), mock_address(0x1007)),
        );
        owner.put_instruction(
            0x0ffc,
            mock_instruction(mock_address(0x0ffc), mock_address(0x0fff)),
        );

        assert_eq!(
            instr.get_next().unwrap().get_min_address(),
            mock_address(0x1004)
        );
        assert_eq!(
            instr.get_previous().unwrap().get_min_address(),
            mock_address(0x0ffc)
        );
    }

    // -- Refresh / deletion -----------------------------------------------------------------

    /// An instruction-table record for `addr` referring to prototype `proto_id`.
    fn instruction_record(addr: i64, proto_id: i32, flags: u8) -> DBRecord {
        let mut record = DBRecord::new(inst_db_adapter::schema(), Field::Long(Some(addr)));
        record.set_int(PROTO_ID_COL, proto_id);
        record.set_byte(FLAGS_COL, flags as i8);
        record
    }

    #[test]
    fn a_missing_instruction_record_means_the_instruction_was_deleted() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        // Nothing in the instruction table at this address.
        assert!(instr.has_been_deleted(None));
        assert!(!instr.refresh(None));
    }

    #[test]
    fn refreshing_against_its_own_record_reloads_the_flag_byte() {
        let (owner, dynamic) = test_owner();
        let proto: Arc<dyn InstructionPrototype> =
            Arc::new(TestPrototype::new(4).with_flow_type(RefType::UnconditionalCall));
        let instr = InstructionDB::new(
            dynamic.clone(),
            mock_address(0x1000),
            0x1000,
            proto.clone(),
            0,
        );
        owner.put_instruction_prototype(7, proto);
        // The stored record carries a RETURN flow override and a length override of 2.
        owner.put_instruction_record(0x1000, instruction_record(0x1000, 7, 0x28));

        assert!(!instr.has_been_deleted(None));

        assert_eq!(instr.get_flow_override(), FlowOverride::Return);
        assert_eq!(instr.get_flow_type(), RefType::Terminator);
        assert!(instr.is_length_overridden());
        assert_eq!(instr.get_length(), 2);
        assert_eq!(instr.flags(), 0x28);

        // The full refresh path also drops the base's caches and reports "not deleted".
        assert!(instr.refresh(None));
    }

    #[test]
    fn a_record_naming_a_different_prototype_means_the_instruction_was_deleted() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        // Prototype 7 exists, but is a *different* prototype object than the instruction's.
        owner.put_instruction_prototype(7, Arc::new(TestPrototype::new(4)));
        owner.put_instruction_record(0x1000, instruction_record(0x1000, 7, 0));

        assert!(instr.has_been_deleted(None));
    }

    #[test]
    fn a_record_whose_prototype_is_missing_means_the_instruction_was_deleted() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        // Record refers to prototype 9, which the owner cannot resolve.
        owner.put_instruction_record(0x1000, instruction_record(0x1000, 9, 0));

        assert!(instr.has_been_deleted(None));
    }

    #[test]
    fn a_record_from_another_table_is_rejected_by_the_schema_check() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        // Java: `else if (!rec.hasSameSchema(InstDBAdapter.INSTRUCTION_SCHEMA)) return true;` --
        // after an undo/redo the record at this key can belong to a different code unit type.
        let foreign = DBRecord::new(comments_db_adapter::schema(), Field::Long(Some(0x1000)));
        assert!(instr.has_been_deleted(Some(&foreign)));

        // Its own schema is accepted (and then fails on the missing prototype, not the schema).
        let own = instruction_record(0x1000, 7, 0);
        assert!(InstructionDB::has_instruction_schema(&own));
        assert!(!InstructionDB::has_instruction_schema(&foreign));
    }

    #[test]
    fn a_refresh_drops_the_mnemonic_cache_and_the_base_caches() {
        let (owner, dynamic) = test_owner();
        let proto: Arc<dyn InstructionPrototype> = Arc::new(TestPrototype::new(4));
        let instr = InstructionDB::new(
            dynamic.clone(),
            mock_address(0x1000),
            0x1000,
            proto.clone(),
            0,
        );
        owner.put_instruction_prototype(1, proto);
        owner.put_instruction_record(0x1000, instruction_record(0x1000, 1, 0));

        assert_eq!(instr.get_mnemonic_string(), "MOV");
        assert_eq!(MemBuffer::get_byte(&*instr, 0).unwrap(), 0x11);

        owner.memory().poke(0, 0xee);
        assert_eq!(
            MemBuffer::get_byte(&*instr, 0).unwrap(),
            0x11,
            "still cached"
        );

        assert!(instr.refresh(None));
        assert_eq!(MemBuffer::get_byte(&*instr, 0).unwrap(), 0xee);
        assert_eq!(instr.get_mnemonic_string(), "MOV");
    }

    // -- Rendering and equality -------------------------------------------------------------

    #[test]
    fn code_unit_string_renders_the_mnemonic_and_default_operands() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        // "MOV" + ' ' + "op0" + "," + "op1"
        assert_eq!(instr.code_unit_string(), "MOV op0,op1");
        assert_eq!(instr.to_string(), "MOV op0,op1");
        assert_eq!(instr.get_default_operand_representation(0), "op0");
        // An out-of-range operand has no representation list at all.
        assert_eq!(instr.get_default_operand_representation(9), "<UNSUPPORTED>");
    }

    #[test]
    fn operand_accessors_delegate_to_the_prototype() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        assert!(matches!(
            instr.get_op_objects(0).as_slice(),
            [OperandValue::Text(text)] if text == "obj0"
        ));
        assert!(instr.get_op_objects(-1).is_empty());
        assert!(instr.get_op_objects(2).is_empty());
        assert!(matches!(
            instr.get_input_objects().as_slice(),
            [OperandValue::Text(text)] if text == "in"
        ));
        assert!(matches!(
            instr.get_result_objects().as_slice(),
            [OperandValue::Text(text)] if text == "out"
        ));
        assert_eq!(Instruction::get_separator(&*instr, 1).as_deref(), Some(","));
        assert_eq!(Instruction::get_separator(&*instr, 0), None);
        assert_eq!(instr.get_operand_ref_type(0), RefType::Data);
        // Java returns null for an out-of-range operand index.
        assert_eq!(instr.get_operand_ref_type(9), RefType::Invalid);
        assert_eq!(instr.get_operand_type(0), 0);
        assert_eq!(CodeUnit::get_scalar(&*instr, 1).unwrap().get_value(), 1);
        assert_eq!(CodeUnit::get_scalar(&*instr, 9), None);
        assert!(Instruction::get_register(&*instr, 0).is_none());
        assert!(CodeUnit::get_address(&*instr, 0).is_none());
        assert!(!instr.is_in_delay_slot());
        assert_eq!(instr.get_delay_slot_depth(), 0);
        assert!(instr.get_pcode().is_empty());
        assert!(instr.get_pcode_with_overrides(true).is_empty());
        assert!(instr.get_pcode_for_operand(0).is_empty());
    }

    #[test]
    fn an_operand_reference_marks_the_operand_type_as_an_address() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        dynamic
            .get_reference_manager()
            .lock()
            .unwrap()
            .add_memory_reference(
                mock_address(0x1000),
                mock_address(0x2000),
                RefType::Data,
                SourceType::UserDefined,
                0,
            );

        // Java ORs in OperandType.ADDRESS when the primary reference targets memory.
        assert_eq!(instr.get_operand_type(0), OperandType::ADDRESS as i32);
        // Java's getAddress(int) prefers the primary reference's target.
        assert_eq!(
            CodeUnit::get_address(&*instr, 0),
            Some(mock_address(0x2000))
        );
    }

    #[test]
    fn equality_compares_the_address_index_the_owner_and_the_prototype() {
        let (_owner_a, dynamic_a) = test_owner();
        let (_owner_b, dynamic_b) = test_owner();
        let proto: Arc<dyn InstructionPrototype> = Arc::new(TestPrototype::new(4));

        let a = InstructionDB::new(
            dynamic_a.clone(),
            mock_address(0x1000),
            0x1000,
            proto.clone(),
            0,
        );
        let same = InstructionDB::new(
            dynamic_a.clone(),
            mock_address(0x1000),
            0x1000,
            proto.clone(),
            0,
        );
        let elsewhere = InstructionDB::new(
            dynamic_a.clone(),
            mock_address(0x1004),
            0x1004,
            proto.clone(),
            0,
        );
        let other_owner = InstructionDB::new(
            dynamic_b.clone(),
            mock_address(0x1000),
            0x1000,
            proto.clone(),
            0,
        );
        let other_proto = InstructionDB::new(
            dynamic_a.clone(),
            mock_address(0x1000),
            0x1000,
            Arc::new(TestPrototype::new(4)),
            0,
        );

        assert!(*a == *same);
        assert!(*a != *elsewhere);
        assert!(*a != *other_owner);
        assert!(*a != *other_proto);
    }

    #[test]
    fn the_instruction_hands_itself_back_out_as_its_own_context() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);

        // Java's getInstructionContext()/getMemBuffer()/getProcessorContext() all return `this`.
        let context = instr.get_instruction_context();
        assert_eq!(Arc::strong_count(&instr), 2, "the context handle is `self`");
        drop(context);
        assert_eq!(
            LangInstructionContext::get_address(&*instr),
            mock_address(0x1000)
        );
        assert_eq!(
            instr.get_mem_buffer().get_address(),
            mock_address(0x1000)
        );
    }

    #[test]
    fn get_fall_from_is_not_yet_portable() {
        let (_owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        // Documented TODO(port): the Java walk needs Listing.getInstructionContaining and
        // SymbolTable.hasSymbol, neither of which is reachable from a code unit here.
        assert_eq!(instr.get_fall_from(), None);
    }

    #[test]
    fn comments_and_properties_forward_to_the_shared_base() {
        let (owner, dynamic) = test_owner();
        let instr = instruction(&dynamic);
        let mut handle = InstructionDB::new(
            dynamic.clone(),
            mock_address(0x1004),
            0x1004,
            Arc::new(TestPrototype::new(4)),
            0,
        );
        let neighbour = Arc::get_mut(&mut handle);
        assert!(neighbour.is_none(), "a self-referential Arc is never unique");

        instr.base().set_comment(CommentType::Eol, Some("hi".to_string()));
        assert_eq!(instr.get_comment(CommentType::Eol).as_deref(), Some("hi"));
        assert_eq!(instr.get_comment_as_array(CommentType::Eol), vec!["hi"]);
        assert_eq!(owner.comment_record_count(), 1);

        instr.base().set_int_property("count", 3);
        assert_eq!(PropertySet::get_int_property(&*instr, "count").unwrap(), 3);
        assert!(PropertySet::has_property(&*instr, "count"));
        assert_eq!(
            PropertySet::property_names(&*instr).collect::<Vec<_>>(),
            vec!["count".to_string()]
        );
        assert_eq!(instr.get_address_string(true, false), "text:1000");
        assert!(instr.get_label().is_none());
        assert!(instr.get_symbols().is_empty());
    }
}
