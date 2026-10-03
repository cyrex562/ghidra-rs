//! Port of `ghidra.program.database.oldfunction.OldStackFrameDB`.
//!
//! The real, concrete [`StackFrame`] representation the whole `oldfunction` package exists to
//! support: reads an [`OldFunctionDataDB`]'s stack/register parameter offsets plus every stack
//! variable record from the [`OldStackVariableDBAdapter`], and answers every read-only
//! [`StackFrame`] query (`getStackVariables`/`getLocals`/`getParameters`/`getFrameSize`/
//! `getVariableContaining`/etc.) purely from that loaded state.
//!
//! ## Construction and `refresh`
//!
//! Java's constructor (`OldStackFrameDB(OldFunctionDataDB function)`) just calls `refresh()`,
//! which is never called again by anything else in the whole Ghidra source tree -- so in practice
//! this state is computed exactly once. [`OldStackFrameDB::new`]/[`OldStackFrameDB::refresh`] are
//! nonetheless both ported faithfully (`refresh` as a real, callable method, using `Cell`/
//! `RefCell` for its backing fields) rather than collapsing `refresh`'s logic into `new` alone, in
//! case a future caller needs it.
//!
//! ## The `Variable` objects this frame hands out
//!
//! Java's private `getStackVariable(DBRecord)` builds a `ParameterImpl` or `LocalVariableImpl`
//! (chosen by [`is_parameter_offset`](OldStackFrameDB::is_parameter_offset)) -- both trivial
//! `VariableImpl` subclasses adding no behavior beyond their constructor. Since every consumer of
//! this class's `Variable[]`-returning methods (`getStackVariables`/`getLocals`/`getParameters`/
//! `getVariableContaining`) only ever sees the `Variable` interface, never `Parameter`, this port
//! uses a single concrete [`OldStackVariableImpl`] for both cases (see its own docs), matching the
//! two Java classes' identical externally-observable behavior. It is built via
//! [`init_fields`] with `stack_offset = Some(offset)`, exactly mirroring what the real
//! `ParameterImpl(name, dataType, offset, program)`/`LocalVariableImpl(name, dataType, offset,
//! program)` constructors do internally.
//!
//! Unlike Java (whose `variables` list holds shared object references, so external mutation
//! through a returned `Variable` would be visible on the next `getStackVariables()` call too),
//! this port's [`OldStackVariableImpl`] is `Clone` and every accessor hands back an independent
//! clone of the cached value. Nothing in this class ever exercises that Java aliasing behavior
//! (there is no "write it back" path anywhere in this read-only migration package), so this is an
//! unobservable, Rust-idiomatic simplification, not a behavior change.
//!
//! **`getFunction()` always returns `None`** (`Some(None)` never happens): ported verbatim from
//! Java's `public Function getFunction() { return null; }`, which is not a bug so much as an
//! acknowledgment that `OldFunctionDataDB` does not implement the real `Function` interface at
//! all (it is a distinct, informal, pre-2.2-only shape), so there is no real `Function` this
//! method could honestly return.
//!
//! ## The `AddressOutOfBoundsException` fallback
//!
//! `getStackVariable`'s Java body catches `AddressOutOfBoundsException` (thrown when a stack
//! variable's `(offset, dataType.getLength())` doesn't fit within the addressable stack frame)
//! and falls back to `new LocalVariableImpl(name, 0, dataType, VariableStorage.BAD_STORAGE,
//! program)`, logging via `Msg.error`. This port's [`init_fields`] reports the equivalent failure
//! (a data type that doesn't fit at a negative stack offset) as `Err(InvalidInputException)`
//! rather than a distinct exception type; since Java's `getStackVariable` also has a *second*,
//! separate `catch (InvalidInputException e) { throw new RuntimeException(e); }` clause for
//! genuinely unexpected failures, and this port's `Err` cannot be reliably attributed to one
//! Java exception type or the other, every `Err` from [`init_fields`] here is treated as the
//! `AddressOutOfBoundsException` case (log + [`BadStorage`] fallback) rather than propagating a
//! panic -- a deliberate, documented, non-panicking choice (see [`build_stack_variable`]).
//!
//! A [`BadStorage`]-backed variable reports `has_stack_storage() == false`, so
//! [`StackVariableComparator`] sorts it after every real stack variable (matching Java's
//! `StackVariableComparator.getStackOffset` returning `null` for a non-stack-storage variable).
//! Several of `OldStackFrameDB`'s private helpers (`getNegativeSize`/`getPositiveSize`/
//! `getNegativeVariables`/`getPositiveVariables`/`getNegativeCount`/`getPositiveCount`) call
//! `Variable.getStackOffset()` unconditionally at specific list positions; for a real Java
//! `BAD_STORAGE` variable landing at one of those positions (only reachable with already-corrupt
//! legacy data), that call throws `UnsupportedOperationException`, uncaught. This port instead
//! derives each such offset via [`stack_offset`] (`Option`-returning, from the variable's last
//! storage varnode, mirroring [`FunctionStackFrame`](crate::program::database::function::FunctionStackFrame)'s
//! identical `getVariableContaining` technique) and falls back to the same value Java's
//! empty-list branch already uses at that call site -- gracefully degrading instead of panicking,
//! for the reasons [`decoupling-first-class`]/`no unsound unsafe` guidance in this port generally
//! prefers a `Result`/`Option`-shaped recovery over reproducing an unchecked-exception crash.
//!
//! ## A faithfully-preserved real Java quirk
//!
//! `getNegativeVariables`'s and `getNegativeCount`'s scan-break conditions differ by one
//! comparison operator in `OldStackFrameDB.java`: `getNegativeVariables` breaks on `start >= 0 ||
//! start > paramStart` (strictly greater), while `getNegativeCount` breaks on `stackOffset >= 0 ||
//! stackOffset >= paramStart` (greater-or-equal) -- the exact same kind of one-operator divergence
//! already documented and preserved on
//! [`StackFrameImpl`](crate::util::stack_frame_impl::StackFrameImpl)'s own
//! `getNegativeVariables`/`getNegativeCount` pair. For a stack variable whose offset exactly
//! equals a negative `paramStart`, this means `getNegativeVariables().len()` and
//! `getNegativeCount()` can disagree -- preserved here as two separate (not shared) partition
//! helpers, [`negative_variables_partition_end`] and [`negative_count_partition_end`], with a test
//! (`negative_variables_and_negative_count_can_disagree_at_the_param_start_boundary`) proving the
//! divergence.
//!
//! ## Left out of this port
//! - `equals(Object)`: Rust has no `Object` identity contract to satisfy. [`OldStackFrameDB::eq`]
//!   ports its real value-comparison algorithm anyway (mirroring
//!   [`FunctionStackFrame::function_stack_frame_eq`](crate::program::database::function::FunctionStackFrame::function_stack_frame_eq)'s
//!   identical treatment of its own `equals`), since nothing about it is Java-`Object`-specific.
//! - `createVariable`/`clearVariable`/`setLocalSize`/`setReturnAddressOffset`: all unconditional
//!   `UnsupportedOperationException`s in Java (`OldStackFrameDB` is a read-only migration-time
//!   view). `set_local_size`/`set_return_address_offset` (no `Result` in their `StackFrame`
//!   signature) `panic!`; `create_variable` (which does return a `Result`) returns
//!   `Err(InvalidInputException(..).into())` -- the same convention
//!   [`StackFrameImpl`](crate::util::stack_frame_impl::StackFrameImpl) already established for
//!   the identical situation.

use std::cell::{Cell, RefCell};
use std::sync::Arc;

use crate::program::database::oldfunction::old_stack_variable_db_adapter::{
    STACK_VAR_COMMENT_COL, STACK_VAR_DATA_TYPE_ID_COL, STACK_VAR_NAME_COL, STACK_VAR_OFFSET_COL,
};
use crate::program::database::oldfunction::{OldFunctionDataDB, OldFunctionManager};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::variable::UnsupportedOperationError;
use crate::program::model::listing::variable_impl::{init_fields, VariableImpl};
use crate::program::model::listing::{
    BadStorage, CreateStackVariableError, Function, Program, StackFrame, StackVariableComparator,
    StackVariableOperand, Variable, VariableStorage,
};
use crate::program::model::lang::RegisterRef;
use crate::program::model::address::Address;
use crate::program::model::pcode::Varnode;
use crate::program::model::symbol::SourceType;
use crate::program::seam_stubs::{share_data_type, share_variable_storage};
use crate::framework::db::{DBRecord, Field};
use crate::util::exception::InvalidInputException;
use crate::util::msg::Msg;

/// A single stack variable owned by an [`OldStackFrameDB`].
///
/// Stands in for both `ghidra.program.database.function.ParameterImpl` and `LocalVariableImpl` as
/// used by `OldStackFrameDB.getStackVariable` -- see the module docs for why one type covers both.
/// Follows the `stored_*`/`variable_impl_*` delegation convention established by
/// [`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl)'s own docs.
#[derive(Clone)]
pub struct OldStackVariableImpl {
    name: Option<String>,
    data_type: Arc<dyn DataType>,
    comment: Option<String>,
    source_type: SourceType,
    storage: Arc<dyn VariableStorage>,
    program: Arc<dyn Program>,
}

impl VariableImpl for OldStackVariableImpl {
    fn stored_name(&self) -> Option<String> {
        self.name.clone()
    }
    fn set_stored_name(&mut self, name: Option<String>) {
        self.name = name;
    }
    fn stored_data_type(&self) -> Box<dyn DataType> {
        share_data_type(&self.data_type)
    }
    fn set_stored_data_type(&mut self, data_type: Box<dyn DataType>) {
        self.data_type = Arc::from(data_type);
    }
    fn stored_comment(&self) -> Option<String> {
        self.comment.clone()
    }
    fn set_stored_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }
    fn stored_source_type(&self) -> SourceType {
        self.source_type
    }
    fn set_stored_source_type(&mut self, source_type: SourceType) {
        self.source_type = source_type;
    }
    fn stored_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        Some(share_variable_storage(&self.storage))
    }
    fn set_stored_variable_storage(&mut self, storage: Option<Box<dyn VariableStorage>>) {
        self.storage = match storage {
            Some(s) => Arc::from(s),
            None => Arc::new(BadStorage),
        };
    }
}

impl Variable for OldStackVariableImpl {
    fn get_data_type(&self) -> Box<dyn DataType> {
        self.variable_impl_get_data_type()
    }
    fn set_data_type_with_storage(
        &mut self,
        data_type: Box<dyn DataType>,
        storage: Box<dyn VariableStorage>,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type_with_storage(data_type, storage, force, source)
    }
    fn set_data_type(
        &mut self,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type(data_type, source)
    }
    fn set_data_type_aligned(
        &mut self,
        data_type: Box<dyn DataType>,
        align: bool,
        force: bool,
        source: SourceType,
    ) -> Result<(), InvalidInputException> {
        self.variable_impl_set_data_type_aligned(data_type, align, force, source)
    }
    fn get_name(&self) -> Option<String> {
        self.variable_impl_get_name()
    }
    fn get_length(&self) -> i32 {
        self.variable_impl_get_length()
    }
    fn is_valid(&self) -> bool {
        self.variable_impl_is_valid()
    }
    fn get_function(&self) -> Option<Box<dyn Function>> {
        self.variable_impl_get_function()
    }
    fn get_program(&self) -> Arc<dyn Program> {
        self.program.clone()
    }
    fn get_source(&self) -> SourceType {
        self.variable_impl_get_source()
    }
    fn set_name(
        &mut self,
        name: &str,
        source: SourceType,
    ) -> Result<(), crate::program::model::listing::variable::SetVariableNameError> {
        self.variable_impl_set_name(name, source)
    }
    fn get_comment(&self) -> Option<String> {
        self.variable_impl_get_comment()
    }
    fn set_comment(&mut self, comment: Option<String>) {
        self.variable_impl_set_comment(comment)
    }
    fn get_variable_storage(&self) -> Option<Box<dyn VariableStorage>> {
        self.variable_impl_get_variable_storage()
    }
    fn get_first_storage_varnode(&self) -> Option<Varnode> {
        self.variable_impl_get_first_storage_varnode()
    }
    fn get_last_storage_varnode(&self) -> Option<Varnode> {
        self.variable_impl_get_last_storage_varnode()
    }
    fn is_stack_variable(&self) -> bool {
        self.variable_impl_is_stack_variable()
    }
    fn has_stack_storage(&self) -> bool {
        self.variable_impl_has_stack_storage()
    }
    fn is_register_variable(&self) -> bool {
        self.variable_impl_is_register_variable()
    }
    fn get_register(&self) -> Option<RegisterRef> {
        self.variable_impl_get_register()
    }
    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.variable_impl_get_registers()
    }
    fn get_min_address(&self) -> Option<Address> {
        self.variable_impl_get_min_address()
    }
    fn get_stack_offset(&self) -> Result<i32, UnsupportedOperationError> {
        self.variable_impl_get_stack_offset()
    }
    fn is_memory_variable(&self) -> bool {
        self.variable_impl_is_memory_variable()
    }
    fn is_unique_variable(&self) -> bool {
        self.variable_impl_is_unique_variable()
    }
    fn is_compound_variable(&self) -> bool {
        self.variable_impl_is_compound_variable()
    }
    fn has_assigned_storage(&self) -> bool {
        self.variable_impl_has_assigned_storage()
    }
    fn get_first_use_offset(&self) -> i32 {
        0
    }
    fn get_symbol(&self) -> Option<Arc<dyn crate::program::model::symbol::Symbol>> {
        None
    }
    fn is_equivalent(&self, other: &dyn Variable) -> bool {
        self.variable_impl_is_equivalent(other)
    }
    fn compare_to(&self, other: &dyn Variable) -> std::cmp::Ordering {
        self.variable_impl_compare_to(other)
    }
}

/// Derives `var`'s stack offset from its last storage varnode, or `None` if it has no stack
/// storage (i.e. the [`BadStorage`] fallback [`build_stack_variable`] uses). See the module docs'
/// "`AddressOutOfBoundsException` fallback" section for why this -- rather than the panicking
/// `Variable::get_stack_offset()` -- backs every internal offset lookup in this file.
fn stack_offset(var: &dyn Variable) -> Option<i32> {
    var.get_last_storage_varnode().map(|vn| vn.get_offset() as i32)
}

/// Builds the stack variable for `record`, matching `OldStackFrameDB.getStackVariable(DBRecord)`.
/// See the module docs' "`AddressOutOfBoundsException` fallback" section.
fn build_stack_variable(
    function_manager: &dyn OldFunctionManager,
    program: Arc<dyn Program>,
    record: &DBRecord,
) -> OldStackVariableImpl {
    let offset = record.get_int(STACK_VAR_OFFSET_COL).unwrap_or(0);
    let data_type_id = record.get_long(STACK_VAR_DATA_TYPE_ID_COL).unwrap_or(0);
    let name = record.get_string(STACK_VAR_NAME_COL).map(str::to_string);
    let comment = record
        .get_string(STACK_VAR_COMMENT_COL)
        .map(str::to_string)
        .filter(|c| !c.is_empty());

    let data_type: Arc<dyn DataType> = Arc::from(function_manager.get_data_type(data_type_id));

    match init_fields(
        name.clone(),
        share_data_type(&data_type),
        None,
        None,
        Some(offset),
        None,
        false,
        program.as_ref(),
        SourceType::UserDefined,
        false,
        false,
    ) {
        Ok(fields) => OldStackVariableImpl {
            name: fields.name,
            data_type: Arc::from(fields.data_type),
            comment,
            source_type: fields.source_type,
            storage: Arc::from(fields.variable_storage),
            program,
        },
        Err(e) => {
            Msg::error(
                "OldStackFrameDB",
                &format!("Invalid stack variable '{}' at offset {offset}: {e}", name.as_deref().unwrap_or("")),
            );
            OldStackVariableImpl {
                name,
                data_type,
                comment,
                source_type: SourceType::UserDefined,
                storage: Arc::new(BadStorage),
                program,
            }
        }
    }
}

/// Returns the index at which the "negative" partition of a sorted `variables` slice ends for
/// [`OldStackFrameDB::get_negative_variables`], breaking on `start >= 0 || start > param_start`.
/// See the module docs for why this is a *separate* function from
/// [`negative_count_partition_end`] rather than a shared helper.
fn negative_variables_partition_end(variables: &[OldStackVariableImpl], param_start: i32) -> usize {
    for (index, var) in variables.iter().enumerate() {
        match stack_offset(var) {
            Some(start) if start < 0 && start <= param_start => continue,
            _ => return index,
        }
    }
    variables.len()
}

/// Returns the index at which the "negative" partition of a sorted `variables` slice ends for
/// [`OldStackFrameDB::get_negative_count`], breaking on `start >= 0 || start >= param_start`. See
/// the module docs for why this is a *separate* function from [`negative_variables_partition_end`].
fn negative_count_partition_end(variables: &[OldStackVariableImpl], param_start: i32) -> usize {
    for (index, var) in variables.iter().enumerate() {
        match stack_offset(var) {
            Some(start) if start < 0 && start < param_start => continue,
            _ => return index,
        }
    }
    variables.len()
}

/// Returns the index at which the "positive" partition of a sorted `variables` slice starts,
/// shared by [`OldStackFrameDB::get_positive_variables`] and
/// [`OldStackFrameDB::get_positive_count`] (identical break condition in Java for both).
fn positive_partition_start(variables: &[OldStackVariableImpl], param_start: i32) -> usize {
    for (index, var) in variables.iter().enumerate() {
        match stack_offset(var) {
            Some(off) if off >= 0 && off >= param_start => return index,
            _ => continue,
        }
    }
    variables.len()
}

/// Real, concrete `StackFrame` representation for old (pre-2.2) functions.
///
/// Port of `ghidra.program.database.oldfunction.OldStackFrameDB`. See the module docs for the
/// full account of what changed shape in translation (the shared `Variable` impl, the
/// `AddressOutOfBoundsException` fallback, and the faithfully-preserved
/// `getNegativeVariables`/`getNegativeCount` discrepancy).
pub struct OldStackFrameDB {
    function: Arc<dyn OldFunctionDataDB>,
    function_manager: Arc<dyn OldFunctionManager>,
    param_start: Cell<i32>,
    return_start: Cell<i32>,
    local_size: Cell<i32>,
    loaded: Cell<bool>,
    variables: RefCell<Vec<OldStackVariableImpl>>,
}

impl OldStackFrameDB {
    /// Constructs a stack frame for `function`, immediately loading its stack variables.
    ///
    /// Port of `OldStackFrameDB(OldFunctionDataDB)`.
    pub fn new(function: Arc<dyn OldFunctionDataDB>) -> Self {
        let function_manager = function.get_function_manager();
        let frame = OldStackFrameDB {
            function,
            function_manager,
            param_start: Cell::new(0),
            return_start: Cell::new(0),
            local_size: Cell::new(0),
            loaded: Cell::new(false),
            variables: RefCell::new(Vec::new()),
        };
        frame.refresh();
        frame
    }

    /// Reloads this frame's cached offsets and stack variables from `self.function`.
    ///
    /// Port of `OldStackFrameDB.refresh()`.
    pub fn refresh(&self) {
        self.param_start.set(self.function.get_stack_param_offset());
        self.return_start.set(self.function.get_stack_return_offset());
        self.local_size.set(self.function.get_stack_local_size());
        self.loaded.set(false);
        self.variables.borrow_mut().clear();
        self.load_stack_variables();
    }

    /// Stands in for the package-private `OldStackFrameDB.getFunctionManager()`.
    pub fn get_function_manager(&self) -> Arc<dyn OldFunctionManager> {
        self.function_manager.clone()
    }

    /// Stands in for the package-private `OldStackFrameDB.getFunctionData()`.
    pub fn get_function_data(&self) -> Arc<dyn OldFunctionDataDB> {
        self.function.clone()
    }

    /// Loads this frame's stack variables from [`OldStackVariableDBAdapter`], sorted by stack
    /// offset (variables with no stack storage sort last).
    ///
    /// Port of `OldStackFrameDB.loadStackVariables()`. Note this only ever runs once per
    /// [`refresh`](Self::refresh) call (including the one made by [`new`](Self::new)): once
    /// [`loaded`](Self::loaded) is set, subsequent calls are a no-op, exactly mirroring Java's
    /// `if (variables != null) return;` early return.
    fn load_stack_variables(&self) {
        if self.loaded.get() {
            return;
        }
        let mut vars: Vec<OldStackVariableImpl> = Vec::new();
        let program = self.function.get_program();
        let result: std::io::Result<()> = (|| {
            let adapter = self.function_manager.get_stack_variable_adapter();
            let keys = adapter.get_stack_variable_keys(self.function.get_key())?;
            for key in keys {
                if let Some(rec) = adapter.get_stack_variable_record(key.get_long_value())? {
                    vars.push(build_stack_variable(
                        self.function_manager.as_ref(),
                        program.clone(),
                        &rec,
                    ));
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                vars.sort_by(|a, b| {
                    StackVariableComparator::compare(
                        &StackVariableOperand::Variable(a),
                        &StackVariableOperand::Variable(b),
                    )
                });
            }
            Err(e) => self.function_manager.db_error(e),
        }
        *self.variables.borrow_mut() = vars;
        self.loaded.set(true);
    }

    /// Stands in for the package-private `OldStackFrameDB.getParameterCount()`.
    pub fn get_parameter_count(&self) -> i32 {
        self.load_stack_variables();
        if self.grows_negative() {
            self.get_positive_count()
        } else {
            self.get_negative_count()
        }
    }

    fn get_negative_size(&self) -> i32 {
        let vars = self.variables.borrow();
        let Some(first) = vars.first() else {
            return if self.grows_negative() { 0 } else { -self.param_start.get() };
        };
        match stack_offset(first) {
            Some(off) if off < 0 => -off,
            _ => if self.grows_negative() { 0 } else { -self.param_start.get() },
        }
    }

    fn get_positive_size(&self) -> i32 {
        let vars = self.variables.borrow();
        let Some(last) = vars.last() else {
            return if self.grows_negative() { self.param_start.get() } else { 0 };
        };
        match stack_offset(last) {
            Some(off) if off >= 0 => off + last.get_length(),
            _ => if self.grows_negative() { self.param_start.get() } else { 0 },
        }
    }

    fn get_negative_variables(&self) -> Vec<Box<dyn Variable>> {
        let vars = self.variables.borrow();
        let end = negative_variables_partition_end(&vars, self.param_start.get());
        if end == 0 {
            return Vec::new();
        }
        // Returned in offset order -1..-n (Java: iterates the sorted sub-list in reverse).
        vars[0..end].iter().rev().map(|v| Box::new(v.clone()) as Box<dyn Variable>).collect()
    }

    fn get_positive_variables(&self) -> Vec<Box<dyn Variable>> {
        let vars = self.variables.borrow();
        let start = positive_partition_start(&vars, self.param_start.get());
        if start == vars.len() {
            return Vec::new();
        }
        vars[start..].iter().map(|v| Box::new(v.clone()) as Box<dyn Variable>).collect()
    }

    fn get_negative_count(&self) -> i32 {
        let vars = self.variables.borrow();
        negative_count_partition_end(&vars, self.param_start.get()) as i32
    }

    fn get_positive_count(&self) -> i32 {
        let vars = self.variables.borrow();
        let start = positive_partition_start(&vars, self.param_start.get());
        (vars.len() - start) as i32
    }

    /// Returns whether `other` is value-equivalent to this stack frame.
    ///
    /// Port of `OldStackFrameDB.equals(Object)`. See the module docs for why this is kept despite
    /// Rust having no `Object` identity contract.
    pub fn eq(&self, other: &OldStackFrameDB) -> bool {
        if self.get_local_size() != other.get_local_size()
            || self.get_parameter_offset() != other.get_parameter_offset()
            || self.return_start.get() != other.return_start.get()
        {
            return false;
        }
        let mine = self.variables.borrow();
        let theirs = other.variables.borrow();
        if mine.len() != theirs.len() {
            return false;
        }
        mine.iter().zip(theirs.iter()).all(|(a, b)| a.is_equivalent(b))
    }
}

impl crate::program::model::listing::StackFrame for OldStackFrameDB {
    fn get_function(&self) -> Option<Box<dyn Function>> {
        None
    }

    fn get_frame_size(&self) -> i32 {
        self.get_local_size()
            + if self.grows_negative() { self.get_positive_size() } else { self.get_negative_size() }
    }

    fn get_local_size(&self) -> i32 {
        let local_size = self.local_size.get();
        if local_size > 0 {
            return local_size;
        }
        if self.grows_negative() {
            self.get_negative_size()
        } else {
            self.get_positive_size()
        }
    }

    fn get_parameter_size(&self) -> i32 {
        if self.grows_negative() {
            self.get_positive_size() - self.get_parameter_offset()
        } else {
            self.get_negative_size() + self.get_parameter_offset()
        }
    }

    fn get_parameter_offset(&self) -> i32 {
        let param_start = self.param_start.get();
        if param_start == 0 {
            let vars = self.variables.borrow();
            if !vars.is_empty() {
                let key = StackVariableOperand::Offset(0);
                let loc = match vars.binary_search_by(|v| {
                    StackVariableComparator::compare(&StackVariableOperand::Variable(v), &key)
                }) {
                    Ok(i) => i,
                    Err(i) => i,
                };
                if loc < vars.len() {
                    if let Some(off) = stack_offset(&vars[loc]) {
                        return off;
                    }
                }
            }
        }
        param_start
    }

    fn is_parameter_offset(&self, offset: i32) -> bool {
        if offset >= 0 { self.grows_negative() } else { !self.grows_negative() }
    }

    fn set_local_size(&mut self, size: i32) {
        let _ = size;
        panic!("OldStackFrameDB may not be modified: setLocalSize is not supported")
    }

    fn set_return_address_offset(&mut self, offset: i32) {
        let _ = offset;
        panic!("OldStackFrameDB may not be modified: setReturnAddressOffset is not supported")
    }

    fn get_return_address_offset(&self) -> i32 {
        self.return_start.get()
    }

    fn get_variable_containing(&self, offset: i32) -> Option<Box<dyn Variable>> {
        self.load_stack_variables();
        let vars = self.variables.borrow();
        let key = StackVariableOperand::Offset(offset);
        let search = vars.binary_search_by(|v| {
            StackVariableComparator::compare(&StackVariableOperand::Variable(v), &key)
        });
        let index = match search {
            Ok(i) => return Some(Box::new(vars[i].clone())),
            Err(insertion_point) => {
                if insertion_point == 0 {
                    return None;
                }
                insertion_point - 1
            }
        };
        let var = &vars[index];
        let stack_varnode = var.get_last_storage_varnode()?;
        if stack_varnode.get_offset() as i32 + stack_varnode.get_size() > offset {
            return Some(Box::new(var.clone()));
        }
        None
    }

    fn create_variable(
        &mut self,
        name: &str,
        offset: i32,
        data_type: Box<dyn DataType>,
        source: SourceType,
    ) -> Result<Box<dyn Variable>, CreateStackVariableError> {
        let _ = (name, offset, data_type, source);
        Err(InvalidInputException::with_message(
            "OldStackFrameDB may not be modified: createVariable is not supported",
        )
        .into())
    }

    fn clear_variable(&mut self, offset: i32) {
        let _ = offset;
        panic!("OldStackFrameDB may not be modified: clearVariable is not supported")
    }

    fn get_stack_variables(&self) -> Vec<Box<dyn Variable>> {
        self.load_stack_variables();
        self.variables.borrow().iter().map(|v| Box::new(v.clone()) as Box<dyn Variable>).collect()
    }

    fn get_locals(&self) -> Vec<Box<dyn Variable>> {
        self.load_stack_variables();
        if self.param_start.get() >= 0 {
            self.get_negative_variables()
        } else {
            self.get_positive_variables()
        }
    }

    fn get_parameters(&self) -> Vec<Box<dyn Variable>> {
        self.load_stack_variables();
        if self.param_start.get() >= 0 {
            self.get_positive_variables()
        } else {
            self.get_negative_variables()
        }
    }

    fn grows_negative(&self) -> bool {
        self.param_start.get() >= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::{DBHandle, DBRecord};
    use crate::program::database::oldfunction::old_stack_variable_db_adapter::OldStackVariableDBAdapter;
    use crate::program::database::oldfunction::old_stack_variable_db_adapter_v1::schema as stack_var_schema;
    use crate::program::database::oldfunction::{
        OldFunctionDBAdapter, OldRegisterVariableDBAdapter, UpgradeError,
    };
    use crate::program::database::map::AddressMap;
    use crate::program::model::address::{
        Address, AddressFactory, AddressSet, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::listing::Parameter;
    use crate::util::task::TaskMonitor;
    use std::io;

    #[derive(Debug, Clone, Copy)]
    struct MockDataType {
        length: i32,
    }

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            format!("mock{}", self.length)
        }
        fn get_length(&self) -> i32 {
            self.length
        }
        fn is_equivalent(&self, dt: &dyn DataType) -> bool {
            self.length == dt.get_length()
        }
    }

    /// Minimal `AddressFactory` whose only real behavior is `get_stack_space`. Not
    /// [`DefaultAddressFactory`](crate::program::model::address::DefaultAddressFactory): that
    /// type's constructor unconditionally panics ("Stack space should not be specified") on any
    /// space with [`AddressSpaceType::Stack`], since real programs plumb their stack space through
    /// some other channel this port's `Program`/`AddressFactory` traits don't model yet -- exactly
    /// the gap [`init_fields`]'s `stack_offset` path needs a stack space for.
    struct MockAddressFactory {
        stack_space: Arc<AddressSpace>,
    }

    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, _addr_string: &str) -> Option<Address> {
            None
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            vec![self.stack_space.clone()]
        }
        fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
            (name == self.stack_space.name()).then(|| self.stack_space.clone())
        }
        fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
            (id == self.stack_space.space_id()).then(|| self.stack_space.clone())
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }
        fn get_num_address_spaces(&self) -> usize {
            1
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            true
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            Vec::new()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.stack_space.clone())
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, _min: &Address, _max: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            false
        }
    }

    struct MockProgram {
        factory: Arc<dyn AddressFactory>,
    }

    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    fn mock_program() -> Arc<dyn Program> {
        let stack_space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1);
        Arc::new(MockProgram { factory: Arc::new(MockAddressFactory { stack_space }) })
    }

    /// A single in-memory `OldStackVariableDBAdapter`, seeded directly with translated (V1
    /// layout) records rather than going through a real [`DBHandle`] table.
    struct MockStackVariableAdapter {
        records: Vec<DBRecord>,
    }

    impl MockStackVariableAdapter {
        fn insert(&mut self, key: i64, function_key: i64, offset: i32, data_type_id: i64, name: &str, comment: Option<&str>) {
            let mut rec = DBRecord::new(stack_var_schema(), Field::Long(Some(key)));
            rec.set_long(STACK_VAR_FUNCTION_KEY_COL_TEST, function_key);
            rec.set_int(STACK_VAR_OFFSET_COL, offset);
            rec.set_long(STACK_VAR_DATA_TYPE_ID_COL, data_type_id);
            rec.set_string(STACK_VAR_NAME_COL, Some(name.to_string()));
            rec.set_string(STACK_VAR_COMMENT_COL, comment.map(str::to_string));
            self.records.push(rec);
        }
    }

    // Local alias matching the trait's own `STACK_VAR_FUNCTION_KEY_COL`, just to keep this test
    // module's `insert` helper readable without an extra import line.
    use crate::program::database::oldfunction::old_stack_variable_db_adapter::STACK_VAR_FUNCTION_KEY_COL as STACK_VAR_FUNCTION_KEY_COL_TEST;

    impl OldStackVariableDBAdapter for MockStackVariableAdapter {
        fn delete_table(&mut self, _handle: &mut DBHandle) -> io::Result<()> {
            self.records.clear();
            Ok(())
        }
        fn get_stack_variable_record(&self, key: i64) -> io::Result<Option<DBRecord>> {
            Ok(self.records.iter().find(|r| r.get_key().get_long_value() == key).cloned())
        }
        fn get_stack_variable_keys(&self, function_key: i64) -> io::Result<Vec<Field>> {
            Ok(self
                .records
                .iter()
                .filter(|r| r.get_long(STACK_VAR_FUNCTION_KEY_COL_TEST) == Some(function_key))
                .map(|r| r.get_key().clone())
                .collect())
        }
    }

    struct NoopFunctionAdapter;
    impl OldFunctionDBAdapter for NoopFunctionAdapter {
        fn delete_table(&mut self, _h: &mut DBHandle) -> io::Result<()> {
            Ok(())
        }
        fn get_record_count(&self) -> i32 {
            0
        }
        fn get_function_record(&self, _k: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn iterate_function_records(&self) -> io::Result<Box<dyn crate::framework::db::RecordIterator + '_>> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_map(&self) -> &dyn AddressMap {
            unimplemented!("not exercised by these tests")
        }
    }

    struct NoopRegisterAdapter;
    impl OldRegisterVariableDBAdapter for NoopRegisterAdapter {
        fn delete_table(&mut self, _h: &mut DBHandle) -> io::Result<()> {
            Ok(())
        }
        fn get_record_count(&self) -> i32 {
            0
        }
        fn get_register_variable_record(&self, _key: i64) -> io::Result<Option<DBRecord>> {
            Ok(None)
        }
        fn get_register_variable_keys(&self, _function_key: i64) -> io::Result<Vec<Field>> {
            Ok(Vec::new())
        }
    }

    struct MockOldFunctionManager {
        function_adapter: NoopFunctionAdapter,
        register_adapter: NoopRegisterAdapter,
        stack_adapter: MockStackVariableAdapter,
        /// data type id -> length, so tests can control which stack variables get an
        /// oversized/undersized data type.
        lengths: std::collections::HashMap<i64, i32>,
    }

    impl crate::framework::db::util::ErrorHandler for MockOldFunctionManager {
        fn db_error(&self, _e: io::Error) {}
    }

    impl OldFunctionManager for MockOldFunctionManager {
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            None
        }
        fn get_function_adapter(&self) -> &dyn OldFunctionDBAdapter {
            &self.function_adapter
        }
        fn get_register_variable_adapter(&self) -> &dyn OldRegisterVariableDBAdapter {
            &self.register_adapter
        }
        fn get_stack_variable_adapter(&self) -> &dyn OldStackVariableDBAdapter {
            &self.stack_adapter
        }
        fn get_data_type(&self, data_type_id: i64) -> Box<dyn DataType> {
            let length = *self.lengths.get(&data_type_id).unwrap_or(&4);
            Box::new(MockDataType { length })
        }
        fn get_data_type_id(&self, _data_type: &dyn DataType) -> i64 {
            0
        }
        fn get_function_body(&self, _function_key: i64) -> io::Result<Box<dyn AddressSetView>> {
            Ok(Box::new(AddressSet::new()))
        }
        fn get_function(&self, _rec: &DBRecord) -> Arc<dyn OldFunctionDataDB> {
            unimplemented!("not exercised by these tests")
        }
        fn upgrade(
            &mut self,
            _upgrade_program: &mut dyn Program,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), UpgradeError> {
            unimplemented!("not exercised by these tests")
        }
        fn dispose(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockOldFunctionDataDB {
        manager: Arc<dyn OldFunctionManager>,
        program: Arc<dyn Program>,
        key: i64,
        param_offset: i32,
        return_offset: i32,
        local_size: i32,
    }

    impl OldFunctionDataDB for MockOldFunctionDataDB {
        fn get_address_map(&self) -> &dyn AddressMap {
            unimplemented!("not exercised by these tests")
        }
        fn get_function_manager(&self) -> Arc<dyn OldFunctionManager> {
            self.manager.clone()
        }
        fn get_program(&self) -> Arc<dyn Program> {
            self.program.clone()
        }
        fn get_comment(&self) -> String {
            String::new()
        }
        fn get_repeatable_comment(&self) -> String {
            String::new()
        }
        fn get_entry_point(&self) -> crate::program::model::address::Address {
            let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
            space.address(0x1000)
        }
        fn get_body(&self) -> Box<dyn AddressSetView> {
            Box::new(AddressSet::new())
        }
        fn get_return_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType { length: 4 })
        }
        fn get_stack_frame(&self) -> Box<dyn StackFrame> {
            unimplemented!("not exercised by these tests")
        }
        fn get_stack_depth_change(&self) -> i32 {
            0
        }
        fn get_stack_param_offset(&self) -> i32 {
            self.param_offset
        }
        fn get_stack_return_offset(&self) -> i32 {
            self.return_offset
        }
        fn get_stack_local_size(&self) -> i32 {
            self.local_size
        }
        fn get_parameters(&self) -> Vec<Box<dyn Parameter>> {
            Vec::new()
        }
        fn get_key(&self) -> i64 {
            self.key
        }
    }

    /// Builds a frame whose stack grows negative (`paramStart = 8 >= 0`), with two locals
    /// (`-4`, `-8`) and two parameters (`8`, `12`), each a real 4-byte `MockDataType`, matching
    /// `OldStackFrameDB.getStackVariable`'s normal (non-`BAD_STORAGE`) construction path.
    fn build_frame(extra: impl FnOnce(&mut MockStackVariableAdapter)) -> OldStackFrameDB {
        let mut stack_adapter = MockStackVariableAdapter { records: Vec::new() };
        stack_adapter.insert(1, 42, -4, 1, "local_4", None);
        stack_adapter.insert(2, 42, -8, 1, "local_8", Some("a comment"));
        stack_adapter.insert(3, 42, 8, 1, "param_1", None);
        stack_adapter.insert(4, 42, 12, 1, "param_2", None);
        stack_adapter.insert(5, 99, 0, 1, "other_function", None); // different function; excluded
        extra(&mut stack_adapter);

        let mut lengths = std::collections::HashMap::new();
        lengths.insert(1, 4);
        let manager: Arc<dyn OldFunctionManager> = Arc::new(MockOldFunctionManager {
            function_adapter: NoopFunctionAdapter,
            register_adapter: NoopRegisterAdapter,
            stack_adapter,
            lengths,
        });
        let function: Arc<dyn OldFunctionDataDB> = Arc::new(MockOldFunctionDataDB {
            manager: manager.clone(),
            program: mock_program(),
            key: 42,
            param_offset: 8,
            return_offset: 4,
            local_size: 0,
        });
        OldStackFrameDB::new(function)
    }

    #[test]
    fn loads_only_this_functions_variables_sorted_by_offset() {
        let frame = build_frame(|_| {});
        let vars = frame.get_stack_variables();
        let offsets: Vec<i32> = vars.iter().map(|v| v.get_stack_offset().unwrap()).collect();
        assert_eq!(offsets, vec![-8, -4, 8, 12]);
    }

    #[test]
    fn splits_locals_and_parameters_by_grows_negative_direction() {
        let frame = build_frame(|_| {});
        assert!(frame.grows_negative());

        let params = frame.get_parameters();
        let param_offsets: Vec<i32> = params.iter().map(|v| v.get_stack_offset().unwrap()).collect();
        assert_eq!(param_offsets, vec![8, 12]);

        let locals = frame.get_locals();
        // Locals are returned in -1..-n order (least-negative first), per
        // `OldStackFrameDB.getNegativeVariables`.
        let local_offsets: Vec<i32> = locals.iter().map(|v| v.get_stack_offset().unwrap()).collect();
        assert_eq!(local_offsets, vec![-4, -8]);
    }

    #[test]
    fn get_variable_containing_finds_exact_and_interior_offsets() {
        let frame = build_frame(|_| {});

        let exact = frame.get_variable_containing(-8).unwrap();
        assert_eq!(exact.get_name(), Some("local_8".to_string()));

        // -6 falls inside the 4-byte variable at -8 (covers [-8, -4)).
        let interior = frame.get_variable_containing(-6).unwrap();
        assert_eq!(interior.get_name(), Some("local_8".to_string()));

        // -100 is before every variable.
        assert!(frame.get_variable_containing(-100).is_none());
    }

    #[test]
    fn comment_round_trips_and_blank_comment_is_dropped() {
        let frame = build_frame(|_| {});
        let vars = frame.get_stack_variables();
        let local8 = vars.iter().find(|v| v.get_name() == Some("local_8".to_string())).unwrap();
        assert_eq!(local8.get_comment(), Some("a comment".to_string()));

        let local4 = vars.iter().find(|v| v.get_name() == Some("local_4".to_string())).unwrap();
        assert_eq!(local4.get_comment(), None);
    }

    #[test]
    fn frame_size_local_size_and_parameter_size_match_java_formulas() {
        let frame = build_frame(|_| {});
        // Negative size = 8 (from the -8 variable), positive size = 12 + 4 = 16 (from the last
        // parameter's offset + length).
        assert_eq!(frame.get_local_size(), 8);
        assert_eq!(frame.get_frame_size(), 8 + 16);
        assert_eq!(frame.get_parameter_size(), 16 - frame.get_parameter_offset());
        assert_eq!(frame.get_return_address_offset(), 4);
    }

    #[test]
    fn get_function_always_returns_none() {
        let frame = build_frame(|_| {});
        assert!(frame.get_function().is_none());
    }

    /// Proves the `AddressOutOfBoundsException` fallback: a variable at a negative offset whose
    /// data type is too large to fit within the stack frame (mirroring Java's `-stackOffset <
    /// dtLength` check) gets `BAD_STORAGE` instead of panicking, and reports no stack offset.
    #[test]
    fn oversized_negative_offset_falls_back_to_bad_storage() {
        let mut stack_adapter = MockStackVariableAdapter { records: Vec::new() };
        stack_adapter.insert(1, 42, -2, 7, "corrupt", None);
        let mut lengths = std::collections::HashMap::new();
        lengths.insert(7, 100); // far larger than the 2 bytes available at offset -2
        let manager: Arc<dyn OldFunctionManager> = Arc::new(MockOldFunctionManager {
            function_adapter: NoopFunctionAdapter,
            register_adapter: NoopRegisterAdapter,
            stack_adapter,
            lengths,
        });
        let function: Arc<dyn OldFunctionDataDB> = Arc::new(MockOldFunctionDataDB {
            manager,
            program: mock_program(),
            key: 42,
            param_offset: 8,
            return_offset: 4,
            local_size: 0,
        });
        let frame = OldStackFrameDB::new(function);

        let vars = frame.get_stack_variables();
        assert_eq!(vars.len(), 1);
        let corrupt = &vars[0];
        assert_eq!(corrupt.get_name(), Some("corrupt".to_string()));
        assert!(!corrupt.has_stack_storage());
        assert!(corrupt.get_stack_offset().is_err());

        // Frame-level computations must not panic even with a BAD_STORAGE variable present.
        assert_eq!(frame.get_frame_size(), frame.get_frame_size());
        assert!(frame.get_variable_containing(-2).is_none());
    }

    /// Proves the faithfully-preserved Java quirk: `getNegativeVariables`'s break condition
    /// (`start > paramStart`) and `getNegativeCount`'s (`start >= paramStart`) diverge for a
    /// variable sitting exactly at a negative `paramStart`.
    #[test]
    fn negative_variables_and_negative_count_can_disagree_at_the_param_start_boundary() {
        let mut stack_adapter = MockStackVariableAdapter { records: Vec::new() };
        // paramStart = -8 (negative): a variable at exactly -8 is included by
        // `getNegativeVariables` (`-8 > -8` is false, so it does not break) but excluded by
        // `getNegativeCount` (`-8 >= -8` is true, so it does break).
        stack_adapter.insert(1, 42, -8, 1, "boundary", None);
        let mut lengths = std::collections::HashMap::new();
        lengths.insert(1, 4);
        let manager: Arc<dyn OldFunctionManager> = Arc::new(MockOldFunctionManager {
            function_adapter: NoopFunctionAdapter,
            register_adapter: NoopRegisterAdapter,
            stack_adapter,
            lengths,
        });
        let function: Arc<dyn OldFunctionDataDB> = Arc::new(MockOldFunctionDataDB {
            manager,
            program: mock_program(),
            key: 42,
            param_offset: -8,
            return_offset: 0,
            local_size: 0,
        });
        let frame = OldStackFrameDB::new(function);

        // paramStart = -8 < 0, so this frame grows positive: parameters are negative, locals are
        // positive (`get_locals` -> `get_positive_variables`, `get_parameters` ->
        // `get_negative_variables`).
        assert!(!frame.grows_negative());
        assert_eq!(frame.get_parameters().len(), 1); // getNegativeVariables includes the boundary var
        assert_eq!(frame.get_negative_count(), 0); // getNegativeCount excludes it
    }

    #[test]
    fn create_variable_and_clear_variable_are_unsupported() {
        let mut frame = build_frame(|_| {});
        let err = match frame.create_variable(
            "x",
            0,
            Box::new(MockDataType { length: 4 }),
            SourceType::UserDefined,
        ) {
            Ok(_) => panic!("expected createVariable to be unsupported"),
            Err(e) => e,
        };
        assert!(matches!(err, CreateStackVariableError::InvalidInput(_)));
    }

    #[test]
    #[should_panic(expected = "setLocalSize")]
    fn set_local_size_panics() {
        let mut frame = build_frame(|_| {});
        frame.set_local_size(4);
    }

    #[test]
    #[should_panic(expected = "clearVariable")]
    fn clear_variable_panics() {
        let mut frame = build_frame(|_| {});
        frame.clear_variable(0);
    }

    #[test]
    #[should_panic(expected = "setReturnAddressOffset")]
    fn set_return_address_offset_panics() {
        let mut frame = build_frame(|_| {});
        frame.set_return_address_offset(0);
    }

    #[test]
    fn eq_compares_by_value_not_identity() {
        let frame_a = build_frame(|_| {});
        let frame_b = build_frame(|_| {});
        assert!(frame_a.eq(&frame_b));

        let frame_c = build_frame(|adapter| {
            adapter.insert(7, 42, -20, 1, "extra", None);
        });
        assert!(!frame_a.eq(&frame_c));
    }

    #[test]
    fn refresh_reloads_state() {
        let frame = build_frame(|_| {});
        assert_eq!(frame.get_stack_variables().len(), 4);
        frame.refresh();
        assert_eq!(frame.get_stack_variables().len(), 4);
    }

    #[test]
    fn is_parameter_offset_matches_growth_direction() {
        let frame = build_frame(|_| {});
        assert!(frame.grows_negative());
        assert!(frame.is_parameter_offset(4));
        assert!(!frame.is_parameter_offset(-4));
    }
}
