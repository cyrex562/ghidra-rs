//! A p-code program that evaluates a Sleigh expression.
//!
//! Corresponds to `ghidra.pcode.exec.PcodeExpression`.
//!
//! Java's class extends [`PcodeProgram`](crate::pcode::exec::pcode_program::PcodeProgram) with one
//! more behavior, [`evaluate`](PcodeExpression::evaluate): compile the expression as
//! `___result(<expression>);`, execute it, and capture whatever value was passed to the
//! `___result` userop as the expression's result. Following this crate's
//! composition-over-inheritance convention, [`PcodeExpression`] composes a `PcodeProgram` (via
//! [`Deref`]) instead of extending it.
//!
//! # Divergences from Java
//!
//! * **No `SleighProgramCompiler` yet.** Java's only constructor is `protected`, meant to be
//!   called by `SleighProgramCompiler` (which compiles Sleigh source into a `PcodeExpression`, not
//!   yet ported in this crate) after it resolves the `___result` invocation to actual p-code. This
//!   port's constructor is `pub(crate)`, matching
//!   [`PcodeProgram::new`](crate::pcode::exec::pcode_program::PcodeProgram::new)'s own visibility,
//!   so it is ready to be called once that compiler exists.
//! * **`getHead()` still reports "PcodeProgram".** Java's `PcodeProgram.getHead()` (used only for
//!   the `<Head:\n...>` header when formatting/displaying a program) is
//!   `getClass().getSimpleName()`, so a `PcodeExpression` instance formats under the header
//!   "PcodeExpression". This crate's `PcodeProgram::get_head` is a private, fixed
//!   `"PcodeProgram"` (see that module's docs), and composition here cannot override it, so a
//!   `PcodeExpression`, when formatted through the composed `PcodeProgram`, is displayed as if it
//!   were a plain `PcodeProgram`. Purely cosmetic: [`evaluate`] does not touch it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use crate::decompiler::slghsymbol::user_op_symbol::UserOpSymbol;
use crate::pcode::exec::annotated_pcode_userop_library::{
    AnnotatedPcodeUseropDefinition, AnnotatedPcodeUseropLibrary, AnnotatedPcodeUseropLibraryBase,
    PcodeUserop, UseropInputs, UseropValue, UseropValueKind,
};
use crate::pcode::exec::pcode_executor::PcodeExecutor;
use crate::pcode::exec::pcode_program::PcodeProgram;
use crate::pcode::exec::pcode_userop_library::{
    ErasedPcodeUseropLibrary, PcodeUseropLibrary, UseropMap,
};
use crate::program::model::lang::language::Language;
use crate::program::model::pcode::PcodeOp;

/// A userop library exporting exactly one userop, `___result`, which stores whatever value it is
/// invoked with.
///
/// Port of the private nested class `PcodeExpression.ValueCapturingPcodeUseropLibrary<T>`. Java
/// stores the captured value directly in a field the outer method then reads after `execute`
/// returns; a Rust userop callback is a `'static` closure that cannot borrow `&mut self`, so the
/// captured value instead lives behind `Rc<RefCell<_>>`, shared between the library and the
/// closure its `collect_definitions` builds. `Rc` (not `Arc`) suffices: nothing here crosses a
/// thread boundary, matching [`UseropCallback`](crate::pcode::exec::annotated_pcode_userop_library::UseropCallback)'s
/// own lack of a `Send`/`Sync` bound.
struct ValueCapturingPcodeUseropLibrary<T: 'static + Clone> {
    base: AnnotatedPcodeUseropLibraryBase<T>,
    result: Rc<RefCell<Option<T>>>,
}

impl<T: 'static + Clone> ValueCapturingPcodeUseropLibrary<T> {
    fn new() -> Self {
        let mut library = Self { base: AnnotatedPcodeUseropLibraryBase::new(), result: Rc::new(RefCell::new(None)) };
        library.init();
        library
    }

    /// Consume the library and return the captured result, if `___result` was ever invoked.
    fn into_result(self) -> Option<T> {
        self.result.borrow_mut().take()
    }
}

impl<T: 'static + Clone> ErasedPcodeUseropLibrary for ValueCapturingPcodeUseropLibrary<T> {}

impl<T: 'static + Clone> PcodeUseropLibrary<T> for ValueCapturingPcodeUseropLibrary<T> {
    fn get_userops(&self) -> &UseropMap<T> {
        self.base.get_userops()
    }
}

impl<T: 'static + Clone> AnnotatedPcodeUseropLibrary<T> for ValueCapturingPcodeUseropLibrary<T> {
    fn base_mut(&mut self) -> &mut AnnotatedPcodeUseropLibraryBase<T> {
        &mut self.base
    }

    fn collect_definitions(&self) -> Vec<AnnotatedPcodeUseropDefinition<T>> {
        let result = Rc::clone(&self.result);
        vec![AnnotatedPcodeUseropDefinition::new(
            PcodeExpression::RESULT_NAME,
            PcodeUserop::default(),
            UseropInputs::Fixed(vec![UseropValueKind::Value]),
            UseropValueKind::Void,
            Box::new(move |_ctx, args| {
                if let UseropValue::Value(value) = args[0].clone() {
                    *result.borrow_mut() = Some(value);
                }
                None
            }),
        )]
    }
}

/// The userop symbols of the result-capturing library, which an expression is compiled against.
///
/// Stands for Java's `PcodeExpression.CAPTURING.getSymbols(language)` as
/// `SleighProgramCompiler.compileExpression` calls it; the capturing library is private to this
/// module.
pub(crate) fn capturing_symbols(
    language: &crate::program::model::lang::sleigh::SleighLanguage,
) -> HashMap<i32, UserOpSymbol> {
    ValueCapturingPcodeUseropLibrary::<i64>::new().get_symbols(language)
}

/// A p-code program that evaluates a Sleigh expression.
pub struct PcodeExpression {
    program: PcodeProgram,
}

impl PcodeExpression {
    /// The name of the userop used to capture an expression's result.
    ///
    /// Port of `PcodeExpression.RESULT_NAME`.
    ///
    /// A clever means of capturing the result of the expression: the compiled source is actually
    /// `___result(<expression>);`, which allows capturing the value (and size) of arbitrary
    /// expressions. Assigning the value to a temp variable instead of a userop does not quite
    /// suffice, since it requires a fixed size, which cannot be known ahead of time.
    pub const RESULT_NAME: &'static str = "___result";

    /// Construct a p-code program from source already compiled into p-code ops.
    ///
    /// Port of the protected constructor `PcodeExpression(SleighLanguage, List<PcodeOp>,
    /// Map<Integer, UserOpSymbol>)`. See this module's docs on why this is `pub(crate)` rather
    /// than a public API yet.
    pub(crate) fn new(
        language: Arc<dyn Language>,
        code: Vec<PcodeOp>,
        userop_symbols: HashMap<i32, UserOpSymbol>,
    ) -> Self {
        Self { program: PcodeProgram::new(language, code, userop_symbols) }
    }

    /// The composed p-code program.
    ///
    /// Not part of the Java class (which simply *is* a `PcodeProgram`); provided since this port
    /// composes one instead of extending it. See also this type's [`Deref`] impl for direct
    /// access to `PcodeProgram`'s own methods.
    pub fn program(&self) -> &PcodeProgram {
        &self.program
    }

    /// Evaluate the expression using the given executor.
    ///
    /// Port of `<T> T evaluate(PcodeExecutor<T> executor)`.
    ///
    /// # Panics
    ///
    /// If executing the underlying program fails (matching
    /// [`PcodeProgram::execute`](crate::pcode::exec::pcode_program::PcodeProgram::execute)'s own
    /// panic-on-`PcodeExecutionException` behavior), or if the compiled expression never actually
    /// invoked `___result` -- which Java cannot detect (`library.result` simply stays `null`, and a
    /// caller expecting a primitive `T` would get a `NullPointerException` unboxing it, or `null`
    /// for a reference `T`); this port makes the mismatch explicit rather than silently returning
    /// a dummy value.
    pub fn evaluate<T: Clone + 'static>(&self, executor: &PcodeExecutor<T>) -> T {
        let library = ValueCapturingPcodeUseropLibrary::<T>::new();
        self.program.execute(executor, &library);
        library.into_result().expect(
            "PcodeExpression's compiled code did not invoke ___result; \
             the expression produced no value",
        )
    }
}

impl std::ops::Deref for PcodeExpression {
    type Target = PcodeProgram;

    fn deref(&self) -> &PcodeProgram {
        &self.program
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::exec::concretion_error::ConcretionError;
    use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
    use crate::pcode::exec::pcode_executor_state::PcodeExecutorState;
    use crate::pcode::exec::pcode_executor_state_piece::{
        ErasedPcodeExecutorStatePiece, PcodeExecutorStatePiece, Reason,
    };
    use crate::pcode::exec::pcode_state_callbacks::PcodeStateCallbacks;
    use crate::pcode::utils::{bytes_to_long, long_to_bytes};
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::endian::Endian;
    use crate::program::model::lang::register::RegisterRef;
    use crate::program::model::mem::mem_buffer::MemBuffer;
    use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};
    use crate::sleigh::grammar::location::Location;
    use std::sync::Mutex;

    #[derive(Debug, Clone, Copy)]
    struct I64Arithmetic;

    impl PcodeArithmetic<i64> for I64Arithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }
        fn unary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn binary_op(&self, _opcode: OpCode, _sizeout: i32, _sizein1: i32, _in1: &i64, _sizein2: i32, _in2: &i64) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn mod_before_store(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }
        fn mod_after_load(&self, _sizein_offset: i32, _space: &AddressSpace, _in_offset: &i64, _sizein_value: i32, in_value: &i64) -> i64 {
            *in_value
        }
        fn from_const_bytes(&self, value: &[u8]) -> i64 {
            bytes_to_long(value, value.len(), false)
        }
        fn to_concrete(&self, value: &i64, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(long_to_bytes(*value, 8, false))
        }
        fn size_of(&self, _value: &i64) -> i64 {
            8
        }
    }

    struct MapState {
        cells: HashMap<i64, i64>,
    }

    impl ErasedPcodeExecutorStatePiece for MapState {}

    impl PcodeExecutorStatePiece<i64, i64> for MapState {
        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by these tests")
        }
        fn get_address_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn get_arithmetic(&self) -> Arc<dyn PcodeArithmetic<i64>> {
            Arc::new(I64Arithmetic)
        }
        fn stream_pieces(&self) -> Vec<&dyn ErasedPcodeExecutorStatePiece> {
            vec![self]
        }
        fn set_var_abstract(&mut self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, val: &i64) {
            self.cells.insert(*offset, *val);
        }
        fn set_var_internal_abstract(&mut self, space: &Arc<AddressSpace>, offset: &i64, size: i32, val: &i64) {
            self.set_var_abstract(space, offset, size, false, val);
        }
        fn get_var_abstract(&self, _space: &Arc<AddressSpace>, offset: &i64, _size: i32, _quantize: bool, _reason: Reason) -> i64 {
            *self.cells.get(offset).unwrap_or(&0)
        }
        fn get_var_internal_abstract(&self, space: &Arc<AddressSpace>, offset: &i64, size: i32, reason: Reason) -> i64 {
            self.get_var_abstract(space, offset, size, false, reason)
        }
        fn get_register_values(&self) -> Vec<(RegisterRef, i64)> {
            vec![]
        }
        fn get_concrete_buffer(&self, _address: &Address, _purpose: Purpose) -> Box<dyn MemBuffer> {
            unimplemented!("not exercised by these tests")
        }
        fn clear(&mut self) {
            self.cells.clear();
        }
    }

    impl PcodeExecutorState<i64> for MapState {}

    /// A language just complete enough to bind a [`PcodeExecutor`]: it answers the two things the
    /// executor's constructor asks of it -- the program counter (none here) and the default space
    /// -- plus the "no userops of its own" the program/executor consult when resolving a
    /// `CALLOTHER`'s op number to a name. Paths are spelled out rather than imported, to keep the
    /// double local (matching the convention already used by, e.g.,
    /// `annotated_pcode_userop_library`'s own tests).
    struct MockLanguage {
        default_space: Arc<AddressSpace>,
    }

    impl Language for MockLanguage {
        fn get_default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.default_space)
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            unimplemented!("not exercised by these tests")
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by these tests")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by these tests")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn crate::program::model::address::AddressFactory> {
            Box::new(crate::program::model::address::DefaultAddressFactory::new(vec![Arc::clone(
                &self.default_space,
            )]))
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(
            &self,
            _task_monitor: &dyn crate::util::task::TaskMonitor,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by these tests")
        }
        fn get_default_compiler_spec(
            &self,
        ) -> Box<dyn crate::program::model::lang::compiler_spec::CompilerSpec> {
            unimplemented!("not exercised by these tests")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(
            &self,
            _instruction_mnemonic: &str,
        ) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> std::collections::HashSet<String> {
            std::collections::HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            Box::new(crate::program::model::address::AddressSet::new())
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn constant_space() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 1)
    }

    fn test_executor() -> PcodeExecutor<i64> {
        PcodeExecutor::new(
            Arc::new(MockLanguage { default_space: ram() }),
            Arc::new(I64Arithmetic),
            Arc::new(Mutex::new(MapState { cells: HashMap::new() })),
            Reason::ExecuteRead,
        )
    }

    fn varnode(offset: i64, size: i32) -> Varnode {
        Varnode::new(ram().address(offset), size)
    }

    fn poke(executor: &PcodeExecutor<i64>, var: &Varnode, value: i64) {
        executor.get_state().lock().unwrap().set_var_varnode(var, &value);
    }

    /// Build a `___result(<value at that varnode>);` expression: a single CALLOTHER whose op
    /// number 0 is named "___result" (via `userop_symbols`, since the language itself declares no
    /// userops) and whose one input is the given varnode.
    fn result_expression(input: Varnode) -> PcodeExpression {
        let op = PcodeOp::new(
            OpCode::CallOther,
            SequenceNumber::new(ram().address(0x1000), 0),
            vec![Varnode::new(constant_space().address(0), 4), input], // inputs[0] is the op-number constant
            None,
        );
        let mut symbol = UserOpSymbol::with_name(Location::new("test".to_string(), 0), PcodeExpression::RESULT_NAME);
        symbol.set_index(0);
        PcodeExpression::new(
            Arc::new(MockLanguage { default_space: ram() }),
            vec![op],
            HashMap::from([(0, symbol)]),
        )
    }

    #[test]
    fn evaluate_captures_the_value_passed_to_result() {
        let executor = test_executor();
        let input = varnode(0x10, 4);
        poke(&executor, &input, 0x2A);

        let expr = result_expression(input);

        assert_eq!(expr.evaluate(&executor), 0x2A);
    }

    #[test]
    fn evaluate_can_be_called_more_than_once_on_the_same_expression() {
        // Each call builds a fresh ValueCapturingPcodeUseropLibrary, so results don't leak
        // between calls even though the expression object is reused.
        let executor = test_executor();
        let input = varnode(0x20, 4);
        let expr = result_expression(input.clone());

        poke(&executor, &input, 1);
        assert_eq!(expr.evaluate(&executor), 1);

        poke(&executor, &input, 2);
        assert_eq!(expr.evaluate(&executor), 2);
    }

    #[test]
    #[should_panic(expected = "did not invoke ___result")]
    fn evaluate_panics_if_result_was_never_invoked() {
        // A program with no ops at all never calls ___result; Java would instead return `null`
        // (or NPE unboxing a primitive `T`) -- see `evaluate`'s doc comment on this divergence.
        let executor = test_executor();
        let expr = PcodeExpression::new(Arc::new(MockLanguage { default_space: ram() }), vec![], HashMap::new());
        let _: i64 = expr.evaluate(&executor);
    }

    #[test]
    fn deref_exposes_the_composed_pcode_program() {
        let expr = result_expression(varnode(0x10, 4));
        // Deref coercion reaches PcodeProgram::get_userop_name.
        assert_eq!(expr.get_userop_name(0).as_deref(), Some(PcodeExpression::RESULT_NAME));
        assert_eq!(expr.program().get_userop_name(0).as_deref(), Some(PcodeExpression::RESULT_NAME));
    }
}
