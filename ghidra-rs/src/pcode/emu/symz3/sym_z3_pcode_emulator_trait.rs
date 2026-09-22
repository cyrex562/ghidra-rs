//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeEmulatorTrait`.
//!
//! # Deviations from Java
//!
//! * Java's `SymZ3PcodeEmulatorTrait extends PcodeMachine<Pair<byte[], SymValueZ3>>,
//!   SymZ3RecordsExecution` and overrides four of `PcodeMachine`'s methods
//!   (`newThread`/`newThread(String)`/`getAllThreads`/`getSharedState`) with covariant return
//!   types narrowed to this package's own types (`SymZ3PcodeThread`, `SymZ3PairedPcodeExecutorState`).
//!   Rust trait methods cannot narrow a supertrait method's return type -- there is no override,
//!   only a same-named method on a different trait, which would make every call site ambiguous.
//!   Following this crate's established practice for the identical problem in
//!   [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::aux_pcode_emulator), this trait does NOT
//!   require [`PcodeMachine`](crate::pcode::emu::pcode_machine::PcodeMachine) as a Rust
//!   supertrait; the four narrowed-return members are distinctly-named methods here
//!   (`new_symz3_thread`, `new_symz3_thread_named`, `get_all_symz3_threads`,
//!   `get_shared_symz3_state`). A concrete implementor (e.g. the not-yet-ported
//!   `state.SymZ3PcodeEmulator`) is expected to implement `PcodeMachine<(Vec<u8>, SymValueZ3)>`
//!   separately, typically delegating its erased methods to these.
//! * Java's `SymZ3RecordsExecution.getInstructions()`/`getOps()` gain *default* bodies here
//!   (delegating to `getSharedSymbolicState()`). Rust cannot supply a default body for a
//!   supertrait's abstract method from a subtrait -- each concrete implementor must still provide
//!   its own one-line `SymZ3RecordsExecution` impl (typically delegating to
//!   `get_shared_symz3_state().get_right()`, exactly mirroring Java's default body); see
//!   [`InternalSymZ3RecordsExecution`](crate::pcode::emu::symz3::internal_sym_z3_records_execution)'s
//!   own test fixture for the shape of such a delegation.
//! * Java's `printSymbolicSummary(PrintStream)`/`printOps(PrintStream)`/
//!   `printInstructions(PrintStream)`/`printCompleteSummary(PrintStream)` take a `PrintStream`;
//!   per this crate's established convention for ported `print(PrintStream)` methods (see e.g.
//!   `AssemblyParser::print_grammar`), these take `&mut dyn std::io::Write` and return
//!   `io::Result<()>`.
//! * `formatOps()` builds an anonymous `StringPcodeFormatter` subclass to render p-code with a
//!   `"[threadname] "` prefix per instruction. `StringPcodeFormatter` is not ported yet, and (per
//!   this crate's established convention of documenting -- not inventing -- a genuinely missing
//!   forward dependency, see `DerefExpr::cast` in `pcode::seam_stubs`) this instead renders each
//!   op directly from its own mnemonic/operands (mirroring
//!   [`RecInstruction::to_display_string`](crate::pcode::emu::symz3::sym_z3_records_execution::RecInstruction)'s
//!   already-established substitution for the same missing `Instruction`/`PcodeOp` `toString()`
//!   machinery), prefixed the same way Java's overridden `formatOpTemplate` prefixes each line.
//!   `get_language`, needed by Java's real formatter, is not required here for the same reason
//!   `PcodeMachine` is not a supertrait (see above); callers that need language-aware formatting
//!   should use the real `StringPcodeFormatter` once it is ported.

use crate::feature::seam_stubs::Z3Context;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state::SymZ3PairedPcodeExecutorState;
use crate::pcode::emu::symz3::sym_z3_records_execution::{RecInstruction, RecOp, SymZ3RecordsExecution};
use crate::pcode::seam_stubs::SymZ3PcodeThread;
use std::io;

/// Port of `ghidra.pcode.emu.symz3.SymZ3PcodeEmulatorTrait`. See the module docs for how the
/// `PcodeMachine` covariant-return overrides are handled.
pub trait SymZ3PcodeEmulatorTrait: SymZ3RecordsExecution {
    /// Java: `SymZ3PcodeThread newThread()`, overriding `PcodeMachine.newThread()`.
    fn new_symz3_thread(&mut self) -> SymZ3PcodeThread;

    /// Java: `SymZ3PcodeThread newThread(String)`, overriding `PcodeMachine.newThread(String)`.
    fn new_symz3_thread_named(&mut self, name: &str) -> SymZ3PcodeThread;

    /// Java: `Collection<? extends SymZ3PcodeThread> getAllThreads()`, overriding
    /// `PcodeMachine.getAllThreads()`.
    fn get_all_symz3_threads(&self) -> Vec<SymZ3PcodeThread>;

    /// Java: `SymZ3PairedPcodeExecutorState getSharedState()`, overriding
    /// `PcodeMachine.getSharedState()`.
    fn get_shared_symz3_state(&self) -> &dyn SymZ3PairedPcodeExecutorState;

    /// Java: `default SymZ3PcodeExecutorStatePiece getSharedSymbolicState()`.
    fn get_shared_symbolic_state(&self) -> &crate::pcode::seam_stubs::SymZ3PcodeExecutorStatePiece {
        self.get_shared_symz3_state().get_right()
    }

    /// Java: `default String printableSummary()`. Unlike Java (which never opens a `Context`
    /// itself here -- it only forwards to pieces that do), the thread-local pieces this needs
    /// (`SymZ3PcodeThread::getLocalSymbolicState`) are not modeled by the placeholder
    /// [`SymZ3PcodeThread`](crate::pcode::seam_stubs::SymZ3PcodeThread) stub yet, so only the
    /// shared state's summary is rendered; a concrete implementor with real threads should extend
    /// this once `SymZ3PcodeThread` is fully ported.
    fn printable_summary(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> String {
        let mut result = self.get_shared_symbolic_state().printable_summary(ctx, z3p);
        result.push('\n');
        result
    }

    /// Java: `default void printSymbolicSummary(PrintStream)`. See the module docs for the
    /// `PrintStream` -> `&mut dyn Write` convention.
    fn print_symbolic_summary(
        &self,
        out: &mut dyn io::Write,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
    ) -> io::Result<()> {
        writeln!(out, "{}", self.printable_summary(ctx, z3p))
    }

    /// Java: `default String formatOps()`. See the module docs for the `StringPcodeFormatter`
    /// substitution.
    fn format_ops(&self) -> String {
        self.get_ops()
            .iter()
            .map(format_rec_op)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Java: `default void printOps(PrintStream)`.
    fn print_ops(&self, out: &mut dyn io::Write) -> io::Result<()> {
        writeln!(out, "{}", self.format_ops())
    }

    /// Java: `default String formatInstructions()`.
    fn format_instructions(&self) -> String {
        self.get_instructions()
            .iter()
            .map(RecInstruction::to_display_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Java: `default void printInstructions(PrintStream)`.
    fn print_instructions(&self, out: &mut dyn io::Write) -> io::Result<()> {
        writeln!(out, "{}", self.format_instructions())
    }

    /// Java: `default void printCompleteSummary(PrintStream)`.
    fn print_complete_summary(
        &self,
        out: &mut dyn io::Write,
        ctx: &dyn Z3Context,
        z3p: &Z3InfixPrinter,
    ) -> io::Result<()> {
        writeln!(out, "Instructions emulated:")?;
        writeln!(out, "----------------------")?;
        self.print_instructions(out)?;
        writeln!(out)?;
        writeln!(out, "Pcode emulated:")?;
        writeln!(out, "---------------")?;
        self.print_ops(out)?;
        writeln!(out)?;
        writeln!(out, "Summary:")?;
        self.print_symbolic_summary(out, ctx, z3p)
    }

    /// Java: `default Stream<String> streamPreconditions(Context, Z3InfixPrinter)`. As with
    /// [`printable_summary`](Self::printable_summary), thread-local preconditions are not
    /// modeled yet (see that method's docs); only the shared state's preconditions are streamed.
    fn stream_preconditions(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<String> {
        self.get_shared_symbolic_state().stream_preconditions(ctx, z3p)
    }

    /// Java: `default Stream<Entry<String, String>> streamValuations(Context, Z3InfixPrinter)`.
    /// See [`stream_preconditions`](Self::stream_preconditions)'s docs for the same thread-local
    /// caveat.
    fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        self.get_shared_symbolic_state().stream_valuations(ctx, z3p)
    }
}

/// Renders one [`RecOp`] the way Java's anonymous `StringPcodeFormatter` override does:
/// `"[threadname] "` followed by the op's rendering. See the module docs for why this substitutes
/// for the unported `StringPcodeFormatter`.
fn format_rec_op(rec: &RecOp) -> String {
    let thread_label = rec.get_thread_name().unwrap_or_default();
    format!("[{}] {}", thread_label, rec.op.get_mnemonic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::seam_stubs::SymZ3PcodeExecutorStatePiece;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, PcodeOp};

    struct FakeEmulator {
        state: FakeState,
    }

    struct FakeState {
        right: SymZ3PcodeExecutorStatePiece,
    }

    impl SymZ3PairedPcodeExecutorState for FakeState {
        fn get_left(
            &self,
        ) -> &dyn crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<Vec<u8>, Vec<u8>>
        {
            unimplemented!("not exercised by this test")
        }
        fn get_right(&self) -> &SymZ3PcodeExecutorStatePiece {
            &self.right
        }
    }
    impl crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece for FakeState {}
    impl crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece<
        (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
        (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
    > for FakeState
    {
        fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
            unimplemented!()
        }
        fn get_address_arithmetic(
            &self,
        ) -> std::sync::Arc<
            dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<
                (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
            >,
        > {
            unimplemented!()
        }
        fn get_arithmetic(
            &self,
        ) -> std::sync::Arc<
            dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<
                (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
            >,
        > {
            unimplemented!()
        }
        fn stream_pieces(
            &self,
        ) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece>
        {
            vec![self]
        }
        fn set_var_abstract(
            &mut self,
            _space: &std::sync::Arc<AddressSpace>,
            _offset: &(Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
            _size: i32,
            _quantize: bool,
            _val: &(Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
        ) {
        }
        fn set_var_internal_abstract(
            &mut self,
            _space: &std::sync::Arc<AddressSpace>,
            _offset: &(Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
            _size: i32,
            _val: &(Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
        ) {
        }
        fn get_var_abstract(
            &self,
            _space: &std::sync::Arc<AddressSpace>,
            _offset: &(Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
            _size: i32,
            _quantize: bool,
            _reason: crate::pcode::exec::pcode_executor_state_piece::Reason,
        ) -> (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3) {
            unimplemented!()
        }
        fn get_var_internal_abstract(
            &self,
            _space: &std::sync::Arc<AddressSpace>,
            _offset: &(Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
            _size: i32,
            _reason: crate::pcode::exec::pcode_executor_state_piece::Reason,
        ) -> (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3) {
            unimplemented!()
        }
        fn get_register_values(
            &self,
        ) -> Vec<(
            crate::program::model::lang::register::RegisterRef,
            (Vec<u8>, crate::feature::symz3::model::sym_value_z3::SymValueZ3),
        )> {
            Vec::new()
        }
        fn get_concrete_buffer(
            &self,
            _address: &Address,
            _purpose: crate::pcode::exec::pcode_arithmetic::Purpose,
        ) -> Box<dyn crate::program::model::mem::MemBuffer> {
            unimplemented!()
        }
        fn clear(&mut self) {}
    }
    impl crate::pcode::exec::pcode_executor_state::PcodeExecutorState<(
        Vec<u8>,
        crate::feature::symz3::model::sym_value_z3::SymValueZ3,
    )> for FakeState
    {
    }

    impl SymZ3RecordsExecution for FakeEmulator {
        fn get_instructions(&self) -> Vec<RecInstruction> {
            self.state.right.get_instructions()
        }
        fn get_ops(&self) -> Vec<RecOp> {
            self.state.right.get_ops()
        }
    }

    impl SymZ3PcodeEmulatorTrait for FakeEmulator {
        fn new_symz3_thread(&mut self) -> SymZ3PcodeThread {
            SymZ3PcodeThread::named("[Threads][0]")
        }
        fn new_symz3_thread_named(&mut self, name: &str) -> SymZ3PcodeThread {
            SymZ3PcodeThread::named(name)
        }
        fn get_all_symz3_threads(&self) -> Vec<SymZ3PcodeThread> {
            Vec::new()
        }
        fn get_shared_symz3_state(&self) -> &dyn SymZ3PairedPcodeExecutorState {
            &self.state
        }
    }

    #[test]
    fn format_ops_prefixes_each_line_with_its_thread_name() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0x400);
        let thread = SymZ3PcodeThread::named("[Threads][2]");
        let mut piece = SymZ3PcodeExecutorStatePiece::default();
        piece.add_op(&thread, PcodeOp::with_address_no_inputs(addr, 0, OpCode::Copy));

        let emu = FakeEmulator { state: FakeState { right: piece } };
        assert_eq!(emu.format_ops(), "[2] COPY");
        assert_eq!(emu.get_ops().len(), 1);
    }
}
