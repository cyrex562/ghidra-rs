//! Port of `ghidra.pcode.emu.symz3.SymZ3PcodeEmulatorTrait`.
//!
//! # Deviations from Java
//!
//! * Java's `SymZ3PcodeEmulatorTrait extends PcodeMachine<Pair<byte[], SymValueZ3>>,
//!   SymZ3RecordsExecution` and narrows `newThread`/`newThread(String)`/`getAllThreads`/
//!   `getSharedState` to this package's types. [`PcodeMachineThreads`](crate::pcode::emu::pcode_machine::PcodeMachineThreads)
//!   already types a machine's threads, so an implementor's `newThread` returns
//!   [`SymZ3PcodeThread`] without a trait of its own; what remains here is
//!   [`get_all_symz3_threads`](SymZ3PcodeEmulatorTrait::get_all_symz3_threads) and the shared
//!   state, [`get_shared_symz3_state`](SymZ3PcodeEmulatorTrait::get_shared_symz3_state), which is
//!   the handle every thread holds. As for
//!   [`AuxPcodeEmulator`](crate::pcode::emu::auxiliary::aux_pcode_emulator), `PcodeMachine` is not
//!   a supertrait, since a narrowed getter would be a second, same-named method.
//! * Java's `getSharedState()` creates the state on demand; creating it mutates the machine (see
//!   [`AbstractPcodeMachineBase::get_shared_state`](crate::pcode::emu::abstract_pcode_machine::AbstractPcodeMachineBase::get_shared_state)),
//!   so the `&self` getter here is `None` until then, and the summaries below treat a machine
//!   without one as having recorded nothing in it.
//! * Java's `default SymZ3PcodeExecutorStatePiece getSharedSymbolicState()` hands out the piece;
//!   the handle cannot lend a borrow through its lock, so callers use
//!   `get_shared_symz3_state()` and the handle's `with_symbolic` (see
//!   [`sym_z3_paired_pcode_executor_state`](crate::pcode::emu::symz3::sym_z3_paired_pcode_executor_state)).
//! * Java's `SymZ3RecordsExecution.getInstructions()`/`getOps()` gain *default* bodies here
//!   (delegating to `getSharedSymbolicState()`). Rust cannot supply a default body for a
//!   supertrait's method from a subtrait, so each implementor writes its own one-line delegation.
//! * Java's `printSymbolicSummary(PrintStream)`/`printOps(PrintStream)`/
//!   `printInstructions(PrintStream)`/`printCompleteSummary(PrintStream)` take a `PrintStream`;
//!   per this crate's established convention for ported `print(PrintStream)` methods (see e.g.
//!   `AssemblyParser::print_grammar`), these take `&mut dyn std::io::Write` and return
//!   `io::Result<()>`. The summaries take the `Context` and `Z3InfixPrinter` Java's pieces open
//!   for themselves.
//! * `formatOps()` builds an anonymous `StringPcodeFormatter` subclass to render p-code with a
//!   `"[threadname] "` prefix per instruction. `StringPcodeFormatter` is not ported yet, so this
//!   instead renders each op from its own mnemonic (mirroring
//!   [`RecInstruction::to_display_string`](crate::pcode::emu::symz3::sym_z3_records_execution::RecInstruction)'s
//!   substitution for the same missing `toString()` machinery), prefixed the same way Java's
//!   overridden `formatOpTemplate` prefixes each line.

use crate::feature::seam_stubs::Z3Context;
use crate::pcode::emu::symz3::lib::z3_infix_printer::Z3InfixPrinter;
use crate::pcode::emu::symz3::sym_z3_pcode_thread::{SymZ3PcodeThread, SymZ3SharedState};
use crate::pcode::emu::symz3::sym_z3_records_execution::{RecInstruction, RecOp, SymZ3RecordsExecution};
use std::io;

/// Port of `ghidra.pcode.emu.symz3.SymZ3PcodeEmulatorTrait`. See the module docs.
pub trait SymZ3PcodeEmulatorTrait: SymZ3RecordsExecution {
    /// Java: `Collection<? extends SymZ3PcodeThread> getAllThreads()`, overriding
    /// `PcodeMachine.getAllThreads()`.
    fn get_all_symz3_threads(&self) -> Vec<&SymZ3PcodeThread>;

    /// Java: `SymZ3PairedPcodeExecutorState getSharedState()`, overriding
    /// `PcodeMachine.getSharedState()`: the handle every thread holds, or `None` until the machine
    /// has created its shared state (see the module docs).
    fn get_shared_symz3_state(&self) -> Option<SymZ3SharedState>;

    /// Java: `default String printableSummary()`: each thread's local symbolic summary, then the
    /// shared one, each followed by a line separator.
    fn printable_summary(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> String {
        let mut result = String::new();
        for thread in self.get_all_symz3_threads() {
            result.push_str(&thread.with_local_symbolic_state(|symbolic| symbolic.printable_summary(ctx, z3p)));
            result.push('\n');
        }
        if let Some(shared) = self.get_shared_symz3_state() {
            result.push_str(&shared.with_symbolic(|symbolic| symbolic.printable_summary(ctx, z3p)));
        }
        result.push('\n');
        result
    }

    /// Java: `default void printSymbolicSummary(PrintStream)`.
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

    /// Java: `default Stream<String> streamPreconditions(Context, Z3InfixPrinter)`: the shared
    /// state's preconditions, then each thread's.
    fn stream_preconditions(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<String> {
        let mut result = self
            .get_shared_symz3_state()
            .map(|shared| shared.with_symbolic(|symbolic| symbolic.stream_preconditions(ctx, z3p)))
            .unwrap_or_default();
        for thread in self.get_all_symz3_threads() {
            result.extend(thread.with_local_symbolic_state(|symbolic| symbolic.stream_preconditions(ctx, z3p)));
        }
        result
    }

    /// Java: `default Stream<Entry<String, String>> streamValuations(Context, Z3InfixPrinter)`:
    /// the shared state's valuations, then each thread's.
    fn stream_valuations(&self, ctx: &dyn Z3Context, z3p: &Z3InfixPrinter) -> Vec<(String, String)> {
        let mut result = self
            .get_shared_symz3_state()
            .map(|shared| shared.with_symbolic(|symbolic| symbolic.stream_valuations(ctx, z3p)))
            .unwrap_or_default();
        for thread in self.get_all_symz3_threads() {
            result.extend(thread.with_local_symbolic_state(|symbolic| symbolic.stream_valuations(ctx, z3p)));
        }
        result
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
    use crate::pcode::emu::symz3::sym_z3_pcode_thread::SymZ3ThreadId;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{OpCode, PcodeOp};

    #[test]
    fn a_formatted_op_is_prefixed_with_its_thread_index() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let op = PcodeOp::with_address_no_inputs(Address::new(space, 0x400), 0, OpCode::Copy);
        let rec = RecOp::new(0, SymZ3ThreadId::new("[Threads][2]"), op);
        assert_eq!(format_rec_op(&rec), "[2] COPY");
    }
}
