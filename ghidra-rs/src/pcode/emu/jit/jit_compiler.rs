//! The Just-in-Time (JIT) translation engine that powers the
//! [`JitPcodeEmulator`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator).
//!
//! Port of `ghidra.pcode.emu.jit.JitCompiler`.
//!
//! This is the translation engine from "any" machine language into JVM bytecode. A passage is
//! decoded at a desired entry point using
//! [`JitPassageDecoder`](crate::pcode::emu::jit::decode::jit_passage_decoder::JitPassageDecoder).
//! This compiler then translates the passage through several analysis phases -- control flow,
//! data flow, variable scope, type assignment, variable allocation, and operation elimination --
//! before code generation emits the final classfile bytes.
//!
//! None of those analysis/code-generation phases are ported yet (their Rust stand-ins in
//! [`seam_stubs`](crate::pcode::seam_stubs) predate this type and are shaped for their own
//! individual callers, not for driving the whole pipeline `compilePassage` chains them into), so
//! [`JitCompiler::compile_passage`] panics, in the same spirit as `BytesPcodeArithmetic`. The
//! configuration it holds is real, since the emulator reads it back on every translation.

use crate::pcode::emu::jit::gen::tgt::JitCompiledPassageClass;
use crate::pcode::emu::jit::jit_configuration::JitConfiguration;
use crate::pcode::seam_stubs::{JitPassage, MethodTooLargeException};

/// Diagnostic toggles for [`JitCompiler`].
///
/// Port of the nested enum `JitCompiler.Diag`. Nothing in this crate reads
/// [`JitCompiler::ENABLE_DIAGNOSTICS`] yet, but the toggles themselves are ported for fidelity
/// with the Java class's public surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Diag {
    /// Print each passage (instructions and p-code ops) before translation.
    PrintPassage,
    /// Print the contents (p-code) of each basic block and flows/branches among them.
    PrintCfm,
    /// Print the ops of each basic block in SSA (sort of) form.
    PrintDfm,
    /// Print the list of live variables for each basic block.
    PrintVsm,
    /// Print each synthetic operation, e.g., catenation, subpiece, phi.
    PrintSynth,
    /// Print each eliminated op.
    PrintOum,
    /// Enable ASM's trace for each generated classfile.
    TraceClass,
    /// Save the generated `.class` file to disk for offline examination.
    DumpClass,
}

/// The set of enabled diagnostic toggles.
///
/// Port of `JitCompiler.ENABLE_DIAGNOSTICS`. In production, this should be empty. Java's field is
/// a mutable `EnumSet` a developer edits temporarily while debugging; modelled here as a
/// [`Mutex`](std::sync::Mutex) around a [`HashSet`](std::collections::HashSet) for the same
/// mutability, guarded by [`once_cell::sync::Lazy`] since Rust statics can't run arbitrary
/// constructors.
pub static ENABLE_DIAGNOSTICS: once_cell::sync::Lazy<std::sync::Mutex<std::collections::HashSet<Diag>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// The Just-in-Time (JIT) translation engine that powers the
/// [`JitPcodeEmulator`](crate::pcode::emu::jit::jit_pcode_emulator::JitPcodeEmulator).
///
/// Port of `ghidra.pcode.emu.jit.JitCompiler`. See the module docs for the translation pipeline
/// and why [`compile_passage`](Self::compile_passage) is not yet functional.
pub struct JitCompiler {
    /// The JIT emulator's configuration.
    config: JitConfiguration,
}

impl JitCompiler {
    /// Exclude a given address offset from ASM's `COMPUTE_MAXS`/`COMPUTE_FRAMES`, to help debug a
    /// crash in that automatic computation. `-1` (the default) excludes nothing.
    ///
    /// Port of `JitCompiler.EXCLUDE_MAXS`. Nothing in this crate reads it yet -- there is no ASM
    /// analogue here -- but it is ported for fidelity with the Java class's public surface.
    pub const EXCLUDE_MAXS: i64 = -1;

    /// Construct a p-code to bytecode translator.
    ///
    /// In general, this should only be used by the JIT emulator and its test suite.
    ///
    /// Port of `new JitCompiler(JitConfiguration)`.
    pub fn new(config: JitConfiguration) -> Self {
        Self { config }
    }

    /// Get this compiler's configuration.
    ///
    /// Port of `JitCompiler.getConfiguration()`.
    pub fn get_configuration(&self) -> &JitConfiguration {
        &self.config
    }

    /// Translate a passage.
    ///
    /// Port of `JitCompiler.compilePassage(Lookup, JitPassage)`. The `Lookup` argument is
    /// dropped: it exists only to define the generated classfile as a hidden class, which this
    /// crate has no JVM to do -- see [`JitCompiledPassageClass`]'s own deviation notes. Java's
    /// thrown `MethodTooLargeException` becomes an `Err`, since that is the one failure the
    /// caller handles rather than propagates.
    ///
    /// # Panics
    ///
    /// Always: the analysis and code-generation phases this chains together are not ported.
    pub fn compile_passage(
        &self,
        _passage: JitPassage,
    ) -> Result<JitCompiledPassageClass, MethodTooLargeException> {
        let _ = &self.config;
        unimplemented!("JitCompiler::compile_passage: analysis/code-generation pipeline not yet ported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_configuration_returns_constructed_config() {
        let config = JitConfiguration::new(100, 1000, 10, true, false, false);
        let compiler = JitCompiler::new(config);
        assert_eq!(compiler.get_configuration().max_passage_ops, 1000);
        assert_eq!(compiler.get_configuration().max_passage_instructions, 100);
        assert!(compiler.get_configuration().remove_unused_operations);
        assert!(!compiler.get_configuration().emit_counters);
    }
}
