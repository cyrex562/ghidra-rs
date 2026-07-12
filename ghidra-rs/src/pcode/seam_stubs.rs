//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use crate::pcode::exec::pcode_arithmetic::Purpose;

/// Placeholder for `ghidra.pcode.exec.PcodeExecutorStatePiece.Reason`, referenced by
/// [`Purpose`](crate::pcode::exec::pcode_arithmetic::Purpose) before the real class is ported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The value is needed as the default program counter or disassembly context.
    ReInit,
    /// The value is being read by the emulator as data in the course of execution.
    ExecuteRead,
    /// The value is being decoded by the emulator as an instruction for execution.
    ExecuteDecode,
    /// The value is being inspected by something other than an emulator.
    Inspect,
}

/// Placeholder for `ghidra.pcode.exec.ConcretionError`, referenced by
/// [`PcodeArithmetic`](crate::pcode::exec::pcode_arithmetic::PcodeArithmetic) before the real
/// exception class (a `PcodeExecutionException`/`RuntimeException` subtype) is ported. Carries
/// only the message and [`Purpose`] fields the real class exposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConcretionError {
    message: String,
    purpose: Purpose,
}

impl ConcretionError {
    /// Create the error with a client-facing message and the reason a concrete value was needed.
    pub fn new(message: impl Into<String>, purpose: Purpose) -> Self {
        Self {
            message: message.into(),
            purpose,
        }
    }

    /// The reason why the emulator needed a concrete value.
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }
}

impl std::fmt::Display for ConcretionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConcretionError {}
