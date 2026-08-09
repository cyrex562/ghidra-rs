//! Minimal placeholder types for core types that a ported interface under [`crate::pcode`]
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members needed by the interface(s) that currently reference it, and is expected to be
//! replaced (or grown into a supertrait/struct of) the real port once that Java class is ported.
//! See `STUBS.tsv` for provenance.

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::Purpose;
use crate::pcode::exec::sleigh_pcode_userop_definition::BuilderStage1;
use crate::pcode::floatformat::big_float::{BigFloat, MathContext};
use crate::program::model::lang::sleigh::SleighLanguage;

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

/// Placeholder for `ghidra.pcode.floatformat.FloatFormat`, referenced by
/// [`BigFloat::to_display_string_with_format`](crate::pcode::floatformat::big_float::BigFloat::to_display_string_with_format)
/// before the real class is ported. Exposes only the members that method needs: the rounding
/// context used to format a decimal string, encoding a value to its bit pattern (`BigInteger` in
/// Java, `i128` here per the crate-wide convention), and decoding a formatted decimal back into a
/// value to check whether a shortened string still round-trips.
pub trait FloatFormat {
    /// Port of `FloatFormat.getDisplayContext()`.
    fn get_display_context(&self) -> MathContext;

    /// Port of `FloatFormat.getEncoding(BigFloat)`.
    fn get_encoding(&self, value: &dyn BigFloat) -> i128;

    /// Port of `FloatFormat.getBigFloat(BigDecimal)`. Takes `f64` rather than `BigDecimal`,
    /// matching how [`BigFloat::to_big_decimal`](crate::pcode::floatformat::big_float::BigFloat::to_big_decimal)
    /// represents that Java type here.
    fn get_big_float(&self, value: f64) -> Box<dyn BigFloat>;
}

/// Placeholder for `ghidra.pcode.pcoderaw.PcodeOpRaw`, referenced by
/// [`BreakTable`](crate::pcode::emulate::break_table::BreakTable) before the real class is ported.
pub trait PcodeOpRaw: Send + Sync {}

/// Placeholder for `ghidra.pcode.emulate.Emulate`, referenced by
/// [`OpBehaviorOther`](crate::pcode::opbehavior::OpBehaviorOther) and
/// [`BreakTable`](crate::pcode::emulate::break_table::BreakTable) before the real class is ported.
/// This is a minimal interface stub exposing only the methods needed by existing references.
pub trait Emulate: Send + Sync {
    /// Placeholder for `Emulate.dispose()`.
    fn dispose(&self);
}

/// Placeholder for `ghidra.pcode.exec.AbstractSleighPcodeUseropDefinition` (and its nested
/// `Builder`), referenced by
/// [`SleighPcodeUseropDefinition::Factory::define`](crate::pcode::exec::sleigh_pcode_userop_definition::Factory::define)
/// before the real class is ported. `Builder::build()` ultimately delegates to the also-unported
/// `FixedSleighPcodeUseropDefinition`/`OverloadedSleighPcodeUseropDefinition`, so this stub's
/// `builder()` panics if actually invoked; it exists only so `Factory::define`'s signature can
/// stay faithful to the Java original ahead of those types being ported.
pub struct AbstractSleighPcodeUseropDefinition;

impl AbstractSleighPcodeUseropDefinition {
    /// Placeholder for `new AbstractSleighPcodeUseropDefinition.Builder(factory, name)`.
    pub fn builder(_language: Arc<SleighLanguage>, _name: String) -> Box<dyn BuilderStage1> {
        unimplemented!("AbstractSleighPcodeUseropDefinition is not yet ported")
    }
}

/// Placeholder for `ghidra.pcode.exec.PcodeProgram`, referenced by
/// [`SleighPcodeUseropDefinition::program_for`](crate::pcode::exec::sleigh_pcode_userop_definition::SleighPcodeUseropDefinition::program_for)
/// before the real class is ported. Used there only as an opaque return type, so no members are
/// exposed yet.
pub trait PcodeProgram: Send + Sync {}

/// Placeholder for `ghidra.pcode.exec.PcodeUseropLibrary`, referenced by
/// [`SleighPcodeUseropDefinition::program_for`](crate::pcode::exec::sleigh_pcode_userop_definition::SleighPcodeUseropDefinition::program_for)
/// before the real class is ported. Used there only as an opaque parameter type, so no members
/// are exposed yet.
pub trait PcodeUseropLibrary: Send + Sync {}
