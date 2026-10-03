//! The p-code arithmetic for [`TraceMemoryState`].
//!
//! Corresponds to `ghidra.pcode.exec.trace.TraceMemoryStatePcodeArithmetic`.
//!
//! This arithmetic is meant to be used as an auxiliary to a concrete arithmetic. It should be used
//! with a state that knows how to load state markings from the same trace as the concrete state,
//! so that it can compute the "state" of a Sleigh expression's value. It essentially works like a
//! rudimentary taint analyzer: If any part of any input to the expression is tainted, i.e., not
//! [`TraceMemoryState::Known`], then the result is [`TraceMemoryState::Unknown`]. This is best
//! exemplified in [`PcodeArithmetic::binary_op`]'s implementation below.
//!
//! Java's `T` is `TraceMemoryState`, whose references may be `null`; as with
//! [`LocationPcodeArithmetic`](crate::pcode::exec::location_pcode_arithmetic::LocationPcodeArithmetic),
//! the Rust port uses `Option<TraceMemoryState>` for `T` to carry that nullability through the
//! generic [`PcodeArithmetic`] trait.

use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::pcode::OpCode;
use crate::trace::model::memory::trace_memory_state::TraceMemoryState;

/// The p-code arithmetic for [`TraceMemoryState`].
///
/// Java models this as an `enum` with a single `INSTANCE` constant; this mirrors that as a
/// one-variant enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TraceMemoryStatePcodeArithmetic {
    /// The singleton instance.
    Instance,
}

impl PcodeArithmetic<Option<TraceMemoryState>> for TraceMemoryStatePcodeArithmetic {
    fn get_domain(&self) -> &'static str {
        "TraceMemoryState"
    }

    fn get_endian(&self) -> Option<Endian> {
        None
    }

    fn unary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        *in1
    }

    fn binary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        in1: &Option<TraceMemoryState>,
        _sizein2: i32,
        in2: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        if *in1 == Some(TraceMemoryState::Known) && *in2 == Some(TraceMemoryState::Known) {
            Some(TraceMemoryState::Known)
        }
        else {
            Some(TraceMemoryState::Unknown)
        }
    }

    /// Shouldn't see STORE during Sleigh eval, anyway.
    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Option<TraceMemoryState>,
        _sizein_value: i32,
        in_value: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        *in_value
    }

    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        in_offset: &Option<TraceMemoryState>,
        _sizein_value: i32,
        in_value: &Option<TraceMemoryState>,
    ) -> Option<TraceMemoryState> {
        if *in_offset == Some(TraceMemoryState::Known) && *in_value == Some(TraceMemoryState::Known)
        {
            Some(TraceMemoryState::Known)
        }
        else {
            Some(TraceMemoryState::Unknown)
        }
    }

    fn from_const_bytes(&self, _value: &[u8]) -> Option<TraceMemoryState> {
        Some(TraceMemoryState::Known)
    }

    fn from_const_u64(&self, _value: u64, _size: i32) -> Option<TraceMemoryState> {
        Some(TraceMemoryState::Known)
    }

    fn from_const_big_int(
        &self,
        _value: i128,
        _size: i32,
        _is_contextreg: bool,
    ) -> Option<TraceMemoryState> {
        Some(TraceMemoryState::Known)
    }

    fn to_concrete(
        &self,
        _value: &Option<TraceMemoryState>,
        purpose: Purpose,
    ) -> Result<Vec<u8>, ConcretionError> {
        Err(ConcretionError::new("Cannot make TraceMemoryState concrete", purpose))
    }

    /// Java: `throw new AssertionError("Cannot get size of a TraceMemoryState")`.
    fn size_of(&self, _value: &Option<TraceMemoryState>) -> i64 {
        panic!("Cannot get size of a TraceMemoryState")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARITH: TraceMemoryStatePcodeArithmetic = TraceMemoryStatePcodeArithmetic::Instance;

    #[test]
    fn domain_and_endian() {
        assert_eq!(ARITH.get_domain(), "TraceMemoryState");
        assert_eq!(ARITH.get_endian(), None);
    }

    #[test]
    fn unary_op_is_identity() {
        assert_eq!(ARITH.unary_op(OpCode::Copy, 1, 1, &Some(TraceMemoryState::Known)), Some(TraceMemoryState::Known));
        assert_eq!(ARITH.unary_op(OpCode::Copy, 1, 1, &Some(TraceMemoryState::Unknown)), Some(TraceMemoryState::Unknown));
        assert_eq!(ARITH.unary_op(OpCode::Copy, 1, 1, &None), None);
    }

    #[test]
    fn binary_op_is_known_only_if_both_inputs_are_known() {
        let known = Some(TraceMemoryState::Known);
        let unknown = Some(TraceMemoryState::Unknown);

        assert_eq!(ARITH.binary_op(OpCode::IntAdd, 4, 4, &known, 4, &known), known);
        assert_eq!(ARITH.binary_op(OpCode::IntAdd, 4, 4, &known, 4, &unknown), unknown);
        assert_eq!(ARITH.binary_op(OpCode::IntAdd, 4, 4, &unknown, 4, &known), unknown);
        // Java's `null` inputs (here, `None`) are not `TraceMemoryState.KNOWN` either, so the
        // taint spreads exactly the same as for an explicit `UNKNOWN`.
        assert_eq!(ARITH.binary_op(OpCode::IntAdd, 4, 4, &None, 4, &known), unknown);
        assert_eq!(ARITH.binary_op(OpCode::IntAdd, 4, 4, &None, 4, &None), unknown);
    }

    #[test]
    fn mod_before_store_returns_the_value_unchanged() {
        let ram = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let value = Some(TraceMemoryState::Unknown);
        assert_eq!(ARITH.mod_before_store(4, &ram, &Some(TraceMemoryState::Known), 4, &value), value);
    }

    #[test]
    fn mod_after_load_is_known_only_if_offset_and_value_are_known() {
        let ram = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let known = Some(TraceMemoryState::Known);
        let unknown = Some(TraceMemoryState::Unknown);

        assert_eq!(ARITH.mod_after_load(4, &ram, &known, 4, &known), known);
        assert_eq!(ARITH.mod_after_load(4, &ram, &unknown, 4, &known), unknown);
        assert_eq!(ARITH.mod_after_load(4, &ram, &known, 4, &unknown), unknown);
    }

    #[test]
    fn from_const_is_always_known() {
        assert_eq!(ARITH.from_const_bytes(&[1, 2, 3]), Some(TraceMemoryState::Known));
        assert_eq!(ARITH.from_const_u64(0x1234, 4), Some(TraceMemoryState::Known));
        assert_eq!(ARITH.from_const_big_int(-1, 4, false), Some(TraceMemoryState::Known));
        assert_eq!(ARITH.from_const_big_int(-1, 4, true), Some(TraceMemoryState::Known));
    }

    #[test]
    fn to_concrete_always_errs() {
        let err = ARITH.to_concrete(&Some(TraceMemoryState::Known), Purpose::Other).unwrap_err();
        assert_eq!(err.message(), "Cannot make TraceMemoryState concrete");
        assert_eq!(err.purpose(), Purpose::Other);
    }

    #[test]
    #[should_panic(expected = "Cannot get size of a TraceMemoryState")]
    fn size_of_panics() {
        let _ = ARITH.size_of(&Some(TraceMemoryState::Known));
    }
}
