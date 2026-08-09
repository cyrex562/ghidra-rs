//! An arithmetic composed from two.
//!
//! Corresponds to `ghidra.pcode.exec.PairedPcodeArithmetic`.
//!
//! The composed arithmetic operates on tuples where each element is subject to its respective
//! arithmetic. One exception is [`PairedPcodeArithmetic::to_concrete`]; this arithmetic defers to
//! the left ("control") arithmetic. Thus, conventionally, when part of the pair represents the
//! concrete value, it should be the left.
//!
//! See [`PairedPcodeExecutorStatePiece`](crate::pcode::exec::paired_pcode_executor_state_piece::PairedPcodeExecutorStatePiece)
//! regarding composing three or more elements. Generally, it's recommended the client provide its
//! own "record" type and the corresponding arithmetic and state piece to manipulate it. Nesting
//! pairs would work, but is not recommended.
//!
//! Java's `org.apache.commons.lang3.tuple.Pair<L, R>` maps to a plain Rust tuple `(L, R)`
//! throughout this port, since Rust has no equivalent third-party "pair" convention. Every method
//! [`PcodeArithmetic`] requires (i.e. every method without a default) is implemented faithfully
//! here, matching the real Java class method-for-method; only `get_domain` relies on
//! [`PcodeArithmetic`]'s default (Java overrides `getDomain` to return `Pair.class`, which has no
//! Rust equivalent).

use std::sync::Arc;

use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::seam_stubs::ConcretionError;
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::pcode::OpCode;

/// An arithmetic composed from two, operating on `(L, R)` tuples.
///
/// - `L` is the type of the left ("control") element.
/// - `R` is the type of the right ("auxiliary") element.
pub struct PairedPcodeArithmetic<L, R> {
    left: Arc<dyn PcodeArithmetic<L>>,
    right: Arc<dyn PcodeArithmetic<R>>,
    endian: Option<Endian>,
}

impl<L, R> PairedPcodeArithmetic<L, R> {
    /// Construct a composed arithmetic from the given two.
    ///
    /// `left_arith` is the left ("control") arithmetic; `right_arith` is the right ("rider")
    /// arithmetic.
    ///
    /// # Panics
    /// Panics if both arithmetics report an endianness and they disagree, matching Java's
    /// `IllegalArgumentException`.
    pub fn new(left_arith: Arc<dyn PcodeArithmetic<L>>, right_arith: Arc<dyn PcodeArithmetic<R>>) -> Self {
        let lend = left_arith.get_endian();
        let rend = right_arith.get_endian();
        if let (Some(l), Some(r)) = (lend, rend) {
            assert!(l == r, "Arithmetics must agree in endianness");
        }
        let endian = lend.or(rend);
        Self { left: left_arith, right: right_arith, endian }
    }

    /// Get the left ("control") arithmetic.
    pub fn get_left(&self) -> &Arc<dyn PcodeArithmetic<L>> {
        &self.left
    }

    /// Get the right ("rider") arithmetic.
    pub fn get_right(&self) -> &Arc<dyn PcodeArithmetic<R>> {
        &self.right
    }
}

impl<L, R> PcodeArithmetic<(L, R)> for PairedPcodeArithmetic<L, R> {
    fn get_endian(&self) -> Option<Endian> {
        self.endian
    }

    fn unary_op(&self, opcode: OpCode, sizeout: i32, sizein1: i32, in1: &(L, R)) -> (L, R) {
        (
            self.left.unary_op(opcode, sizeout, sizein1, &in1.0),
            self.right.unary_op(opcode, sizeout, sizein1, &in1.1),
        )
    }

    fn binary_op(
        &self,
        opcode: OpCode,
        sizeout: i32,
        sizein1: i32,
        in1: &(L, R),
        sizein2: i32,
        in2: &(L, R),
    ) -> (L, R) {
        (
            self.left.binary_op(opcode, sizeout, sizein1, &in1.0, sizein2, &in2.0),
            self.right.binary_op(opcode, sizeout, sizein1, &in1.1, sizein2, &in2.1),
        )
    }

    fn mod_before_store(
        &self,
        sizein_offset: i32,
        space: &AddressSpace,
        in_offset: &(L, R),
        sizein_value: i32,
        in_value: &(L, R),
    ) -> (L, R) {
        (
            self.left.mod_before_store(sizein_offset, space, &in_offset.0, sizein_value, &in_value.0),
            self.right.mod_before_store(sizein_offset, space, &in_offset.1, sizein_value, &in_value.1),
        )
    }

    fn mod_after_load(
        &self,
        sizein_offset: i32,
        space: &AddressSpace,
        in_offset: &(L, R),
        sizein_value: i32,
        in_value: &(L, R),
    ) -> (L, R) {
        (
            self.left.mod_after_load(sizein_offset, space, &in_offset.0, sizein_value, &in_value.0),
            self.right.mod_after_load(sizein_offset, space, &in_offset.1, sizein_value, &in_value.1),
        )
    }

    fn from_const_bytes(&self, value: &[u8]) -> (L, R) {
        (self.left.from_const_bytes(value), self.right.from_const_bytes(value))
    }

    fn to_concrete(&self, value: &(L, R), purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
        self.left.to_concrete(&value.0, purpose)
    }

    fn size_of(&self, value: &(L, R)) -> i64 {
        self.left.size_of(&value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    /// Trivial little-endian byte-array arithmetic, mirroring the one used to exercise
    /// [`PcodeArithmetic`]'s default methods.
    struct LittleEndianBytesArithmetic;

    impl PcodeArithmetic<Vec<u8>> for LittleEndianBytesArithmetic {
        fn get_endian(&self) -> Option<Endian> {
            Some(Endian::Little)
        }

        fn unary_op(&self, _opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
            let mut out = in1.clone();
            out.resize(sizeout as usize, 0);
            out
        }

        fn binary_op(
            &self,
            opcode: OpCode,
            sizeout: i32,
            _sizein1: i32,
            in1: &Vec<u8>,
            _sizein2: i32,
            in2: &Vec<u8>,
        ) -> Vec<u8> {
            let a = crate::pcode::utils::bytes_to_long(in1, in1.len(), false);
            let b = crate::pcode::utils::bytes_to_long(in2, in2.len(), false);
            let result = match opcode {
                OpCode::IntAdd => a.wrapping_add(b),
                OpCode::IntMult => a.wrapping_mul(b),
                _ => 0,
            };
            crate::pcode::utils::long_to_bytes(result, sizeout as usize, false)
        }

        fn mod_before_store(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }

        fn mod_after_load(
            &self,
            _sizein_offset: i32,
            _space: &AddressSpace,
            _in_offset: &Vec<u8>,
            _sizein_value: i32,
            in_value: &Vec<u8>,
        ) -> Vec<u8> {
            in_value.clone()
        }

        fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
            value.to_vec()
        }

        fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
            Ok(value.clone())
        }

        fn size_of(&self, value: &Vec<u8>) -> i64 {
            value.len() as i64
        }
    }

    fn paired() -> PairedPcodeArithmetic<Vec<u8>, Vec<u8>> {
        PairedPcodeArithmetic::new(Arc::new(LittleEndianBytesArithmetic), Arc::new(LittleEndianBytesArithmetic))
    }

    #[test]
    fn new_agrees_on_endianness() {
        let p = paired();
        assert_eq!(p.get_endian(), Some(Endian::Little));
    }

    #[test]
    #[should_panic(expected = "Arithmetics must agree in endianness")]
    fn new_panics_on_endian_mismatch() {
        struct BigEndianBytesArithmetic;
        impl PcodeArithmetic<Vec<u8>> for BigEndianBytesArithmetic {
            fn get_endian(&self) -> Option<Endian> {
                Some(Endian::Big)
            }
            fn unary_op(&self, _opcode: OpCode, sizeout: i32, _sizein1: i32, in1: &Vec<u8>) -> Vec<u8> {
                let mut out = in1.clone();
                out.resize(sizeout as usize, 0);
                out
            }
            fn binary_op(
                &self,
                _opcode: OpCode,
                sizeout: i32,
                _sizein1: i32,
                _in1: &Vec<u8>,
                _sizein2: i32,
                _in2: &Vec<u8>,
            ) -> Vec<u8> {
                vec![0; sizeout as usize]
            }
            fn mod_before_store(
                &self,
                _sizein_offset: i32,
                _space: &AddressSpace,
                _in_offset: &Vec<u8>,
                _sizein_value: i32,
                in_value: &Vec<u8>,
            ) -> Vec<u8> {
                in_value.clone()
            }
            fn mod_after_load(
                &self,
                _sizein_offset: i32,
                _space: &AddressSpace,
                _in_offset: &Vec<u8>,
                _sizein_value: i32,
                in_value: &Vec<u8>,
            ) -> Vec<u8> {
                in_value.clone()
            }
            fn from_const_bytes(&self, value: &[u8]) -> Vec<u8> {
                value.to_vec()
            }
            fn to_concrete(&self, value: &Vec<u8>, _purpose: Purpose) -> Result<Vec<u8>, ConcretionError> {
                Ok(value.clone())
            }
            fn size_of(&self, value: &Vec<u8>) -> i64 {
                value.len() as i64
            }
        }

        PairedPcodeArithmetic::new(Arc::new(LittleEndianBytesArithmetic), Arc::new(BigEndianBytesArithmetic));
    }

    #[test]
    fn binary_op_applies_to_both_sides_independently() {
        let p = paired();
        let two = p.from_const_bytes(&2u32.to_le_bytes());
        let three = p.from_const_bytes(&3u32.to_le_bytes());

        let sum = p.binary_op(OpCode::IntAdd, 4, 4, &two, 4, &three);
        assert_eq!(crate::pcode::utils::bytes_to_long(&sum.0, sum.0.len(), false), 5);
        assert_eq!(crate::pcode::utils::bytes_to_long(&sum.1, sum.1.len(), false), 5);
    }

    #[test]
    fn to_concrete_and_size_of_defer_to_left() {
        let p = paired();
        let value = (vec![1, 2, 3], vec![9, 9]);

        assert_eq!(p.to_concrete(&value, Purpose::Other).unwrap(), vec![1, 2, 3]);
        assert_eq!(p.size_of(&value), 3);
    }

    #[test]
    fn get_left_and_get_right_return_the_constructed_arithmetics() {
        let p = paired();
        assert_eq!(p.get_left().get_endian(), Some(Endian::Little));
        assert_eq!(p.get_right().get_endian(), Some(Endian::Little));
    }
}
