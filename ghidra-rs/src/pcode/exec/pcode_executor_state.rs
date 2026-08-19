//! An interface that provides storage for values of type `T`
//!
//! Corresponds to `ghidra.pcode.exec.PcodeExecutorState`.
//!
//! This is a stricter form of `PcodeExecutorStatePiece`, in that it requires the value and
//! address offset types to agree, so that a p-code executor or emulator can perform loads and
//! stores using indirect addresses. The typical pattern for implementing a state is to compose it
//! from pieces. See [`PcodeExecutorStatePiece`].

use crate::pcode::exec::pcode_executor_state_piece::PcodeExecutorStatePiece;

/// An interface that provides storage for values of type `T`.
///
/// This trait requires both the address offset type and the value type to be the same (`T`),
/// allowing for indirect loads and stores using those values as addresses.
///
/// In Java, `PcodeExecutorState<T>` extends `PcodeExecutorStatePiece<T, T>` and provides
/// a default implementation of `getAddressArithmetic()` that returns `getArithmetic()`, as well
/// as a `paired()` default method. This Rust port uses a marker trait to enforce the constraint
/// that offset and value types agree, with implementors deriving the default behavior from
/// `PcodeExecutorStatePiece`.
pub trait PcodeExecutorState<T>: PcodeExecutorStatePiece<T, T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_executor_state_marker_trait() {
        fn check_trait_bound<T: PcodeExecutorState<i64>>(_v: &T) {}

        struct TestState;
        impl PcodeExecutorStatePiece<i64, i64> for TestState {
            fn get_language(&self) -> Box<dyn crate::program::model::lang::language::Language> {
                unimplemented!()
            }
            fn get_address_arithmetic(&self) -> std::sync::Arc<dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<i64>> {
                unimplemented!()
            }
            fn get_arithmetic(&self) -> std::sync::Arc<dyn crate::pcode::exec::pcode_arithmetic::PcodeArithmetic<i64>> {
                unimplemented!()
            }
            fn stream_pieces(&self) -> Vec<&dyn crate::pcode::exec::pcode_executor_state_piece::ErasedPcodeExecutorStatePiece> {
                vec![]
            }
            fn set_var_abstract(&mut self, _: &std::sync::Arc<crate::program::model::address::AddressSpace>, _: &i64, _: i32, _: bool, _: &i64) {
                unimplemented!()
            }
            fn set_var_internal_abstract(&mut self, _: &std::sync::Arc<crate::program::model::address::AddressSpace>, _: &i64, _: i32, _: &i64) {
                unimplemented!()
            }
            fn get_var_abstract(&self, _: &std::sync::Arc<crate::program::model::address::AddressSpace>, _: &i64, _: i32, _: bool, _: crate::pcode::exec::pcode_executor_state_piece::Reason) -> i64 {
                0
            }
            fn get_var_internal_abstract(&self, _: &std::sync::Arc<crate::program::model::address::AddressSpace>, _: &i64, _: i32, _: crate::pcode::exec::pcode_executor_state_piece::Reason) -> i64 {
                0
            }
            fn get_register_values(&self) -> Vec<(crate::program::model::lang::register::RegisterRef, i64)> {
                vec![]
            }
            fn get_concrete_buffer(&self, _: &crate::program::model::address::Address, _: crate::pcode::exec::pcode_arithmetic::Purpose) -> Box<dyn crate::program::model::mem::mem_buffer::MemBuffer> {
                unimplemented!()
            }
            fn clear(&mut self) {}
        }

        impl PcodeExecutorState<i64> for TestState {}

        let test = TestState;
        check_trait_bound(&test);
    }
}
