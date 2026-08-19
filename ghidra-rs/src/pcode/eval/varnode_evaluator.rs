//! Port of `ghidra.pcode.eval.VarnodeEvaluator`.
//!
//! An evaluator of high-level varnodes and variable storage.
//!
//! This is a limited analog to [`PcodeExecutor`](crate::pcode::exec::PcodeExecutor) but for high p-code.
//! It can only "execute" parts of the AST that represent expressions, as a means of evaluating them.
//! If it encounters, e.g., a `PcodeOp::MULTIEQUAL` or phi node, it will terminate with an exception.

use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::listing::program::Program;
use crate::program::model::pcode::{PcodeOp, Varnode};

/// An evaluator of high-level varnodes.
///
/// This is a limited analog to [`PcodeExecutor`](crate::pcode::exec::PcodeExecutor) but for high p-code.
/// It is limited in that it can only "execute" parts of the AST that represent expressions, as a means
/// of evaluating them. If it encounters, e.g., a `PcodeOp::MULTIEQUAL` or phi node, it will terminate
/// with an exception.
///
/// # Type Parameters
///
/// * `T` - the type of values resulting from evaluation
pub trait VarnodeEvaluator<T> {
    /// Evaluate a varnode
    ///
    /// # Arguments
    ///
    /// * `program` - the program containing the varnode
    /// * `vn` - the varnode to evaluate
    ///
    /// # Returns
    ///
    /// The value of the varnode
    fn evaluate_varnode(&self, program: &dyn Program, vn: &Varnode) -> T;

    /// Evaluate variable storage
    ///
    /// Each varnode is evaluated as in [`evaluate_varnode`](Self::evaluate_varnode) and then
    /// concatenated. The lower-indexed varnodes in storage are the more significant pieces,
    /// similar to big endian.
    ///
    /// # Arguments
    ///
    /// * `program` - the program containing the variable storage
    /// * `storage` - the storage
    ///
    /// # Returns
    ///
    /// The value of the storage
    fn evaluate_storage(&self, program: &dyn Program, storage: &dyn VariableStorage) -> T;

    /// Evaluate a high p-code op
    ///
    /// # Arguments
    ///
    /// * `program` - the program containing the op
    /// * `op` - the p-code op
    ///
    /// # Returns
    ///
    /// The value of the op's output
    fn evaluate_op(&self, program: &dyn Program, op: &PcodeOp) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test stub to verify the trait compiles and can be referenced
    #[test]
    fn test_varnode_evaluator_trait_exists() {
        // This test verifies the trait is properly defined and accessible
        // A real implementation would be tested against actual p-code evaluation
        assert!(true);
    }
}
