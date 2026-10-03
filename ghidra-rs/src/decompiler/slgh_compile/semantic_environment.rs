use crate::decompiler::slghsymbol::{LabelSymbol, MacroSymbol, SpecificSymbol, UserOpSymbol};
use crate::decompiler::sleigh_base::NamedSymbolProvider;
use crate::decompiler::translate::BasicSpaceProvider;
use crate::decompiler::opcodes::OpCode;
use crate::decompiler::slgh_compile::{ExprTree, StarQuality};
use crate::generic::stl::vector_stl::VectorStl;
use crate::program::model::lang::sleigh::template::{ConstructTpl, OpTpl, VarnodeTpl};
use crate::sleigh::grammar::Location;

/// Semantic environment for SLEIGH compiler.
///
/// Provides methods for building semantic constructs during SLEIGH compilation,
/// including expression trees, operations, and label management.
///
/// Models `ghidra.pcodeCPort.slgh_compile.SemanticEnvironment`.
pub trait SemanticEnvironment: NamedSymbolProvider + BasicSpaceProvider {
    /// Records a no-op at the given location.
    fn record_nop(&mut self, location: Location);

    /// Produce a constant varnode that is the offset portion of the given varnode.
    fn address_of(&self, var: &VarnodeTpl, size: i32) -> VarnodeTpl;

    /// Set the constructor's result varnode.
    fn set_result_varnode(&self, ct: ConstructTpl, vn: VarnodeTpl) -> ConstructTpl;

    /// Set the constructor's result to be the value pointed at by the given varnode.
    fn set_result_star_varnode(
        &self,
        ct: ConstructTpl,
        star: &StarQuality,
        vn: VarnodeTpl,
    ) -> ConstructTpl;

    /// Create a new output from the given expression.
    fn new_output(
        &mut self,
        location: Location,
        rhs: &mut dyn ExprTree,
        varname: &str,
    ) -> VectorStl<OpTpl>;

    /// Create a new output from the given expression with specified size.
    fn new_output_sized(
        &mut self,
        location: Location,
        rhs: &mut dyn ExprTree,
        varname: &str,
        size: i32,
    ) -> VectorStl<OpTpl>;

    /// Create a new expression with the given opcode and single input.
    fn create_op(&mut self, location: Location, opc: OpCode, vn: &mut dyn ExprTree) -> Box<dyn ExprTree>;

    /// Create a new expression with the given opcode and two inputs.
    fn create_op_binary(
        &mut self,
        location: Location,
        opc: OpCode,
        vn1: &mut dyn ExprTree,
        vn2: &mut dyn ExprTree,
    ) -> Box<dyn ExprTree>;

    /// Create an operation with no output.
    fn create_op_no_out(&mut self, location: Location, opc: OpCode, vn: &mut dyn ExprTree) -> VectorStl<OpTpl>;

    /// Create a binary operation with no output.
    fn create_op_no_out_binary(
        &mut self,
        location: Location,
        opc: OpCode,
        vn1: &mut dyn ExprTree,
        vn2: &mut dyn ExprTree,
    ) -> VectorStl<OpTpl>;

    /// Create a constant operation.
    fn create_op_const(&mut self, location: Location, opc: OpCode, val: i64) -> VectorStl<OpTpl>;

    /// Create a load expression from the given pointer expression.
    fn create_load(
        &mut self,
        location: Location,
        qual: &StarQuality,
        ptr: &mut dyn ExprTree,
    ) -> Box<dyn ExprTree>;

    /// Create a store expression.
    fn create_store(
        &mut self,
        location: Location,
        qual: &StarQuality,
        ptr: &mut dyn ExprTree,
        val: &mut dyn ExprTree,
    ) -> VectorStl<OpTpl>;

    /// Create a user-defined p-code operation.
    fn create_user_op(
        &mut self,
        sym: &UserOpSymbol,
        param: VectorStl<Box<dyn ExprTree>>,
    ) -> Box<dyn ExprTree>;

    /// Create a user-defined p-code operation with no output.
    fn create_user_op_no_out(
        &mut self,
        location: Location,
        sym: &UserOpSymbol,
        param: VectorStl<Box<dyn ExprTree>>,
    ) -> VectorStl<OpTpl>;

    /// Create an expression assigning to a bitrange within a varnode.
    fn assign_bit_range(
        &mut self,
        location: Location,
        vn: &VarnodeTpl,
        bitoffset: i32,
        numbits: i32,
        rhs: &mut dyn ExprTree,
    ) -> VectorStl<OpTpl>;

    /// Create an expression computing the indicated bitrange of a symbol.
    fn create_bit_range(
        &self,
        location: Location,
        sym: &dyn SpecificSymbol,
        bitoffset: i32,
        numbits: i32,
    ) -> Box<dyn ExprTree>;

    /// Create a macro build directive.
    fn create_macro_use(
        &mut self,
        location: Location,
        sym: &MacroSymbol,
        param: VectorStl<Box<dyn ExprTree>>,
    ) -> VectorStl<OpTpl>;

    /// Create a label symbol.
    fn define_label(&mut self, location: Location, name: &str) -> LabelSymbol;

    /// Create a placeholder OpTpl for a label.
    fn place_label(&mut self, location: Location, labsym: &LabelSymbol) -> VectorStl<OpTpl>;

    /// Find an internal function by name.
    fn find_internal_function(
        &self,
        location: Location,
        name: &str,
        operands: VectorStl<Box<dyn ExprTree>>,
    ) -> Option<Box<dyn std::any::Any>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_environment_is_object_safe() {
        fn _accepts_dyn_trait(_: &dyn SemanticEnvironment) {}
    }
}
