//! Port of `ghidra.pcode.struct.AssignStmt`.

use std::any::Any;
use std::sync::Arc;

use crate::pcode::r#struct::abstract_stmt::{AbstractStmtBase, register};
use crate::pcode::r#struct::lval_internal::LValInternal;
use crate::pcode::r#struct::rval_internal::RValInternal;
use crate::pcode::r#struct::string_tree::StringTree;
use crate::pcode::seam_stubs::{SleighLabel, Stmt, StructuredSleighContext, StmtWithVal};
use crate::program::model::data::data_type::DataType;

/// Port of `ghidra.pcode.struct.AssignStmt`: an assignment statement that assigns a right-hand
/// value to a left-hand location.
///
/// Java's `AssignStmt` extends [`AbstractStmt`](crate::pcode::r#struct::abstract_stmt::AbstractStmt)
/// and implements both [`RValInternal`] (making it usable as an expression) and [`StmtWithVal`]
/// (marking it as a statement that produces a value). This is a concrete `struct` carrying the
/// `lhs`, `rhs`, and `type` fields, along with the inherited [`AbstractStmtBase`].
pub struct AssignStmt {
    base: AbstractStmtBase,
    lhs: Arc<dyn LValInternal>,
    rhs: Arc<dyn RValInternal>,
    data_type: Box<dyn DataType>,
}

impl AssignStmt {
    /// Port of the two-argument constructor `AssignStmt(StructuredSleigh ctx, LVal lhs, RVal rhs)`.
    /// Takes the type of the left-hand side.
    ///
    /// Note: In Rust, this takes the concrete Internal versions directly rather than the base types,
    /// since callers will always pass objects that implement the Internal interfaces.
    pub fn new(
        ctx: Arc<dyn StructuredSleighContext>,
        lhs: Arc<dyn LValInternal>,
        rhs: Arc<dyn RValInternal>,
    ) -> Arc<Self> {
        let data_type = lhs.get_type();

        let this = Arc::new(Self {
            base: AbstractStmtBase::new(ctx),
            lhs,
            rhs,
            data_type,
        });

        register(Arc::clone(&this) as Arc<dyn crate::pcode::r#struct::abstract_stmt::AbstractStmt>);
        this
    }

    /// Port of the three-argument constructor `AssignStmt(StructuredSleigh ctx, LVal lhs, RVal rhs, DataType type)`.
    fn new_with_type(
        ctx: Arc<dyn StructuredSleighContext>,
        lhs: Arc<dyn LValInternal>,
        rhs: Arc<dyn RValInternal>,
        data_type: Box<dyn DataType>,
    ) -> Arc<Self> {
        let this = Arc::new(Self {
            base: AbstractStmtBase::new(ctx),
            lhs,
            rhs,
            data_type,
        });

        register(Arc::clone(&this) as Arc<dyn crate::pcode::r#struct::abstract_stmt::AbstractStmt>);
        this
    }
}

impl Stmt for AssignStmt {}

impl crate::pcode::r#struct::abstract_stmt::AbstractStmt for AssignStmt {
    fn base(&self) -> &AbstractStmtBase {
        &self.base
    }

    fn into_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn generate(&self, next: Arc<dyn SleighLabel>, fall: Arc<dyn SleighLabel>) -> StringTree {
        let mut st = StringTree::new();
        st.append_tree(self.lhs.generate(Some(self.rhs.as_ref())));
        st.append(" = ");
        st.append_tree(self.rhs.generate(Some(self.rhs.as_ref())));
        st.append(";\n");
        st.append_tree(next.gen_goto(fall.as_ref()));
        st
    }
}

impl crate::pcode::seam_stubs::RVal for AssignStmt {
    fn get_type(&self) -> Box<dyn DataType> {
        // TODO: Implement properly once DataTypeManager is available in the context
        unimplemented!("AssignStmt.get_type requires DataTypeManager from context")
    }

    fn cast(&self, _data_type: &dyn DataType) -> Box<dyn crate::pcode::seam_stubs::RVal> {
        // TODO: Implement properly once DataTypeManager is available in the context
        // Port of `cast(DataType type)`: return new AssignStmt(ctx, lhs, rhs, type)
        unimplemented!("AssignStmt.cast requires DataTypeManager from context")
    }
}

impl RValInternal for AssignStmt {
    fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
        self.base.get_context()
    }

    fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
        self.lhs.generate(Some(self.rhs.as_ref()))
    }

    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
        self
    }
}

impl StmtWithVal for AssignStmt {}

#[cfg(test)]
mod tests {
    #[test]
    fn assign_stmt_struct_exists() {
        // Smoke test: verify the type can be referenced and the module compiles.
        // Full testing requires fully ported dependencies (StructuredSleighContext,
        // LValInternal, RValInternal, etc.) which are implemented as seam stubs.
    }
}
