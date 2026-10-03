pub mod constructor_impl;
pub mod context_commit;
pub mod context_op;

pub use constructor_impl::Constructor;
pub use context_commit::ContextCommit;
pub use context_op::ContextOp;

use crate::program::model::lang::sleigh::walker::{ParserWalker, SleighError};

/// A change to context made when a constructor matches. Port of the Java interface
/// `ghidra.app.plugin.processors.sleigh.ContextChange`, whose two implementations are
/// [`ContextOp`] and [`ContextCommit`].
#[derive(Debug, Clone)]
pub enum ContextChange {
    Op(ContextOp),
    Commit(ContextCommit),
}

impl ContextChange {
    /// Port of `ContextChange.apply(ParserWalker, SleighDebugLogger)`.
    ///
    /// # Errors
    /// A [`SleighError`] if a context expression cannot be evaluated.
    pub fn apply(&self, walker: &ParserWalker<'_>) -> Result<(), SleighError> {
        match self {
            ContextChange::Op(op) => op.apply(walker),
            ContextChange::Commit(commit) => commit.apply(walker),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::processors::sleigh::sleigh_parser_context::SleighParserContext;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::sleigh::expression::PatternExpression;
    use crate::program::model::mem::{ByteMemBufferImpl, MemBuffer};
    use std::sync::Arc;

    fn context() -> SleighParserContext {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let mem: Arc<dyn MemBuffer> =
            Arc::new(ByteMemBufferImpl::new(Address::new(space, 0), vec![0], true));
        SleighParserContext::for_tests(mem, vec![0x0000_00ff, 0])
    }

    #[test]
    fn context_op_sets_the_shifted_value_under_the_mask() {
        let ctx = context();
        let mut walker = ParserWalker::new(&ctx);
        walker.base_state();
        let op = ContextChange::Op(ContextOp {
            patexp: PatternExpression::Constant(5),
            num: 0,
            mask: 0x0000_0f00,
            shift: 8,
        });
        op.apply(&walker).unwrap();
        assert_eq!(ctx.get_context_words(), vec![0x0000_05ff, 0]);
    }

    #[test]
    fn context_commit_records_the_current_value_at_the_walker_node() {
        let ctx = context();
        let mut walker = ParserWalker::new(&ctx);
        walker.base_state();
        walker.allocate_operand().unwrap();
        let commit = ContextChange::Commit(ContextCommit {
            sym: Some(4),
            num: 0,
            mask: 0x0000_000f,
        });
        commit.apply(&walker).unwrap();
        let commits = ctx.get_context_commits();
        assert_eq!(commits.len(), 1);
        assert_eq!((commits[0].sym, commits[0].point, commits[0].value), (4, 1, 0xf));
    }
}
