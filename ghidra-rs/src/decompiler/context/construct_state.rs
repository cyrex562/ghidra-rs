//! Models `ghidra.pcodeCPort.context.ConstructState`.

use crate::decompiler::context::fixed_handle::FixedHandle;
use crate::decompiler::seam_stubs::Constructor;

/// One node of the parse tree built while matching a SLEIGH constructor against instruction
/// bytes: which [`Constructor`] matched, the resolved sub-operands (`resolve`), and where this
/// match sits within its parent's operand list.
///
/// Models the data class `ghidra.pcodeCPort.context.ConstructState`, whose fields are all public
/// with no methods of their own -- ported as a plain struct rather than a trait, matching that
/// shape. `ct` uses the existing [`Constructor`] seam trait rather than waiting on `Constructor`
/// itself to be ported to a concrete type (a much larger effort: `Constructor` is mutually
/// dependent with `SubtableSymbol`, and needs several `OperandSymbol` fields -- `hand`,
/// `localexp`, offset-irrelevance, a defining-symbol accessor -- this crate's `OperandSymbol`
/// doesn't carry yet).
pub struct ConstructState {
    /// The constructor that matched at this parse-tree node (`ct` in Java).
    pub ct: Option<Box<dyn Constructor>>,
    /// The resolved handle (location/size) this node represents.
    pub hand: FixedHandle,
    /// The resolved sub-operands, one per operand of `ct`, in operand order.
    pub resolve: Vec<ConstructState>,
    /// The enclosing parse-tree node, or `None` at the root.
    pub parent: Option<Box<ConstructState>>,
    /// Length, in bytes, of this instantiation of the constructor.
    pub length: i32,
    /// Absolute offset from the start of the instruction.
    pub offset: i32,
    /// Index of the operand currently being processed.
    pub oper: i32,
}

impl ConstructState {
    /// An empty parse-tree node with no constructor resolved yet (matching Java's implicit
    /// zero/`null`-initialized fields from `new ConstructState()`).
    pub fn new() -> Self {
        Self {
            ct: None,
            hand: FixedHandle::new(),
            resolve: Vec::new(),
            parent: None,
            length: 0,
            offset: 0,
            oper: 0,
        }
    }
}

impl Default for ConstructState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::slghsymbol::OperandSymbol;
    use crate::decompiler::utils::MutableInt;
    use crate::sleigh::grammar::Location;

    struct MockConstructor {
        id: u64,
        parent_id: u64,
        operand: OperandSymbol,
    }

    impl Constructor for MockConstructor {
        fn location(&self) -> &Location {
            unimplemented!("not exercised by these tests")
        }
        fn get_operand(&self, _index: i32) -> &OperandSymbol {
            &self.operand
        }
        fn get_operand_sub_value(&self, _index: i32, _replace: &[i64], _listpos: &mut MutableInt) -> i64 {
            unimplemented!("not exercised by these tests")
        }
        fn parent_id(&self) -> u64 {
            self.parent_id
        }
        fn id(&self) -> u64 {
            self.id
        }
        fn set_id(&mut self, id: u64) {
            self.id = id;
        }
        fn collect_local_exports(&self, _results: &mut Vec<i64>) {}
        fn num_operands(&self) -> i32 {
            1
        }
        fn add_operand(&mut self, sym: OperandSymbol) -> i32 {
            self.operand = sym;
            0
        }
        fn add_invisible_operand(&mut self, sym: OperandSymbol) -> i32 {
            self.operand = sym;
            0
        }
        fn get_operand_mut(&mut self, _index: i32) -> &mut OperandSymbol {
            &mut self.operand
        }
        fn set_source_file_index(&mut self, _index: i32) {}
        fn add_equation(&mut self, _pateq: Box<dyn crate::decompiler::slghpatexpress::PatternEquationOps>) {}
        fn remove_trailing_space(&mut self) {}
        fn add_context(&mut self, _contvec: Vec<Box<dyn crate::decompiler::slghsymbol::ContextChange>>) {}
        fn set_main_section(&mut self, _section: Option<crate::program::model::lang::sleigh::template::ConstructTpl>) {}
        fn set_named_section(&mut self, _section: crate::program::model::lang::sleigh::template::ConstructTpl, _index: i32) {}
    }

    fn loc() -> Location {
        Location::new("test.sleigh", 1)
    }

    #[test]
    fn new_is_empty() {
        let state = ConstructState::new();
        assert!(state.ct.is_none());
        assert!(state.resolve.is_empty());
        assert!(state.parent.is_none());
        assert_eq!(state.length, 0);
        assert_eq!(state.offset, 0);
        assert_eq!(state.oper, 0);
    }

    #[test]
    fn stores_a_resolved_constructor() {
        let mut state = ConstructState::new();
        state.ct = Some(Box::new(MockConstructor {
            id: 7,
            parent_id: 3,
            operand: OperandSymbol::with_name(loc(), "op0"),
        }));
        assert_eq!(state.ct.as_deref().unwrap().id(), 7);
    }

    #[test]
    fn resolve_holds_child_states_for_each_operand() {
        let mut state = ConstructState::new();
        state.resolve.push(ConstructState::new());
        state.resolve.push(ConstructState::new());
        assert_eq!(state.resolve.len(), 2);
    }

    #[test]
    fn parent_links_to_the_enclosing_node() {
        let mut child = ConstructState::new();
        child.oper = 2;
        let mut parent = ConstructState::new();
        parent.length = 4;
        child.parent = Some(Box::new(parent));

        assert_eq!(child.parent.as_ref().unwrap().length, 4);
        assert_eq!(child.oper, 2);
    }

    #[test]
    fn length_offset_and_oper_are_independently_settable() {
        let mut state = ConstructState::new();
        state.length = 4;
        state.offset = 12;
        state.oper = 1;
        assert_eq!(state.length, 4);
        assert_eq!(state.offset, 12);
        assert_eq!(state.oper, 1);
    }
}
