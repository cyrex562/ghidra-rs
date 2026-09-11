//! Port of `ghidra.program.model.pcode.PcodeOpAST`.
//!
//! Java's `PcodeOpAST extends PcodeOp`, adding basic-block/list-position bookkeeping used while
//! walking/mutating a decompiler syntax tree: is this op currently "alive" in the tree
//! (`isDead`/`bDead`), which `PcodeBlockBasic` contains it (`getParent`/`setParent`/`parent`),
//! and its iterator/cursor position within that block's op list (`getBasicIter`/`setBasicIter`/
//! `basiciter`) and within the tree's alive/dead list (`getInsertIter`/`setInsertIter`/
//! `insertiter`). This is the concrete runtime type
//! [`PcodeBlockBasic`](crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic) downcasts
//! every stored `PcodeOp` to on each insert/remove -- previously stubbed as
//! [`crate::program::seam_stubs::PcodeOpAst`] (a minimal trait exposing only the three members
//! `PcodeBlockBasic`'s insertion/removal logic touches). That trait is **not** graduated away by
//! this file (unlike `PcodeBlock`'s placeholder): it is a legitimate, still-useful interface
//! cut-point (more `Block*`/tree-walking consumers than just this struct may want to depend on
//! "something `PcodeOpAst`-shaped" without depending on this concrete struct), matching this
//! session's established "trait exists as cut-point, concrete implementor needed" pattern. This
//! file adds [`PcodeOpAST`] as a real, concrete implementor of that trait.
//!
//! Named `PcodeOpAST` (matching Java's exact class name, including its capitalization) rather
//! than the more idiomatically-Rust-cased `PcodeOpAst`, since that identifier is already taken by
//! the trait above; Rust identifiers are case-sensitive, so the two do not collide.
//!
//! ## Scope boundary with `PcodeOp.java`
//!
//! `PcodeOpAST` extends `PcodeOp`, and its two constructors both delegate to a `PcodeOp` super
//! constructor that records the opcode/sequence-number/input-count/output. `PcodeOp.java` itself
//! is already marked `DONE` in `PORT_MANIFEST.tsv`, with its own (different-shaped) port at
//! [`crate::program::model::pcode::PcodeOp`] -- a simple immutable value struct (`opcode`,
//! `seqnum`, `inputs: Vec<Varnode>`, `output: Option<Varnode>`) used elsewhere in this crate. That
//! struct is not reused here: Java's real `PcodeOp` constructor pre-allocates a `numinputs`-sized
//! array of *null* `Varnode` slots (filled in later, one at a time, via the base class's
//! `setInput`/`setOutput`/`setOpcode` mutators), which the existing `PcodeOp` struct's
//! `Vec<Varnode>` (non-optional elements, fully supplied up front) cannot represent, and those
//! mutators are not modeled by it either. Faithfully reproducing that constructor shape -- and
//! nothing more -- this file stores its own `seqnum`/`opcode`/`inputs`/`output` fields directly,
//! with `inputs: Vec<Option<Varnode>>` sized to `numinputs` and initially all `None`,
//! matching Java's real starting state. // TODO(port): `PcodeOp.java`'s own accessors/mutators for
//! these fields (`getOpcode`, `getInput`, `setInput`, `setOutput`, `setOpcode`, `getSeqnum`, and
//! everything else in that 752-line base class) are out of scope for this file, which only ports
//! `PcodeOpAST.java`'s own 114 lines; only trivial read-only accessors for the constructor-recorded
//! state are exposed below, for testability.

use crate::program::model::address::Address;
use crate::program::model::pcode::list_linked::LinkedIter;
use crate::program::model::pcode::pcode_block_basic::PcodeBlockBasic;
use crate::program::model::pcode::{OpCode, SequenceNumber, Varnode};
use crate::program::seam_stubs::PcodeOpAst;
use std::cell::{Cell, RefCell};
use std::sync::Arc;

/// Some extra things attached to `PcodeOp` for ease of walking the syntax tree.
///
/// Port of `ghidra.program.model.pcode.PcodeOpAST`. See this module's docs for the scope boundary
/// with the (already separately-ported) `PcodeOp.java` base class.
pub struct PcodeOpAST {
    /// Port of the inherited `SequenceNumber seqnum` field, recorded by the constructor.
    pub seqnum: SequenceNumber,
    /// Port of the inherited `int opcode` field, recorded by the constructor.
    opcode: OpCode,
    /// Port of the inherited `Varnode[] input` field: `numinputs` slots, each `None` ("null" in
    /// Java) until `PcodeOp.setInput` (out of scope; see module docs) fills it in.
    inputs: RefCell<Vec<Option<Varnode>>>,
    /// Port of the inherited `Varnode output` field, `null`/`None` until `PcodeOp.setOutput` (out
    /// of scope; see module docs) sets it.
    output: RefCell<Option<Varnode>>,

    /// Is this operation currently in the syntax tree. Starts `true` ("dead until actually in
    /// the syntax tree"), matching the Java constructor comment.
    b_dead: Cell<bool>,
    /// Parent basic block.
    parent: RefCell<Option<Arc<dyn PcodeBlockBasic>>>,
    /// Iterator/cursor within the parent basic block's op list.
    basic_iter: RefCell<Option<LinkedIter>>,
    /// Position in the alive/dead list. Modeled as `Option<LinkedIter>` (rather than requiring a
    /// dedicated not-yet-ported alive/dead-list container type) since nothing in this crate
    /// currently consumes it; see module docs.
    insert_iter: RefCell<Option<LinkedIter>>,
}

impl PcodeOpAST {
    /// Port of `PcodeOpAST(SequenceNumber sq, int op, int numinputs)`.
    pub fn new(seqnum: SequenceNumber, op: OpCode, numinputs: usize) -> Self {
        Self {
            seqnum,
            opcode: op,
            inputs: RefCell::new(vec![None; numinputs]),
            output: RefCell::new(None),
            b_dead: Cell::new(true),
            parent: RefCell::new(None),
            basic_iter: RefCell::new(None),
            insert_iter: RefCell::new(None),
        }
    }

    /// Port of `PcodeOpAST(Address a, int uq, int op, int numinputs)`.
    pub fn with_address(addr: Address, uq: i32, op: OpCode, numinputs: usize) -> Self {
        Self::new(SequenceNumber::new(addr, uq), op, numinputs)
    }

    /// Port of the inherited `PcodeOp.getSeqnum()`.
    pub fn get_seqnum(&self) -> &SequenceNumber {
        &self.seqnum
    }

    /// Port of the inherited `PcodeOp.getOpcode()`.
    pub fn get_opcode(&self) -> OpCode {
        self.opcode
    }

    /// Port of the inherited `PcodeOp.getNumInputs()` (the constructor-recorded input-slot
    /// count, not the number of slots actually filled in).
    pub fn num_inputs(&self) -> usize {
        self.inputs.borrow().len()
    }

    /// Port of the inherited `PcodeOp.getInput(int)`.
    pub fn get_input(&self, i: usize) -> Option<Varnode> {
        self.inputs.borrow()[i].clone()
    }

    /// Port of the inherited `PcodeOp.getOutput()`.
    pub fn get_output(&self) -> Option<Varnode> {
        self.output.borrow().clone()
    }

    /// Port of `PcodeOpAST.isDead()`.
    pub fn is_dead(&self) -> bool {
        self.b_dead.get()
    }

    /// Port of `PcodeOpAST.getParent()`.
    pub fn get_parent(&self) -> Option<Arc<dyn PcodeBlockBasic>> {
        self.parent.borrow().clone()
    }

    /// Port of `PcodeOpAST.getInsertIter()`.
    pub fn get_insert_iter(&self) -> Option<LinkedIter> {
        *self.insert_iter.borrow()
    }

    /// Port of `PcodeOpAST.setInsertIter(Iterator<Object>)`.
    pub fn set_insert_iter(&self, iter: Option<LinkedIter>) {
        *self.insert_iter.borrow_mut() = iter;
    }
}

impl PcodeOpAst for PcodeOpAST {
    /// Port of `PcodeOpAST.setParent(PcodeBlockBasic)`.
    fn set_parent(&self, parent: Option<Arc<dyn PcodeBlockBasic>>) {
        *self.parent.borrow_mut() = parent;
    }

    /// Port of `PcodeOpAST.setBasicIter(Iterator<PcodeOp>)`.
    fn set_basic_iter(&self, iter: LinkedIter) {
        *self.basic_iter.borrow_mut() = Some(iter);
    }

    /// Port of `PcodeOpAST.getBasicIter()`. Panics if the iterator was never set, matching this
    /// crate's established convention for the `PcodeOpAst` trait (see
    /// `crate::program::model::pcode::pcode_block_basic`'s `MockOp` test helper) rather than
    /// Java's `return null`, since the trait's `get_basic_iter` returns a non-`Option`
    /// [`LinkedIter`].
    fn get_basic_iter(&self) -> LinkedIter {
        self.basic_iter
            .borrow()
            .expect("PcodeOpAST::get_basic_iter: basic iter not set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::block_map::BlockMap;
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use crate::program::seam_stubs::PcodeBlock;
    use std::cell::Cell as StdCell;
    use std::io;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn new_starts_dead_with_no_parent_and_unfilled_inputs() {
        let ram = ram_space();
        let pc = Address::new(ram, 0x1000);
        let seqnum = SequenceNumber::new(pc, 0);

        let op = PcodeOpAST::new(seqnum.clone(), OpCode::IntAdd, 2);

        assert!(op.is_dead(), "PcodeOpAST starts dead until actually in the syntax tree");
        assert!(op.get_parent().is_none());
        assert_eq!(op.get_seqnum(), &seqnum);
        assert_eq!(op.get_opcode(), OpCode::IntAdd);
        assert_eq!(op.num_inputs(), 2);
        assert!(op.get_input(0).is_none());
        assert!(op.get_input(1).is_none());
        assert!(op.get_output().is_none());
        assert!(op.get_insert_iter().is_none());
    }

    #[test]
    fn with_address_constructor_delegates_like_java() {
        let ram = ram_space();
        let pc = Address::new(ram, 0x2000);

        let op = PcodeOpAST::with_address(pc.clone(), 5, OpCode::Copy, 1);

        assert_eq!(op.get_seqnum().pc, pc);
        assert_eq!(op.get_seqnum().uniq, 5);
        assert_eq!(op.get_opcode(), OpCode::Copy);
        assert_eq!(op.num_inputs(), 1);
    }

    #[test]
    #[should_panic(expected = "basic iter not set")]
    fn get_basic_iter_panics_before_set() {
        let ram = ram_space();
        let pc = Address::new(ram, 0x3000);
        let op = PcodeOpAST::new(SequenceNumber::new(pc, 0), OpCode::Copy, 0);
        op.get_basic_iter();
    }

    #[test]
    fn set_insert_iter_round_trips() {
        let ram = ram_space();
        let pc = Address::new(ram, 0x4000);
        let op = PcodeOpAST::new(SequenceNumber::new(pc, 0), OpCode::Copy, 0);
        assert!(op.get_insert_iter().is_none());

        // Borrow a real LinkedIter shape from a ListLinked so we're not fabricating one.
        let list: crate::program::model::pcode::list_linked::ListLinked<i32> =
            crate::program::model::pcode::list_linked::ListLinked::new();
        let cursor = list.add(42);
        op.set_insert_iter(Some(cursor));
        assert_eq!(op.get_insert_iter(), Some(cursor));

        op.set_insert_iter(None);
        assert!(op.get_insert_iter().is_none());
    }

    /// A minimal real `PcodeBlockBasic` (using a self-referential `Arc`, matching this crate's
    /// established convention for `insert_before`/`insert_after`/`insert_end`) so this test can
    /// exercise `PcodeOpAST` playing its real role: the `Arc<dyn PcodeOpAst>` that
    /// `PcodeBlockBasic::insert_end`/`remove` actually manipulate.
    struct MinimalBasicBlock {
        index: StdCell<i32>,
        oplist: crate::program::model::pcode::list_linked::ListLinked<Arc<dyn PcodeOpAst>>,
        self_ref: RefCell<Option<Arc<dyn PcodeBlockBasic>>>,
    }

    impl MinimalBasicBlock {
        fn new() -> Arc<MinimalBasicBlock> {
            let block = Arc::new(MinimalBasicBlock {
                index: StdCell::new(0),
                oplist: crate::program::model::pcode::list_linked::ListLinked::new(),
                self_ref: RefCell::new(None),
            });
            *block.self_ref.borrow_mut() = Some(block.clone() as Arc<dyn PcodeBlockBasic>);
            block
        }
    }

    impl PcodeBlock for MinimalBasicBlock {
        fn get_index(&self) -> i32 {
            self.index.get()
        }
        fn set_index(&self, index: i32) {
            self.index.set(index);
        }
        fn get_block_type(&self) -> i32 {
            crate::program::seam_stubs::PCODE_BLOCK_BASIC
        }
        fn add_in_edge(&self, _begin: Arc<dyn PcodeBlock>, _label: i32) {}
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            Ok(())
        }
        fn decode(&self, _decoder: &dyn Decoder, _resolver: &dyn BlockMap) -> Result<(), DecoderException> {
            Ok(())
        }
    }

    impl PcodeBlockBasic for MinimalBasicBlock {
        fn get_start(&self) -> Address {
            Address::new(ram_space(), 0)
        }
        fn get_stop(&self) -> Address {
            Address::new(ram_space(), 0)
        }
        fn contains(&self, _addr: &Address) -> bool {
            false
        }
        fn get_address_ranges(&self) -> Vec<(Address, Address)> {
            Vec::new()
        }
        fn add_range(&self, _start: Address, _stop: Address) {}

        fn insert_before(&self, iter: &LinkedIter, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(self.self_ref.borrow().clone());
            let newiter = self.oplist.insert_before(iter, op.clone());
            op.set_basic_iter(newiter);
        }
        fn insert_after(&self, iter: &LinkedIter, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(self.self_ref.borrow().clone());
            let newiter = self.oplist.insert_after(iter, op.clone());
            op.set_basic_iter(newiter);
        }
        fn insert_end(&self, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(self.self_ref.borrow().clone());
            let newiter = self.oplist.add(op.clone());
            op.set_basic_iter(newiter);
        }
        fn remove(&self, op: Arc<dyn PcodeOpAst>) {
            op.set_parent(None);
            self.oplist.remove(&op.get_basic_iter());
        }
        fn get_iterator(&self) -> LinkedIter {
            self.oplist.iterator()
        }
        fn get_first_op(&self) -> Option<Arc<dyn PcodeOpAst>> {
            self.oplist.first().map(|op| op.clone())
        }
        fn get_last_op(&self) -> Option<Arc<dyn PcodeOpAst>> {
            self.oplist.last().map(|op| op.clone())
        }
    }

    #[test]
    fn real_pcode_op_ast_tracks_parent_and_position_through_pcode_block_basic() {
        let ram = ram_space();
        let block = MinimalBasicBlock::new();

        let op1: Arc<dyn PcodeOpAst> = Arc::new(PcodeOpAST::with_address(
            Address::new(ram.clone(), 0x100),
            0,
            OpCode::Copy,
            1,
        ));
        let op2: Arc<dyn PcodeOpAst> = Arc::new(PcodeOpAST::with_address(
            Address::new(ram.clone(), 0x104),
            0,
            OpCode::IntAdd,
            2,
        ));

        block.insert_end(op1.clone());
        block.insert_end(op2.clone());

        // Both real PcodeOpAST instances got a basic-iter cursor recorded by insert_end (would
        // panic via the trait's documented convention if it were never set).
        let _ = op1.get_basic_iter();
        let _ = op2.get_basic_iter();
        assert!(is_op(&block.get_first_op(), &op1));
        assert!(is_op(&block.get_last_op(), &op2));

        block.remove(op1.clone());
        assert!(is_op(&block.get_first_op(), &op2));
    }

    fn is_op(candidate: &Option<Arc<dyn PcodeOpAst>>, expected: &Arc<dyn PcodeOpAst>) -> bool {
        match candidate {
            Some(op) => Arc::ptr_eq(op, expected),
            None => false,
        }
    }
}
