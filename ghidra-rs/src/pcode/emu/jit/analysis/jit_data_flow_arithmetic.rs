//! A p-code arithmetic for interpreting p-code and constructing a use-def graph.
//!
//! Port of `ghidra.pcode.emu.jit.analysis.JitDataFlowArithmetic`.

use std::sync::Arc;

use crate::pcode::emu::jit::op::{jit_op_bin_op, jit_op_un_op, JitOp};
use crate::pcode::emu::jit::var::{jit_val, JitVal};
use crate::pcode::exec::concretion_error::ConcretionError;
use crate::pcode::exec::pcode_arithmetic::{PcodeArithmetic, Purpose};
use crate::pcode::seam_stubs::{
    JitAnalysisContext, JitCatenateOp, JitDataFlowModel, JitDefOp, JitLoadOp, JitOutVar,
    JitStoreOp, JitSynthSubPieceOp, OpBehaviorSubpiece,
};
use crate::pcode::utils::{big_integer_to_bytes, bytes_to_big_integer};
use crate::program::model::address::AddressSpace;
use crate::program::model::lang::endian::Endian;
use crate::program::model::pcode::{OpCode, PcodeOp, Varnode};

/// A p-code arithmetic for interpreting p-code and constructing a use-def graph.
///
/// This is used for intra-block data flow analysis. We leverage the same API as is used for
/// concrete p-code interpretation, but we use it for an abstraction. The type of the
/// interpretation is [`JitVal`], which can consist of constants and variables in the use-def
/// graph. The arithmetic must be provided to `JitDataFlowExecutor` (not yet ported). The
/// intra-block portions of the use-def graph are populated as each block is interpreted by the
/// executor.
///
/// The general strategy for each of the arithmetic operations is to 1) generate the output SSA
/// variable for the op, 2) generate the op node for the generated output and given inputs, 3)
/// enter the op into the use-def graph as the definition of its output, 4) record the inputs and
/// used by the new op, and finally 5) return the generated output.
///
/// There should only need to be one of these per data flow model, not per block.
///
/// # Differences from Java
///
/// Java's `PcodeArithmetic<JitVal>` becomes [`PcodeArithmetic<Arc<dyn JitVal>>`]: values in the
/// use-def graph are shared nodes, reachable from every op that uses them, so `Arc` -- not
/// ownership -- is how a value is passed around. The owning
/// [`JitDataFlowModel`] is likewise held as a trait object: it is the forward edge of a
/// dependency cycle (the model constructs this arithmetic and this arithmetic calls back into
/// it), and is not ported yet.
pub struct JitDataFlowArithmetic {
    dfm: Arc<dyn JitDataFlowModel>,
    endian: Endian,
}

impl JitDataFlowArithmetic {
    /// Construct the arithmetic.
    ///
    /// # Arguments
    ///
    /// * `context` - the analysis context
    /// * `dfm` - the owning data flow model
    pub fn new(context: &JitAnalysisContext, dfm: Arc<dyn JitDataFlowModel>) -> Self {
        Self { dfm, endian: context.get_endian() }
    }

    /// Remove the given number of bytes from the higher-offset end of the varnode.
    pub fn trunc_vn_from_right(&self, vn: &Varnode, amt: i32) -> Varnode {
        Varnode::new(vn.get_address().clone(), vn.get_size() - amt)
    }

    /// Remove `amt` bytes from the right of the *varnode*.
    ///
    /// "Right" is considered with respect to the machine endianness. If it is little endian, then
    /// the bytes are shaved from the *left* of the value. This should be used when getting values
    /// from the state to remove pieces from off-cut values. It should be applied before the pieces
    /// are ordered according to machine endianness.
    ///
    /// # Arguments
    ///
    /// * `in1_vn` - the varnode representing the input
    /// * `amt` - the number of bytes to remove
    /// * `in1` - the input (really a value read from the state)
    pub fn trunc_from_right(
        &self,
        in1_vn: &Varnode,
        amt: i32,
        in1: Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        let out_vn = self.trunc_vn_from_right(in1_vn, amt);
        let offset = if self.endian.is_big_endian() { amt } else { 0 };
        self.subpiece_to_vn(&out_vn, offset, in1)
    }

    /// Remove the given number of bytes from the lower-offset end of the varnode.
    pub fn trunc_vn_from_left(&self, vn: &Varnode, amt: i32) -> Varnode {
        let address = vn
            .get_address()
            .add(amt as i64)
            .expect("AddressOverflowException truncating varnode from the left");
        Varnode::new(address, vn.get_size() - amt)
    }

    /// Remove `amt` bytes from the left of the *varnode*.
    ///
    /// "Left" is considered with respect to the machine endianness. If it is little endian, then
    /// the bytes are shaved from the *right* of the value. See [`Self::trunc_from_right`].
    pub fn trunc_from_left(
        &self,
        in1_vn: &Varnode,
        amt: i32,
        in1: Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        let out_vn = self.trunc_vn_from_left(in1_vn, amt);
        let offset = if self.endian.is_big_endian() { 0 } else { amt };
        self.subpiece_to_vn(&out_vn, offset, in1)
    }

    /// Drop whole parts off the high-offset end of `parts` until `offset` bytes are gone, shaving
    /// the last part if it straddles the boundary.
    ///
    /// Port of the private `removeOffsetFromRight(List<JitVal>, int)`.
    fn remove_offset_from_right(&self, parts: &mut Vec<Arc<dyn JitVal>>, mut offset: i32) {
        let mut p;
        loop {
            p = parts.pop().expect("ran out of parts removing offset from the right");
            offset -= p.size();
            if offset <= 0 {
                break;
            }
        }
        if offset < 0 {
            let np = self.shave_from_right(-offset, p);
            offset += np.size();
            parts.push(np);
            debug_assert_eq!(offset, 0);
        }
    }

    /// Drop whole parts off the low-offset end of `parts` until only `size` bytes remain.
    ///
    /// Port of the private `removeFromLeftToSize(List<JitVal>, int)`. Note that Java's
    /// straddling-part branch passes `-size` (not the overshoot) to `shaveFromLeft` and writes the
    /// result to index `i + 1` rather than `i`; that is ported verbatim, so -- exactly as in Java
    /// -- reaching it with a part that overshoots panics with an out-of-range index instead of
    /// trimming. Only the `actualSize == size` path is exercised by any caller in this crate.
    fn remove_from_left_to_size(&self, parts: &mut Vec<Arc<dyn JitVal>>, size: i32) {
        let mut actual_size = 0;
        let mut i = parts.len();
        let p;
        loop {
            i -= 1;
            actual_size += parts[i].size();
            if actual_size >= size {
                p = Arc::clone(&parts[i]);
                break;
            }
        }
        if actual_size > size {
            let np = self.shave_from_left(-size, p.clone());
            actual_size -= p.size();
            actual_size += np.size();
            parts[i + 1] = np;
            debug_assert_eq!(actual_size, size);
        }
        parts.drain(..i);
    }

    /// Try to produce a simplified [`JitSynthSubPieceOp`] or [`JitCatenateOp`].
    ///
    /// This takes an input, subpiece offset, and output variable. If the input variable is the
    /// result of another subpiece, the result can be a single simplified subpiece. Similarly, if
    /// the input is the result of a catenation, then the result can be a simplified catenation, or
    /// possibly subpiece.
    ///
    /// If either of these situations applies, and simplification is possible, this returns
    /// `Some`, and that result is added to the use-def graph specifying the given output variable
    /// as the simplified output. Otherwise, the result is `None` and the caller should create a
    /// new subpiece op.
    fn try_simplified_sub_piece(
        &self,
        out: &Arc<dyn JitOutVar>,
        offset: i32,
        v: &Arc<dyn JitVal>,
    ) -> Option<Arc<dyn JitVal>> {
        let definition = v.as_out_var()?.definition()?;
        if let Some(subsub) = definition.as_synth_sub_piece_op() {
            subsub.unlink();
            let op: Arc<dyn JitDefOp> = Arc::new(JitSynthSubPieceOp::new(
                Arc::clone(out),
                offset + subsub.offset(),
                Arc::clone(subsub.v()),
            ));
            return Some(self.dfm.notify_def_op(op));
        }
        if let Some(cat) = definition.as_catenate_op() {
            cat.unlink();
            let mut new_parts = cat.parts().to_vec();
            self.remove_offset_from_right(&mut new_parts, offset);
            self.remove_from_left_to_size(&mut new_parts, out.size());
            assert!(!new_parts.is_empty());
            if new_parts.len() == 1 {
                // Context should already be notified
                return Some(Arc::clone(&new_parts[0]));
            }
            let op: Arc<dyn JitDefOp> = Arc::new(JitCatenateOp::new(Arc::clone(out), new_parts));
            return Some(self.dfm.notify_def_op(op));
        }
        None
    }

    /// Construct the result of taking the subpiece.
    ///
    /// If the input is another subpiece or a catenation, the result may be simplified. In
    /// particular, the subpiece of a catenation may be a smaller catenation. No matter the case,
    /// the given output variable is made the output of the subpiece result, and the use-def graph
    /// is updated accordingly.
    ///
    /// Port of the private `subpiece(Varnode, int, JitVal)` overload, renamed since Rust has no
    /// overloading; the public [`Self::subpiece`] is the `(JitVal, int, int)` one.
    fn subpiece_to_vn(
        &self,
        out_vn: &Varnode,
        offset: i32,
        v: Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        let out = self.dfm.generate_out_var(out_vn);
        if let Some(simplified) = self.try_simplified_sub_piece(&out, offset, &v) {
            return simplified;
        }
        let op: Arc<dyn JitDefOp> = Arc::new(JitSynthSubPieceOp::new(out, offset, v));
        self.dfm.notify_def_op(op)
    }

    /// Compute the varnode representing a subpiece of the given varnode.
    ///
    /// # Arguments
    ///
    /// * `endian` - the endianness of the emulation target
    /// * `whole` - the whole varnode
    /// * `offset` - the number of least-significant bytes to remove
    /// * `size` - the size of the subpiece (maximum, since truncation may occur)
    ///
    /// # Panics
    ///
    /// If `offset` and `size` would leave a non-positive size, mirroring Java's `AssertionError`.
    pub fn sub_piece_vn(endian: Endian, whole: &Varnode, offset: i32, size: i32) -> Varnode {
        let min_size = (whole.get_size() - offset).min(size);
        assert!(min_size >= 1, "AssertionError: subpiece would have non-positive size");
        let addr_offset = match endian {
            Endian::Big => whole.get_size() - offset - min_size,
            Endian::Little => offset,
        };
        Varnode::new(
            whole.get_address().add(addr_offset as i64).expect("address overflow"),
            min_size,
        )
    }

    /// Remove `amt` bytes from the right of the value.
    ///
    /// The value is unaffected by the machine endianness, except to designate the output varnode.
    pub fn shave_from_right(&self, amt: i32, in1: Arc<dyn JitVal>) -> Arc<dyn JitVal> {
        let size = in1.size() - amt;
        self.subpiece(&in1, amt, size)
    }

    /// Remove `amt` bytes from the left of the value.
    ///
    /// The value is unaffected by the machine endianness, except to designate the output varnode.
    pub fn shave_from_left(&self, amt: i32, in1: Arc<dyn JitVal>) -> Arc<dyn JitVal> {
        let size = in1.size() - amt;
        self.subpiece(&in1, 0, size)
    }

    /// Compute the subpiece of a value.
    ///
    /// The result is added to the use-def graph. The output varnode is computed from the input
    /// varnode and the subpiece parameters. This is used to handle variable retrieval when an
    /// access only includes parts of a value previously written. Consider the x86 assembly:
    ///
    /// ```text
    /// MOV RAX, qword ptr [...]
    /// MOV dword ptr [...], EAX
    /// ```
    ///
    /// The second line reads `EAX`, which consists of only the lower part of `RAX`. Thus, we
    /// synthesize a subpiece op. These are distinct from an actual [`OpCode::Subpiece`] op, since
    /// we sometimes need to filter out synthetic ops.
    ///
    /// # Arguments
    ///
    /// * `v` - the input value
    /// * `offset` - the subpiece offset (number of bytes shifted right)
    /// * `size` - the size of the output variable in bytes
    pub fn subpiece(&self, v: &Arc<dyn JitVal>, offset: i32, size: i32) -> Arc<dyn JitVal> {
        if let Some(c) = v.as_const_val() {
            return Arc::new(jit_val::constant(
                size,
                OpBehaviorSubpiece::evaluate_binary_big(size, v.size(), c.value(), offset as i128),
            ));
        }
        if let Some(vv) = v.as_varnode_var() {
            let in_vn = vv.varnode();
            let out_vn = Self::sub_piece_vn(self.endian, &in_vn, offset, size);
            return self.subpiece_to_vn(&out_vn, offset, Arc::clone(v));
        }
        panic!("UnsupportedOperationException: unsupported subpiece of a {}-byte value", v.size())
    }

    /// Construct the catenation of the given values to form the given output varnode.
    ///
    /// The result is added to the use-def graph. This is used to handle variable retrieval when
    /// the pattern of accesses indicates catenation. Consider the x86 assembly:
    ///
    /// ```text
    /// MOV AH, byte ptr [...]
    /// MOV AL, byte ptr [...]
    /// MOV word ptr [...], AX
    /// ```
    ///
    /// On the third line, the value in `AX` is the catenation of whatever values were written into
    /// `AH` and `AL`. Thus, we synthesize a catenation op node in the use-def graph.
    ///
    /// # Arguments
    ///
    /// * `out_vn` - the output varnode
    /// * `parts` - the list of values to catenate, ordered by machine endianness
    pub fn catenate(&self, out_vn: &Varnode, parts: Vec<Arc<dyn JitVal>>) -> Arc<dyn JitVal> {
        let out = self.dfm.generate_out_var(out_vn);
        let op: Arc<dyn JitDefOp> = Arc::new(JitCatenateOp::new(out, parts));
        self.dfm.notify_def_op(op)
    }
}

impl PcodeArithmetic<Arc<dyn JitVal>> for JitDataFlowArithmetic {
    /// Port of `getDomain()`, which returns `JitVal.class`.
    fn get_domain(&self) -> &'static str {
        "ghidra.pcode.emu.jit.var.JitVal"
    }

    fn get_endian(&self) -> Option<Endian> {
        Some(self.endian)
    }

    /// Java throws `AssertionError`: this arithmetic needs the whole p-code op, not just the
    /// operand sizes. See [`Self::unary_op_from_pcode_op`].
    fn unary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        _in1: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        panic!("AssertionError: JitDataFlowArithmetic requires the full p-code op")
    }

    fn unary_op_from_pcode_op(&self, op: &PcodeOp, in1: &Arc<dyn JitVal>) -> Arc<dyn JitVal> {
        let out = self.dfm.generate_out_var(op_output(op));
        self.dfm.notify_def_op(jit_op_un_op(op, out, Arc::clone(in1)))
    }

    /// Java throws `AssertionError`. See [`Self::binary_op_from_pcode_op`].
    fn binary_op(
        &self,
        _opcode: OpCode,
        _sizeout: i32,
        _sizein1: i32,
        _in1: &Arc<dyn JitVal>,
        _sizein2: i32,
        _in2: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        panic!("AssertionError: JitDataFlowArithmetic requires the full p-code op")
    }

    fn binary_op_from_pcode_op(
        &self,
        op: &PcodeOp,
        in1: &Arc<dyn JitVal>,
        in2: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        let out = self.dfm.generate_out_var(op_output(op));
        self.dfm.notify_def_op(jit_op_bin_op(op, out, Arc::clone(in1), Arc::clone(in2)))
    }

    /// Java throws `AssertionError`. See [`Self::mod_before_store_from_pcode_op`].
    fn mod_before_store(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Arc<dyn JitVal>,
        _sizein_value: i32,
        _in_value: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        panic!("AssertionError: JitDataFlowArithmetic requires the full p-code op")
    }

    /// Records the store op into the use-def graph. As "output" we just return `in_value`. The
    /// executor will call `JitDataFlowState::setVar`, but the state will just ignore it, because
    /// it will be an indirect memory write.
    fn mod_before_store_from_pcode_op(
        &self,
        op: &PcodeOp,
        space: &AddressSpace,
        in_offset: &Arc<dyn JitVal>,
        in_value: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        let store = Arc::new(JitStoreOp::new(
            op.clone(),
            space.clone(),
            Arc::clone(in_offset),
            Arc::clone(in_value),
        ));
        let value = Arc::clone(store.value());
        self.dfm.notify_op(store);
        value
    }

    /// Java throws `AssertionError`. See [`Self::mod_after_load_from_pcode_op`].
    fn mod_after_load(
        &self,
        _sizein_offset: i32,
        _space: &AddressSpace,
        _in_offset: &Arc<dyn JitVal>,
        _sizein_value: i32,
        _in_value: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        panic!("AssertionError: JitDataFlowArithmetic requires the full p-code op")
    }

    /// Records the load op into the use-def graph. For our `in_value`, the `JitDataFlowState` will
    /// have just returned the dummy indirect variable definition
    /// ([`JitIndirectMemoryVar::INSTANCE`](crate::pcode::seam_stubs::JitIndirectMemoryVar::INSTANCE)).
    /// We must not "use" this. Instead, we must take our other parameters to construct the load op
    /// and return its output.
    fn mod_after_load_from_pcode_op(
        &self,
        op: &PcodeOp,
        space: &AddressSpace,
        in_offset: &Arc<dyn JitVal>,
        _in_value: &Arc<dyn JitVal>,
    ) -> Arc<dyn JitVal> {
        let out = self.dfm.generate_out_var(op_output(op));
        let load: Arc<dyn JitDefOp> =
            Arc::new(JitLoadOp::new(op.clone(), out, space.clone(), Arc::clone(in_offset)));
        self.dfm.notify_def_op(load)
    }

    fn from_const_bytes(&self, value: &[u8]) -> Arc<dyn JitVal> {
        let big_val =
            bytes_to_big_integer(value, value.len(), self.endian.is_big_endian(), false);
        Arc::new(jit_val::constant(value.len() as i32, big_val))
    }

    fn to_concrete(
        &self,
        value: &Arc<dyn JitVal>,
        purpose: Purpose,
    ) -> Result<Vec<u8>, ConcretionError> {
        match value.as_const_val() {
            Some(c) => Ok(big_integer_to_bytes(
                c.value(),
                c.size() as usize,
                self.endian.is_big_endian(),
            )),
            None => Err(ConcretionError::new(
                format!("Cannot concretize a {}-byte non-constant value", value.size()),
                purpose,
            )),
        }
    }

    fn size_of(&self, value: &Arc<dyn JitVal>) -> i64 {
        value.size() as i64
    }
}

/// The output varnode of an op that must have one, mirroring Java's implicit NPE on
/// `op.getOutput()`.
fn op_output(op: &PcodeOp) -> &Varnode {
    op.output.as_ref().expect("p-code op building a use-def node has no output")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::emu::jit::var::{JitVar, JitVarnodeVar};
    use crate::pcode::seam_stubs::{JitConstVal, JitLocalOutVar};
    use crate::program::model::address::{Address, AddressSpaceType};
    use crate::program::model::pcode::SequenceNumber;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    /// A varnode-backed input value: stands in for the (unported) real `JitVarnodeVar`
    /// implementors an executor would read out of the data-flow state.
    struct InputVal(Varnode);

    impl JitVal for InputVal {
        fn size(&self) -> i32 {
            self.0.get_size()
        }

        fn add_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn remove_use(&self, _op: &dyn JitOp, _position: i32) {}

        fn as_varnode_var(&self) -> Option<&dyn JitVarnodeVar> {
            Some(self)
        }
    }

    impl JitVar for InputVal {
        fn id(&self) -> i32 {
            -1
        }

        fn space(&self) -> Arc<AddressSpace> {
            Arc::clone(self.0.get_address().space())
        }
    }

    impl JitVarnodeVar for InputVal {
        fn varnode(&self) -> Varnode {
            self.0.clone()
        }
    }

    /// A minimal stand-in for the unported `JitDataFlowModel`: it allocates output variables the
    /// way Java's `generateOutVar` does and records every op it is notified of.
    #[derive(Default)]
    struct RecordingModel {
        next_id: AtomicI32,
        notified: Mutex<Vec<Arc<dyn JitOp>>>,
    }

    impl JitDataFlowModel for RecordingModel {
        fn generate_out_var(&self, out: &Varnode) -> Arc<dyn JitOutVar> {
            // Java also has a JitMemoryOutVar branch; every varnode these tests use is a plain
            // memory location, but only the local flavor models `definition` bookkeeping the
            // same way, so keep it uniform here.
            Arc::new(JitLocalOutVar::new(
                self.next_id.fetch_add(1, Ordering::Relaxed),
                out.clone(),
            ))
        }

        fn notify_op(&self, op: Arc<dyn JitOp>) {
            op.link();
            self.notified.lock().unwrap().push(op);
        }
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn varnode(space: &Arc<AddressSpace>, offset: i64, size: i32) -> Varnode {
        Varnode::new(Address::new(Arc::clone(space), offset), size)
    }

    fn arithmetic(endian: Endian) -> (JitDataFlowArithmetic, Arc<RecordingModel>) {
        let dfm = Arc::new(RecordingModel::default());
        let context = JitAnalysisContext::new(endian);
        (JitDataFlowArithmetic::new(&context, Arc::clone(&dfm) as Arc<dyn JitDataFlowModel>), dfm)
    }

    // Java: `subPieceVn(BIG, whole, offset, size)` puts the piece at
    // `whole.size - offset - min(whole.size - offset, size)`; `LITTLE` puts it at `offset`.
    #[test]
    fn sub_piece_vn_places_the_piece_by_endianness() {
        let space = space();
        let whole = varnode(&space, 0x1000, 8);

        let big = JitDataFlowArithmetic::sub_piece_vn(Endian::Big, &whole, 2, 4);
        assert_eq!(big.get_address().offset(), 0x1000 + 8 - 2 - 4);
        assert_eq!(big.get_size(), 4);

        let little = JitDataFlowArithmetic::sub_piece_vn(Endian::Little, &whole, 2, 4);
        assert_eq!(little.get_address().offset(), 0x1002);
        assert_eq!(little.get_size(), 4);

        // `minSize` clamps to what is left of the whole above `offset`.
        let clamped = JitDataFlowArithmetic::sub_piece_vn(Endian::Little, &whole, 6, 4);
        assert_eq!(clamped.get_size(), 2);
    }

    // Java: `truncVnFromRight` keeps the address and shrinks the size; `truncVnFromLeft` advances
    // the address by `amt` and shrinks the size. Neither consults endianness.
    #[test]
    fn trunc_vn_shaves_the_named_end() {
        let (arith, _) = arithmetic(Endian::Little);
        let space = space();
        let vn = varnode(&space, 0x1000, 8);

        let right = arith.trunc_vn_from_right(&vn, 3);
        assert_eq!(right.get_address().offset(), 0x1000);
        assert_eq!(right.get_size(), 5);

        let left = arith.trunc_vn_from_left(&vn, 3);
        assert_eq!(left.get_address().offset(), 0x1003);
        assert_eq!(left.get_size(), 5);
    }

    // Java: `subpiece(JitConstVal, offset, size)` folds to a new constant via
    // `OpBehaviorSubpiece.evaluateBinary`, i.e. `value >>> (offset * 8)` truncated to `size`.
    #[test]
    fn subpiece_of_a_constant_folds_to_a_constant() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let v: Arc<dyn JitVal> = Arc::new(JitConstVal::new(8, 0x1122_3344_5566_7788));

        let piece = arith.subpiece(&v, 2, 4);

        assert_eq!(piece.size(), 4);
        assert_eq!(piece.as_const_val().unwrap().value(), 0x1122_3344_5566);
        // Constant folding never touches the use-def graph.
        assert!(dfm.notified.lock().unwrap().is_empty());
    }

    // Java: `fromConst(byte[])` reads the bytes in machine order; `toConcrete(JitConstVal)`
    // writes them back. Little endian `0x0403_0201` round-trips through `[1, 2, 3, 4]`.
    #[test]
    fn from_const_and_to_concrete_round_trip_in_machine_order() {
        let (little, _) = arithmetic(Endian::Little);
        let v = little.from_const_bytes(&[1, 2, 3, 4]);
        assert_eq!(v.as_const_val().unwrap().value(), 0x0403_0201);
        assert_eq!(little.to_concrete(&v, Purpose::Other).unwrap(), vec![1, 2, 3, 4]);

        let (big, _) = arithmetic(Endian::Big);
        let v = big.from_const_bytes(&[1, 2, 3, 4]);
        assert_eq!(v.as_const_val().unwrap().value(), 0x0102_0304);
        assert_eq!(big.to_concrete(&v, Purpose::Other).unwrap(), vec![1, 2, 3, 4]);
    }

    // Java: `toConcrete` of anything but a `JitConstVal` throws `ConcretionError`.
    #[test]
    fn to_concrete_rejects_non_constants() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let space = space();
        let v: Arc<dyn JitVal> = dfm.generate_out_var(&varnode(&space, 0x1000, 4));

        let err = arith.to_concrete(&v, Purpose::Store).unwrap_err();

        assert_eq!(err.purpose(), Purpose::Store);
    }

    // Java: `sizeOf(JitVal)` is just `value.size()`, and `getEndian` echoes the context's.
    #[test]
    fn size_of_and_endian_come_from_the_value_and_context() {
        let (arith, _) = arithmetic(Endian::Big);
        let v: Arc<dyn JitVal> = Arc::new(JitConstVal::new(3, 7));

        assert_eq!(arith.size_of(&v), 3);
        assert_eq!(arith.get_endian(), Some(Endian::Big));
        assert_eq!(arith.get_domain(), "ghidra.pcode.emu.jit.var.JitVal");
    }

    // Java: `subpiece` of a varnode-backed value generates an out var, then a
    // `JitSynthSubPieceOp` defining it, and notifies the model.
    #[test]
    fn subpiece_of_a_varnode_var_synthesizes_a_sub_piece_op() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let space = space();
        let v: Arc<dyn JitVal> = Arc::new(InputVal(varnode(&space, 0x1000, 8)));

        let piece = arith.subpiece(&v, 2, 4);

        assert_eq!(piece.size(), 4);
        // Little endian: the piece sits `offset` bytes above the whole.
        let out = piece.as_out_var().expect("subpiece output should be an out var");
        assert_eq!(out.varnode().get_address().offset(), 0x1002);
        let definition = out.definition().expect("out var should be defined by the new op");
        let piece_op = definition.as_synth_sub_piece_op().expect("defined by a subpiece op");
        assert_eq!(piece_op.offset(), 2);
        assert_eq!(dfm.notified.lock().unwrap().len(), 1);
    }

    // Java: `trySimplifiedSubPiece` folds a subpiece of a subpiece into one op whose offset is
    // the sum of the two, taking the *inner* op's input as its own.
    #[test]
    fn subpiece_of_a_subpiece_folds_the_offsets() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let space = space();
        let whole: Arc<dyn JitVal> = Arc::new(InputVal(varnode(&space, 0x1000, 8)));

        let inner = arith.subpiece(&whole, 2, 6);
        let outer = arith.subpiece(&inner, 1, 4);

        let definition = outer.as_out_var().unwrap().definition().unwrap();
        let piece_op = definition.as_synth_sub_piece_op().expect("defined by a subpiece op");
        assert_eq!(piece_op.offset(), 3);
        // The folded op reads the original whole, not the intermediate piece.
        assert_eq!(piece_op.v().size(), 8);
        // Two subpiece calls, two notified ops -- the simplified one replaces, not adds to, the
        // op it folded (which was unlinked).
        assert_eq!(dfm.notified.lock().unwrap().len(), 2);
    }

    // Java: `catenate` builds a `JitCatenateOp` over the given parts, defining the out var.
    #[test]
    fn catenate_builds_a_catenate_op_over_the_parts() {
        let (arith, dfm) = arithmetic(Endian::Big);
        let space = space();
        let parts: Vec<Arc<dyn JitVal>> = vec![
            Arc::new(InputVal(varnode(&space, 0x1000, 1))),
            Arc::new(InputVal(varnode(&space, 0x1001, 1))),
        ];

        let cat = arith.catenate(&varnode(&space, 0x1000, 2), parts);

        let definition = cat.as_out_var().unwrap().definition().unwrap();
        assert_eq!(definition.as_catenate_op().unwrap().parts().len(), 2);
        assert_eq!(dfm.notified.lock().unwrap().len(), 1);
    }

    // Java: `trySimplifiedSubPiece` of a catenation drops whole parts. Shifting a 4-byte
    // big-endian catenation of two 2-byte parts right by 2 bytes leaves exactly the first (most
    // significant) part, which is returned as-is ("Context should already be notified") rather
    // than wrapped in a new op.
    #[test]
    fn subpiece_of_a_catenation_drops_whole_parts() {
        let (arith, dfm) = arithmetic(Endian::Big);
        let space = space();
        let high: Arc<dyn JitVal> = Arc::new(InputVal(varnode(&space, 0x1000, 2)));
        let parts: Vec<Arc<dyn JitVal>> =
            vec![Arc::clone(&high), Arc::new(InputVal(varnode(&space, 0x1002, 2)))];
        let cat = arith.catenate(&varnode(&space, 0x1000, 4), parts);
        let notified_after_catenate = dfm.notified.lock().unwrap().len();

        let piece = arith.subpiece(&cat, 2, 2);

        assert_eq!(piece.size(), 2);
        assert!(Arc::ptr_eq(&piece, &high));
        // The lone surviving part is returned directly, so no new op is notified.
        assert_eq!(dfm.notified.lock().unwrap().len(), notified_after_catenate);
    }

    // Java: `unaryOp(PcodeOp, JitVal)` generates the out var, builds the node via `JitOp.unOp`,
    // and returns the node's output.
    #[test]
    fn unary_op_builds_the_node_for_its_opcode() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let space = space();
        let out_vn = varnode(&space, 0x2000, 1);
        let op = PcodeOp::new(
            OpCode::BoolNegate,
            SequenceNumber::new(Address::new(Arc::clone(&space), 0), 0),
            vec![varnode(&space, 0x1000, 1)],
            Some(out_vn.clone()),
        );
        let in1: Arc<dyn JitVal> = Arc::new(InputVal(varnode(&space, 0x1000, 1)));

        let result = arith.unary_op_from_pcode_op(&op, &in1);

        assert_eq!(result.size(), 1);
        assert_eq!(result.as_out_var().unwrap().varnode().get_address().offset(), 0x2000);
        assert_eq!(dfm.notified.lock().unwrap().len(), 1);
    }

    // Java: `unaryOp(int, int, int, JitVal)` -- the size-only overload -- throws `AssertionError`.
    #[test]
    #[should_panic(expected = "AssertionError")]
    fn size_only_unary_op_is_unusable() {
        let (arith, _) = arithmetic(Endian::Little);
        let v: Arc<dyn JitVal> = Arc::new(JitConstVal::new(4, 0));

        arith.unary_op(OpCode::BoolNegate, 1, 4, &v);
    }

    // Java: `modBeforeStore` records a `JitStoreOp` and returns `inValue` unchanged.
    #[test]
    fn mod_before_store_records_the_op_and_returns_the_value() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let space = space();
        let op = PcodeOp::new(
            OpCode::Store,
            SequenceNumber::new(Address::new(Arc::clone(&space), 0), 0),
            vec![],
            None,
        );
        let offset: Arc<dyn JitVal> = Arc::new(JitConstVal::new(8, 0x1000));
        let value: Arc<dyn JitVal> = Arc::new(JitConstVal::new(4, 0xdead_beef));

        let result = arith.mod_before_store_from_pcode_op(&op, &space, &offset, &value);

        assert!(Arc::ptr_eq(&result, &value));
        assert_eq!(dfm.notified.lock().unwrap().len(), 1);
    }

    // Java: `modAfterLoad` ignores the (dummy indirect) `inValue` and returns the load op's own
    // freshly generated output.
    #[test]
    fn mod_after_load_returns_the_loads_output_not_the_dummy() {
        let (arith, dfm) = arithmetic(Endian::Little);
        let space = space();
        let out_vn = varnode(&space, 0x3000, 4);
        let op = PcodeOp::new(
            OpCode::Load,
            SequenceNumber::new(Address::new(Arc::clone(&space), 0), 0),
            vec![],
            Some(out_vn),
        );
        let offset: Arc<dyn JitVal> = Arc::new(JitConstVal::new(8, 0x1000));
        let dummy: Arc<dyn JitVal> = Arc::new(crate::pcode::seam_stubs::JitIndirectMemoryVar);

        let result = arith.mod_after_load_from_pcode_op(&op, &space, &offset, &dummy);

        assert_eq!(result.size(), 4);
        assert_eq!(result.as_out_var().unwrap().varnode().get_address().offset(), 0x3000);
        assert_eq!(dfm.notified.lock().unwrap().len(), 1);
    }

    // Java: `truncFromRight` shaves the varnode's high-offset end, but takes the subpiece from
    // offset `amt` on a big-endian target and offset 0 on a little-endian one.
    #[test]
    fn trunc_from_right_picks_its_offset_by_endianness() {
        let space = space();
        let vn = varnode(&space, 0x1000, 4);

        for (endian, expected_offset) in [(Endian::Big, 1), (Endian::Little, 0)] {
            let (arith, _) = arithmetic(endian);
            let in1: Arc<dyn JitVal> = Arc::new(InputVal(vn.clone()));

            let result = arith.trunc_from_right(&vn, 1, in1);

            let definition = result.as_out_var().unwrap().definition().unwrap();
            assert_eq!(definition.as_synth_sub_piece_op().unwrap().offset(), expected_offset);
            assert_eq!(result.size(), 3);
        }
    }
}
