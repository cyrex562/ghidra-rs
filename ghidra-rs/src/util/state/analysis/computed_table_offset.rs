//! Mirrors `ghidra.util.state.analysis.ComputedTableOffset`.

use crate::program::model::pcode::OpCode;
use crate::util::state::{VarnodeOperand, VarnodeOperation};

/// Reports whether `operand` is a constant, dispatching on the `Varnode`/`VarnodeOperation`
/// polymorphism [`VarnodeOperand`] stands in for. Mirrors `Varnode.isConstant()`/the
/// unconditionally-`false` `VarnodeOperation.isConstant()` override.
fn operand_is_constant(operand: &VarnodeOperand) -> bool {
    match operand {
        VarnodeOperand::Plain(v) => v.is_constant(),
        VarnodeOperand::Operation(_) => false,
    }
}

/// The offset of `operand`, dispatching the same way [`operand_is_constant`] does. Mirrors
/// `Varnode.getOffset()` (inherited, unoverridden, by `VarnodeOperation`).
fn operand_offset(operand: &VarnodeOperand) -> i64 {
    match operand {
        VarnodeOperand::Plain(v) => v.get_offset(),
        VarnodeOperand::Operation(op) => op.get_offset(),
    }
}

/// Represents a value used to compute an offset into a switch table, together with the size (in
/// bytes) of each table entry.
///
/// Port of `ghidra.util.state.analysis.ComputedTableOffset`, a package-private class used
/// internally by other classes in the same Java package (`MySwitchAnalyzer`,
/// `RelativeJumpTableSwitch`, none ported yet). Following this crate's convention of exposing
/// ported items as `pub` regardless of Java's package-private visibility (Rust's module system
/// already scopes access differently -- see e.g.
/// [`BufferNode`](crate::framework::db::buffers::buffer_node::BufferNode) for the same treatment
/// of another package-private Java class), every member here is `pub`.
#[derive(Debug, Clone)]
pub struct ComputedTableOffset {
    factor: i32,
    /// Mirrors the nullable `Varnode indexValue` field: `None` only when
    /// [`get_computed_table_offset`](Self::get_computed_table_offset)'s final zero-extend-unwrap
    /// step reads a `null`/missing input value, which Java's unchecked `op.getInputValues()[0]`
    /// array access would silently accept too. See that method's own docs.
    index_value: Option<VarnodeOperand>,
}

impl ComputedTableOffset {
    /// Mirrors the package-private `ComputedTableOffset(Varnode indexValue, int factor)`
    /// constructor.
    fn new(index_value: Option<VarnodeOperand>, factor: i32) -> Self {
        ComputedTableOffset { factor, index_value }
    }

    /// Returns the index value `Varnode` or `VarnodeOperation`.
    ///
    /// Mirrors `ComputedTableOffset.getIndexValue()`. See the struct's own docs for why this is
    /// `Option`-typed.
    pub fn get_index_value(&self) -> Option<&VarnodeOperand> {
        self.index_value.as_ref()
    }

    /// Returns table entry size in bytes.
    ///
    /// Mirrors `ComputedTableOffset.getTableEntrySize()`.
    pub fn get_table_entry_size(&self) -> i32 {
        self.factor
    }

    /// Get the [`ComputedTableOffset`] which corresponds to the specified input value `v`. No
    /// qualification is performed.
    ///
    /// Mirrors the package-private static `ComputedTableOffset.getComputedTableOffset(Varnode
    /// v)`. Java's `Varnode v` parameter may itself be an `instanceof VarnodeOperation`, which is
    /// exactly the recursive polymorphism [`VarnodeOperand`] was introduced to model (see that
    /// type's own docs on [`VarnodeOperation`]), so this takes `v: &VarnodeOperand` rather than a
    /// bare `Varnode`.
    ///
    /// # Preserved quirks
    /// * Java indexes `inputValues[1]`/`inputValues[0]` (and calls `.isConstant()` on them)
    ///   without a bounds or null check; an out-of-bounds or `null` element would throw
    ///   `ArrayIndexOutOfBoundsException`/`NullPointerException`. This is reproduced via a panic
    ///   with a descriptive message, matching this crate's established convention for unchecked
    ///   Java exceptions (see e.g.
    ///   [`VarnodeOperation::eq`](crate::util::state::VarnodeOperation)'s own preserved-NPE
    ///   quirks).
    /// * The final zero-extend-unwrap step's `op.getInputValues()[0]` read has *no* such check in
    ///   Java (unlike the two above, which are guarded by the preceding `factor <= 0 ||
    ///   factor > 8` return and thus always execute on a `MULT`/`LEFT` op with at least two real
    ///   inputs) and *can* legally read past the end or read a `null` slot without throwing --
    ///   Java simply assigns whatever it finds (including `null`) to `indexValue`. This is why
    ///   [`get_index_value`](Self::get_index_value) is `Option`-typed rather than panicking here.
    pub fn get_computed_table_offset(v: &VarnodeOperand) -> Option<ComputedTableOffset> {
        if let VarnodeOperand::Operation(computed_table_offset_operation) = v {
            let opcode = computed_table_offset_operation.get_pcode_op().get_opcode();
            if opcode != OpCode::IntMult && opcode != OpCode::IntLeft {
                return None;
            }
            let input_values = computed_table_offset_operation.get_input_values();
            let input1 = input_values
                .get(1)
                .and_then(|o| o.as_ref())
                .expect("ComputedTableOffset::get_computed_table_offset: missing/null inputValues[1] (Java's equivalent would ArrayIndexOutOfBoundsException/NullPointerException too)");
            let input0 = input_values
                .get(0)
                .and_then(|o| o.as_ref())
                .expect("ComputedTableOffset::get_computed_table_offset: missing/null inputValues[0] (Java's equivalent would ArrayIndexOutOfBoundsException/NullPointerException too)");

            let (factor, index_value) = if operand_is_constant(input1) {
                let mut f = operand_offset(input1);
                if opcode == OpCode::IntLeft {
                    f = 1i64 << f;
                }
                (f, input0.clone())
            } else if opcode == OpCode::IntMult && operand_is_constant(input0) {
                (operand_offset(input0), input1.clone())
            } else {
                (1i64, v.clone())
            };

            if factor <= 0 || factor > 8 {
                return None;
            }
            return Some(ComputedTableOffset::finish(index_value, factor as i32));
        }

        // v is a plain Varnode (not a VarnodeOperation).
        Some(ComputedTableOffset::finish(v.clone(), 1))
    }

    /// Applies the shared "ignore a unique zero-extend wrapping the real index value" step, then
    /// builds the result. Factored out of
    /// [`get_computed_table_offset`](Self::get_computed_table_offset) since every branch there
    /// funnels into it.
    fn finish(index_value: VarnodeOperand, factor: i32) -> ComputedTableOffset {
        if let VarnodeOperand::Operation(op) = &index_value {
            let pcode_op = op.get_pcode_op();
            if let Some(output) = pcode_op.get_output() {
                if output.is_unique() && pcode_op.get_opcode() == OpCode::IntZext {
                    // Mirrors `op.getInputValues()[0]`: unchecked, and may legally be missing.
                    let replacement = op.get_input_values().get(0).and_then(|o| o.clone());
                    return ComputedTableOffset::new(replacement, factor);
                }
            }
        }
        ComputedTableOffset::new(Some(index_value), factor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::{PcodeOp, SequenceNumber, Varnode};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn const_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("const", 32, 1, AddressSpaceType::Constant, 1)
    }

    fn unique_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 2)
    }

    fn addr_in(space: &std::sync::Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    fn plain(offset: i64, size: i32) -> Varnode {
        Varnode::new(addr_in(&ram_space(), offset), size)
    }

    fn constant(value: i64, size: i32) -> Varnode {
        Varnode::new(addr_in(&const_space(), value), size)
    }

    fn op_at(
        offset: i64,
        opcode: OpCode,
        inputs: Vec<Varnode>,
        output: Option<Varnode>,
    ) -> PcodeOp {
        PcodeOp::new(opcode, SequenceNumber::new(addr_in(&ram_space(), offset), 0), inputs, output)
    }

    #[test]
    fn plain_varnode_yields_index_value_itself_with_factor_one() {
        let v = VarnodeOperand::Plain(plain(0x10, 4));
        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(result.get_table_entry_size(), 1);
        assert_eq!(result.get_index_value(), Some(&v));
    }

    #[test]
    fn non_mult_non_left_operation_returns_none() {
        let index = plain(0x10, 4);
        let op = op_at(0x1000, OpCode::IntAdd, vec![index.clone(), constant(4, 4)], Some(plain(0x1000, 4)));
        let operation = VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(index)),
                Some(VarnodeOperand::Plain(constant(4, 4))),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(operation));
        assert!(ComputedTableOffset::get_computed_table_offset(&v).is_none());
    }

    #[test]
    fn int_mult_with_constant_second_input_extracts_factor_and_index() {
        // index * 4
        let index = plain(0x10, 4);
        let op = op_at(0x1000, OpCode::IntMult, vec![index.clone(), constant(4, 4)], Some(plain(0x1000, 4)));
        let operation = VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(index.clone())),
                Some(VarnodeOperand::Plain(constant(4, 4))),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(operation));
        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(result.get_table_entry_size(), 4);
        assert_eq!(result.get_index_value(), Some(&VarnodeOperand::Plain(index)));
    }

    #[test]
    fn int_mult_with_constant_first_input_extracts_factor_and_index() {
        // 2 * index
        let index = plain(0x20, 4);
        let op = op_at(0x1000, OpCode::IntMult, vec![constant(2, 4), index.clone()], Some(plain(0x1000, 4)));
        let operation = VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(constant(2, 4))),
                Some(VarnodeOperand::Plain(index.clone())),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(operation));
        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(result.get_table_entry_size(), 2);
        assert_eq!(result.get_index_value(), Some(&VarnodeOperand::Plain(index)));
    }

    #[test]
    fn int_left_shifts_factor_as_power_of_two() {
        // index << 3  =>  factor = 1 << 3 = 8
        let index = plain(0x30, 4);
        let op = op_at(0x1000, OpCode::IntLeft, vec![index.clone(), constant(3, 4)], Some(plain(0x1000, 4)));
        let operation = VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(index.clone())),
                Some(VarnodeOperand::Plain(constant(3, 4))),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(operation));
        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(result.get_table_entry_size(), 8);
        assert_eq!(result.get_index_value(), Some(&VarnodeOperand::Plain(index)));
    }

    #[test]
    fn factor_out_of_range_returns_none() {
        // index << 4  =>  factor = 1 << 4 = 16, which is > 8, so unsupported.
        let index = plain(0x30, 4);
        let op = op_at(0x1000, OpCode::IntLeft, vec![index.clone(), constant(4, 4)], Some(plain(0x1000, 4)));
        let operation = VarnodeOperation::new(
            op,
            vec![
                Some(VarnodeOperand::Plain(index)),
                Some(VarnodeOperand::Plain(constant(4, 4))),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(operation));
        assert!(ComputedTableOffset::get_computed_table_offset(&v).is_none());
    }

    #[test]
    fn neither_input_constant_falls_back_to_factor_one_and_the_whole_operation() {
        let a = plain(0x10, 4);
        let b = plain(0x20, 4);
        let op = op_at(0x1000, OpCode::IntMult, vec![a.clone(), b.clone()], Some(plain(0x1000, 4)));
        let operation = VarnodeOperation::new(
            op,
            vec![Some(VarnodeOperand::Plain(a)), Some(VarnodeOperand::Plain(b))],
        );
        let v = VarnodeOperand::Operation(Box::new(operation));
        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(result.get_table_entry_size(), 1);
        assert_eq!(result.get_index_value(), Some(&v));
    }

    #[test]
    fn unwraps_a_unique_zero_extend_around_the_index_value() {
        // index * 4, where index itself is `zext(inner)` stored to a unique varnode.
        let inner = plain(0x40, 1);
        let zext_output = Varnode::new(addr_in(&unique_space(), 0), 4);
        assert!(zext_output.is_unique());
        let zext_op = op_at(0x2000, OpCode::IntZext, vec![inner.clone()], Some(zext_output.clone()));
        let zext_operation =
            VarnodeOperation::new(zext_op, vec![Some(VarnodeOperand::Plain(inner.clone()))]);

        let outer_op = op_at(
            0x1000,
            OpCode::IntMult,
            vec![zext_output.clone(), constant(4, 4)],
            Some(plain(0x1000, 4)),
        );
        let outer_operation = VarnodeOperation::new(
            outer_op,
            vec![
                Some(VarnodeOperand::Operation(Box::new(zext_operation))),
                Some(VarnodeOperand::Plain(constant(4, 4))),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(outer_operation));

        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(result.get_table_entry_size(), 4);
        // The zero-extend is unwrapped, exposing `inner` directly.
        assert_eq!(result.get_index_value(), Some(&VarnodeOperand::Plain(inner)));
    }

    #[test]
    fn does_not_unwrap_a_non_unique_zero_extend() {
        let inner = plain(0x40, 1);
        // A non-unique (e.g. register) output space.
        let zext_output = plain(0x50, 4);
        assert!(!zext_output.is_unique());
        let zext_op = op_at(0x2000, OpCode::IntZext, vec![inner.clone()], Some(zext_output.clone()));
        let zext_operation =
            VarnodeOperation::new(zext_op, vec![Some(VarnodeOperand::Plain(inner))]);

        let outer_op = op_at(
            0x1000,
            OpCode::IntMult,
            vec![zext_output.clone(), constant(4, 4)],
            Some(plain(0x1000, 4)),
        );
        let outer_operation = VarnodeOperation::new(
            outer_op,
            vec![
                Some(VarnodeOperand::Operation(Box::new(zext_operation.clone()))),
                Some(VarnodeOperand::Plain(constant(4, 4))),
            ],
        );
        let v = VarnodeOperand::Operation(Box::new(outer_operation));

        let result = ComputedTableOffset::get_computed_table_offset(&v).unwrap();
        assert_eq!(
            result.get_index_value(),
            Some(&VarnodeOperand::Operation(Box::new(zext_operation)))
        );
    }
}
