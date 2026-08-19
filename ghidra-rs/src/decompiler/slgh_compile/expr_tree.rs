use crate::decompiler::context::SleighError;
use crate::decompiler::opcodes::OpCode;
use crate::program::model::lang::sleigh::template::{ConstTpl, OpTpl, VarnodeTpl};
use crate::sleigh::grammar::Location;

/// A flattened expression tree.
///
/// Mirrors `ghidra.pcodeCPort.slgh_compile.ExprTree`. The Java class is a mutable value type with
/// two private fields (`ops`, the flattened list of ops making up the expression, and `outvn`,
/// the expression's output varnode) that its own static helpers (`appendParams`, `toVector`)
/// reach into on *other* `ExprTree` instances. Those fields are exposed here as required accessor
/// methods so storage stays with the implementor while the Java behavior is reproduced in default
/// methods, mirroring how [`crate::decompiler::space::ConstantSpace`] treats construction as an
/// implementor concern.
///
/// The Java `VarnodeTpl` this type wraps carries a `location` field and an `isUnnamed()` query
/// (`unnamed_flag`); the in-repo [`VarnodeTpl`] port does not yet expose either, so
/// [`ExprTree::out_is_unnamed`] is a required method here rather than a call into `VarnodeTpl`,
/// to be simplified once that gap closes.
pub trait ExprTree {
    /// The source location the expression tree originated at (the Java `location` field).
    fn location(&self) -> &Location;

    /// The flattened list of ops making up the expression (the Java `ops` field). `None` mirrors
    /// Java's `ops == null`, which occurs both before the "ops from an op" constructor path is
    /// taken and after the ops have been claimed by [`ExprTree::to_vector`].
    fn ops(&self) -> Option<&Vec<OpTpl>>;

    /// Mutable access to the whole `ops` slot, needed to append, drain, or edit-in-place.
    fn ops_mut(&mut self) -> &mut Option<Vec<OpTpl>>;

    /// The output varnode of the expression (the Java `outvn` field).
    fn out_varnode(&self) -> Option<&VarnodeTpl>;

    /// Mutable access to the whole `outvn` slot.
    fn out_varnode_mut(&mut self) -> &mut Option<VarnodeTpl>;

    /// Whether the current output varnode is unnamed (the Java `outvn.isUnnamed()` query used by
    /// [`ExprTree::set_output`]). See the trait-level docs for why this isn't a `VarnodeTpl`
    /// method yet.
    fn out_is_unnamed(&self) -> bool;

    /// Appends an op to `ops`, creating the vector if this expression had none yet (the Java
    /// `ops.push_back(op)` call sites, which always follow an `ops = new VectorSTL<OpTpl>()`).
    fn push_op(&mut self, op: OpTpl) {
        match self.ops_mut() {
            Some(ops) => ops.push(op),
            slot => *slot = Some(vec![op]),
        }
    }

    /// The last op in `ops`, mutably (Java's `ops.back()`).
    fn last_op_mut(&mut self) -> Option<&mut OpTpl> {
        self.ops_mut().as_mut().and_then(|ops| ops.last_mut())
    }

    /// Takes `ops`, leaving `None` behind (the shared behavior of Java's `ExprTree.toVector` and
    /// the per-parameter `param.get(i).ops.clear()` in `appendParams`).
    fn take_ops(&mut self) -> Option<Vec<OpTpl>> {
        self.ops_mut().take()
    }

    /// Takes `outvn`, leaving `None` behind (the per-parameter `param.get(i).outvn = null` in
    /// `appendParams`).
    fn take_out_varnode(&mut self) -> Option<VarnodeTpl> {
        self.out_varnode_mut().take()
    }

    /// The size of the expression's output (the Java package-private `getSize`, which reads
    /// `outvn.getSize()`).
    fn get_size(&self) -> Option<&ConstTpl> {
        self.out_varnode().map(|vn| &vn.size)
    }

    /// Forces the output of the expression to be `newout`. If the original output is unnamed,
    /// this replaces the last op's output in place; otherwise the original (named) output must be
    /// preserved as an input, so an extra COPY op is appended.
    ///
    /// Mirrors `ExprTree.setOutput`, which throws `SleighError` when the expression has no
    /// output.
    fn set_output(
        &mut self,
        new_location: Location,
        newout: VarnodeTpl,
    ) -> Result<(), SleighError> {
        if self.out_varnode().is_none() {
            return Err(SleighError::new("Expression has no output", new_location));
        }

        if self.out_is_unnamed() {
            let op = self
                .last_op_mut()
                .expect("an expression with an output has at least one op");
            op.clear_output();
            op.set_output(newout.clone());
        } else {
            let outvn = self
                .out_varnode()
                .cloned()
                .expect("checked for an output above");
            let mut op = OpTpl::with_opcode(OpCode::CpuiCopy);
            op.add_input(outvn);
            op.set_output(newout.clone());
            self.push_op(op);
        }

        *self.out_varnode_mut() = Some(newout);
        Ok(())
    }

    /// Grabs the op vector and clears the expression's own copy.
    ///
    /// Mirrors the public static `ExprTree.toVector`, restated as an instance method since the
    /// Java version's only argument is the `ExprTree` it operates on.
    fn to_vector(&mut self) -> Option<Vec<OpTpl>> {
        self.take_ops()
    }
}

/// Creates an op expression with the entire list of expression inputs.
///
/// Mirrors the static, package-private `ExprTree.appendParams`: flattens every parameter's ops
/// into the result (in order), wires each parameter's output varnode as an input to `op`, and
/// finally appends `op` itself. Each parameter's `ops`/`outvn` are left empty afterward, matching
/// Java's `param.get(i).ops.clear()` / `param.get(i).outvn = null`.
///
/// This is a free function rather than a trait method because it operates across a whole slice of
/// (boxed, dynamically-dispatched) `ExprTree`s rather than through `&self`.
pub fn append_params(mut op: OpTpl, params: &mut [Box<dyn ExprTree>]) -> Vec<OpTpl> {
    let mut res = Vec::new();
    for param in params.iter_mut() {
        if let Some(mut ops) = param.take_ops() {
            res.append(&mut ops);
        }
        if let Some(vn) = param.take_out_varnode() {
            op.add_input(vn);
        }
    }
    res.push(op);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExprTree {
        location: Location,
        ops: Option<Vec<OpTpl>>,
        outvn: Option<VarnodeTpl>,
        unnamed: bool,
    }

    impl ExprTree for MockExprTree {
        fn location(&self) -> &Location {
            &self.location
        }

        fn ops(&self) -> Option<&Vec<OpTpl>> {
            self.ops.as_ref()
        }

        fn ops_mut(&mut self) -> &mut Option<Vec<OpTpl>> {
            &mut self.ops
        }

        fn out_varnode(&self) -> Option<&VarnodeTpl> {
            self.outvn.as_ref()
        }

        fn out_varnode_mut(&mut self) -> &mut Option<VarnodeTpl> {
            &mut self.outvn
        }

        fn out_is_unnamed(&self) -> bool {
            self.unnamed
        }
    }

    fn loc() -> Location {
        Location::new("test.sla", 1)
    }

    fn real_varnode(offset: u64, size: u64) -> VarnodeTpl {
        VarnodeTpl {
            space: ConstTpl::new(),
            offset: {
                let mut c = ConstTpl::new();
                c.value_real = offset;
                c
            },
            size: {
                let mut c = ConstTpl::new();
                c.value_real = size;
                c
            },
        }
    }

    fn from_op(op: OpTpl) -> MockExprTree {
        let outvn = op.get_out().cloned();
        MockExprTree {
            location: loc(),
            ops: Some(vec![op]),
            outvn,
            unnamed: true,
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let expr = MockExprTree {
            location: loc(),
            ops: None,
            outvn: None,
            unnamed: false,
        };
        let dyn_expr: &dyn ExprTree = &expr;
        assert!(dyn_expr.ops().is_none());
        assert!(dyn_expr.out_varnode().is_none());
    }

    #[test]
    fn get_size_reads_output_varnode_size() {
        let mut op = OpTpl::with_opcode(OpCode::CpuiCopy);
        op.set_output(real_varnode(0, 4));
        let expr = from_op(op);
        assert_eq!(expr.get_size().unwrap().value_real, 4);
    }

    #[test]
    fn get_size_none_without_output() {
        let expr = MockExprTree {
            location: loc(),
            ops: None,
            outvn: None,
            unnamed: false,
        };
        assert!(expr.get_size().is_none());
    }

    #[test]
    fn set_output_errors_when_expression_has_no_output() {
        let mut expr = MockExprTree {
            location: loc(),
            ops: None,
            outvn: None,
            unnamed: false,
        };
        let err = expr.set_output(loc(), real_varnode(0, 4)).unwrap_err();
        assert_eq!(err.message(), "Expression has no output");
    }

    #[test]
    fn set_output_replaces_last_op_output_when_unnamed() {
        let op = OpTpl::with_opcode(OpCode::CpuiCopy);
        let mut expr = MockExprTree {
            location: loc(),
            ops: Some(vec![op]),
            outvn: Some(real_varnode(0, 4)),
            unnamed: true,
        };

        expr.set_output(loc(), real_varnode(8, 4)).unwrap();

        assert_eq!(expr.ops().unwrap().len(), 1);
        let updated = expr.ops().unwrap()[0].get_out().unwrap();
        assert_eq!(updated.offset.value_real, 8);
        assert_eq!(expr.out_varnode().unwrap().offset.value_real, 8);
    }

    #[test]
    fn set_output_appends_copy_op_when_named() {
        let op = OpTpl::with_opcode(OpCode::CpuiCopy);
        let mut expr = MockExprTree {
            location: loc(),
            ops: Some(vec![op]),
            outvn: Some(real_varnode(0, 4)),
            unnamed: false,
        };

        expr.set_output(loc(), real_varnode(8, 4)).unwrap();

        let ops = expr.ops().unwrap();
        assert_eq!(ops.len(), 2);
        let copy_op = &ops[1];
        assert_eq!(copy_op.get_opcode(), OpCode::CpuiCopy);
        assert_eq!(copy_op.get_in(0).offset.value_real, 0);
        assert_eq!(copy_op.get_out().unwrap().offset.value_real, 8);
        assert_eq!(expr.out_varnode().unwrap().offset.value_real, 8);
    }

    #[test]
    fn to_vector_takes_ops_and_clears_them() {
        let op = OpTpl::with_opcode(OpCode::CpuiCopy);
        let mut expr = from_op(op);

        let taken = expr.to_vector().unwrap();
        assert_eq!(taken.len(), 1);
        assert!(expr.ops().is_none());
    }

    #[test]
    fn append_params_flattens_ops_and_wires_inputs() {
        let mut op1 = OpTpl::with_opcode(OpCode::CpuiIntAdd);
        op1.set_output(real_varnode(0, 4));
        let param1 = from_op(op1);

        let mut op2 = OpTpl::with_opcode(OpCode::CpuiIntSub);
        op2.set_output(real_varnode(4, 4));
        let param2 = from_op(op2);

        let mut params: Vec<Box<dyn ExprTree>> = vec![Box::new(param1), Box::new(param2)];

        let combine = OpTpl::with_opcode(OpCode::CpuiIntAnd);
        let res = append_params(combine, &mut params);

        // Both parameter ops, then the combining op.
        assert_eq!(res.len(), 3);
        assert_eq!(res[0].get_opcode(), OpCode::CpuiIntAdd);
        assert_eq!(res[1].get_opcode(), OpCode::CpuiIntSub);
        let combine_op = &res[2];
        assert_eq!(combine_op.get_opcode(), OpCode::CpuiIntAnd);
        assert_eq!(combine_op.num_input(), 2);
        assert_eq!(combine_op.get_in(0).offset.value_real, 0);
        assert_eq!(combine_op.get_in(1).offset.value_real, 4);

        // Parameters are drained, matching Java's ops.clear()/outvn = null.
        for param in &params {
            assert!(param.ops().is_none());
            assert!(param.out_varnode().is_none());
        }
    }
}
