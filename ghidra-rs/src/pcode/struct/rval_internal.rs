//! Port of `ghidra.pcode.struct.RValInternal`.

use std::sync::Arc;

use crate::pcode::r#struct::lval_internal::LValInternal;
use crate::pcode::r#struct::string_tree::StringTree;
use crate::pcode::seam_stubs::{
    ArithBinExpr, ArithBinExprOp, CmpExpr, CmpExprOp, DerefExpr, InvExpr, NotExpr, RVal,
    StructuredSleighContext,
};
use crate::program::model::address::AddressSpace;
use crate::program::model::data::data_type::DataType;

/// Corresponds to `ghidra.pcode.struct.RValInternal`.
///
/// The implementation side of [`RVal`]: every value node in a Structured Sleigh expression tree
/// implements this. Beyond `RVal`'s user-facing surface it exposes the owning
/// [context](StructuredSleighContext) and the [`generate`](Self::generate) hook that renders the
/// node (and, recursively, its children) into a [`StringTree`] of Sleigh source.
///
/// Java's `getType()` re-declaration is dropped: it only narrows the return type for javadoc
/// purposes, and `RVal::get_type` already carries it.
///
/// # Receivers and `as_rval_internal`
///
/// Java's default methods pass `this` into the expression node they build, so each node keeps a
/// reference to its operands. Rust models those shared, immutable children as
/// `Arc<dyn RValInternal>`, which is why the combinators below take `self: Arc<Self>` rather than
/// `&self`. Rust cannot coerce an `Arc<Self>` to `Arc<dyn RValInternal>` inside a provided method
/// body (`Self` is `?Sized` there), so implementors supply that one coercion via
/// [`as_rval_internal`](Self::as_rval_internal); its body is always `self`.
///
/// The combinators take and return `Arc<dyn RValInternal>` where Java says `RVal`. That is not a
/// widening: Java's `BinExpr`/`UnExpr` constructors immediately downcast every operand with
/// `(RValInternal) lhs`, so `RValInternal` is the real contract. Stating it in the signature makes
/// the results chainable, which in Java comes for free from interface inheritance.
pub trait RValInternal: RVal {
    /// Port of `getContext()`.
    fn get_context(&self) -> Arc<dyn StructuredSleighContext>;

    /// Port of `generate(RValInternal parent)`: render this node as Sleigh source.
    ///
    /// `parent` is the node this one is being emitted into, or `None` at the root of the
    /// expression (Java passes `null`). Nodes consult it to decide whether they need parentheses.
    fn generate(&self, parent: Option<&dyn RValInternal>) -> StringTree;

    /// Coerces to the trait object the combinators build expression nodes out of. Implementors
    /// write `{ self }`; see the [trait docs](RValInternal#receivers-and-as_rval_internal).
    fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal>;

    /// Port of `deref()`: dereference through the language's default address space.
    fn deref(self: Arc<Self>) -> Arc<dyn LValInternal> {
        let space = self.get_context().default_space();
        self.deref_space(space)
    }

    /// Port of `deref(AddressSpace space)`.
    fn deref_space(self: Arc<Self>, space: Arc<AddressSpace>) -> Arc<dyn LValInternal> {
        let ctx = self.get_context();
        Arc::new(DerefExpr::new(ctx, space, self.as_rval_internal()))
    }

    /// Port of `notb()`: boolean negation.
    fn notb(self: Arc<Self>) -> Arc<dyn RValInternal> {
        let ctx = self.get_context();
        Arc::new(NotExpr::new(ctx, self.as_rval_internal()))
    }

    /// Port of `noti()`: bitwise inversion.
    fn noti(self: Arc<Self>) -> Arc<dyn RValInternal> {
        let ctx = self.get_context();
        Arc::new(InvExpr::new(ctx, self.as_rval_internal()))
    }

    /// Port of `eq(RVal rhs)`.
    fn eq(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Eq, rhs)
    }

    /// Port of `eq(long rhs)`.
    fn eq_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.eq(lit)
    }

    /// Port of `eqf(RVal rhs)`.
    fn eqf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Eqf, rhs)
    }

    /// Port of `neq(RVal rhs)`.
    fn neq(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Neq, rhs)
    }

    /// Port of `neq(long rhs)`.
    fn neq_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.neq(lit)
    }

    /// Port of `neqf(RVal rhs)`.
    fn neqf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Neqf, rhs)
    }

    /// Port of `ltiu(RVal rhs)`.
    fn ltiu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Ltiu, rhs)
    }

    /// Port of `ltiu(long rhs)`.
    fn ltiu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.ltiu(lit)
    }

    /// Port of `ltis(RVal rhs)`.
    fn ltis(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Ltis, rhs)
    }

    /// Port of `ltis(long rhs)`.
    fn ltis_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.ltis(lit)
    }

    /// Port of `ltf(RVal rhs)`.
    fn ltf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Ltf, rhs)
    }

    /// Port of `gtiu(RVal rhs)`.
    fn gtiu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Gtiu, rhs)
    }

    /// Port of `gtiu(long rhs)`.
    fn gtiu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.gtiu(lit)
    }

    /// Port of `gtis(RVal rhs)`.
    fn gtis(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Gtis, rhs)
    }

    /// Port of `gtis(long rhs)`.
    fn gtis_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.gtis(lit)
    }

    /// Port of `gtf(RVal rhs)`.
    fn gtf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Gtf, rhs)
    }

    /// Port of `lteiu(RVal rhs)`.
    fn lteiu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Lteiu, rhs)
    }

    /// Port of `lteiu(long rhs)`.
    fn lteiu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.lteiu(lit)
    }

    /// Port of `lteis(RVal rhs)`.
    fn lteis(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Lteis, rhs)
    }

    /// Port of `lteis(long rhs)`.
    fn lteis_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.lteis(lit)
    }

    /// Port of `ltef(RVal rhs)`.
    fn ltef(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Ltef, rhs)
    }

    /// Port of `gteiu(RVal rhs)`.
    fn gteiu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Gteiu, rhs)
    }

    /// Port of `gteiu(long rhs)`.
    fn gteiu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.gteiu(lit)
    }

    /// Port of `gteis(RVal rhs)`.
    fn gteis(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Gteis, rhs)
    }

    /// Port of `gteis(long rhs)`.
    fn gteis_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.gteis(lit)
    }

    /// Port of `gtef(RVal rhs)`.
    fn gtef(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        cmp(self.as_rval_internal(), CmpExprOp::Gtef, rhs)
    }

    /// Port of `orb(RVal rhs)`.
    fn orb(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Orb, rhs)
    }

    /// Port of `orb(long rhs)`.
    fn orb_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.orb(lit)
    }

    /// Port of `ori(RVal rhs)`.
    fn ori(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Ori, rhs)
    }

    /// Port of `ori(long rhs)`.
    fn ori_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.ori(lit)
    }

    /// Port of `xorb(RVal rhs)`.
    fn xorb(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Xorb, rhs)
    }

    /// Port of `xorb(long rhs)`.
    fn xorb_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.xorb(lit)
    }

    /// Port of `xori(RVal rhs)`.
    fn xori(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Xori, rhs)
    }

    /// Port of `xori(long rhs)`.
    fn xori_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.xori(lit)
    }

    /// Port of `andb(RVal rhs)`.
    fn andb(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Andb, rhs)
    }

    /// Port of `andb(long rhs)`.
    fn andb_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.andb(lit)
    }

    /// Port of `andi(RVal rhs)`.
    fn andi(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Andi, rhs)
    }

    /// Port of `andi(long rhs)`.
    fn andi_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.andi(lit)
    }

    /// Port of `shli(RVal rhs)`.
    fn shli(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Shli, rhs)
    }

    /// Port of `shli(long rhs)`.
    fn shli_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.shli(lit)
    }

    /// Port of `shriu(RVal rhs)`.
    fn shriu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Shriu, rhs)
    }

    /// Port of `shriu(long rhs)`.
    fn shriu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.shriu(lit)
    }

    /// Port of `shris(RVal rhs)`.
    fn shris(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Shris, rhs)
    }

    /// Port of `shris(long rhs)`.
    fn shris_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.shris(lit)
    }

    /// Port of `addi(RVal rhs)`.
    // TODO: Validate types? At least warn? (carried over from the Java)
    fn addi(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Addi, rhs)
    }

    /// Port of `addi(long rhs)`.
    fn addi_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.addi(lit)
    }

    /// Port of `addf(RVal rhs)`.
    // TODO: Validate types? At least warn? (carried over from the Java)
    fn addf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Addf, rhs)
    }

    /// Port of `subi(RVal rhs)`.
    fn subi(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Subi, rhs)
    }

    /// Port of `subi(long rhs)`.
    fn subi_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.subi(lit)
    }

    /// Port of `subf(RVal rhs)`.
    fn subf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Subf, rhs)
    }

    /// Port of `muli(RVal rhs)`.
    fn muli(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Muli, rhs)
    }

    /// Port of `muli(long rhs)`.
    fn muli_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.muli(lit)
    }

    /// Port of `mulf(RVal rhs)`.
    fn mulf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Mulf, rhs)
    }

    /// Port of `diviu(RVal rhs)`.
    fn diviu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Diviu, rhs)
    }

    /// Port of `diviu(long rhs)`.
    fn diviu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.diviu(lit)
    }

    /// Port of `divis(RVal rhs)`.
    fn divis(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Divis, rhs)
    }

    /// Port of `divis(long rhs)`.
    fn divis_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.divis(lit)
    }

    /// Port of `divf(RVal rhs)`.
    fn divf(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Divf, rhs)
    }

    /// Port of `remiu(RVal rhs)`.
    fn remiu(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Remiu, rhs)
    }

    /// Port of `remiu(long rhs)`.
    fn remiu_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.remiu(lit)
    }

    /// Port of `remis(RVal rhs)`.
    fn remis(self: Arc<Self>, rhs: Arc<dyn RValInternal>) -> Arc<dyn RValInternal> {
        arith(self.as_rval_internal(), ArithBinExprOp::Remis, rhs)
    }

    /// Port of `remis(long rhs)`.
    fn remis_long(self: Arc<Self>, rhs: i64) -> Arc<dyn RValInternal> {
        let lit = self.lit_like_self(rhs);
        self.remis(lit)
    }

    /// The `getContext().lit(rhs, getType().getLength())` the `long` overloads all share.
    fn lit_like_self(&self, rhs: i64) -> Arc<dyn RValInternal> {
        self.get_context().lit(rhs, self.get_type().get_length())
    }
}

/// Shared body of the comparison combinators: `new CmpExpr(getContext(), this, op, rhs)`.
fn cmp(
    lhs: Arc<dyn RValInternal>,
    op: CmpExprOp,
    rhs: Arc<dyn RValInternal>,
) -> Arc<dyn RValInternal> {
    let ctx = lhs.get_context();
    Arc::new(CmpExpr::new(ctx, lhs, op, rhs))
}

/// Shared body of the arithmetic combinators: `new ArithBinExpr(getContext(), this, op, rhs)`.
fn arith(
    lhs: Arc<dyn RValInternal>,
    op: ArithBinExprOp,
    rhs: Arc<dyn RValInternal>,
) -> Arc<dyn RValInternal> {
    let ctx = lhs.get_context();
    Arc::new(ArithBinExpr::new(ctx, lhs, op, rhs))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    /// Stands in for `StructuredSleigh` itself: supplies the default space and the literal
    /// factory the `long` overloads reach through.
    struct TestCtx {
        space: Arc<AddressSpace>,
    }

    impl TestCtx {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                space: AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0),
            })
        }
    }

    impl StructuredSleighContext for TestCtx {
        fn default_space(&self) -> Arc<AddressSpace> {
            Arc::clone(&self.space)
        }

        fn lit(&self, val: i64, size: i32) -> Arc<dyn RValInternal> {
            // Mirrors `LiteralExpr.generate`'s `0x<hex>:<size>` rendering.
            TestVar::new(format!("{:#x}:{}", val, size))
        }

        fn compute_deref_type(&self, _addr: &dyn RValInternal) -> Box<dyn DataType> {
            Box::new(TestType { length: 4 })
        }
    }

    #[derive(Debug)]
    struct TestType {
        length: i32,
    }

    impl DataType for TestType {
        fn get_name(&self) -> String {
            "int".to_string()
        }

        fn get_length(&self) -> i32 {
            self.length
        }
    }

    /// A leaf value node, standing in for `DefaultVar`: it renders as its own name.
    struct TestVar {
        name: String,
    }

    impl TestVar {
        fn new(name: impl Into<String>) -> Arc<dyn RValInternal> {
            Arc::new(Self { name: name.into() })
        }
    }

    impl RVal for TestVar {
        fn get_type(&self) -> Box<dyn DataType> {
            Box::new(TestType { length: 4 })
        }

        fn cast(&self, _type_: &dyn DataType) -> Box<dyn RVal> {
            unimplemented!()
        }
    }

    impl RValInternal for TestVar {
        fn get_context(&self) -> Arc<dyn StructuredSleighContext> {
            TestCtx::new()
        }

        fn generate(&self, _parent: Option<&dyn RValInternal>) -> StringTree {
            StringTree::single(&self.name)
        }

        fn as_rval_internal(self: Arc<Self>) -> Arc<dyn RValInternal> {
            self
        }
    }

    fn render(val: &Arc<dyn RValInternal>) -> String {
        val.generate(None).to_string()
    }

    #[test]
    fn arithmetic_renders_like_java_bin_expr() {
        // Java: BinExpr.generate emits "(" lhs " " op " " rhs ")".
        let sum = TestVar::new("a").addi(TestVar::new("b"));
        assert_eq!(render(&sum), "(a + b)");

        let shifted = TestVar::new("a").shris(TestVar::new("b"));
        assert_eq!(render(&shifted), "(a s>> b)");
    }

    #[test]
    fn long_overloads_route_through_context_lit() {
        // Java: eq(long) -> eq(getContext().lit(rhs, getType().getLength())); TestType is 4 bytes.
        let cmp = TestVar::new("a").eq_long(5);
        assert_eq!(render(&cmp), "(a == 0x5:4)");

        let diff = TestVar::new("a").subi_long(1);
        assert_eq!(render(&diff), "(a - 0x1:4)");
    }

    #[test]
    fn unary_ops_render_like_java_un_expr() {
        // Java: UnExpr.generate emits "(" op u ")".
        assert_eq!(render(&TestVar::new("a").notb()), "(!a)");
        assert_eq!(render(&TestVar::new("a").noti()), "(~a)");
    }

    #[test]
    fn double_negation_collapses_like_java() {
        // Java: NotExpr.notb() returns u, InvExpr.noti() returns u -- no wrapper is added.
        assert_eq!(render(&TestVar::new("a").notb().notb()), "a");
        assert_eq!(render(&TestVar::new("a").noti().noti()), "a");
    }

    #[test]
    fn negating_a_comparison_flips_the_operator() {
        // Java: CmpExpr.notb() rebuilds with op.not(); LTIU.not() == GTEIU.
        let lt = TestVar::new("a").ltiu(TestVar::new("b"));
        assert_eq!(render(&lt), "(a < b)");
        assert_eq!(render(&lt.notb()), "(a >= b)");
    }

    #[test]
    fn deref_uses_the_default_space_and_omits_its_name() {
        // Java: DerefExpr.generate only names the space when it differs from the default one,
        // and appends ":<length>" for a sized type.
        let deref = TestVar::new("p").deref();
        assert_eq!(deref.generate(None).to_string(), "(*:4 p)");
    }

    #[test]
    fn deref_names_a_non_default_space() {
        let other = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let deref = TestVar::new("p").deref_space(other);
        assert_eq!(deref.generate(None).to_string(), "(*[register]:4 p)");
    }
}
