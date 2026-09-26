//! Port of `ghidra.pcode.emu.symz3.lib.Z3InfixPrinter`.
//!
//! Renders a Z3 [`Expr`] tree as human-readable infix notation (e.g. `(x + 0x5:32)`) instead of
//! Z3's native S-expression form. This is the concrete implementation behind the
//! [`crate::feature::seam_stubs::Z3InfixPrinter`] seam trait that
//! [`SymValueZ3`](crate::feature::symz3::model::sym_value_z3::SymValueZ3) depends on; see that
//! module for the general Z3 seam this crate uses in place of a real `z3` binding.
//!
//! # Deviations from Java
//!
//! * Java's `infixHelper(Expr, ...)` accepts a possibly-`null` `Expr` and returns the literal
//!   string `"null"` in that case. `&dyn Expr` cannot be null in Rust, and every call site here
//!   (both the public wrappers and the internal recursion through [`Expr::args`]) always supplies
//!   a real expression, so that defensive branch has no equivalent and is not modeled.
//! * Java's `infixHelper` reorders a commutative operator's operands by literally rebuilding a
//!   new `Expr` (`e = normalize(e)`, via `Expr.update`) before re-reading `e.getFuncDecl()`/
//!   `e.getArgs()`. Since `normalize` only ever reorders (never changes the declaration or argument
//!   count), and nothing downstream observes the rebuilt `Expr`'s identity, [`Z3InfixPrinter::infix_helper`]
//!   instead computes the (possibly reordered) argument list once, up front, without constructing
//!   a new `Expr` node. [`Z3InfixPrinter::normalize`] is still ported faithfully as its own public
//!   method, built on [`Expr::with_args`], for parity with Java's public API.
//! * `fetchListOfStringsHelper` terminates with `System.lineSeparator()` (platform-dependent);
//!   this always appends `'\n'`, matching the rest of this crate's `Display`/formatting code.
//! * [`Z3InfixPrinter::print_simplifications`] and [`Z3InfixPrinter::print_simplifications_concat`]
//!   are ported faithfully, but note that Java's own `infixHelper` never actually calls
//!   `printSimplifications` -- the call site is commented out (`//e = print_simplifications(e);`)
//!   -- so, as in Java, these methods are dead code from `infix()`'s perspective; they remain
//!   here (and tested) only because they are public API on the class being ported.
//! * Java's final `return "multi-arg" + ...` fallback in `infixHelper` is unreachable: it is
//!   reached only when `getNumArgs()` is none of `>= 2`, `== 1`, or `== 0`, which is impossible
//!   for a non-negative count. Preserved faithfully as dead code (see
//!   [`Z3InfixPrinter::infix_helper`]'s last branch).

use std::sync::Arc;

use crate::feature::seam_stubs::{BitVecExpr, BoolExpr, Expr, Z3Context, Z3DeclKind};
use crate::feature::symz3::model::sym_value_z3::SymValueZ3;

/// Port of `ghidra.pcode.emu.symz3.lib.Z3InfixPrinter`.
pub struct Z3InfixPrinter {
    ctx: Arc<dyn Z3Context>,
}

/// Port of the nested (non-static) class `Z3InfixPrinter.RegisterPlusConstant`. Not constructed
/// anywhere else in the Ghidra codebase this was ported from; kept as a plain, flat struct per
/// this crate's composition-over-inheritance convention (Rust has no nested/inner classes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterPlusConstant {
    pub register_name: String,
    pub constant: i128,
    pub is_negative: bool,
}

impl RegisterPlusConstant {
    /// Java: `RegisterPlusConstant(String name, BigInteger c, boolean isneg)`.
    pub fn new(name: impl Into<String>, constant: i128, is_negative: bool) -> Self {
        Self { register_name: name.into(), constant, is_negative }
    }
}

impl Z3InfixPrinter {
    const SHOW_ALL_SIZES: bool = true;
    /// Any numeric values will display as unsigned values.
    const FORCE_UNSIGNED: bool = false;

    /// Java: `Z3InfixPrinter(Context ctx)`.
    pub fn new(ctx: Arc<dyn Z3Context>) -> Self {
        Self { ctx }
    }

    /// Java: `symbolForZ3(Z3_decl_kind)`.
    pub fn symbol_for_z3(&self, op: &Z3DeclKind) -> String {
        match op {
            Z3DeclKind::Eq => "==".to_string(),
            Z3DeclKind::Bmul => "*".to_string(),
            Z3DeclKind::Badd => "+".to_string(),
            Z3DeclKind::Bsub => "-".to_string(),
            Z3DeclKind::Sleq => "<=".to_string(),
            Z3DeclKind::Not => "not".to_string(),
            Z3DeclKind::And => "&&".to_string(),
            Z3DeclKind::Or => "||".to_string(),
            Z3DeclKind::Concat => "::".to_string(),
            Z3DeclKind::Uleq => "u<=".to_string(),
            Z3DeclKind::Band => "&".to_string(),
            Z3DeclKind::Bor => "|".to_string(),
            other => other.to_string(),
        }
    }

    /// Java: `printSimplificationsConcat(Expr)`. See the [module docs](self) for why this is
    /// unreachable from [`Self::infix`].
    pub fn print_simplifications_concat(&self, e: Box<dyn Expr>) -> Box<dyn Expr> {
        let num_args = e.num_args();
        if num_args == 2 {
            let mut args = e.args();
            if args[0].is_numeral() {
                let bvn = args[0]
                    .as_bit_vec()
                    .expect("Java: unchecked cast (BitVecNum) arg0, guarded by arg0.isNumeral()");
                if bvn.to_int() == Some(0) {
                    return args.remove(1);
                }
            }
        }
        else if num_args > 2 {
            let args = e.args();
            if args[0].is_numeral() {
                let bvn = args[0]
                    .as_bit_vec()
                    .expect("Java: unchecked cast (BitVecNum) arg0, guarded by arg0.isNumeral()");
                if bvn.to_int() == Some(0) {
                    let a1 = args[1]
                        .as_bit_vec()
                        .expect("Java: unchecked cast (BitVecExpr) arg, per ctx.mkConcat's signature");
                    let a2 = args[2]
                        .as_bit_vec()
                        .expect("Java: unchecked cast (BitVecExpr) arg, per ctx.mkConcat's signature");
                    let mut result: Box<dyn BitVecExpr> = self.ctx.mk_concat(a1, a2);
                    for i in 0..(num_args - 3) {
                        let ai = args[i + 3].as_bit_vec().expect(
                            "Java: unchecked cast (BitVecExpr) arg, per ctx.mkConcat's signature",
                        );
                        result = self.ctx.mk_concat(&*result, ai);
                    }
                    let result: Box<dyn Expr> = result;
                    return result;
                }
            }
        }
        e
    }

    /// Java: `normalize(Expr)`. Precondition: `e`'s operator is commutative (see
    /// [`Self::is_commutative`]).
    pub fn normalize(&self, e: Box<dyn Expr>) -> Box<dyn Expr> {
        if e.num_args() == 2 {
            let args = e.args();
            if args[0].is_numeral() && !args[1].is_numeral() {
                let mut it = args.into_iter();
                let arg0 = it.next().unwrap();
                let arg1 = it.next().unwrap();
                return e.with_args(vec![arg1, arg0]);
            }
        }
        e
    }

    /// [`Self::normalize`]'s effect, computed directly from `e`'s arguments without constructing a
    /// new `Expr`. See the [module docs](self) for why [`Self::infix_helper`] uses this instead of
    /// calling [`Self::normalize`] itself.
    fn normalized_args(e: &dyn Expr) -> Vec<Box<dyn Expr>> {
        let mut args = e.args();
        if args.len() == 2 && args[0].is_numeral() && !args[1].is_numeral() {
            args.swap(0, 1);
        }
        args
    }

    /// Java: `printSimplifications(Expr)`. See the [module docs](self) for why this is
    /// unreachable from [`Self::infix`].
    pub fn print_simplifications(&self, e: Box<dyn Expr>) -> Box<dyn Expr> {
        if e.decl_kind() == Z3DeclKind::Concat {
            return self.print_simplifications_concat(e);
        }
        e
    }

    /// Java: `infix(Expr)`.
    pub fn infix(&self, e: &dyn Expr) -> String {
        self.infix_helper(e, '(', ')', Self::SHOW_ALL_SIZES, Self::FORCE_UNSIGNED)
    }

    /// Java: `infixForceSize(Expr)`.
    pub fn infix_force_size(&self, e: &dyn Expr) -> String {
        self.infix_helper(e, '(', ')', true, Self::FORCE_UNSIGNED)
    }

    /// Java: `infixWithBrackets(Expr)`.
    pub fn infix_with_brackets(&self, e: &dyn Expr) -> String {
        self.infix_helper(e, '[', ']', Self::SHOW_ALL_SIZES, Self::FORCE_UNSIGNED)
    }

    /// Java: `infixTopLevel(Expr)`.
    pub fn infix_top_level(&self, e: &dyn Expr) -> String {
        self.infix_helper(e, ' ', ' ', Self::SHOW_ALL_SIZES, Self::FORCE_UNSIGNED)
    }

    /// Java: `uninterpretedStringHelper(Expr)`.
    pub fn uninterpreted_string_helper(&self, e: &dyn Expr) -> String {
        let name = e.decl_name();
        if e.num_args() == 0 {
            return name;
        }
        if e.num_args() != 1 {
            return e.to_smt_string();
        }
        if matches!(name.as_str(), "load_64_8" | "load_64_16" | "load_64_32" | "load_64_64") {
            let args = e.args();
            let eb = e
                .as_bit_vec()
                .expect("Java: unchecked cast (BitVecExpr) e for a load_64_* uninterpreted function");
            let bit_size = eb.sort_size();
            return format!("MEM{}:{}", self.infix_with_brackets(args[0].as_ref()), bit_size);
        }
        format!("(print helper needed){}", e.to_smt_string())
    }

    /// Java: `isNegativeConstant(BitVecExpr)`. If `eb` represents a negative number, returns its
    /// magnitude (e.g. for "-6" returns 6); otherwise `None`.
    pub fn is_negative_constant(&self, eb: &dyn BitVecExpr) -> Option<i128> {
        if !BitVecExpr::is_numeral(eb) {
            return None;
        }
        let ebstring = eb.to_binary_string();

        // When converted by Z3, leading zeroes are removed! So what we do is check the size of
        // the string versus the sort size. Previously we used extract but there is some sort of
        // Z3 issue...
        if (ebstring.len() as u32) < eb.sort_size() || ebstring.len() == 1 {
            return None;
        }

        assert_eq!(ebstring.chars().next(), Some('1'));
        // Java flips each bit via a temporary 'F' marker (to avoid a `1`->`0` replacement being
        // re-matched by the following `0`->`1` pass); a direct per-character flip is equivalent.
        let flipped: String =
            ebstring.chars().map(|c| if c == '1' { '0' } else { '1' }).collect();
        let bi = i128::from_str_radix(&flipped, 2).ok()? + 1;
        Some(bi)
    }

    /// Java: `isConstant(BitVecExpr)`.
    pub fn is_constant(&self, eb: &dyn BitVecExpr) -> Option<i128> {
        if !BitVecExpr::is_numeral(eb) {
            return None;
        }
        eb.to_big_integer()
    }

    /// Java: `isCommutative(Z3_decl_kind)`.
    pub fn is_commutative(&self, op: &Z3DeclKind) -> bool {
        matches!(op, Z3DeclKind::Badd | Z3DeclKind::Bmul | Z3DeclKind::Bor | Z3DeclKind::Band)
    }

    /// Java: `isSizeForcing(Z3_decl_kind)`.
    pub fn is_size_forcing(&self, op: &Z3DeclKind) -> bool {
        matches!(op, Z3DeclKind::Concat | Z3DeclKind::Bor | Z3DeclKind::Band)
    }

    /// Java: the two-arg overload `infixHelper(Expr, boolean forceSize)`. Always uses literal
    /// parentheses, regardless of what bracket the *caller's* current invocation was asked to
    /// use -- only the outermost `infix*` entry point's bracket choice ever reaches the final
    /// assembled result; see the [module docs](self).
    pub fn infix_with_force_size(&self, e: &dyn Expr, force_size: bool) -> String {
        self.infix_helper(e, '(', ')', force_size, Self::FORCE_UNSIGNED)
    }

    /// Java: `infixUnsigned(Expr)`.
    pub fn infix_unsigned(&self, e: &dyn Expr) -> String {
        self.infix_helper(e, '(', ')', Self::SHOW_ALL_SIZES, true)
    }

    /// Java: the five-arg `infixHelper(Expr, char, char, boolean, boolean)`, the recursive engine
    /// every other `infix*` method is built on.
    pub fn infix_helper(
        &self,
        e: &dyn Expr,
        lchr: char,
        rchr: char,
        force_size: bool,
        force_unsigned: bool,
    ) -> String {
        let op = e.decl_kind();

        // Java: `if (!forceSize) { //e = print_simplifications(e); }` -- the call is commented
        // out in the original, so `print_simplifications` never actually runs here. See the
        // module docs.

        // Java: `if (isCommutative(op)) e = normalize(e);` -- see the module docs for why this is
        // implemented as a locally reordered argument list rather than a rebuilt `Expr`.
        let args: Vec<Box<dyn Expr>> =
            if self.is_commutative(&op) { Self::normalized_args(e) } else { e.args() };

        if op == Z3DeclKind::Uninterpreted {
            let result = self.uninterpreted_string_helper(e);
            if lchr == '[' {
                return format!("{}{}{}", lchr, result, rchr);
            }
            return result;
        }

        if op == Z3DeclKind::Extract {
            let params = e.decl_int_params();
            // This is more Sleigh-opinionated....
            return format!(
                "{}[{}:{}]",
                self.infix_force_size(args[0].as_ref()),
                params[1],
                params[0] - params[1] + 1
            );
        }

        if op == Z3DeclKind::Ite {
            // Java fetches `e.getFuncDecl().getParameters()` here but never uses the result -- a
            // genuine dead local, preserved faithfully.
            let _params = e.decl_int_params();
            return format!(
                "{} ? {} : {}",
                self.infix_force_size(args[0].as_ref()),
                self.infix_force_size(args[1].as_ref()),
                self.infix_force_size(args[2].as_ref())
            );
        }

        // problem here... the helper might transform our expression.
        let op_string = self.symbol_for_z3(&op);
        if args.len() >= 2 {
            let is_size_forcing = self.is_size_forcing(&op);
            let mut result = self.infix_with_force_size(
                args[0].as_ref(),
                Self::SHOW_ALL_SIZES || (is_size_forcing && args[0].is_numeral()),
            );
            for a in &args[1..] {
                result.push(' ');
                result.push_str(&op_string);
                result.push(' ');
                result.push_str(&self.infix_with_force_size(
                    a.as_ref(),
                    Self::SHOW_ALL_SIZES || (is_size_forcing && a.is_numeral()),
                ));
            }
            return format!("{}{}{}", lchr, result, rchr);
        }
        if args.len() == 1 {
            let arg0 = args[0].as_ref();
            return format!("{}{}{}{}", op_string, lchr, self.infix(arg0), rchr);
        }
        if args.is_empty() {
            if e.is_bv() {
                let eb = e
                    .as_bit_vec()
                    .expect("Java: unchecked cast (BitVecExpr) e, guarded by e.isBV()");
                let mut size_string = String::new();
                if Self::SHOW_ALL_SIZES || force_size {
                    size_string = format!(":{}", eb.sort_size());
                }
                if e.is_numeral() {
                    if force_unsigned {
                        let bi = eb.to_big_integer().unwrap_or(0);
                        return format!("{}0x{:x}{}{}", lchr, bi, size_string, rchr);
                    }
                    return match self.is_negative_constant(eb) {
                        None => {
                            let bi = eb.to_big_integer().unwrap_or(0);
                            format!("{}0x{:x}{}{}", lchr, bi, size_string, rchr)
                        }
                        Some(b) => format!("{}-0x{:x}{}{}", lchr, b, size_string, rchr),
                    };
                }
                return format!("{}{}", eb.as_expr().to_smt_string(), size_string);
            }
            return e.to_smt_string();
        }
        // Unreachable: `args.len()` is always one of `>= 2`, `== 1`, or `== 0`. Preserved
        // faithfully as dead code; see the module docs.
        format!("multi-arg for {}yields: {}", op, e.to_smt_string())
    }

    /// Java: `fetchListOfStringsHelper(List<String>)`.
    pub fn fetch_list_of_strings_helper(&self, elements: &[String]) -> String {
        let mut result = String::new();
        for (i, r) in elements.iter().enumerate() {
            if i > 0 {
                result.push_str(", ");
            }
            result.push_str(r);
        }
        result.push('\n');
        result
    }

    /// Java: `infix(SymValueZ3)`. Named `infix_value` here since Rust has no method overloading;
    /// see also [`Self::infix`] for the `Expr`-typed overload. Returns `None` where Java's
    /// `getBitVecExpr`/`getBoolExpr` would return `null` (an invalid/unparseable `SymValueZ3`).
    pub fn infix_value(&self, value: &SymValueZ3) -> Option<String> {
        if let Some(b) = value.get_bool_expr(&*self.ctx) {
            return Some(self.infix(b.as_expr()));
        }
        let b = value.get_bit_vec_expr(&*self.ctx)?;
        Some(self.infix(b.as_expr()))
    }

    /// Java: `infixWithSexpr(SymValueZ3)`.
    pub fn infix_with_sexpr(&self, value: &SymValueZ3) -> Option<String> {
        let e_str = if value.has_bool_expr() {
            value.get_bool_expr(&*self.ctx)?.as_expr().to_smt_string()
        }
        else {
            value.get_bit_vec_expr(&*self.ctx)?.as_expr().to_smt_string()
        };
        let prefix = self.infix_value(value)?;
        Some(format!("{} internal sexpr: {}", prefix, e_str))
    }
}

impl crate::feature::seam_stubs::Z3InfixPrinter for Z3InfixPrinter {
    fn infix(&self, e: &dyn Expr) -> String {
        self.infix(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as Rc;

    /// A tiny expression tree node used only to exercise `Z3InfixPrinter` -- it needs a much
    /// richer `Expr` surface (decl kind/name/params, argument lists) than
    /// `SymValueZ3`'s own leaf-only test mocks.
    #[derive(Clone)]
    struct Node {
        kind: Z3DeclKind,
        name: String,
        args: Vec<Rc<Node>>,
        is_bv: bool,
        size: u32,
        numeral: Option<i64>,
        int_params: Vec<i32>,
    }

    impl Node {
        fn sym(name: &str, size: u32) -> Self {
            Self {
                // A free symbol/register is a real Z3 `Z3_OP_UNINTERPRETED` declaration with 0
                // arguments -- `uninterpreted_string_helper` prints these as their bare name,
                // with no size suffix (only numerals and other non-uninterpreted leaves get one).
                kind: Z3DeclKind::Uninterpreted,
                name: name.to_string(),
                args: vec![],
                is_bv: true,
                size,
                numeral: None,
                int_params: vec![],
            }
        }

        fn num(value: i64, size: u32) -> Self {
            Self {
                // Real Z3 numerals have a distinct declaration kind of their own (they are not
                // "uninterpreted" the way a free symbol/register is), so `Z3InfixPrinter` never
                // special-cases them the way it does `Z3_OP_UNINTERPRETED` -- they fall through
                // to the generic zero-arg leaf formatting at the bottom of `infix_helper`.
                kind: Z3DeclKind::Other("Z3_OP_BNUM".to_string()),
                name: String::new(),
                args: vec![],
                is_bv: true,
                size,
                numeral: Some(value),
                int_params: vec![],
            }
        }

        fn op(kind: Z3DeclKind, args: Vec<Node>, is_bv: bool, size: u32) -> Self {
            Self {
                kind,
                name: String::new(),
                args: args.into_iter().map(Rc::new).collect(),
                is_bv,
                size,
                numeral: None,
                int_params: vec![],
            }
        }

        fn uninterpreted(name: &str, args: Vec<Node>, size: u32) -> Self {
            Self {
                kind: Z3DeclKind::Uninterpreted,
                name: name.to_string(),
                args: args.into_iter().map(Rc::new).collect(),
                is_bv: true,
                size,
                numeral: None,
                int_params: vec![],
            }
        }

        fn extract(high: i32, low: i32, arg: Node) -> Self {
            Self {
                kind: Z3DeclKind::Extract,
                name: String::new(),
                args: vec![Rc::new(arg)],
                is_bv: true,
                size: (high - low + 1) as u32,
                numeral: None,
                int_params: vec![high, low],
            }
        }

        fn ite(cond: Node, t: Node, f: Node) -> Self {
            let size = t.size;
            Self {
                kind: Z3DeclKind::Ite,
                name: String::new(),
                args: vec![Rc::new(cond), Rc::new(t), Rc::new(f)],
                is_bv: true,
                size,
                numeral: None,
                int_params: vec![],
            }
        }
    }

    impl Expr for Node {
        fn to_smt_string(&self) -> String {
            if let Some(v) = self.numeral {
                return format!("#x{:x}", v);
            }
            if self.args.is_empty() {
                return self.name.clone();
            }
            let arg_strs: Vec<String> = self.args.iter().map(|a| a.to_smt_string()).collect();
            format!("({} {})", self.name, arg_strs.join(" "))
        }

        fn num_args(&self) -> usize {
            self.args.len()
        }

        fn args(&self) -> Vec<Box<dyn Expr>> {
            self.args.iter().map(|a| Box::new((**a).clone()) as Box<dyn Expr>).collect()
        }

        fn decl_kind(&self) -> Z3DeclKind {
            self.kind.clone()
        }

        fn decl_name(&self) -> String {
            self.name.clone()
        }

        fn decl_int_params(&self) -> Vec<i32> {
            self.int_params.clone()
        }

        fn is_numeral(&self) -> bool {
            self.numeral.is_some()
        }

        fn is_bv(&self) -> bool {
            self.is_bv
        }

        fn as_bit_vec(&self) -> Option<&dyn BitVecExpr> {
            if self.is_bv {
                Some(self)
            }
            else {
                None
            }
        }

        fn with_args(&self, args: Vec<Box<dyn Expr>>) -> Box<dyn Expr> {
            let new_args: Vec<Rc<Node>> = args
                .into_iter()
                .map(|a| {
                    let node = a
                        .as_any()
                        .downcast_ref::<Node>()
                        .expect("test mock: with_args only supports Node children")
                        .clone();
                    Rc::new(node)
                })
                .collect();
            Box::new(Node { args: new_args, ..self.clone() })
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    impl BitVecExpr for Node {
        fn as_expr(&self) -> &dyn Expr {
            self
        }

        fn sort_size(&self) -> u32 {
            self.size
        }

        fn is_numeral(&self) -> bool {
            self.numeral.is_some()
        }

        fn to_big_integer(&self) -> Option<i128> {
            self.numeral.map(i128::from)
        }

        fn to_long(&self) -> Option<i64> {
            self.numeral
        }
    }

    /// A `Z3Context` that only implements `mk_concat` (the only method
    /// `print_simplifications_concat` needs); every other method panics if called.
    struct MockCtx;

    impl Z3Context for MockCtx {
        fn smt_lib_for_bit_vec(&self, _b: &dyn BitVecExpr) -> String {
            unimplemented!()
        }
        fn smt_lib_for_bool(&self, _b: &dyn BoolExpr) -> String {
            unimplemented!()
        }
        fn parse_smt_lib2(&self, _smt: &str) -> Option<Box<dyn BoolExpr>> {
            unimplemented!()
        }
        fn mk_bv(&self, _value: i64, _size_bits: u32) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bv_const(&self, _name: &str, _size_bits: u32) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_true(&self) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_false(&self) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_eq(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_ite_bv(
            &self,
            _predicate: &dyn BoolExpr,
            _t: &dyn BitVecExpr,
            _f: &dyn BitVecExpr,
        ) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_ite_bool(
            &self,
            _predicate: &dyn BoolExpr,
            _t: &dyn BoolExpr,
            _f: &dyn BoolExpr,
        ) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bvslt(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bvsle(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bvult(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bvule(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bv_add_no_overflow(
            &self,
            _l: &dyn BitVecExpr,
            _r: &dyn BitVecExpr,
            _signed: bool,
        ) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bv_sub_no_overflow(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_bvadd(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvsub(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvxor(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvand(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvor(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvmul(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvudiv(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvsdiv(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvshl(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvlshr(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_bvashr(&self, _l: &dyn BitVecExpr, _r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_concat(&self, l: &dyn BitVecExpr, r: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            let name = format!("(concat {} {})", l.as_expr().to_smt_string(), r.as_expr().to_smt_string());
            Box::new(Node {
                kind: Z3DeclKind::Concat,
                name,
                args: vec![],
                is_bv: true,
                size: l.sort_size() + r.sort_size(),
                numeral: None,
                int_params: vec![],
            })
        }
        fn mk_zero_ext(&self, _bits: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_sign_ext(&self, _bits: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_extract(&self, _high: u32, _low: u32, _b: &dyn BitVecExpr) -> Box<dyn BitVecExpr> {
            unimplemented!()
        }
        fn mk_not(&self, _u: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_xor(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_and(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
        fn mk_or(&self, _l: &dyn BoolExpr, _r: &dyn BoolExpr) -> Box<dyn BoolExpr> {
            unimplemented!()
        }
    }

    fn printer() -> Z3InfixPrinter {
        Z3InfixPrinter::new(Arc::new(MockCtx))
    }

    #[test]
    fn symbolic_leaf_prints_its_bare_name_with_no_size_suffix() {
        // A free symbol is `Z3_OP_UNINTERPRETED`, which `infix_helper` special-cases before it
        // ever reaches the generic size-annotated leaf formatting -- so no size suffix appears.
        let p = printer();
        let x = Node::sym("x", 32);
        assert_eq!(p.infix(&x), "x");
    }

    #[test]
    fn non_uninterpreted_non_numeral_bv_leaf_gets_a_size_suffix() {
        // The generic `eb.toString() + sizeString` leaf branch that `SHOW_ALL_SIZES` feeds is
        // only reachable for a bit-vector leaf that is neither `Z3_OP_UNINTERPRETED` nor a
        // numeral -- an edge case real Z3 registers/constants don't actually hit (see the test
        // above), but the class still has to handle it.
        let p = printer();
        let leaf = Node {
            kind: Z3DeclKind::Other("Z3_OP_SOME_OTHER_LEAF".to_string()),
            name: "weird".to_string(),
            args: vec![],
            is_bv: true,
            size: 16,
            numeral: None,
            int_params: vec![],
        };
        assert_eq!(p.infix(&leaf), "weird:16");
    }

    #[test]
    fn numeral_leaf_prints_hex_with_size_wrapped_in_parens() {
        let p = printer();
        let n = Node::num(5, 8);
        assert_eq!(p.infix(&n), "(0x5:8)");
    }

    #[test]
    fn negative_numeral_prints_with_minus_sign() {
        let p = printer();
        // 8-bit 0xFA (250) is -6 in two's complement.
        let n = Node::num(250, 8);
        assert_eq!(p.infix(&n), "(-0x6:8)");
    }

    #[test]
    fn force_unsigned_ignores_the_sign_bit() {
        let p = printer();
        let n = Node::num(250, 8);
        assert_eq!(p.infix_unsigned(&n), "(0xfa:8)");
    }

    #[test]
    fn binary_op_prints_infix_with_symbol() {
        let p = printer();
        let e = Node::op(Z3DeclKind::Eq, vec![Node::sym("x", 8), Node::sym("y", 8)], false, 0);
        assert_eq!(p.infix(&e), "(x == y)");
    }

    #[test]
    fn commutative_op_moves_a_leading_numeral_to_the_end() {
        let p = printer();
        let e = Node::op(Z3DeclKind::Badd, vec![Node::num(5, 8), Node::sym("x", 8)], true, 8);
        assert_eq!(p.infix(&e), "(x + (0x5:8))");
    }

    #[test]
    fn non_commutative_op_keeps_operand_order() {
        let p = printer();
        let e = Node::op(Z3DeclKind::Bsub, vec![Node::num(5, 8), Node::sym("x", 8)], true, 8);
        assert_eq!(p.infix(&e), "((0x5:8) - x)");
    }

    #[test]
    fn unary_op_wraps_argument_in_outer_brackets() {
        let p = printer();
        let e = Node::op(Z3DeclKind::Not, vec![Node::sym("p", 1)], false, 0);
        assert_eq!(p.infix_with_brackets(&e), "not[p]");
    }

    #[test]
    fn extract_prints_offset_and_width() {
        let p = printer();
        let e = Node::extract(7, 4, Node::sym("x", 8));
        assert_eq!(p.infix(&e), "x[4:4]");
    }

    #[test]
    fn ite_prints_ternary_form() {
        let p = printer();
        let e = Node::ite(Node::sym("p", 1), Node::sym("t", 8), Node::sym("f", 8));
        assert_eq!(p.infix(&e), "p ? t : f");
    }

    #[test]
    fn uninterpreted_zero_arg_prints_bare_name() {
        let p = printer();
        let e = Node::uninterpreted("foo", vec![], 8);
        assert_eq!(p.infix(&e), "foo");
    }

    #[test]
    fn uninterpreted_load_prints_mem_with_brackets() {
        let p = printer();
        let e = Node::uninterpreted("load_64_8", vec![Node::sym("addr", 64)], 8);
        assert_eq!(p.infix(&e), "MEM[addr]:8");
    }

    #[test]
    fn uninterpreted_wraps_in_outer_brackets_only_when_asked() {
        let p = printer();
        let e = Node::uninterpreted("foo", vec![], 8);
        assert_eq!(p.infix_with_brackets(&e), "[foo]");
    }

    #[test]
    fn is_negative_constant_matches_java_example() {
        let p = printer();
        let n = Node::num(250, 8); // 0xFA, -6 in 8-bit two's complement
        assert_eq!(p.is_negative_constant(&n), Some(6));

        let pos = Node::num(5, 8);
        assert_eq!(p.is_negative_constant(&pos), None);
    }

    #[test]
    fn is_constant_returns_the_raw_value() {
        let p = printer();
        let n = Node::num(42, 32);
        assert_eq!(p.is_constant(&n), Some(42));
        let sym = Node::sym("x", 32);
        assert_eq!(p.is_constant(&sym), None);
    }

    #[test]
    fn is_commutative_and_is_size_forcing_match_java() {
        let p = printer();
        assert!(p.is_commutative(&Z3DeclKind::Badd));
        assert!(p.is_commutative(&Z3DeclKind::Bmul));
        assert!(p.is_commutative(&Z3DeclKind::Bor));
        assert!(p.is_commutative(&Z3DeclKind::Band));
        assert!(!p.is_commutative(&Z3DeclKind::Bsub));

        assert!(p.is_size_forcing(&Z3DeclKind::Concat));
        assert!(p.is_size_forcing(&Z3DeclKind::Bor));
        assert!(p.is_size_forcing(&Z3DeclKind::Band));
        assert!(!p.is_size_forcing(&Z3DeclKind::Badd));
    }

    #[test]
    fn symbol_for_z3_matches_java_table_and_falls_back_to_debug_name() {
        let p = printer();
        assert_eq!(p.symbol_for_z3(&Z3DeclKind::Eq), "==");
        assert_eq!(p.symbol_for_z3(&Z3DeclKind::Band), "&");
        assert_eq!(p.symbol_for_z3(&Z3DeclKind::Other("Z3_OP_BXOR".to_string())), "Z3_OP_BXOR");
    }

    #[test]
    fn fetch_list_of_strings_helper_joins_with_commas_and_trailing_newline() {
        let p = printer();
        let items = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert_eq!(p.fetch_list_of_strings_helper(&items), "a, b, c\n");
        assert_eq!(p.fetch_list_of_strings_helper(&[]), "\n");
    }

    #[test]
    fn normalize_swaps_a_leading_numeral_for_a_commutative_op() {
        let p = printer();
        let e: Box<dyn Expr> = Box::new(Node::op(Z3DeclKind::Badd, vec![Node::num(5, 8), Node::sym("x", 8)], true, 8));
        let normalized = p.normalize(e);
        let args = normalized.args();
        assert!(!args[0].is_numeral());
        assert!(args[1].is_numeral());
    }

    #[test]
    fn normalize_is_a_no_op_when_both_or_neither_operand_is_numeral() {
        let p = printer();
        let both_sym: Box<dyn Expr> =
            Box::new(Node::op(Z3DeclKind::Badd, vec![Node::sym("x", 8), Node::sym("y", 8)], true, 8));
        let n = p.normalize(both_sym);
        let args = n.args();
        assert_eq!(args[0].to_smt_string(), "x");
        assert_eq!(args[1].to_smt_string(), "y");
    }

    #[test]
    fn print_simplifications_concat_drops_a_leading_zero_operand() {
        let p = printer();
        let e: Box<dyn Expr> =
            Box::new(Node::op(Z3DeclKind::Concat, vec![Node::num(0, 8), Node::sym("x", 32)], true, 40));
        let simplified = p.print_simplifications_concat(e);
        assert_eq!(simplified.to_smt_string(), "x");
    }

    #[test]
    fn print_simplifications_concat_keeps_nonzero_leading_operand() {
        let p = printer();
        let e: Box<dyn Expr> =
            Box::new(Node::op(Z3DeclKind::Concat, vec![Node::num(1, 8), Node::sym("x", 32)], true, 40));
        let simplified = p.print_simplifications_concat(e);
        // Unchanged: the leading operand is non-zero, so Java's guard never fires.
        assert_eq!(simplified.num_args(), 2);
    }

    #[test]
    fn print_simplifications_dispatches_only_for_concat() {
        let p = printer();
        let concat: Box<dyn Expr> =
            Box::new(Node::op(Z3DeclKind::Concat, vec![Node::num(0, 8), Node::sym("x", 32)], true, 40));
        assert_eq!(p.print_simplifications(concat).to_smt_string(), "x");

        let add: Box<dyn Expr> =
            Box::new(Node::op(Z3DeclKind::Badd, vec![Node::num(0, 8), Node::sym("x", 8)], true, 8));
        let unchanged = p.print_simplifications(add);
        assert_eq!(unchanged.num_args(), 2);
    }

    #[test]
    fn register_plus_constant_holds_its_fields() {
        let r = RegisterPlusConstant::new("RAX", 6, true);
        assert_eq!(r.register_name, "RAX");
        assert_eq!(r.constant, 6);
        assert!(r.is_negative);
    }
}
