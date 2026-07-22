//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

use std::io;

/// Placeholder for `ghidra.pcodeCPort.slghpatexpress.PatternExpression`, needed by
/// [`crate::decompiler::slghpatexpress::PatternValue`] as its supertype (`PatternValue extends
/// PatternExpression` in Java).
pub trait PatternExpression: Send + Sync {
    /// Encodes this pattern expression to the given encoder.
    /// This method is required by subclasses that need to serialize their structure.
    fn encode(&self, _encoder: &mut dyn crate::program::model::pcode::encoder::Encoder) -> io::Result<()> {
        Ok(())
    }

    /// Collects every `PatternValue` leaf reachable from this expression into `list` (Java's
    /// abstract `listValues(VectorSTL<PatternValue>)`). Defaults to a no-op since none of this
    /// trait's real subclasses are ported yet; a leaf `PatternValue` implementation overrides
    /// this to push itself, and a composite expression would override it to recurse into its
    /// operands.
    fn list_values<'a>(&'a self, _list: &mut Vec<&'a dyn crate::decompiler::slghpatexpress::PatternValue>) {}

    /// Appends this expression's min/max bounds, one entry per `PatternValue` leaf, to
    /// `minlist`/`maxlist` (Java's abstract `getMinMax`). Defaults to a no-op for the same
    /// reason as [`PatternExpression::list_values`].
    fn get_min_max(
        &self,
        _minlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>,
        _maxlist: &mut crate::generic::stl::vector_stl::VectorStl<i64>,
    ) {
    }

    /// Evaluates this expression given per-leaf replacement values, consuming entries from
    /// `replace` starting at `listpos` (Java's abstract `getSubValue(VectorSTL<Long>,
    /// MutableInt)`). Defaults to reading and advancing past the next replacement value, which
    /// matches the behavior a leaf `PatternValue` needs; a composite expression would override
    /// this to combine the sub-values of its operands.
    fn get_sub_value(
        &self,
        replace: &crate::generic::stl::vector_stl::VectorStl<i64>,
        listpos: &mut crate::decompiler::utils::MutableInt,
    ) -> i64 {
        let res = *replace.get(listpos.get() as usize);
        listpos.increment();
        res
    }
}

/// Placeholder for `ghidra.pcodeCPort.slghpattern.Pattern`, needed by
/// [`crate::decompiler::slghpatexpress::TokenPattern::get_pattern`].
pub trait Pattern: Send + Sync {}

/// Placeholder for `ghidra.pcodeCPort.semantics.VarnodeTpl`, needed by
/// [`crate::decompiler::slghsymbol::SpecificSymbol::get_varnode`].
pub trait VarnodeTpl: Send + Sync {}

/// Placeholder for `ghidra.pcodeCPort.slghsymbol.ValueSymbol`, needed as the supertype of
/// [`crate::decompiler::slghsymbol::ContextSymbol`] (`ContextSymbol extends ValueSymbol` in
/// Java). The real `ValueSymbol` in turn extends `FamilySymbol`, which is not yet ported either;
/// only the member this interface actually needs (the backing pattern value) is stubbed here.
pub trait ValueSymbol: Send + Sync {
    /// The pattern value this symbol resolves to (the Java `patval` field, exposed via
    /// `ValueSymbol.getPatternValue`).
    fn get_pattern_value(&self) -> &dyn crate::decompiler::slghpatexpress::PatternValue;
}

/// Placeholder for `ghidra.pcodeCPort.translate.BasicSpaceProvider`, needed as the supertrait of
/// [`crate::decompiler::translate::Translate`] (`Translate implements BasicSpaceProvider` in
/// Java).
pub trait BasicSpaceProvider: Send + Sync {
    /// The processor's official default address space (usually the main RAM databus).
    fn get_default_space(&self) -> &dyn crate::decompiler::space::AddrSpace;

    /// The address space used to encode constant values.
    fn get_constant_space(&self) -> &dyn crate::decompiler::space::AddrSpace;
}

/// Placeholder for `ghidra.pcodeCPort.address.RangeList`, needed by
/// [`crate::decompiler::translate::Translate::high_ptr_possible`] (backs the Java `nohighptr`
/// field).
pub trait RangeList: Send + Sync {
    /// Whether `[loc, loc + size)` falls within one of the registered ranges.
    fn in_range(
        &self,
        loc: &crate::program::model::address::Address,
        size: i32,
    ) -> bool;
}

/// Placeholder for `ghidra.pcodeCPort.slghsymbol.Constructor`, needed by
/// [`crate::decompiler::slghpatexpress::OperandValue`] to resolve its operand index against the
/// constructor that defines it. `Constructor` itself has not been ported to a concrete struct
/// yet (only the narrower [`crate::decompiler::slghsymbol::ConstructorLike`] seam used by
/// `DecisionProperties` exists so far).
pub trait Constructor: Send + Sync {
    /// This constructor's source location (Java's `Constructor.location` field).
    fn location(&self) -> &crate::sleigh::grammar::Location;

    /// The operand symbol at `index` (`Constructor.getOperand`).
    fn get_operand(&self, index: i32) -> &crate::decompiler::slghsymbol::OperandSymbol;

    /// Resolves `replace`/`listpos` through the defining expression of the operand at `index`
    /// (`getOperand(index).getDefiningExpression().getSubValue(replace, listpos)`).
    /// `OperandSymbol`'s defining-expression field has not been ported yet, so this seam bundles
    /// the two-step Java traversal into a single method rather than splitting it further.
    fn get_operand_sub_value(
        &self,
        index: i32,
        replace: &[i64],
        listpos: &mut crate::decompiler::utils::MutableInt,
    ) -> i64;

    /// This constructor's parent subtable's id (`Constructor.getParent().getId()`).
    fn parent_id(&self) -> u64;

    /// This constructor's own id (`Constructor.getId()`).
    fn id(&self) -> u64;
}

/// Placeholder for `ghidra.pcodeCPort.context.ConstructState`, needed by
/// [`crate::decompiler::context::ContextSet::point`]. `ContextSet` itself doesn't call any
/// methods on `ConstructState` (it just holds a reference to the parse-tree point where the
/// context set was made), so this seam has no members yet.
pub trait ConstructState: Send + Sync {}
