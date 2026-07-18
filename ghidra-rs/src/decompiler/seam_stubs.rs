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
