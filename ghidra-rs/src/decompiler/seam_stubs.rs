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
