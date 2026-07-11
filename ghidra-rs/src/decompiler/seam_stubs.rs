//! Minimal placeholder traits for core types not yet ported, used to break
//! dependency cycles. Each placeholder is replaced by the real port later.

/// Placeholder for `ghidra.pcodeCPort.slghpatexpress.PatternExpression`, needed by
/// [`crate::decompiler::slghpatexpress::PatternValue`] as its supertype (`PatternValue extends
/// PatternExpression` in Java).
pub trait PatternExpression: Send + Sync {}

/// Placeholder for `ghidra.pcodeCPort.slghpatexpress.TokenPattern`, needed by
/// [`crate::decompiler::slghpatexpress::PatternValue::gen_pattern`].
pub trait TokenPattern: Send + Sync {}
