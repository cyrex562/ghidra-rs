//! Stand-in for the boxed-primitive `Object` that LiSA's `it.unive.lisa.symbolic.value.Constant
//! .getValue()` returns, narrowed to exactly the `instanceof` checks
//! [`PcodeParity::eval_non_null_constant`](super::pcode_parity::PcodeParity::eval_non_null_constant)
//! and
//! [`PcodeSign::eval_non_null_constant`](super::pcode_sign::PcodeSign::eval_non_null_constant)
//! perform against it: `Long`, `Integer`, `Short`, `Byte`, `Boolean`, or anything else.
//!
//! `Constant`/`Object` are external third-party dependencies (`it.unive.lisa.symbolic.value
//! .Constant`, `java.lang.Object`) with no Rust port anywhere in this crate, so, following this
//! crate's established seam-stub convention, this narrow enum takes their place rather than a
//! full `Constant` port.

/// The boxed primitive value a [`Constant`](it.unive.lisa.symbolic.value.Constant)'s `getValue()`
/// can hold, as far as `evalNonNullConstant` in this package cares. See the module docs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConstantValue {
    /// Java: `cval instanceof Long lval`.
    Long(i64),
    /// Java: `cval instanceof Integer ival`.
    Integer(i32),
    /// Java: `cval instanceof Short sval`.
    Short(i16),
    /// Java: `cval instanceof Byte bval`.
    Byte(i8),
    /// Java: `cval instanceof Boolean bval`.
    Boolean(bool),
    /// Any other boxed type Java's `Msg.error` branch falls through to.
    Other,
}
