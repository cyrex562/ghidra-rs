//! Port of `ghidra.program.model.data.PointerType`, promoted to a trait because it was selected
//! as a dependency-cycle cut-point.
//!
//! The Java type is a closed `enum` with four constants (`DEFAULT`, `IMAGE_BASE_RELATIVE`,
//! `RELATIVE`, `FILE_OFFSET`), each carrying a package-private `int value`, plus a static
//! `valueOf(int)` factory that recovers a constant from its `value`. Rust traits cannot carry
//! per-implementor state directly, so each constant becomes its own unit struct implementing
//! [`PointerType`], and `value_of` becomes a free function returning a boxed trait object
//! (matching the "prefer trait objects over concrete types" cycle-cutting rule).
//!
//! The single external reference in the Java source (`PointerTypedefInspector`, imported only for
//! a `@see` javadoc tag, never used in code) needs no placeholder since it is not actually called.

use std::error::Error;
use std::fmt;

/// The pointer-type associated with a pointer-typedef.
///
/// Port of the Java `enum PointerType`.
pub trait PointerType {
    /// The integer value associated with this pointer type.
    ///
    /// Port of the package-private `PointerType.value` field, exposed as a method since Rust
    /// traits cannot declare a shared data field for implementors to store directly.
    fn value(&self) -> i32;
}

/// Normal absolute pointer offset.
///
/// Port of the `PointerType.DEFAULT` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefaultPointerType;

impl PointerType for DefaultPointerType {
    fn value(&self) -> i32 {
        0
    }
}

/// Pointer offset relative to program image base.
///
/// Port of the `PointerType.IMAGE_BASE_RELATIVE` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageBaseRelativePointerType;

impl PointerType for ImageBaseRelativePointerType {
    fn value(&self) -> i32 {
        1
    }
}

/// Pointer offset relative to pointer storage address.
///
/// NOTE: This type has limited usefulness since it can only be applied to a pointer stored in
/// memory based upon its storage location. Type-propagation should be avoided on the resulting
/// pointer typedef.
///
/// Port of the `PointerType.RELATIVE` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelativePointerType;

impl PointerType for RelativePointerType {
    fn value(&self) -> i32 {
        2
    }
}

/// Pointer offset corresponds to file offset within an associated file.
///
/// Port of the `PointerType.FILE_OFFSET` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileOffsetPointerType;

impl PointerType for FileOffsetPointerType {
    fn value(&self) -> i32 {
        3
    }
}

/// Error produced by [`value_of`] when no `PointerType` constant has the requested value,
/// standing in for `java.util.NoSuchElementException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoSuchPointerTypeValue(pub i32);

impl fmt::Display for NoSuchPointerTypeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown type value: {}", self.0)
    }
}

impl Error for NoSuchPointerTypeValue {}

/// Get the [`PointerType`] associated with the specified value.
///
/// Port of the static `PointerType.valueOf(int)` factory method.
///
/// # Errors
/// Returns [`NoSuchPointerTypeValue`] if `val` does not match any known constant, mirroring the
/// Java method's `NoSuchElementException`.
pub fn value_of(val: i32) -> Result<Box<dyn PointerType>, NoSuchPointerTypeValue> {
    match val {
        0 => Ok(Box::new(DefaultPointerType)),
        1 => Ok(Box::new(ImageBaseRelativePointerType)),
        2 => Ok(Box::new(RelativePointerType)),
        3 => Ok(Box::new(FileOffsetPointerType)),
        _ => Err(NoSuchPointerTypeValue(val)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPointerType(i32);

    impl PointerType for MockPointerType {
        fn value(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn usable_as_trait_object() {
        let mock = MockPointerType(42);
        let dyn_pt: &dyn PointerType = &mock;
        assert_eq!(dyn_pt.value(), 42);
    }

    #[test]
    fn constants_report_expected_values() {
        assert_eq!(DefaultPointerType.value(), 0);
        assert_eq!(ImageBaseRelativePointerType.value(), 1);
        assert_eq!(RelativePointerType.value(), 2);
        assert_eq!(FileOffsetPointerType.value(), 3);
    }

    #[test]
    fn value_of_recovers_each_constant() {
        assert_eq!(value_of(0).unwrap().value(), 0);
        assert_eq!(value_of(1).unwrap().value(), 1);
        assert_eq!(value_of(2).unwrap().value(), 2);
        assert_eq!(value_of(3).unwrap().value(), 3);
    }

    #[test]
    fn value_of_rejects_unknown_value() {
        let err = value_of(99).err().unwrap();
        assert_eq!(err, NoSuchPointerTypeValue(99));
        assert_eq!(err.to_string(), "unknown type value: 99");
    }
}
