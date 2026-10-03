//! Port of the `ghidra.pyghidra.property` package.

pub mod abstract_java_property;
pub mod java_property;

pub use abstract_java_property::{AbstractJavaProperty, JavaInvocationError, JavaObject, PyPropertyValue};
pub use java_property::JavaProperty;
