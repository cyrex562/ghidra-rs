//! Port of `ghidra.pyghidra.property.JavaProperty`.
//!
//! Property interface for creating a Python property for getters and setters. Each implementation
//! is required to have a defined `fget` method which returns the corresponding primitive type, so
//! that Python's duck typing and the Jpype conversion system can automatically convert the return
//! value to the equivalent Python type. `fget`/`fset` are named to correspond with the `fget`/
//! `fset` members of Python's `property` type.
//!
//! # Shape
//!
//! Java is `sealed interface JavaProperty<T> permits AbstractJavaProperty` -- a CLOSED set of
//! exactly one alternative, so per `scripts/shape_rules.py` (rule R-sealed-closed-set) this
//! becomes `pub enum JavaProperty` with one variant, not a trait (which would reopen a set Java
//! deliberately closed to a single implementor, and would make every caller take `&dyn
//! JavaProperty` for what is here a plain value delegating straight through to
//! [`AbstractJavaProperty`]).

use super::abstract_java_property::{AbstractJavaProperty, JavaInvocationError, JavaObject, PyPropertyValue};

/// Property interface for creating a Python property for getters and setters.
///
/// Port of `ghidra.pyghidra.property.JavaProperty`. The sole permitted implementor,
/// [`AbstractJavaProperty`], is this enum's only variant; see the module docs.
pub enum JavaProperty {
    /// The (only) permitted implementor, `AbstractJavaProperty` (and, through it, each of its own
    /// nine variants).
    Abstract(AbstractJavaProperty),
}

impl JavaProperty {
    /// The method to be used as the `fset` value for a Python property.
    ///
    /// Port of `JavaProperty.fset(Object, T)`.
    pub fn fset(&self, self_obj: &JavaObject, value: PyPropertyValue) -> Result<(), JavaInvocationError> {
        match self {
            JavaProperty::Abstract(inner) => inner.fset(self_obj, value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::abstract_java_property::PropertyHandles;
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn fset_delegates_to_the_wrapped_abstract_java_property() {
        let setter: Box<dyn Fn(&JavaObject, i32) -> Result<(), JavaInvocationError> + Send + Sync> =
            Box::new(|self_obj, value| {
                *self_obj.downcast_ref::<Mutex<i32>>().unwrap().lock().unwrap() = value;
                Ok(())
            });
        let abstract_property =
            AbstractJavaProperty::Integer(PropertyHandles::new("count", None, Some(setter)));
        let property = JavaProperty::Abstract(abstract_property);
        let obj: JavaObject = Arc::new(Mutex::new(0));

        property.fset(&obj, PyPropertyValue::Integer(7)).unwrap();

        assert_eq!(*obj.downcast_ref::<Mutex<i32>>().unwrap().lock().unwrap(), 7);
    }

    #[test]
    fn fset_with_a_mismatched_value_kind_propagates_the_error() {
        let setter: Box<dyn Fn(&JavaObject, i32) -> Result<(), JavaInvocationError> + Send + Sync> =
            Box::new(|_, _| Ok(()));
        let property = JavaProperty::Abstract(AbstractJavaProperty::Integer(PropertyHandles::new(
            "count",
            None,
            Some(setter),
        )));
        let obj: JavaObject = Arc::new(Mutex::new(0));

        let result = property.fset(&obj, PyPropertyValue::Boolean(true));

        assert!(result.is_err());
    }
}
