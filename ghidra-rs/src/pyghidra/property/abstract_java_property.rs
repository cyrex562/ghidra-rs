//! Port of `ghidra.pyghidra.property.AbstractJavaProperty`.
//!
//! Abstract base class for implementing a `JavaProperty`. In Java it provides the `fset`
//! implementation as well as all helpers so that each child class only needs to define a
//! constructor and an `fget` method returning the correct primitive type.
//!
//! # Shape
//!
//! Java is `abstract sealed class AbstractJavaProperty<T> implements JavaProperty<T> permits
//! BooleanJavaProperty, ByteJavaProperty, CharacterJavaProperty, DoubleJavaProperty,
//! FloatJavaProperty, IntegerJavaProperty, LongJavaProperty, ObjectJavaProperty,
//! ShortJavaProperty` -- a CLOSED set of nine alternatives, so per
//! `scripts/shape_rules.py` (rule R-sealed-closed-set) this becomes `pub enum
//! AbstractJavaProperty` with one variant per permitted subclass, not a trait. Each subclass'
//! entire body (beyond its constructor) is a single `fget` one-liner delegating to the inherited
//! `doGet`, so this port folds all nine subclasses (`BooleanJavaProperty` etc., otherwise queued
//! separately later in `PORT_ORDER.tsv`) directly into this enum's variants rather than porting
//! them as nine near-empty structs that would each just wrap one field of this type -- there is no
//! separate Rust type for them to be.
//!
//! # Seams
//!
//! * **`MethodHandle` (Java reflection).** `getter`/`setter` are `java.lang.invoke.MethodHandle`s
//!   bound (by the unported `PropertyUtils`/`JavaPropertyFactory`) to a specific public
//!   getter/setter method on some arbitrary Java class, then invoked reflectively and unchecked-
//!   cast to `T` (`(T) getter.invoke(self)`). Rust has no reflective method handle; the closest
//!   equivalent already used in this crate for a bound, fallible, later-invoked callback is
//!   [`crate::util::function::ExceptionalFunction`], so `getter`/`setter` become boxed closures of
//!   that shape over an opaque `self` object (see [`JavaObject`]) instead.
//! * **`Object self` / `Object` values.** Java's `doGet(Object self)`/`fset(Object self, T
//!   value)` operate on an arbitrary Java object via reflection. There is no bridged live JVM
//!   object type in this crate, so `Object` becomes [`JavaObject`], a type-erased
//!   `Arc<dyn Any + Send + Sync>` -- used both for the receiver (`self`) and, for
//!   `ObjectJavaProperty`, for the property's own value type `T`.
//! * **`throws Throwable`.** Both `doGet`/`fset` can throw arbitrary Java exceptions (a failed
//!   reflective invocation). [`JavaInvocationError`] models this minimally as a message, mirroring
//!   Java's own untyped `Throwable` at this boundary.
//! * **Per-subclass `fget` unifying into one enum method.** Since Java gives each subclass its own
//!   statically-typed `fget` (`boolean fget(Object)`, `byte fget(Object)`, ...) so that Python's
//!   duck typing (via jpype) receives the right primitive type, and this port folds all nine into
//!   one enum, [`AbstractJavaProperty::fget`] returns one [`PyPropertyValue`] instead: a tagged
//!   union over exactly the nine possible primitive/reference results. This is not a loss of
//!   fidelity -- Python is dynamically typed regardless, so a runtime-tagged result is precisely
//!   what a Python caller already receives via jpype's own primitive-boxing.
//! * **`hasValidSetter()`'s type-compatibility check.** Java's getter and setter `MethodHandle`s
//!   are obtained independently via reflection with no static guarantee they agree on type, so
//!   `hasValidSetter()` compares `PropertyUtils.boxPrimitive(getter.type().returnType())` against
//!   the setter's boxed parameter type at runtime. Here, each variant's getter and setter closures
//!   share one Rust type parameter `T` by construction (see [`PropertyHandles`]), so that mismatch
//!   is impossible to construct in the first place; [`AbstractJavaProperty::has_valid_setter`]
//!   therefore degenerates to "a setter is present" (matching Java's own fallback when there is no
//!   getter to compare against).
//!
//! Java's `PropertyUtils` (used by `hasValidSetter`) is not ported (its actual job -- reflectively
//! discovering getter/setter method pairs on an arbitrary class -- is out of scope for this
//! type), so [`AbstractJavaProperty::has_valid_setter`] does not call out to it; see the note above
//! for why it does not need to.

use std::any::Any;
use std::sync::Arc;

/// Stand-in for Java's `Object` at the `AbstractJavaProperty`/`JavaProperty` boundary: the
/// property's receiver (`self`), and (for [`AbstractJavaProperty::Object`]) the property's own
/// value type. See the module docs' Seams section.
pub type JavaObject = Arc<dyn Any + Send + Sync>;

/// Mirrors an invocation-time Java `Throwable` thrown while reflectively invoking a bound
/// getter/setter `MethodHandle`. See the module docs' Seams section for why this is minimal.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct JavaInvocationError(pub String);

/// A getter closure standing in for a bound `MethodHandle` invoked with the receiver as its sole
/// argument. Mirrors `(T) getter.invoke(self)` in `AbstractJavaProperty.doGet`.
type Getter<T> = Box<dyn Fn(&JavaObject) -> Result<T, JavaInvocationError> + Send + Sync>;

/// A setter closure standing in for a bound `MethodHandle` invoked with the receiver and the new
/// value. Mirrors `setter.invoke(self, value)` in `AbstractJavaProperty.fset`.
type Setter<T> = Box<dyn Fn(&JavaObject, T) -> Result<(), JavaInvocationError> + Send + Sync>;

/// The `field`/`getter`/`setter` state every `AbstractJavaProperty` variant shares, parameterized
/// over that variant's primitive/reference type `T`.
///
/// Port of `AbstractJavaProperty<T>`'s three fields plus `hasGetter`/`hasSetter`/`hasValidSetter`/
/// `doGet`/`fset`. Kept as a separate generic struct (rather than duplicating these five members
/// nine times across the enum's variants) since every variant's behavior is otherwise identical.
pub struct PropertyHandles<T> {
    /// The name of the property. Mirrors the public final field `AbstractJavaProperty.field`.
    pub field: String,
    getter: Option<Getter<T>>,
    setter: Option<Setter<T>>,
}

impl<T> PropertyHandles<T> {
    /// Port of `AbstractJavaProperty(String, MethodHandle, MethodHandle)`.
    pub fn new(field: impl Into<String>, getter: Option<Getter<T>>, setter: Option<Setter<T>>) -> Self {
        Self { field: field.into(), getter, setter }
    }

    /// Port of `hasGetter()`.
    pub fn has_getter(&self) -> bool {
        self.getter.is_some()
    }

    /// Port of `hasSetter()`.
    pub fn has_setter(&self) -> bool {
        self.setter.is_some()
    }

    /// Port of the package-private `hasValidSetter()`. Java's two branches are: no setter ->
    /// `false`; setter but no getter -> `true`; both present -> compare their (boxed) types. See
    /// the module docs' Seams section for why the third branch is unconditionally `true` here,
    /// collapsing all three into "a setter is present".
    fn has_valid_setter(&self) -> bool {
        self.setter.is_some()
    }

    /// Port of the protected final `doGet(Object)`. Panics if there is no getter, mirroring
    /// Java's `NullPointerException` from `getter.invoke(self)` on a null `getter`.
    fn do_get(&self, self_obj: &JavaObject) -> Result<T, JavaInvocationError> {
        let getter = self.getter.as_ref().expect("doGet() called on a property with no getter");
        getter(self_obj)
    }

    /// Port of the public final `fset(Object, T)`. Panics if there is no setter, mirroring Java's
    /// `NullPointerException` from `setter.invoke(self, value)` on a null `setter`.
    fn fset(&self, self_obj: &JavaObject, value: T) -> Result<(), JavaInvocationError> {
        let setter = self.setter.as_ref().expect("fset() called on a property with no setter");
        setter(self_obj, value)
    }
}

/// A property's value, tagged by which of the nine `AbstractJavaProperty` alternatives produced
/// or accepts it. See the module docs' Seams section for why `fget` returns this rather than nine
/// separately-typed methods.
#[derive(Debug, Clone)]
pub enum PyPropertyValue {
    /// Mirrors `BooleanJavaProperty.fget`.
    Boolean(bool),
    /// Mirrors `ByteJavaProperty.fget`.
    Byte(i8),
    /// Mirrors `CharacterJavaProperty.fget`.
    Character(char),
    /// Mirrors `DoubleJavaProperty.fget`.
    Double(f64),
    /// Mirrors `FloatJavaProperty.fget`.
    Float(f32),
    /// Mirrors `IntegerJavaProperty.fget`.
    Integer(i32),
    /// Mirrors `LongJavaProperty.fget`.
    Long(i64),
    /// Mirrors `ObjectJavaProperty.fget`.
    Object(JavaObject),
    /// Mirrors `ShortJavaProperty.fget`.
    Short(i16),
}

/// Abstract base class for implementing a `JavaProperty`.
///
/// Port of `ghidra.pyghidra.property.AbstractJavaProperty`. See the module docs for the shape and
/// seam decisions this port makes.
pub enum AbstractJavaProperty {
    /// Port of `BooleanJavaProperty`, the `JavaProperty` for the primitive `boolean` type.
    Boolean(PropertyHandles<bool>),
    /// Port of `ByteJavaProperty`, the `JavaProperty` for the primitive `byte` type.
    Byte(PropertyHandles<i8>),
    /// Port of `CharacterJavaProperty`, the `JavaProperty` for the primitive `char` type.
    Character(PropertyHandles<char>),
    /// Port of `DoubleJavaProperty`, the `JavaProperty` for the primitive `double` type.
    Double(PropertyHandles<f64>),
    /// Port of `FloatJavaProperty`, the `JavaProperty` for the primitive `float` type.
    Float(PropertyHandles<f32>),
    /// Port of `IntegerJavaProperty`, the `JavaProperty` for the primitive `int` type.
    Integer(PropertyHandles<i32>),
    /// Port of `LongJavaProperty`, the `JavaProperty` for the primitive `long` type.
    Long(PropertyHandles<i64>),
    /// Port of `ObjectJavaProperty`, the `JavaProperty` for a reference type.
    Object(PropertyHandles<JavaObject>),
    /// Port of `ShortJavaProperty`, the `JavaProperty` for the primitive `short` type.
    Short(PropertyHandles<i16>),
}

macro_rules! for_each_variant {
    ($self:expr, $handles:ident => $body:expr) => {
        match $self {
            AbstractJavaProperty::Boolean($handles) => $body,
            AbstractJavaProperty::Byte($handles) => $body,
            AbstractJavaProperty::Character($handles) => $body,
            AbstractJavaProperty::Double($handles) => $body,
            AbstractJavaProperty::Float($handles) => $body,
            AbstractJavaProperty::Integer($handles) => $body,
            AbstractJavaProperty::Long($handles) => $body,
            AbstractJavaProperty::Object($handles) => $body,
            AbstractJavaProperty::Short($handles) => $body,
        }
    };
}

impl AbstractJavaProperty {
    /// Port of the public final field `AbstractJavaProperty.field`.
    pub fn field(&self) -> &str {
        for_each_variant!(self, h => &h.field)
    }

    /// Port of `hasGetter()`.
    pub fn has_getter(&self) -> bool {
        for_each_variant!(self, h => h.has_getter())
    }

    /// Port of `hasSetter()`.
    pub fn has_setter(&self) -> bool {
        for_each_variant!(self, h => h.has_setter())
    }

    /// Port of the package-private `hasValidSetter()` (Java: "this is only for testing").
    pub(crate) fn has_valid_setter(&self) -> bool {
        for_each_variant!(self, h => h.has_valid_setter())
    }

    /// Port of each subclass's `fget(Object)`, unified. See the module docs' Seams section for
    /// why this returns a [`PyPropertyValue`] rather than nine separately-typed methods.
    pub fn fget(&self, self_obj: &JavaObject) -> Result<PyPropertyValue, JavaInvocationError> {
        match self {
            AbstractJavaProperty::Boolean(h) => h.do_get(self_obj).map(PyPropertyValue::Boolean),
            AbstractJavaProperty::Byte(h) => h.do_get(self_obj).map(PyPropertyValue::Byte),
            AbstractJavaProperty::Character(h) => h.do_get(self_obj).map(PyPropertyValue::Character),
            AbstractJavaProperty::Double(h) => h.do_get(self_obj).map(PyPropertyValue::Double),
            AbstractJavaProperty::Float(h) => h.do_get(self_obj).map(PyPropertyValue::Float),
            AbstractJavaProperty::Integer(h) => h.do_get(self_obj).map(PyPropertyValue::Integer),
            AbstractJavaProperty::Long(h) => h.do_get(self_obj).map(PyPropertyValue::Long),
            AbstractJavaProperty::Object(h) => h.do_get(self_obj).map(PyPropertyValue::Object),
            AbstractJavaProperty::Short(h) => h.do_get(self_obj).map(PyPropertyValue::Short),
        }
    }

    /// Port of `fset(Object, T)`.
    ///
    /// Returns a [`JavaInvocationError`] if `value`'s tag does not match this property's own
    /// type. Java has no equivalent check here (`setter.invoke(self, value)` is an unchecked
    /// reflective call), but since [`PyPropertyValue`] erases the type Java's generic `T`
    /// preserved statically, a mismatch must be caught explicitly instead.
    pub fn fset(&self, self_obj: &JavaObject, value: PyPropertyValue) -> Result<(), JavaInvocationError> {
        match (self, value) {
            (AbstractJavaProperty::Boolean(h), PyPropertyValue::Boolean(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Byte(h), PyPropertyValue::Byte(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Character(h), PyPropertyValue::Character(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Double(h), PyPropertyValue::Double(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Float(h), PyPropertyValue::Float(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Integer(h), PyPropertyValue::Integer(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Long(h), PyPropertyValue::Long(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Object(h), PyPropertyValue::Object(v)) => h.fset(self_obj, v),
            (AbstractJavaProperty::Short(h), PyPropertyValue::Short(v)) => h.fset(self_obj, v),
            (property, value) => Err(JavaInvocationError(format!(
                "cannot set a value of a different type onto property '{}': {value:?}",
                property.field()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn stored_object(value: i32) -> JavaObject {
        Arc::new(Mutex::new(value))
    }

    fn get_i32(obj: &JavaObject) -> i32 {
        *obj.downcast_ref::<Mutex<i32>>().unwrap().lock().unwrap()
    }

    #[test]
    fn integer_property_round_trips_through_fget_and_fset() {
        let getter: Getter<i32> = Box::new(|self_obj| Ok(get_i32(self_obj)));
        let setter: Setter<i32> = Box::new(|self_obj, value| {
            *self_obj.downcast_ref::<Mutex<i32>>().unwrap().lock().unwrap() = value;
            Ok(())
        });
        let property =
            AbstractJavaProperty::Integer(PropertyHandles::new("count", Some(getter), Some(setter)));
        let obj = stored_object(41);

        match property.fget(&obj).unwrap() {
            PyPropertyValue::Integer(v) => assert_eq!(v, 41),
            other => panic!("expected Integer, got {other:?}"),
        }

        property.fset(&obj, PyPropertyValue::Integer(99)).unwrap();
        assert_eq!(get_i32(&obj), 99);
    }

    #[test]
    fn field_has_getter_and_has_setter_reflect_construction() {
        let getter_only = AbstractJavaProperty::Short(PropertyHandles::new(
            "half",
            Some(Box::new(|_: &JavaObject| Ok(7i16))),
            None,
        ));
        assert_eq!(getter_only.field(), "half");
        assert!(getter_only.has_getter());
        assert!(!getter_only.has_setter());
    }

    #[test]
    fn has_valid_setter_is_false_with_no_setter_and_true_with_a_setter_but_no_getter() {
        let no_setter =
            AbstractJavaProperty::Boolean(PropertyHandles::new("flag", Some(Box::new(|_| Ok(true))), None));
        assert!(!no_setter.has_valid_setter());

        let setter_only_setter: Setter<bool> = Box::new(|_, _| Ok(()));
        let setter_only =
            AbstractJavaProperty::Boolean(PropertyHandles::new("flag", None, Some(setter_only_setter)));
        assert!(setter_only.has_valid_setter());

        let getter: Getter<bool> = Box::new(|_| Ok(true));
        let setter: Setter<bool> = Box::new(|_, _| Ok(()));
        let both = AbstractJavaProperty::Boolean(PropertyHandles::new("flag", Some(getter), Some(setter)));
        assert!(both.has_valid_setter());
    }

    #[test]
    fn fset_with_a_mismatched_value_kind_is_an_error() {
        let getter: Getter<i32> = Box::new(|_| Ok(1));
        let setter: Setter<i32> = Box::new(|_, _| Ok(()));
        let property =
            AbstractJavaProperty::Integer(PropertyHandles::new("count", Some(getter), Some(setter)));
        let obj = stored_object(0);

        let result = property.fset(&obj, PyPropertyValue::Boolean(true));
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "no getter")]
    fn fget_without_a_getter_panics_like_javas_null_pointer_exception() {
        let property: AbstractJavaProperty =
            AbstractJavaProperty::Integer(PropertyHandles::new("count", None, None));
        let obj = stored_object(0);
        let _ = property.fget(&obj);
    }
}
