//! Port of `ghidra.app.tablechooser.AbstractColumnDisplay`.

use std::marker::PhantomData;

/// A base implementation of [`ColumnDisplay`](super::ColumnDisplay) that knows how to figure out
/// the column type dynamically.
///
/// Java's version uses `ReflectionUtilities.getTypeArguments` to recover the concrete
/// `COLUMN_TYPE` at runtime from a subclass's generic superclass signature. Rust generics are
/// monomorphized at compile time rather than reified via reflection, so [`std::any::type_name`]
/// stands in for that reflection here: it recovers the same information (the concrete `T` a
/// given `ColumnDisplay<T>` implementor was instantiated with) via the compiler instead of the
/// JVM.
///
/// Per this crate's composition-over-inheritance convention, a concrete column display embeds
/// this as a `base: AbstractColumnDisplay<T>` field and implements
/// [`ColumnDisplay::get_column_class`](super::ColumnDisplay::get_column_class) by delegating to
/// [`AbstractColumnDisplay::get_column_class`].
pub struct AbstractColumnDisplay<T> {
    _marker: PhantomData<fn() -> T>,
}

impl<T> AbstractColumnDisplay<T> {
    pub fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Java: `AbstractColumnDisplay.getColumnClass()`.
    pub fn get_column_class(&self) -> String {
        std::any::type_name::<T>().to_string()
    }
}

impl<T> Default for AbstractColumnDisplay<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for AbstractColumnDisplay<T> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<T> std::fmt::Debug for AbstractColumnDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AbstractColumnDisplay<{}>", std::any::type_name::<T>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::seam_stubs::GColumnRenderer;
    use crate::app::tablechooser::AddressableRowObject;
    use crate::app::tablechooser::ColumnDisplay;
    use std::cmp::Ordering;

    /// A `ColumnDisplay<i32>` that gets its `get_column_class` for free via composition, mirroring
    /// how a Java subclass would extend `AbstractColumnDisplay<Integer>`.
    struct IntColumnDisplay {
        base: AbstractColumnDisplay<i32>,
    }

    impl ColumnDisplay<i32> for IntColumnDisplay {
        fn get_column_value(&self, _row_object: &dyn AddressableRowObject) -> i32 {
            42
        }

        fn get_column_name(&self) -> String {
            "Int Column".to_string()
        }

        fn get_column_class(&self) -> String {
            self.base.get_column_class()
        }

        fn compare(&self, _o1: &dyn AddressableRowObject, _o2: &dyn AddressableRowObject) -> Ordering {
            Ordering::Equal
        }

        fn get_renderer(&self) -> Option<Box<dyn GColumnRenderer>> {
            None
        }
    }

    /// A second concrete display over a different `COLUMN_TYPE`, to confirm each instantiation
    /// recovers its own type name independently.
    struct StringColumnDisplay {
        base: AbstractColumnDisplay<String>,
    }

    impl ColumnDisplay<String> for StringColumnDisplay {
        fn get_column_value(&self, _row_object: &dyn AddressableRowObject) -> String {
            "value".to_string()
        }

        fn get_column_name(&self) -> String {
            "String Column".to_string()
        }

        fn get_column_class(&self) -> String {
            self.base.get_column_class()
        }

        fn compare(&self, _o1: &dyn AddressableRowObject, _o2: &dyn AddressableRowObject) -> Ordering {
            Ordering::Equal
        }
    }

    #[test]
    fn get_column_class_recovers_the_generic_type_name() {
        let display = IntColumnDisplay { base: AbstractColumnDisplay::new() };
        assert!(display.get_column_class().ends_with("i32"));
    }

    #[test]
    fn different_instantiations_report_their_own_type() {
        let ints = IntColumnDisplay { base: AbstractColumnDisplay::new() };
        let strings = StringColumnDisplay { base: AbstractColumnDisplay::default() };
        assert!(ints.get_column_class().ends_with("i32"));
        assert!(strings.get_column_class().contains("String"));
        assert_ne!(ints.get_column_class(), strings.get_column_class());
    }

    #[test]
    fn default_and_clone_are_independent_but_equivalent() {
        let a: AbstractColumnDisplay<i32> = AbstractColumnDisplay::default();
        let b = a.clone();
        assert_eq!(a.get_column_class(), b.get_column_class());
    }

    #[test]
    fn debug_includes_the_type_name() {
        let a: AbstractColumnDisplay<i32> = AbstractColumnDisplay::new();
        assert!(format!("{:?}", a).contains("i32"));
    }
}
