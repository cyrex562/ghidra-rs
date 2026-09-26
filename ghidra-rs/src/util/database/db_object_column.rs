//! Mirrors `ghidra.util.database.DBObjectColumn`: an opaque handle to the column backing an
//! object field.
//!
//! Each should be declared as a static field of the same class whose field it describes, and
//! annotated with [`DBAnnotatedColumn`](super::DBAnnotatedColumn). The annotated field receives
//! its value the first time a store is created for the containing class; until then, it is
//! uninitialized.
//!
//! Java identifies each handle with a private, un-overridable class carrying a single
//! package-private `columnNumber` field, interned per column index by the static `get(int)`
//! factory so that repeated lookups for the same index return the same instance. The port keeps
//! that shape: [`DBObjectColumn`] exposes the column index through [`DBObjectColumn::column_number`]
//! (standing in for the direct field reads other classes in the Java package perform, e.g.
//! `DBCachedObjectStore`/`DBAnnotatedObject` reading `column.columnNumber`), and [`get`] is the
//! interning factory, caching handles behind a process-wide index-keyed table exactly like the
//! Java `static List<DBObjectColumn> instances`.

use std::sync::{Arc, Mutex, OnceLock};

/// An opaque handle to the column backing an object field, mirroring `DBObjectColumn`.
pub trait DBObjectColumn: Send + Sync {
    /// The raw column index this handle refers to, mirroring the package-private `columnNumber`
    /// field.
    fn column_number(&self) -> i32;
}

/// The concrete handle produced by [`get`], mirroring the private `DBObjectColumn` constructor.
struct ColumnHandle {
    column_number: i32,
}

impl DBObjectColumn for ColumnHandle {
    fn column_number(&self) -> i32 {
        self.column_number
    }
}

fn instances() -> &'static Mutex<Vec<Option<Arc<dyn DBObjectColumn>>>> {
    static INSTANCES: OnceLock<Mutex<Vec<Option<Arc<dyn DBObjectColumn>>>>> = OnceLock::new();
    INSTANCES.get_or_init(|| Mutex::new(Vec::with_capacity(20)))
}

/// Returns the interned handle for `column_number`, creating it on first request, mirroring
/// `DBObjectColumn.get(int)`.
pub fn get(column_number: i32) -> Arc<dyn DBObjectColumn> {
    let mut instances = instances().lock().unwrap();
    let index = column_number as usize;
    if instances.len() <= index {
        instances.resize(index + 1, None);
    }
    if instances[index].is_none() {
        instances[index] = Some(Arc::new(ColumnHandle { column_number }));
    }
    instances[index].clone().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockColumn(i32);
    impl DBObjectColumn for MockColumn {
        fn column_number(&self) -> i32 {
            self.0
        }
    }

    #[test]
    fn object_safe_and_reports_column_number() {
        let column: Box<dyn DBObjectColumn> = Box::new(MockColumn(7));
        assert_eq!(column.column_number(), 7);
    }

    #[test]
    fn get_interns_handles_by_column_number() {
        let a = get(1000);
        let b = get(1000);
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.column_number(), 1000);
    }

    #[test]
    fn get_returns_distinct_handles_for_distinct_columns() {
        let a = get(1001);
        let b = get(1002);
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(a.column_number(), 1001);
        assert_eq!(b.column_number(), 1002);
    }
}
