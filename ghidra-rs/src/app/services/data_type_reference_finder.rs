//! Extension point for locating references to a data type within a program.
//!
//! Mirrors `ghidra.app.services.DataTypeReferenceFinder`.

use crate::app::seam_stubs::{DataTypeReference, FieldMatcher};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::program::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// An interface for extension points to implement. Implementations know how to find data type
/// references.
///
/// Implementation type names must end with `DataTypeReferenceFinder`.
///
/// Port of `ghidra.app.services.DataTypeReferenceFinder`. The Java interface also extends
/// `ExtensionPoint`, a marker interface with no methods that exists solely to aid Ghidra's
/// classpath scanner; it has no Rust equivalent and is omitted (see
/// [`Analyzer`](crate::app::services::Analyzer) for the same convention).
///
/// Java overloads `findReferences` three ways (by data type, by data type + field name, and by
/// `FieldMatcher`); since Rust has no method overloading, each overload below gets a distinct
/// name.
pub trait DataTypeReferenceFinder {
    /// Finds references in the current program in a manner appropriate with the given
    /// implementation.
    ///
    /// Note that this operation is multi-threaded and that results will be delivered as they
    /// are found via the `callback`.
    fn find_references(
        &self,
        program: &dyn Program,
        data_type: &dyn DataType,
        callback: &mut dyn FnMut(DataTypeReference),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Finds references in the current program to a specific field of the given `Composite`
    /// type in a manner appropriate with the given implementation.
    ///
    /// `field_name` mirrors Java's nullable `String` parameter: `None` means "match any field",
    /// matching Java's `null`.
    ///
    /// Note that this operation is multi-threaded and that results will be delivered as they
    /// are found via the `callback`.
    fn find_references_to_field(
        &self,
        program: &dyn Program,
        data_type: &dyn DataType,
        field_name: Option<&str>,
        callback: &mut dyn FnMut(DataTypeReference),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Finds references in the current program to a specific field of the given `Composite`
    /// type in a manner appropriate with the given implementation.
    ///
    /// The supplied field matcher is used to restrict matches to the given field. The matcher
    /// may be 'empty', supplying only the data type for which to search; in that case, all uses
    /// of the type are matched, regardless of field.
    ///
    /// Note that this operation is multi-threaded and that results will be delivered as they
    /// are found via the `callback`.
    fn find_references_with_matcher(
        &self,
        program: &dyn Program,
        field_matcher: &FieldMatcher,
        callback: &mut dyn FnMut(DataTypeReference),
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    struct MockDataType;

    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            "Foo".to_string()
        }
    }

    /// Stand-in implementation whose "hits" list mirrors what a real finder would discover by
    /// scanning a program: each entry is the field name (if any) a reference touches. Field
    /// filtering here mirrors the Java javadoc semantics: `None`/empty matcher matches every hit,
    /// `Some(name)` (or a non-ignored matcher) matches only hits with that field name.
    struct MockDataTypeReferenceFinder {
        hits: Vec<Option<&'static str>>,
    }

    impl DataTypeReferenceFinder for MockDataTypeReferenceFinder {
        fn find_references(
            &self,
            _program: &dyn Program,
            _data_type: &dyn DataType,
            callback: &mut dyn FnMut(DataTypeReference),
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            for _ in &self.hits {
                if monitor.is_cancelled() {
                    return Err(CancelledException::default());
                }
                callback(DataTypeReference);
            }
            Ok(())
        }

        fn find_references_to_field(
            &self,
            _program: &dyn Program,
            _data_type: &dyn DataType,
            field_name: Option<&str>,
            callback: &mut dyn FnMut(DataTypeReference),
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            for hit in &self.hits {
                if monitor.is_cancelled() {
                    return Err(CancelledException::default());
                }
                if field_name.is_none() || *hit == field_name {
                    callback(DataTypeReference);
                }
            }
            Ok(())
        }

        fn find_references_with_matcher(
            &self,
            _program: &dyn Program,
            field_matcher: &FieldMatcher,
            callback: &mut dyn FnMut(DataTypeReference),
            monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            for hit in &self.hits {
                if monitor.is_cancelled() {
                    return Err(CancelledException::default());
                }
                if field_matcher.is_ignored() || *hit == field_matcher.field_name.as_deref() {
                    callback(DataTypeReference);
                }
            }
            Ok(())
        }
    }

    #[test]
    fn find_references_delivers_every_hit_via_callback() {
        let finder = MockDataTypeReferenceFinder {
            hits: vec![Some("a"), None, Some("b")],
        };
        let program = MockProgram;
        let data_type = MockDataType;
        let monitor = crate::util::task::DummyMonitor;

        let mut count = 0;
        let result = finder.find_references(
            &program,
            &data_type,
            &mut |_r| count += 1,
            &monitor,
        );

        assert_eq!(result, Ok(()));
        assert_eq!(count, 3);
    }

    #[test]
    fn find_references_to_field_with_none_matches_every_hit() {
        let finder = MockDataTypeReferenceFinder {
            hits: vec![Some("a"), Some("b")],
        };
        let program = MockProgram;
        let data_type = MockDataType;
        let monitor = crate::util::task::DummyMonitor;

        let mut count = 0;
        finder
            .find_references_to_field(&program, &data_type, None, &mut |_r| count += 1, &monitor)
            .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn find_references_to_field_with_name_matches_only_that_field() {
        let finder = MockDataTypeReferenceFinder {
            hits: vec![Some("a"), Some("b"), Some("a")],
        };
        let program = MockProgram;
        let data_type = MockDataType;
        let monitor = crate::util::task::DummyMonitor;

        let mut count = 0;
        finder
            .find_references_to_field(
                &program,
                &data_type,
                Some("a"),
                &mut |_r| count += 1,
                &monitor,
            )
            .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn find_references_with_ignored_matcher_matches_every_hit() {
        let finder = MockDataTypeReferenceFinder {
            hits: vec![Some("a"), None],
        };
        let program = MockProgram;
        let matcher = FieldMatcher::default();
        let monitor = crate::util::task::DummyMonitor;

        let mut count = 0;
        finder
            .find_references_with_matcher(&program, &matcher, &mut |_r| count += 1, &monitor)
            .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn find_references_stops_and_errors_when_cancelled() {
        struct CancelledMonitor;
        impl TaskMonitor for CancelledMonitor {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(
                &self,
                _listener: Box<dyn crate::util::task::CancelledListener>,
            ) {
            }
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let finder = MockDataTypeReferenceFinder {
            hits: vec![Some("a")],
        };
        let program = MockProgram;
        let data_type = MockDataType;
        let monitor = CancelledMonitor;

        let result = finder.find_references(&program, &data_type, &mut |_r| {}, &monitor);

        assert_eq!(result, Err(CancelledException::default()));
    }
}
