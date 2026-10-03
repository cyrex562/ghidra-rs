//! Port of `ghidra.feature.fid.service.FidPopulateResultReporter`.

use crate::feature::fid::service::fid_populate_result::FidPopulateResult;

/// Callback for reporting the outcome of a FID library populate operation.
///
/// Port of `ghidra.feature.fid.service.FidPopulateResultReporter`.
pub trait FidPopulateResultReporter {
    /// Java: `void report(FidPopulateResult result)`.
    fn report(&self, result: &FidPopulateResult);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::fid::db::library_record::LibraryRecord;
    use std::cell::RefCell;

    /// Minimal `LibraryRecord`, built the same way as
    /// [`crate::feature::fid::service::fid_populate_result`]'s own test helper: nothing here
    /// inspects its contents.
    fn library_record() -> LibraryRecord {
        use crate::framework::db::field::{Field, FieldType};
        use crate::framework::db::record::DBRecord;
        use crate::framework::db::schema::Schema;
        use std::sync::Arc;

        let schema = Arc::new(Schema::new(
            0,
            FieldType::Long,
            "Key".to_string(),
            vec![FieldType::String; 8],
            vec![
                "LibraryFamilyName".to_string(),
                "LibraryVersion".to_string(),
                "LibraryVariant".to_string(),
                "GhidraVersion".to_string(),
                "GhidraLanguageID".to_string(),
                "GhidraLanguageVersion".to_string(),
                "GhidraLanguageMinorVersion".to_string(),
                "GhidraCompilerSpecID".to_string(),
            ],
            vec![],
        ));
        let record = DBRecord::new(schema, Field::Long(Some(1)));
        LibraryRecord::new(record)
    }

    /// A reporter that records how many times, and with what totals, it was called -- enough to
    /// prove a caller can drive an arbitrary [`FidPopulateResultReporter`] implementor through the
    /// trait, mirroring how `DefaultFidPopulateResultReporter` (the only Java implementor, not yet
    /// ported) is invoked by `FidService`.
    struct RecordingReporter {
        calls: RefCell<Vec<(i32, i32)>>,
    }

    impl FidPopulateResultReporter for RecordingReporter {
        fn report(&self, result: &FidPopulateResult) {
            self.calls
                .borrow_mut()
                .push((result.get_total_added(), result.get_total_attempted()));
        }
    }

    #[test]
    fn report_is_invoked_with_the_supplied_result() {
        let reporter = RecordingReporter { calls: RefCell::new(Vec::new()) };
        let mut result = FidPopulateResult::new(library_record());
        result.disposition(
            None,
            "foo".to_string(),
            None,
            crate::feature::fid::service::fid_populate_result::Disposition::Included,
        );

        reporter.report(&result);

        assert_eq!(reporter.calls.borrow().as_slice(), &[(1, 1)]);
    }

    #[test]
    fn report_can_be_invoked_through_a_trait_object() {
        let reporter = RecordingReporter { calls: RefCell::new(Vec::new()) };
        let result = FidPopulateResult::new(library_record());

        let boxed: Box<dyn FidPopulateResultReporter> = Box::new(reporter);
        boxed.report(&result);
        // The trait object owns the recorder now; just confirm the call didn't panic and the
        // trait is object safe.
        let _ = boxed;
    }

    #[test]
    fn report_can_be_invoked_multiple_times() {
        let reporter = RecordingReporter { calls: RefCell::new(Vec::new()) };
        let result_a = FidPopulateResult::new(library_record());
        let result_b = FidPopulateResult::new(library_record());

        reporter.report(&result_a);
        reporter.report(&result_b);

        assert_eq!(reporter.calls.borrow().len(), 2);
    }
}
