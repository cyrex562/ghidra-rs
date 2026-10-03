use crate::framework::model::DomainObject;
use crate::program::seam_stubs::DomainObjectMergeManager;
use std::sync::Arc;

/// Port of `ghidra.program.database.GhidraProgramMultiUserMergeManagerFactory`.
///
/// The Java class overrides `ProgramMultiUserMergeManagerFactory.doGetMergeManager(...)` (a
/// pluggable-service factory hook) to build a `ProgramMultiUserMergeManager` for the four
/// `DomainObject`s (results/source/original/latest) involved in a multi-user merge. Modeled as a
/// trait (this class was selected as a cycle cut-point) so implementors can supply their own merge
/// manager construction without depending on the concrete `ProgramMultiUserMergeManager` (not yet
/// ported); the four `DomainObject` parameters mirror the overridden method's signature exactly
/// (the Java body's cast to `Program`/`ProgramDB` is an implementation detail of a given
/// `do_get_merge_manager` impl, not part of the abstract contract).
pub trait GhidraProgramMultiUserMergeManagerFactory {
    /// Stands in for the overridden `doGetMergeManager(DomainObject, DomainObject, DomainObject,
    /// DomainObject)`.
    fn do_get_merge_manager(
        &self,
        results_obj: Arc<dyn DomainObject>,
        source_obj: Arc<dyn DomainObject>,
        original_obj: Arc<dyn DomainObject>,
        latest_obj: Arc<dyn DomainObject>,
    ) -> Box<dyn DomainObjectMergeManager>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubDomainObject(&'static str);

    impl DomainObject for StubDomainObject {
        fn get_name(&self) -> String {
            self.0.to_string()
        }
    }

    struct RecordingMergeManager {
        results_name: String,
        source_name: String,
        original_name: String,
        latest_name: String,
    }

    impl DomainObjectMergeManager for RecordingMergeManager {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct MockFactory;

    impl GhidraProgramMultiUserMergeManagerFactory for MockFactory {
        fn do_get_merge_manager(
            &self,
            results_obj: Arc<dyn DomainObject>,
            source_obj: Arc<dyn DomainObject>,
            original_obj: Arc<dyn DomainObject>,
            latest_obj: Arc<dyn DomainObject>,
        ) -> Box<dyn DomainObjectMergeManager> {
            Box::new(RecordingMergeManager {
                results_name: results_obj.get_name(),
                source_name: source_obj.get_name(),
                original_name: original_obj.get_name(),
                latest_name: latest_obj.get_name(),
            })
        }
    }

    #[test]
    fn do_get_merge_manager_is_object_safe_and_receives_all_four_objects() {
        let factory: Box<dyn GhidraProgramMultiUserMergeManagerFactory> = Box::new(MockFactory);

        let results: Arc<dyn DomainObject> = Arc::new(StubDomainObject("results"));
        let source: Arc<dyn DomainObject> = Arc::new(StubDomainObject("source"));
        let original: Arc<dyn DomainObject> = Arc::new(StubDomainObject("original"));
        let latest: Arc<dyn DomainObject> = Arc::new(StubDomainObject("latest"));

        let manager = factory.do_get_merge_manager(results, source, original, latest);
        let recording = manager
            .as_any()
            .downcast_ref::<RecordingMergeManager>()
            .expect("expected RecordingMergeManager");

        assert_eq!(recording.results_name, "results");
        assert_eq!(recording.source_name, "source");
        assert_eq!(recording.original_name, "original");
        assert_eq!(recording.latest_name, "latest");
    }
}
