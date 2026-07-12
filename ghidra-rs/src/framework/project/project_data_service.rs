use crate::framework::model::ProjectData;

/// Interface for providing the ProjectData
///
/// Mirrors `ghidra.framework.project.ProjectDataService`.
///
/// This trait defines a service interface for accessing the project data
/// for the currently open project.
pub trait ProjectDataService {
    /// Returns the ProjectData for the currently open project.
    fn get_project_data(&self) -> Box<dyn ProjectData>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProjectData;
    impl ProjectData for MockProjectData {}

    struct MockProjectDataService;
    impl ProjectDataService for MockProjectDataService {
        fn get_project_data(&self) -> Box<dyn ProjectData> {
            Box::new(MockProjectData)
        }
    }

    #[test]
    fn get_project_data_returns_boxed_trait_object() {
        let service = MockProjectDataService;
        let data = service.get_project_data();
        assert_eq!(data.get_file_count(), -1);
    }

    #[test]
    fn trait_object_usable() {
        let service = MockProjectDataService;
        let service_obj: &dyn ProjectDataService = &service;
        let data = service_obj.get_project_data();
        assert!(data.get_root_folder().is_empty());
    }
}
