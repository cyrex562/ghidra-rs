//! Port of `ghidra.features.bsim.query.facade.SFQueryServiceFactory`.

use std::sync::{Arc, Mutex};

use crate::feature::bsim::query::facade::SimilarFunctionQueryService;
use crate::program::model::listing::Program;

/// Factory for [`SimilarFunctionQueryService`]s.
///
/// Port of `ghidra.features.bsim.query.facade.SFQueryServiceFactory`, an abstract class with one
/// abstract method.
pub trait SFQueryServiceFactory {
    /// Java: `abstract SimilarFunctionQueryService createSFQueryService(Program program)`.
    fn create_sf_query_service(
        &self,
        program: Arc<Mutex<dyn Program>>,
    ) -> SimilarFunctionQueryService;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct DefaultFactory;
    impl SFQueryServiceFactory for DefaultFactory {
        fn create_sf_query_service(
            &self,
            program: Arc<Mutex<dyn Program>>,
        ) -> SimilarFunctionQueryService {
            SimilarFunctionQueryService::new(program)
        }
    }

    #[test]
    fn factory_builds_a_service_for_the_given_program() {
        let program: Arc<Mutex<dyn Program>> = Arc::new(Mutex::new(MockProgram));
        let factory = DefaultFactory;
        let service = factory.create_sf_query_service(Arc::clone(&program));
        assert_eq!(service.get_database_status(), crate::feature::bsim::query::function_database::Status::Unconnected);
    }

    #[test]
    fn trait_is_object_safe() {
        let factory: Box<dyn SFQueryServiceFactory> = Box::new(DefaultFactory);
        let program: Arc<Mutex<dyn Program>> = Arc::new(Mutex::new(MockProgram));
        let _service = factory.create_sf_query_service(program);
    }
}
