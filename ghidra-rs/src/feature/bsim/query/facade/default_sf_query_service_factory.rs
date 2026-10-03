//! Port of `ghidra.features.bsim.query.facade.DefaultSFQueryServiceFactory`.

use std::sync::{Arc, Mutex};

use crate::feature::bsim::query::facade::{SFQueryServiceFactory, SimilarFunctionQueryService};
use crate::program::model::listing::Program;

/// The default [`SFQueryServiceFactory`] implementation.
///
/// Port of `ghidra.features.bsim.query.facade.DefaultSFQueryServiceFactory`, a concrete class
/// extending [`SFQueryServiceFactory`] (an abstract class in Java, ported as a trait) and
/// implementing its one abstract method by constructing a plain [`SimilarFunctionQueryService`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultSFQueryServiceFactory;

impl SFQueryServiceFactory for DefaultSFQueryServiceFactory {
    /// Java: `createSFQueryService(Program program)`.
    fn create_sf_query_service(
        &self,
        program: Arc<Mutex<dyn Program>>,
    ) -> SimilarFunctionQueryService {
        SimilarFunctionQueryService::new(program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature::bsim::query::function_database::Status;
    use crate::framework::model::DomainObject;

    struct MockProgram;
    impl DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:32:default".to_string()
        }
    }

    fn mock_program() -> Arc<Mutex<dyn Program>> {
        Arc::new(Mutex::new(MockProgram))
    }

    #[test]
    fn creates_a_service_with_no_database_connected() {
        let factory = DefaultSFQueryServiceFactory;
        let service = factory.create_sf_query_service(mock_program());
        // A freshly constructed service has no database yet, matching
        // `new SimilarFunctionQueryService(program)`'s single-argument constructor.
        assert_eq!(service.get_database_status(), Status::Unconnected);
    }

    #[test]
    fn each_call_builds_an_independent_service() {
        let factory = DefaultSFQueryServiceFactory;
        let program = mock_program();
        let service_a = factory.create_sf_query_service(Arc::clone(&program));
        let service_b = factory.create_sf_query_service(Arc::clone(&program));
        assert_eq!(service_a.get_database_status(), Status::Unconnected);
        assert_eq!(service_b.get_database_status(), Status::Unconnected);
    }

    #[test]
    fn trait_object_is_usable() {
        let factory: Box<dyn SFQueryServiceFactory> = Box::new(DefaultSFQueryServiceFactory);
        let service = factory.create_sf_query_service(mock_program());
        assert_eq!(service.get_database_status(), Status::Unconnected);
    }
}
