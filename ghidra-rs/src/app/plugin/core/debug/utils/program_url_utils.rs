use crate::program::model::listing::Program;

/// Utility for deriving a program's canonical Ghidra URL.
///
/// Port of `ghidra.app.plugin.core.debug.utils.ProgramURLUtils`. Java's enum-with-no-constants
/// idiom for a static-only utility class has no Rust equivalent, so this is a zero-sized struct
/// exposing associated functions, matching [`Msg`](crate::util::msg::Msg). Only
/// `getUrlFromProgram`, the one overload referenced by
/// [`InfoPerProgram`](crate::app::plugin::core::debug::service::modules::InfoPerProgram), is
/// ported; `isProjectDataURL`/`getDomainFileFromOpenProject`/`openDomainFileFromOpenProject` are
/// not needed yet. `java.net.URL` is represented as `String`, matching how this crate already
/// represents Ghidra URLs elsewhere.
pub struct ProgramURLUtils;

impl ProgramURLUtils {
    /// Get any URL for the given program, preferably its URL in a shared project.
    ///
    /// Returns `None` if the program does not belong to a project.
    pub fn get_url_from_program(program: &dyn Program) -> Option<String> {
        let file = program.get_domain_file()?;
        file.get_shared_project_url(None)
            .or_else(|| file.get_local_project_url(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_file::DomainFile;
    use crate::framework::model::domain_object::DomainObject;

    struct MockDomainFile {
        shared: Option<String>,
        local: Option<String>,
    }

    impl DomainFile for MockDomainFile {
        fn get_shared_project_url(&self, _reference: Option<&str>) -> Option<String> {
            self.shared.clone()
        }

        fn get_local_project_url(&self, _reference: Option<&str>) -> Option<String> {
            self.local.clone()
        }
    }

    struct MockProgram {
        file: Option<MockDomainFile>,
    }

    impl DomainObject for MockProgram {
        fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
            self.file.as_ref().map(|f| {
                Box::new(MockDomainFile {
                    shared: f.shared.clone(),
                    local: f.local.clone(),
                }) as Box<dyn DomainFile>
            })
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    #[test]
    fn prefers_shared_project_url_over_local() {
        let program = MockProgram {
            file: Some(MockDomainFile {
                shared: Some("ghidra://repo/shared".to_string()),
                local: Some("ghidra:/local".to_string()),
            }),
        };
        assert_eq!(
            ProgramURLUtils::get_url_from_program(&program),
            Some("ghidra://repo/shared".to_string())
        );
    }

    #[test]
    fn falls_back_to_local_project_url() {
        let program = MockProgram {
            file: Some(MockDomainFile {
                shared: None,
                local: Some("ghidra:/local".to_string()),
            }),
        };
        assert_eq!(
            ProgramURLUtils::get_url_from_program(&program),
            Some("ghidra:/local".to_string())
        );
    }

    #[test]
    fn returns_none_when_program_has_no_domain_file() {
        let program = MockProgram { file: None };
        assert_eq!(ProgramURLUtils::get_url_from_program(&program), None);
    }
}
