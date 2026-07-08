use std::collections::HashMap;

use crate::program::model::lang::{Language, LanguageID};

/// Manages options and metadata for a trace.
///
/// Port of `ghidra.trace.model.TraceOptionsManager`.
///
/// This trait provides access to and modification of trace-level configuration including:
/// - Trace name
/// - Creation date (as milliseconds since Unix epoch)
/// - Base language and compiler specification
/// - Platform identifier
/// - Executable path
pub trait TraceOptionsManager {
    /// Returns all options as a map of string key-value pairs.
    fn as_map(&self) -> HashMap<String, String>;

    /// Sets the name of this trace.
    fn set_name(&mut self, name: String);

    /// Returns the name of this trace.
    fn get_name(&self) -> &str;

    /// Returns the creation date as milliseconds since Unix epoch.
    fn get_creation_date(&self) -> i64;

    /// Returns the base language of this trace.
    fn get_base_language(&self) -> Box<dyn Language>;

    /// Returns the base language ID of this trace.
    fn get_base_language_id(&self) -> &LanguageID;

    /// Returns the base language ID as a string.
    fn get_base_language_id_name(&self) -> &str;

    /// Sets the platform for this trace.
    fn set_platform(&mut self, platform: String);

    /// Returns the platform of this trace.
    fn get_platform(&self) -> &str;

    /// Sets the executable path for this trace.
    fn set_executable_path(&mut self, path: String);

    /// Returns the executable path of this trace.
    fn get_executable_path(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    struct MockLanguageID;

    impl MockLanguageID {
        fn new() -> LanguageID {
            LanguageID::new("test:LE:32:default").unwrap()
        }
    }

    struct MockLanguage;

    impl crate::program::model::lang::Language for MockLanguage {
        fn get_language_id(&self) -> LanguageID {
            MockLanguageID::new()
        }

        fn get_language_description(&self) -> Box<dyn crate::program::seam_stubs::LanguageDescription> {
            unimplemented!()
        }

        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>> {
            None
        }
    }

    struct MockTraceOptionsManager {
        name: String,
        creation_date: i64,
        base_language_id: LanguageID,
        platform: String,
        executable_path: String,
    }

    impl MockTraceOptionsManager {
        fn new() -> Self {
            Self {
                name: "test_trace".to_string(),
                creation_date: 1234567890000,
                base_language_id: MockLanguageID::new(),
                platform: "x86".to_string(),
                executable_path: "/bin/test".to_string(),
            }
        }
    }

    impl TraceOptionsManager for MockTraceOptionsManager {
        fn as_map(&self) -> HashMap<String, String> {
            let mut map = HashMap::new();
            map.insert("name".to_string(), self.name.clone());
            map.insert("creationDate".to_string(), self.creation_date.to_string());
            map.insert(
                "baseLanguageID".to_string(),
                self.base_language_id.get_id_as_string().to_string(),
            );
            map.insert("platform".to_string(), self.platform.clone());
            map.insert("executablePath".to_string(), self.executable_path.clone());
            map
        }

        fn set_name(&mut self, name: String) {
            self.name = name;
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_creation_date(&self) -> i64 {
            self.creation_date
        }

        fn get_base_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage)
        }

        fn get_base_language_id(&self) -> &LanguageID {
            &self.base_language_id
        }

        fn get_base_language_id_name(&self) -> &str {
            self.base_language_id.get_id_as_string()
        }

        fn set_platform(&mut self, platform: String) {
            self.platform = platform;
        }

        fn get_platform(&self) -> &str {
            &self.platform
        }

        fn set_executable_path(&mut self, path: String) {
            self.executable_path = path;
        }

        fn get_executable_path(&self) -> &str {
            &self.executable_path
        }
    }

    #[test]
    fn as_map_returns_all_options() {
        let manager = MockTraceOptionsManager::new();
        let map = manager.as_map();

        assert_eq!(map.get("name"), Some(&"test_trace".to_string()));
        assert_eq!(map.get("creationDate"), Some(&"1234567890000".to_string()));
        assert_eq!(
            map.get("baseLanguageID"),
            Some(&"test:LE:32:default".to_string())
        );
        assert_eq!(map.get("platform"), Some(&"x86".to_string()));
        assert_eq!(map.get("executablePath"), Some(&"/bin/test".to_string()));
    }

    #[test]
    fn set_name_updates_name() {
        let mut manager = MockTraceOptionsManager::new();
        assert_eq!(manager.get_name(), "test_trace");

        manager.set_name("updated_trace".to_string());
        assert_eq!(manager.get_name(), "updated_trace");
    }

    #[test]
    fn get_creation_date_returns_milliseconds() {
        let manager = MockTraceOptionsManager::new();
        assert_eq!(manager.get_creation_date(), 1234567890000);
    }

    #[test]
    fn get_base_language_returns_language() {
        let manager = MockTraceOptionsManager::new();
        let language = manager.get_base_language();
        assert_eq!(
            language.get_language_id().get_id_as_string(),
            "test:LE:32:default"
        );
    }

    #[test]
    fn get_base_language_id_returns_language_id() {
        let manager = MockTraceOptionsManager::new();
        assert_eq!(
            manager.get_base_language_id().get_id_as_string(),
            "test:LE:32:default"
        );
    }

    #[test]
    fn get_base_language_id_name_returns_string() {
        let manager = MockTraceOptionsManager::new();
        assert_eq!(
            manager.get_base_language_id_name(),
            "test:LE:32:default"
        );
    }

    #[test]
    fn set_platform_updates_platform() {
        let mut manager = MockTraceOptionsManager::new();
        assert_eq!(manager.get_platform(), "x86");

        manager.set_platform("arm".to_string());
        assert_eq!(manager.get_platform(), "arm");
    }

    #[test]
    fn set_executable_path_updates_path() {
        let mut manager = MockTraceOptionsManager::new();
        assert_eq!(manager.get_executable_path(), "/bin/test");

        manager.set_executable_path("/usr/bin/myapp".to_string());
        assert_eq!(manager.get_executable_path(), "/usr/bin/myapp");
    }

    #[test]
    fn as_map_reflects_after_set_name() {
        let mut manager = MockTraceOptionsManager::new();
        manager.set_name("new_name".to_string());

        let map = manager.as_map();
        assert_eq!(map.get("name"), Some(&"new_name".to_string()));
    }

    #[test]
    fn as_map_reflects_after_set_platform() {
        let mut manager = MockTraceOptionsManager::new();
        manager.set_platform("mips".to_string());

        let map = manager.as_map();
        assert_eq!(map.get("platform"), Some(&"mips".to_string()));
    }

    #[test]
    fn as_map_reflects_after_set_executable_path() {
        let mut manager = MockTraceOptionsManager::new();
        manager.set_executable_path("/path/to/binary".to_string());

        let map = manager.as_map();
        assert_eq!(
            map.get("executablePath"),
            Some(&"/path/to/binary".to_string())
        );
    }
}
