use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use std::fmt;
use std::hash::{Hash, Hasher};

/// A basic implementation of [`CompilerSpecDescription`].
///
/// Port of `ghidra.program.model.lang.BasicCompilerSpecDescription`.
#[derive(Debug, Clone)]
pub struct BasicCompilerSpecDescription {
    id: CompilerSpecID,
    name: String,
}

impl BasicCompilerSpecDescription {
    /// Creates a new compiler spec description.
    pub fn new(id: CompilerSpecID, name: impl Into<String>) -> Self {
        BasicCompilerSpecDescription {
            id,
            name: name.into(),
        }
    }
}

impl CompilerSpecDescription for BasicCompilerSpecDescription {
    fn get_compiler_spec_id(&self) -> CompilerSpecID {
        self.id.clone()
    }

    fn get_compiler_spec_name(&self) -> String {
        self.name.clone()
    }

    fn get_source(&self) -> String {
        format!("{} {}", self.id, self.name)
    }
}

impl PartialEq for BasicCompilerSpecDescription {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for BasicCompilerSpecDescription {}

impl Hash for BasicCompilerSpecDescription {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl fmt::Display for BasicCompilerSpecDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_creates_instance() {
        let id = CompilerSpecID::new(Some("gcc"));
        let desc = BasicCompilerSpecDescription::new(id.clone(), "GCC");
        assert_eq!(desc.get_compiler_spec_id(), id);
        assert_eq!(desc.get_compiler_spec_name(), "GCC");
    }

    #[test]
    fn get_source_concatenates_id_and_name() {
        let id = CompilerSpecID::new(Some("msvc"));
        let desc = BasicCompilerSpecDescription::new(id, "Microsoft Visual C++");
        assert_eq!(desc.get_source(), "msvc Microsoft Visual C++");
    }

    #[test]
    fn to_string_returns_name() {
        let id = CompilerSpecID::new(Some("borlandcpp"));
        let desc = BasicCompilerSpecDescription::new(id, "Borland C++");
        assert_eq!(desc.to_string(), "Borland C++");
    }

    #[test]
    fn equality_based_on_id_only() {
        let id1 = CompilerSpecID::new(Some("gcc"));
        let desc1 = BasicCompilerSpecDescription::new(id1.clone(), "GCC Compiler");
        let desc2 = BasicCompilerSpecDescription::new(id1, "GNU Compiler Collection");
        assert_eq!(desc1, desc2);
    }

    #[test]
    fn inequality_when_ids_differ() {
        let id1 = CompilerSpecID::new(Some("gcc"));
        let id2 = CompilerSpecID::new(Some("clang"));
        let desc1 = BasicCompilerSpecDescription::new(id1, "GCC");
        let desc2 = BasicCompilerSpecDescription::new(id2, "GCC");
        assert_ne!(desc1, desc2);
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let id1 = CompilerSpecID::new(Some("gcc"));
        let id2 = CompilerSpecID::new(Some("gcc"));
        let desc1 = BasicCompilerSpecDescription::new(id1, "GCC");
        let desc2 = BasicCompilerSpecDescription::new(id2, "Different Name");

        let mut set = HashSet::new();
        set.insert(desc1);
        assert!(set.contains(&desc2));
    }

    #[test]
    fn clone_preserves_values() {
        let id = CompilerSpecID::new(Some("default"));
        let desc = BasicCompilerSpecDescription::new(id.clone(), "Default Compiler");
        let cloned = desc.clone();
        assert_eq!(cloned.get_compiler_spec_id(), id);
        assert_eq!(cloned.get_compiler_spec_name(), "Default Compiler");
    }

    #[test]
    fn implements_compiler_spec_description_trait() {
        let id = CompilerSpecID::new(Some("arm"));
        let desc = BasicCompilerSpecDescription::new(id, "ARM");
        let _: &dyn CompilerSpecDescription = &desc;
    }
}
