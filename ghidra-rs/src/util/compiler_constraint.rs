use crate::generic::constraint::constraint_data::ConstraintData;
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;
use crate::util::constraint::ProgramConstraint;
use crate::util::xml::xml_attribute_exception::XmlAttributeException;
use std::any::Any;

/// A constraint that checks if a program's compiler ID or compiler name matches.
///
/// Port of `ghidra.util.constraint.CompilerConstraint`.
pub struct CompilerConstraint {
    compiler_id: Option<String>,
    compiler_name: Option<String>,
}

impl CompilerConstraint {
    /// Creates a new CompilerConstraint with the default name.
    pub fn new() -> Self {
        Self {
            compiler_id: None,
            compiler_name: None,
        }
    }
}

impl Default for CompilerConstraint {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramConstraint for CompilerConstraint {
    fn name(&self) -> &str {
        "compiler"
    }

    fn is_satisfied(&self, program: &dyn Program) -> bool {
        if self.compiler_id.is_none() && self.compiler_name.is_none() {
            return false;
        }

        let mut satisfied = true;

        if let Some(compiler_id) = &self.compiler_id {
            let program_compiler_id = program
                .get_compiler_spec_id()
                .map(|id| id.get_id_as_string().to_string())
                .unwrap_or_default();
            satisfied &= *compiler_id == program_compiler_id;
        }

        if let Some(compiler_name) = &self.compiler_name {
            satisfied &= compiler_name.contains(&program.get_compiler());
        }

        satisfied
    }

    fn load_constraint_data(&mut self, data: &ConstraintData) {
        if data.has_value("id") {
            self.compiler_id = Some(data.get_string("id"));
        }

        if data.has_value("name") {
            self.compiler_name = Some(data.get_string("name"));
        }

        if self.compiler_id.is_none() && self.compiler_name.is_none() {
            panic!(
                "{}",
                XmlAttributeException::new("Missing both id and name attributes")
            );
        }
    }

    fn equals(&self, other: &dyn ProgramConstraint) -> bool {
        if let Some(other) = (other as &dyn Any).downcast_ref::<CompilerConstraint>() {
            self.compiler_id == other.compiler_id && self.compiler_name == other.compiler_name
        } else {
            false
        }
    }

    fn get_description(&self) -> String {
        format!(
            "compiler = {} compilerName = {}",
            self.compiler_id.as_deref().unwrap_or("null"),
            self.compiler_name.as_deref().unwrap_or("null")
        )
    }
}

impl ExtensionPoint for CompilerConstraint {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::lang::CompilerSpecID;
    use std::collections::HashMap;

    struct TestProgram {
        compiler: String,
        compiler_spec_id: Option<CompilerSpecID>,
    }

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }

        fn get_compiler(&self) -> String {
            self.compiler.clone()
        }

        fn get_compiler_spec_id(&self) -> Option<CompilerSpecID> {
            self.compiler_spec_id.clone()
        }
    }

    fn data(pairs: &[(&str, &str)]) -> ConstraintData {
        let mut map = HashMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v.to_string());
        }
        ConstraintData::new(map)
    }

    #[test]
    fn not_satisfied_when_neither_field_set() {
        let program = TestProgram {
            compiler: "GCC".to_string(),
            compiler_spec_id: Some(CompilerSpecID::new(Some("gcc"))),
        };
        let constraint = CompilerConstraint::new();
        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_when_id_matches() {
        let program = TestProgram {
            compiler: "GCC".to_string(),
            compiler_spec_id: Some(CompilerSpecID::new(Some("gcc"))),
        };
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("id", "gcc")]));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn not_satisfied_when_id_does_not_match() {
        let program = TestProgram {
            compiler: "GCC".to_string(),
            compiler_spec_id: Some(CompilerSpecID::new(Some("gcc"))),
        };
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("id", "borlandcpp")]));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_when_name_contains_program_compiler() {
        let program = TestProgram {
            compiler: "GCC".to_string(),
            compiler_spec_id: None,
        };
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("name", "some GCC variant")]));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn not_satisfied_when_name_does_not_contain_program_compiler() {
        let program = TestProgram {
            compiler: "MSVC".to_string(),
            compiler_spec_id: None,
        };
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("name", "some GCC variant")]));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_requires_both_when_both_set() {
        let program = TestProgram {
            compiler: "GCC".to_string(),
            compiler_spec_id: Some(CompilerSpecID::new(Some("borlandcpp"))),
        };
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("id", "gcc"), ("name", "some GCC variant")]));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    #[should_panic(expected = "Missing both id and name attributes")]
    fn load_constraint_data_panics_when_both_missing() {
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[]));
    }

    #[test]
    fn equals_same_fields() {
        let mut c1 = CompilerConstraint::new();
        let mut c2 = CompilerConstraint::new();
        c1.load_constraint_data(&data(&[("id", "gcc")]));
        c2.load_constraint_data(&data(&[("id", "gcc")]));

        assert!(c1.equals(&c2));
    }

    #[test]
    fn not_equals_different_fields() {
        let mut c1 = CompilerConstraint::new();
        let mut c2 = CompilerConstraint::new();
        c1.load_constraint_data(&data(&[("id", "gcc")]));
        c2.load_constraint_data(&data(&[("id", "borlandcpp")]));

        assert!(!c1.equals(&c2));
    }

    #[test]
    fn get_description_returns_formatted_string() {
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("id", "gcc"), ("name", "GNU C")]));

        assert_eq!(
            constraint.get_description(),
            "compiler = gcc compilerName = GNU C"
        );
    }

    #[test]
    fn get_description_shows_null_for_unset_field() {
        let mut constraint = CompilerConstraint::new();
        constraint.load_constraint_data(&data(&[("id", "gcc")]));

        assert_eq!(constraint.get_description(), "compiler = gcc compilerName = null");
    }

    #[test]
    fn name_is_correct() {
        let constraint = CompilerConstraint::new();
        assert_eq!(constraint.name(), "compiler");
    }
}
