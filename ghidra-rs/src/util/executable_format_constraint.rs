use crate::generic::constraint::constraint_data::ConstraintData;
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;
use crate::util::constraint::ProgramConstraint;
use std::any::Any;

/// A constraint that checks if a program's executable format matches a specified format.
///
/// Port of `ghidra.util.constraint.ExecutableFormatConstraint`.
pub struct ExecutableFormatConstraint {
    executable_format: String,
}

impl ExecutableFormatConstraint {
    /// Creates a new ExecutableFormatConstraint with the default name.
    pub fn new() -> Self {
        Self {
            executable_format: String::new(),
        }
    }
}

impl Default for ExecutableFormatConstraint {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramConstraint for ExecutableFormatConstraint {
    fn name(&self) -> &str {
        "executable_format"
    }

    fn is_satisfied(&self, program: &dyn Program) -> bool {
        let format = program.get_executable_format();
        let format = if format.is_empty() { "" } else { &format };
        self.executable_format == format
    }

    fn load_constraint_data(&mut self, data: &ConstraintData) {
        self.executable_format = data.get_string("name");
    }

    fn equals(&self, other: &dyn ProgramConstraint) -> bool {
        if let Some(other) = (other as &dyn Any).downcast_ref::<ExecutableFormatConstraint>() {
            self.executable_format == other.executable_format
        } else {
            false
        }
    }

    fn get_description(&self) -> String {
        format!("executableFormat = {}", self.executable_format)
    }
}

impl ExtensionPoint for ExecutableFormatConstraint {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestProgram {
        executable_format: String,
    }

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }

        fn get_executable_format(&self) -> String {
            self.executable_format.clone()
        }
    }

    #[test]
    fn is_satisfied_when_format_matches() {
        let program = TestProgram {
            executable_format: "ELF".to_string(),
        };
        let mut constraint = ExecutableFormatConstraint::new();
        let mut data = HashMap::new();
        data.insert("name".to_string(), "ELF".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn not_satisfied_when_format_does_not_match() {
        let program = TestProgram {
            executable_format: "ELF".to_string(),
        };
        let mut constraint = ExecutableFormatConstraint::new();
        let mut data = HashMap::new();
        data.insert("name".to_string(), "PE".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_when_both_empty() {
        let program = TestProgram {
            executable_format: String::new(),
        };
        let mut constraint = ExecutableFormatConstraint::new();
        let data = HashMap::new();
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn equals_same_format() {
        let mut c1 = ExecutableFormatConstraint::new();
        let mut c2 = ExecutableFormatConstraint::new();
        let mut data = HashMap::new();
        data.insert("name".to_string(), "ELF".to_string());
        c1.load_constraint_data(&ConstraintData::new(data.clone()));
        c2.load_constraint_data(&ConstraintData::new(data));

        assert!(c1.equals(&c2));
    }

    #[test]
    fn not_equals_different_format() {
        let mut c1 = ExecutableFormatConstraint::new();
        let mut c2 = ExecutableFormatConstraint::new();
        let mut data1 = HashMap::new();
        data1.insert("name".to_string(), "ELF".to_string());
        let mut data2 = HashMap::new();
        data2.insert("name".to_string(), "PE".to_string());
        c1.load_constraint_data(&ConstraintData::new(data1));
        c2.load_constraint_data(&ConstraintData::new(data2));

        assert!(!c1.equals(&c2));
    }

    #[test]
    fn get_description_returns_formatted_string() {
        let mut constraint = ExecutableFormatConstraint::new();
        let mut data = HashMap::new();
        data.insert("name".to_string(), "ELF".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        let desc = constraint.get_description();
        assert_eq!(desc, "executableFormat = ELF");
    }

    #[test]
    fn name_is_correct() {
        let constraint = ExecutableFormatConstraint::new();
        assert_eq!(constraint.name(), "executable_format");
    }
}
