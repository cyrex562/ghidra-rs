use crate::generic::constraint::constraint_data::ConstraintData;
use crate::program::model::listing::Program;
use crate::util::classfinder::ExtensionPoint;
use crate::util::constraint::ProgramConstraint;
use std::any::Any;

/// A constraint that checks if a program's language ID matches a specified pattern.
///
/// The pattern supports wildcards ("*") for individual language ID components.
/// For example, "x86:LE:*:default" would match any 64-bit or 32-bit x86 LE variant.
///
/// Port of `ghidra.util.constraint.LanguageConstraint`.
pub struct LanguageConstraint {
    language_id: String,
}

impl LanguageConstraint {
    /// Creates a new LanguageConstraint with the default name.
    pub fn new() -> Self {
        Self {
            language_id: String::new(),
        }
    }
}

impl Default for LanguageConstraint {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramConstraint for LanguageConstraint {
    fn name(&self) -> &str {
        "language"
    }

    fn is_satisfied(&self, program: &dyn Program) -> bool {
        let program_lang_id = program.get_language_id();

        let mut pattern_tokens = self.language_id.split(':').peekable();
        let mut program_tokens = program_lang_id.split(':').peekable();

        while pattern_tokens.peek().is_some() || program_tokens.peek().is_some() {
            if pattern_tokens.peek().is_none() || program_tokens.peek().is_none() {
                return false;
            }

            let pattern_token = pattern_tokens.next().unwrap_or("");
            let program_token = program_tokens.next().unwrap_or("");

            if pattern_token == "*" {
                continue;
            }

            if pattern_token != program_token {
                return false;
            }
        }

        true
    }

    fn load_constraint_data(&mut self, data: &ConstraintData) {
        self.language_id = data.get_string("id");
    }

    fn equals(&self, other: &dyn ProgramConstraint) -> bool {
        if let Some(other) = (other as &dyn Any).downcast_ref::<LanguageConstraint>() {
            self.language_id == other.language_id
        } else {
            false
        }
    }

    fn get_description(&self) -> String {
        format!("languageID = {}", self.language_id)
    }
}

impl ExtensionPoint for LanguageConstraint {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct TestProgram {
        language_id: String,
    }

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test_program".to_string()
        }

        fn get_language_id(&self) -> String {
            self.language_id.clone()
        }

        fn get_executable_format(&self) -> String {
            String::new()
        }
    }

    #[test]
    fn is_satisfied_when_language_id_matches_exactly() {
        let program = TestProgram {
            language_id: "x86:LE:64:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:LE:64:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn not_satisfied_when_language_id_does_not_match() {
        let program = TestProgram {
            language_id: "x86:LE:64:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "ARM:LE:32:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_with_wildcard_at_end() {
        let program = TestProgram {
            language_id: "x86:LE:64:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:LE:*:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_with_wildcard_in_middle() {
        let program = TestProgram {
            language_id: "x86:LE:64:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:*:64:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_with_multiple_wildcards() {
        let program = TestProgram {
            language_id: "x86:LE:64:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:*:*:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn not_satisfied_when_token_count_differs() {
        let program = TestProgram {
            language_id: "x86:LE:64:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:LE:64".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn not_satisfied_when_pattern_has_more_tokens() {
        let program = TestProgram {
            language_id: "x86:LE".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:LE:64:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(!constraint.is_satisfied(&program));
    }

    #[test]
    fn is_satisfied_when_both_empty() {
        let program = TestProgram {
            language_id: String::new(),
        };
        let mut constraint = LanguageConstraint::new();
        let data = HashMap::new();
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }

    #[test]
    fn equals_same_language_id() {
        let mut c1 = LanguageConstraint::new();
        let mut c2 = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:LE:64:default".to_string());
        c1.load_constraint_data(&ConstraintData::new(data.clone()));
        c2.load_constraint_data(&ConstraintData::new(data));

        assert!(c1.equals(&c2));
    }

    #[test]
    fn not_equals_different_language_id() {
        let mut c1 = LanguageConstraint::new();
        let mut c2 = LanguageConstraint::new();
        let mut data1 = HashMap::new();
        data1.insert("id".to_string(), "x86:LE:64:default".to_string());
        let mut data2 = HashMap::new();
        data2.insert("id".to_string(), "ARM:LE:32:default".to_string());
        c1.load_constraint_data(&ConstraintData::new(data1));
        c2.load_constraint_data(&ConstraintData::new(data2));

        assert!(!c1.equals(&c2));
    }

    #[test]
    fn equals_same_pattern_with_wildcard() {
        let mut c1 = LanguageConstraint::new();
        let mut c2 = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:*:64:default".to_string());
        c1.load_constraint_data(&ConstraintData::new(data.clone()));
        c2.load_constraint_data(&ConstraintData::new(data));

        assert!(c1.equals(&c2));
    }

    #[test]
    fn get_description_returns_formatted_string() {
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "x86:LE:64:default".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        let desc = constraint.get_description();
        assert_eq!(desc, "languageID = x86:LE:64:default");
    }

    #[test]
    fn name_is_correct() {
        let constraint = LanguageConstraint::new();
        assert_eq!(constraint.name(), "language");
    }

    #[test]
    fn arm_32_bit_matches_wildcard_pattern() {
        let program = TestProgram {
            language_id: "ARM:LE:32:default".to_string(),
        };
        let mut constraint = LanguageConstraint::new();
        let mut data = HashMap::new();
        data.insert("id".to_string(), "ARM:*:*:*".to_string());
        constraint.load_constraint_data(&ConstraintData::new(data));

        assert!(constraint.is_satisfied(&program));
    }
}
