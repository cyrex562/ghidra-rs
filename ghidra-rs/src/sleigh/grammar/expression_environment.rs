/// Environment for evaluating Sleigh preprocessor expressions.
///
/// Mirrors `ghidra.sleigh.grammar.ExpressionEnvironment`, a Java interface used by
/// the Sleigh grammar to resolve variable values and report errors during expression
/// evaluation.
pub trait ExpressionEnvironment {
    /// Return the value of a named variable, or an empty string if undefined.
    fn lookup(&self, variable: &str) -> String;

    /// Return `true` if `lhs` and `rhs` represent the same value in this environment.
    fn equals(&self, lhs: &str, rhs: &str) -> bool;

    /// Report a non-fatal evaluation error.
    fn report_error(&self, msg: &str);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct TestEnv {
        errors: RefCell<Vec<String>>,
    }

    impl TestEnv {
        fn new() -> Self {
            Self { errors: RefCell::new(Vec::new()) }
        }
    }

    impl ExpressionEnvironment for TestEnv {
        fn lookup(&self, variable: &str) -> String {
            match variable {
                "FOO" => "bar".to_string(),
                _ => String::new(),
            }
        }

        fn equals(&self, lhs: &str, rhs: &str) -> bool {
            self.lookup(lhs) == self.lookup(rhs)
        }

        fn report_error(&self, msg: &str) {
            self.errors.borrow_mut().push(msg.to_string());
        }
    }

    #[test]
    fn lookup_known_variable() {
        let env = TestEnv::new();
        assert_eq!(env.lookup("FOO"), "bar");
    }

    #[test]
    fn lookup_unknown_variable_returns_empty() {
        let env = TestEnv::new();
        assert_eq!(env.lookup("UNDEFINED"), "");
    }

    #[test]
    fn equals_same_resolved_value() {
        let env = TestEnv::new();
        assert!(env.equals("FOO", "FOO"));
    }

    #[test]
    fn equals_different_resolved_values() {
        let env = TestEnv::new();
        assert!(!env.equals("FOO", "UNDEFINED"));
    }

    #[test]
    fn report_error_collects_messages() {
        let env = TestEnv::new();
        env.report_error("something went wrong");
        env.report_error("another error");
        let errs = env.errors.borrow();
        assert_eq!(errs.len(), 2);
        assert_eq!(errs[0], "something went wrong");
        assert_eq!(errs[1], "another error");
    }
}
