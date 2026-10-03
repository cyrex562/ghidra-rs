use crate::util::error_logger::{DefaultErrorLogger, ErrorLogger};
use std::time::SystemTime;

/// A test runner that repeats its base closure 1 or more times.
///
/// This is the Rust equivalent of the JUnit `RepeatedStatement` class.
/// It runs a provided closure multiple times with logging, useful for
/// diagnosing non-deterministic test failures.
pub struct RepeatedStatement<F>
where
    F: FnMut() -> Result<(), Box<dyn std::error::Error>>,
{
    base: F,
    description: String,
    count: u32,
}

impl<F> RepeatedStatement<F>
where
    F: FnMut() -> Result<(), Box<dyn std::error::Error>>,
{
    /// Construct the statement.
    ///
    /// # Arguments
    /// * `base` - the base closure to repeat
    /// * `description` - the description of the test
    /// * `count` - the number of repetitions, must be positive
    ///
    /// # Errors
    /// Returns an error if count is not positive
    pub fn new(base: F, description: String, count: u32) -> Result<Self, String> {
        if count == 0 {
            return Err(
                "@Repeated count must be positive. To ignore a test. Use @Ignore".to_string(),
            );
        }
        Ok(RepeatedStatement {
            base,
            description,
            count,
        })
    }

    /// Execute the statement, running the base closure count times.
    ///
    /// If count > 1, logs debug information for each repetition.
    pub fn evaluate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let logger = DefaultErrorLogger;

        for i in 0..self.count {
            if self.count > 1 {
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| format!("{:?}", d))
                    .unwrap_or_else(|_| "unknown time".to_string());

                let msg = format!(
                    "{}\n  *** REPETITION {}/{} of {} ***",
                    now,
                    i + 1,
                    self.count,
                    self.description
                );
                logger.debug("RepeatedStatement", &msg);
            }
            (self.base)()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_positive_count_accepted() {
        let closure = || Ok(());
        let result = RepeatedStatement::new(closure, "test".to_string(), 1);
        assert!(result.is_ok());
    }

    #[test]
    fn test_positive_count_high() {
        let closure = || Ok(());
        let result = RepeatedStatement::new(closure, "test".to_string(), 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_zero_count_rejected() {
        let closure = || Ok(());
        let result = RepeatedStatement::new(closure, "test".to_string(), 0);
        match result {
            Err(msg) => assert_eq!(
                msg,
                "@Repeated count must be positive. To ignore a test. Use @Ignore"
            ),
            Ok(_) => panic!("expected zero count to be rejected"),
        }
    }

    #[test]
    fn test_evaluate_runs_closure_once() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);
        let closure = move || {
            *counter_clone.lock().unwrap() += 1;
            Ok(())
        };

        let mut stmt = RepeatedStatement::new(closure, "test".to_string(), 1).unwrap();
        stmt.evaluate().unwrap();

        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[test]
    fn test_evaluate_runs_closure_multiple_times() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);
        let closure = move || {
            *counter_clone.lock().unwrap() += 1;
            Ok(())
        };

        let mut stmt = RepeatedStatement::new(closure, "test".to_string(), 5).unwrap();
        stmt.evaluate().unwrap();

        assert_eq!(*counter.lock().unwrap(), 5);
    }

    #[test]
    fn test_evaluate_executes_high_repetition_count() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);
        let closure = move || {
            *counter_clone.lock().unwrap() += 1;
            Ok(())
        };

        let mut stmt = RepeatedStatement::new(closure, "test".to_string(), 100).unwrap();
        stmt.evaluate().unwrap();

        assert_eq!(*counter.lock().unwrap(), 100);
    }

    #[test]
    fn test_evaluate_propagates_errors() {
        let closure = || Err::<(), _>(Box::from("test error"));

        let mut stmt = RepeatedStatement::new(closure, "test".to_string(), 3).unwrap();
        let result = stmt.evaluate();

        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_stops_on_first_error() {
        let counter = Arc::new(Mutex::new(0));
        let counter_clone = Arc::clone(&counter);
        let closure = move || {
            let count = *counter_clone.lock().unwrap();
            *counter_clone.lock().unwrap() += 1;
            if count == 1 {
                Err::<(), _>(Box::from("error on second iteration"))
            } else {
                Ok(())
            }
        };

        let mut stmt = RepeatedStatement::new(closure, "test".to_string(), 5).unwrap();
        let result = stmt.evaluate();

        assert!(result.is_err());
        assert_eq!(*counter.lock().unwrap(), 2);
    }
}
