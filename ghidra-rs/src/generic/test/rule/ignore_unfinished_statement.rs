use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct TODOException {
    message: String,
}

impl TODOException {
    pub fn new(message: String) -> Self {
        TODOException { message }
    }

    pub fn default_message() -> Self {
        TODOException {
            message: "TODO".to_string(),
        }
    }
}

impl fmt::Display for TODOException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for TODOException {}

#[derive(Debug, Clone)]
pub struct AssumptionViolatedException {
    message: String,
    cause: Option<Box<TODOException>>,
}

impl AssumptionViolatedException {
    pub fn new(message: String, cause: TODOException) -> Self {
        AssumptionViolatedException {
            message,
            cause: Some(Box::new(cause)),
        }
    }
}

impl fmt::Display for AssumptionViolatedException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for AssumptionViolatedException {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_ref().map(|e| e.as_ref() as &(dyn Error))
    }
}

/// A test statement that ignores `TODOException`.
///
/// This is the Rust equivalent of the JUnit `IgnoreUnfinishedStatement` class.
/// It wraps another statement (represented as a closure) and catches `TODOException`,
/// converting it to `AssumptionViolatedException` which test frameworks can handle as
/// a skipped test.
pub struct IgnoreUnfinishedStatement<F>
where
    F: FnMut() -> Result<(), Box<dyn Error>>,
{
    base: F,
}

impl<F> IgnoreUnfinishedStatement<F>
where
    F: FnMut() -> Result<(), Box<dyn Error>>,
{
    /// Construct the statement with a base closure.
    pub fn new(base: F) -> Self {
        IgnoreUnfinishedStatement { base }
    }

    /// Execute the statement, catching `TODOException` and converting it to `AssumptionViolatedException`.
    ///
    /// # Errors
    /// Returns an error if the base statement fails, or if a `TODOException` is caught
    /// (converted to `AssumptionViolatedException`).
    pub fn evaluate(&mut self) -> Result<(), Box<dyn Error>> {
        match (self.base)() {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(todo) = e.downcast_ref::<TODOException>() {
                    Err(Box::new(AssumptionViolatedException::new(
                        "Unfinished".to_string(),
                        todo.clone(),
                    )))
                } else {
                    Err(e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_successful_statement_passes() {
        let closure = || Ok(());
        let mut stmt = IgnoreUnfinishedStatement::new(closure);
        assert!(stmt.evaluate().is_ok());
    }

    #[test]
    fn test_todo_exception_converted() {
        let closure = || {
            Err::<(), _>(Box::new(TODOException::new(
                "Test TODO".to_string(),
            )) as Box<dyn Error>)
        };
        let mut stmt = IgnoreUnfinishedStatement::new(closure);
        let result = stmt.evaluate();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.downcast_ref::<AssumptionViolatedException>().is_some());
    }

    #[test]
    fn test_todo_exception_default_message() {
        let closure = || {
            Err::<(), _>(Box::new(TODOException::default_message()) as Box<dyn Error>)
        };
        let mut stmt = IgnoreUnfinishedStatement::new(closure);
        let result = stmt.evaluate();

        assert!(result.is_err());
        let err = result.unwrap_err();
        let assumption_err = err.downcast_ref::<AssumptionViolatedException>();
        assert!(assumption_err.is_some());
    }

    #[test]
    fn test_non_todo_exception_propagates() {
        let closure = || Err::<(), _>(Box::from("Some other error"));
        let mut stmt = IgnoreUnfinishedStatement::new(closure);
        let result = stmt.evaluate();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.downcast_ref::<AssumptionViolatedException>().is_none());
        assert_eq!(err.to_string(), "Some other error");
    }

    #[test]
    fn test_multiple_executions() {
        let counter = std::sync::Arc::new(std::sync::Mutex::new(0));
        let counter_clone = std::sync::Arc::clone(&counter);

        let closure = move || {
            *counter_clone.lock().unwrap() += 1;
            Ok(())
        };

        let mut stmt = IgnoreUnfinishedStatement::new(closure);
        assert!(stmt.evaluate().is_ok());
        assert_eq!(*counter.lock().unwrap(), 1);
    }
}
