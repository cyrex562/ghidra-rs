/// Exception handler that captures the last error encountered during DEX-to-JAR translation.
///
/// Mirrors `ghidra.file.formats.android.dex.DexToJarExceptionHandler`.
#[derive(Debug, Default)]
pub struct DexToJarExceptionHandler {
    error: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl DexToJarExceptionHandler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an error raised while translating a method.
    pub fn handle_method_translate_exception(
        &mut self,
        error: Box<dyn std::error::Error + Send + Sync>,
    ) {
        self.error = Some(error);
    }

    /// Records an error raised while processing a file.
    pub fn handle_file_exception(&mut self, error: Box<dyn std::error::Error + Send + Sync>) {
        self.error = Some(error);
    }

    /// Returns the last captured error, if any.
    pub fn get_file_exception(&self) -> Option<&(dyn std::error::Error + Send + Sync)> {
        self.error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    #[derive(Debug)]
    struct TestError(String);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    fn make_err(msg: &str) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(TestError(msg.to_string()))
    }

    #[test]
    fn new_has_no_exception() {
        let h = DexToJarExceptionHandler::new();
        assert!(h.get_file_exception().is_none());
    }

    #[test]
    fn default_has_no_exception() {
        let h = DexToJarExceptionHandler::default();
        assert!(h.get_file_exception().is_none());
    }

    #[test]
    fn handle_file_exception_stores_error() {
        let mut h = DexToJarExceptionHandler::new();
        h.handle_file_exception(make_err("file error"));
        assert_eq!(h.get_file_exception().unwrap().to_string(), "file error");
    }

    #[test]
    fn handle_method_translate_exception_stores_error() {
        let mut h = DexToJarExceptionHandler::new();
        h.handle_method_translate_exception(make_err("method error"));
        assert_eq!(h.get_file_exception().unwrap().to_string(), "method error");
    }

    #[test]
    fn later_exception_overwrites_earlier() {
        let mut h = DexToJarExceptionHandler::new();
        h.handle_file_exception(make_err("first"));
        h.handle_method_translate_exception(make_err("second"));
        assert_eq!(h.get_file_exception().unwrap().to_string(), "second");
    }
}
