use std::fmt;

/// Delimiter used by Ghidra external paths.
pub const EXTERNAL_PATH_DELIMITER: &str = "::";

/// Path to an external symbol, including library name and label.
///
/// This mirrors Ghidra's `ExternalPath`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalPath {
    elements: Vec<String>,
}

impl ExternalPath {
    /// Creates an external path from path elements.
    pub fn new<I, S>(elements: I) -> Result<Self, ExternalPathError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let elements: Vec<String> = elements.into_iter().map(Into::into).collect();

        if elements.iter().any(|element| element.is_empty()) {
            return Err(ExternalPathError::EmptyElement);
        }
        if elements.len() < 2 {
            return Err(ExternalPathError::TooFewElements);
        }

        Ok(Self { elements })
    }

    /// Returns the library name.
    pub fn library_name(&self) -> &str {
        &self.elements[0]
    }

    /// Returns the final label name.
    pub fn name(&self) -> &str {
        &self.elements[self.elements.len() - 1]
    }

    /// Returns a defensive copy of the path elements.
    pub fn path_elements(&self) -> Vec<String> {
        self.elements.clone()
    }

    /// Returns the path elements as borrowed strings.
    pub fn path_elements_ref(&self) -> &[String] {
        &self.elements
    }
}

impl fmt::Display for ExternalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.elements.join(EXTERNAL_PATH_DELIMITER))
    }
}

/// Error returned for invalid external paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalPathError {
    /// External paths must contain at least library and label.
    TooFewElements,
    /// External path elements cannot be empty.
    EmptyElement,
}

impl fmt::Display for ExternalPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewElements => {
                f.write_str("An external path must specify a library name and a label.")
            }
            Self::EmptyElement => {
                f.write_str("An external path cannot contain a null or empty string.")
            }
        }
    }
}

impl std::error::Error for ExternalPathError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_external_path_and_accesses_parts() {
        let path = ExternalPath::new(["libc.so", "printf"]).unwrap();

        assert_eq!(path.library_name(), "libc.so");
        assert_eq!(path.name(), "printf");
        assert_eq!(path.path_elements(), vec!["libc.so", "printf"]);
        assert_eq!(path.to_string(), "libc.so::printf");
    }

    #[test]
    fn supports_nested_path_elements() {
        let path = ExternalPath::new(["lib", "namespace", "symbol"]).unwrap();

        assert_eq!(path.library_name(), "lib");
        assert_eq!(path.name(), "symbol");
        assert_eq!(path.to_string(), "lib::namespace::symbol");
    }

    #[test]
    fn rejects_too_few_elements() {
        assert_eq!(
            ExternalPath::new(["lib"]).unwrap_err(),
            ExternalPathError::TooFewElements
        );
    }

    #[test]
    fn rejects_empty_elements() {
        assert_eq!(
            ExternalPath::new(["lib", ""]).unwrap_err(),
            ExternalPathError::EmptyElement
        );
    }

    #[test]
    fn path_elements_are_defensive_copy() {
        let path = ExternalPath::new(["lib", "name"]).unwrap();
        let mut elements = path.path_elements();
        elements[0] = "changed".to_string();

        assert_eq!(path.library_name(), "lib");
        assert_eq!(
            path.path_elements_ref(),
            &["lib".to_string(), "name".to_string()]
        );
    }
}
