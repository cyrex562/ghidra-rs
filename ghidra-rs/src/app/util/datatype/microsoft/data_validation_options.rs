/// Options controlling how validation is performed when determining whether to create data
/// structures at a particular location.
///
/// Mirrors `ghidra.app.util.datatype.microsoft.DataValidationOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataValidationOptions {
    pub validate_referred_to_data: bool,
    pub ignore_instructions: bool,
    pub ignore_defined_data: bool,
}

impl Default for DataValidationOptions {
    fn default() -> Self {
        Self {
            validate_referred_to_data: true,
            ignore_instructions: false,
            ignore_defined_data: true,
        }
    }
}

impl DataValidationOptions {
    /// Creates a `DataValidationOptions` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if structures should be validated for referred-to data.
    ///
    /// When `true`, data is only considered valid if its referred-to data is also valid.
    /// Default is `true`.
    pub fn should_validate_referred_to_data(&self) -> bool {
        self.validate_referred_to_data
    }

    /// Sets whether follow-on data referred to by the current structure should be validated.
    pub fn set_validate_referred_to_data(&mut self, validate_referred_to_data: bool) {
        self.validate_referred_to_data = validate_referred_to_data;
    }

    /// Returns `false` if existing instructions should cause new data creation to be invalid.
    ///
    /// Default is `false`.
    pub fn should_ignore_instructions(&self) -> bool {
        self.ignore_instructions
    }

    /// Sets whether existing instructions should invalidate the creation of new data.
    pub fn set_ignore_instructions(&mut self, ignore_instructions: bool) {
        self.ignore_instructions = ignore_instructions;
    }

    /// Returns `false` if existing defined data should cause new data creation to be invalid.
    ///
    /// Default is `true`.
    pub fn should_ignore_defined_data(&self) -> bool {
        self.ignore_defined_data
    }

    /// Sets whether existing defined data should invalidate the creation of new data.
    pub fn set_ignore_defined_data(&mut self, ignore_defined_data: bool) {
        self.ignore_defined_data = ignore_defined_data;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let opts = DataValidationOptions::new();
        assert!(opts.should_validate_referred_to_data());
        assert!(!opts.should_ignore_instructions());
        assert!(opts.should_ignore_defined_data());
    }

    #[test]
    fn test_clone_is_equal() {
        let opts = DataValidationOptions::new();
        let cloned = opts.clone();
        assert_eq!(opts, cloned);
    }

    #[test]
    fn test_setters() {
        let mut opts = DataValidationOptions::new();

        opts.set_validate_referred_to_data(false);
        assert!(!opts.should_validate_referred_to_data());

        opts.set_ignore_instructions(true);
        assert!(opts.should_ignore_instructions());

        opts.set_ignore_defined_data(false);
        assert!(!opts.should_ignore_defined_data());
    }

    #[test]
    fn test_clone_is_independent() {
        let original = DataValidationOptions::new();
        let mut copy = original.clone();
        copy.set_validate_referred_to_data(false);
        assert!(original.should_validate_referred_to_data());
        assert!(!copy.should_validate_referred_to_data());
    }

    #[test]
    fn test_debug() {
        let opts = DataValidationOptions::new();
        let s = format!("{:?}", opts);
        assert!(s.contains("DataValidationOptions"));
    }
}
