/// Container for the parameters used when collecting function-start data to be mined.
///
/// Mirrors `ghidra.bitpatterns.info.DataGatheringParams`.
#[derive(Debug, Clone, Default)]
pub struct DataGatheringParams {
    num_pre_bytes: i32,
    num_first_bytes: i32,
    num_return_bytes: i32,
    num_pre_instructions: i32,
    num_first_instructions: i32,
    num_return_instructions: i32,
    context_registers: Vec<String>,
}

impl DataGatheringParams {
    /// Creates a new `DataGatheringParams` with all fields at their zero/empty defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of pre-bytes (bytes before a function start).
    pub fn get_num_pre_bytes(&self) -> i32 {
        self.num_pre_bytes
    }

    /// Sets the number of pre-bytes.
    pub fn set_num_pre_bytes(&mut self, pre_bytes: i32) {
        self.num_pre_bytes = pre_bytes;
    }

    /// Returns the number of first bytes (bytes at and immediately after a function start).
    pub fn get_num_first_bytes(&self) -> i32 {
        self.num_first_bytes
    }

    /// Sets the number of first bytes.
    pub fn set_num_first_bytes(&mut self, first_bytes: i32) {
        self.num_first_bytes = first_bytes;
    }

    /// Returns the number of return bytes (bytes at and immediately before a return instruction).
    pub fn get_num_return_bytes(&self) -> i32 {
        self.num_return_bytes
    }

    /// Sets the number of return bytes.
    pub fn set_num_return_bytes(&mut self, return_bytes: i32) {
        self.num_return_bytes = return_bytes;
    }

    /// Returns the number of pre-instructions (instructions immediately before a function start).
    pub fn get_num_pre_instructions(&self) -> i32 {
        self.num_pre_instructions
    }

    /// Sets the number of pre-instructions.
    pub fn set_num_pre_instructions(&mut self, pre_instructions: i32) {
        self.num_pre_instructions = pre_instructions;
    }

    /// Returns the number of first instructions (instructions at and after a function start).
    pub fn get_num_first_instructions(&self) -> i32 {
        self.num_first_instructions
    }

    /// Sets the number of first instructions.
    pub fn set_num_first_instructions(&mut self, first_instructions: i32) {
        self.num_first_instructions = first_instructions;
    }

    /// Returns the number of return instructions (instructions at and before a return instruction).
    pub fn get_num_return_instructions(&self) -> i32 {
        self.num_return_instructions
    }

    /// Sets the number of return instructions.
    pub fn set_num_return_instructions(&mut self, return_instructions: i32) {
        self.num_return_instructions = return_instructions;
    }

    /// Returns the list of context registers tracked during data gathering.
    pub fn get_context_registers(&self) -> &[String] {
        &self.context_registers
    }

    /// Sets the context registers to track during data gathering.
    pub fn set_context_registers(&mut self, regs: Vec<String>) {
        self.context_registers = regs;
    }

    /// Parses a list of context register names from a comma-separated string.
    ///
    /// Returns an empty list when the input is `None`, an empty string, or the
    /// literal string `"null"`. Each token is trimmed; blank tokens are skipped.
    /// It is assumed the input contains no duplicates.
    pub fn get_context_register_list(context_regs_csv: Option<&str>) -> Vec<String> {
        let csv = match context_regs_csv {
            None => return Vec::new(),
            Some(s) => s.trim(),
        };

        if csv.is_empty() || csv == "null" {
            return Vec::new();
        }

        csv.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_null_string() {
        let regs = DataGatheringParams::get_context_register_list(None);
        assert!(regs.is_empty());
    }

    #[test]
    fn test_empty_string() {
        let regs = DataGatheringParams::get_context_register_list(Some(""));
        assert!(regs.is_empty());
    }

    #[test]
    fn test_literal_null() {
        let regs = DataGatheringParams::get_context_register_list(Some("null"));
        assert!(regs.is_empty());
    }

    #[test]
    fn test_basic_csv() {
        let regs = DataGatheringParams::get_context_register_list(Some("reg1,reg2,reg3"));
        let set: HashSet<&str> = regs.iter().map(String::as_str).collect();
        assert_eq!(set.len(), 3);
        assert!(set.contains("reg1"));
        assert!(set.contains("reg2"));
        assert!(set.contains("reg3"));
    }

    #[test]
    fn test_empty_reg_name_skipped() {
        let regs = DataGatheringParams::get_context_register_list(Some("reg1, ,reg2"));
        let set: HashSet<&str> = regs.iter().map(String::as_str).collect();
        assert_eq!(set.len(), 2);
        assert!(set.contains("reg1"));
        assert!(set.contains("reg2"));
    }

    #[test]
    fn test_name_trimming() {
        let regs = DataGatheringParams::get_context_register_list(Some(" reg1, reg2 ,reg3 "));
        let set: HashSet<&str> = regs.iter().map(String::as_str).collect();
        assert_eq!(set.len(), 3);
        assert!(set.contains("reg1"));
        assert!(set.contains("reg2"));
        assert!(set.contains("reg3"));
    }

    #[test]
    fn test_getters_setters() {
        let mut params = DataGatheringParams::new();
        params.set_num_pre_bytes(4);
        params.set_num_first_bytes(8);
        params.set_num_return_bytes(6);
        params.set_num_pre_instructions(2);
        params.set_num_first_instructions(3);
        params.set_num_return_instructions(5);
        params.set_context_registers(vec!["TMode".to_string()]);

        assert_eq!(params.get_num_pre_bytes(), 4);
        assert_eq!(params.get_num_first_bytes(), 8);
        assert_eq!(params.get_num_return_bytes(), 6);
        assert_eq!(params.get_num_pre_instructions(), 2);
        assert_eq!(params.get_num_first_instructions(), 3);
        assert_eq!(params.get_num_return_instructions(), 5);
        assert_eq!(params.get_context_registers(), &["TMode"]);
    }

    #[test]
    fn test_default_is_zero() {
        let params = DataGatheringParams::default();
        assert_eq!(params.get_num_pre_bytes(), 0);
        assert_eq!(params.get_num_first_bytes(), 0);
        assert_eq!(params.get_num_return_bytes(), 0);
        assert_eq!(params.get_num_pre_instructions(), 0);
        assert_eq!(params.get_num_first_instructions(), 0);
        assert_eq!(params.get_num_return_instructions(), 0);
        assert!(params.get_context_registers().is_empty());
    }

    #[test]
    fn test_whitespace_only_csv_is_empty() {
        let regs = DataGatheringParams::get_context_register_list(Some("   "));
        assert!(regs.is_empty());
    }
}
