/// Information about an instruction entry in a processor manual.
///
/// Port of `ghidra.util.ManualEntry`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManualEntry {
    mnemonic: String,
    manual_path: String,
    missing_manual_description: String,
    page_number: String,
}

impl ManualEntry {
    /// Creates a new ManualEntry with the given details.
    pub fn new(
        mnemonic: String,
        manual_path: String,
        missing_manual_description: String,
        page_number: String,
    ) -> Self {
        Self {
            mnemonic,
            manual_path,
            missing_manual_description,
            page_number,
        }
    }

    /// Returns the instruction mnemonic.
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Returns the path to the instruction manual.
    pub fn manual_path(&self) -> &str {
        &self.manual_path
    }

    /// Returns a description for when the manual is missing.
    pub fn missing_manual_description(&self) -> &str {
        &self.missing_manual_description
    }

    /// Returns the page number in the manual.
    pub fn page_number(&self) -> &str {
        &self.page_number
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_and_getters() {
        let entry = ManualEntry::new(
            "ADD".to_string(),
            "Intel 64 Manual".to_string(),
            "Instruction not found in manual".to_string(),
            "123".to_string(),
        );
        assert_eq!(entry.mnemonic(), "ADD");
        assert_eq!(entry.manual_path(), "Intel 64 Manual");
        assert_eq!(
            entry.missing_manual_description(),
            "Instruction not found in manual"
        );
        assert_eq!(entry.page_number(), "123");
    }

    #[test]
    fn equality_same_values() {
        let entry1 = ManualEntry::new(
            "MOV".to_string(),
            "x86 Manual".to_string(),
            "Not found".to_string(),
            "456".to_string(),
        );
        let entry2 = ManualEntry::new(
            "MOV".to_string(),
            "x86 Manual".to_string(),
            "Not found".to_string(),
            "456".to_string(),
        );
        assert_eq!(entry1, entry2);
    }

    #[test]
    fn equality_different_mnemonic() {
        let entry1 = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        let entry2 = ManualEntry::new(
            "SUB".to_string(),
            "Manual".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        assert_ne!(entry1, entry2);
    }

    #[test]
    fn equality_different_manual_path() {
        let entry1 = ManualEntry::new(
            "ADD".to_string(),
            "Manual1".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        let entry2 = ManualEntry::new(
            "ADD".to_string(),
            "Manual2".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        assert_ne!(entry1, entry2);
    }

    #[test]
    fn equality_different_missing_description() {
        let entry1 = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found 1".to_string(),
            "1".to_string(),
        );
        let entry2 = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found 2".to_string(),
            "1".to_string(),
        );
        assert_ne!(entry1, entry2);
    }

    #[test]
    fn equality_different_page_number() {
        let entry1 = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        let entry2 = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found".to_string(),
            "2".to_string(),
        );
        assert_ne!(entry1, entry2);
    }

    #[test]
    fn clone() {
        let entry1 = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        let entry2 = entry1.clone();
        assert_eq!(entry1, entry2);
    }

    #[test]
    fn debug_format() {
        let entry = ManualEntry::new(
            "ADD".to_string(),
            "Manual".to_string(),
            "Not found".to_string(),
            "1".to_string(),
        );
        let debug_str = format!("{:?}", entry);
        assert!(debug_str.contains("ManualEntry"));
        assert!(debug_str.contains("ADD"));
    }
}
