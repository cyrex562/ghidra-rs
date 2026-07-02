use crate::util::CharsetInfo;

/// A table row containing charset information and associated Unicode scripts.
///
/// Port of `ghidra.util.charset.picker.CharsetTableRow`, a record type with two fields:
/// - `csi`: The charset information object.
/// - `scripts`: A string representing the Unicode scripts supported by this charset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CharsetTableRow {
    /// The charset information for this row.
    pub csi: CharsetInfo,
    /// String representation of the Unicode scripts supported by this charset.
    pub scripts: String,
}

impl CharsetTableRow {
    /// Creates a new `CharsetTableRow` with the given charset info and scripts.
    pub fn new(csi: CharsetInfo, scripts: String) -> Self {
        Self { csi, scripts }
    }

    /// Returns a reference to the charset information.
    pub fn csi(&self) -> &CharsetInfo {
        &self.csi
    }

    /// Returns a reference to the scripts string.
    pub fn scripts(&self) -> &str {
        &self.scripts
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};
    use super::*;

    #[test]
    fn create_charset_table_row() {
        let csi = CharsetInfo::new(
            "UTF-8",
            Some("UTF-8 (Unicode)".to_string()),
            1,
            4,
            1,
            0,
            false,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        let scripts = "Latin Common".to_string();

        let row = CharsetTableRow::new(csi.clone(), scripts.clone());

        assert_eq!(*row.csi(), &csi);
        assert_eq!(row.scripts(), "Latin Common");
    }

    #[test]
    fn charset_table_row_fields_accessible() {
        let csi = CharsetInfo::new(
            "ISO-8859-1",
            None,
            1,
            1,
            1,
            0,
            false,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        let scripts = "Latin Greek".to_string();

        let row = CharsetTableRow::new(csi.clone(), scripts);

        assert_eq!(row.csi.name(), "ISO-8859-1");
        assert_eq!(row.scripts, "Latin Greek");
    }

    #[test]
    fn charset_table_row_equality() {
        let csi1 = CharsetInfo::new(
            "UTF-16",
            Some("UTF-16 (Unicode)".to_string()),
            2,
            4,
            2,
            0,
            false,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        let csi2 = csi1.clone();

        let row1 = CharsetTableRow::new(csi1, "Common".to_string());
        let row2 = CharsetTableRow::new(csi2, "Common".to_string());

        assert_eq!(row1, row2);
    }

    #[test]
    fn charset_table_row_inequality() {
        let csi1 = CharsetInfo::from_charset_name("UTF-8");
        let csi2 = CharsetInfo::from_charset_name("UTF-16");

        let row1 = CharsetTableRow::new(csi1, "Scripts1".to_string());
        let row2 = CharsetTableRow::new(csi2, "Scripts1".to_string());

        assert_ne!(row1, row2);
    }

    #[test]
    fn charset_table_row_clone() {
        let csi = CharsetInfo::new(
            "ASCII",
            Some("ASCII".to_string()),
            1,
            1,
            1,
            0,
            false,
            false,
            BTreeSet::new(),
            HashSet::new(),
        );
        let scripts = "Latin".to_string();

        let row1 = CharsetTableRow::new(csi, scripts);
        let row2 = row1.clone();

        assert_eq!(row1, row2);
    }
}
