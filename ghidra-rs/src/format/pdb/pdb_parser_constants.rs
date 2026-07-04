/// Option key which indicates if PDB has been loaded/applied to program (Boolean).
pub const PDB_LOADED: &str = "PDB Loaded";

/// Option key which indicates PDB filename or path as specified by loaded program (String).
pub const PDB_FILE: &str = "PDB File";

/// Option key which indicates PDB Age as specified by loaded program (String, hex value without 0x prefix).
pub const PDB_AGE: &str = "PDB Age";

/// Option key which indicates PDB Signature as specified by loaded program (String).
pub const PDB_SIGNATURE: &str = "PDB Signature";

/// Option key which indicates PDB Version as specified by loaded program (String).
pub const PDB_VERSION: &str = "PDB Version";

/// Option key which indicates PDB GUID as specified by loaded program (String).
pub const PDB_GUID: &str = "PDB GUID";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_values_match_java_source() {
        assert_eq!(PDB_LOADED, "PDB Loaded");
        assert_eq!(PDB_FILE, "PDB File");
        assert_eq!(PDB_AGE, "PDB Age");
        assert_eq!(PDB_SIGNATURE, "PDB Signature");
        assert_eq!(PDB_VERSION, "PDB Version");
        assert_eq!(PDB_GUID, "PDB GUID");
    }

    #[test]
    fn constants_are_distinct() {
        let values = [PDB_LOADED, PDB_FILE, PDB_AGE, PDB_SIGNATURE, PDB_VERSION, PDB_GUID];
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j], "duplicate constant values");
            }
        }
    }
}
