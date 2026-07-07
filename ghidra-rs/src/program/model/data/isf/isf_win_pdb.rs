use std::collections::HashMap;

use super::IsfObject;

/// Represents an ISF Windows PDB descriptor.
///
/// Mirrors `IsfWinPDB` from Ghidra's `Debugger-isf` module. Fields are
/// populated from a metadata map using the same keys as the Java constructor.
/// `machine_type` is always `0`; the Java source hardcoded this value with a
/// comment indicating "PDB Version" was the intended source but was never wired.
pub struct IsfWinPDB {
    pub guid: Option<String>,
    pub age: Option<i32>,
    pub database: Option<String>,
    pub machine_type: i32,
}

impl IsfWinPDB {
    /// Creates a new `IsfWinPDB` from the provided metadata map.
    ///
    /// Looks up `"PDB GUID"`, `"PDB Age"`, and `"PDB File"` in `meta_data`.
    /// `machine_type` is always `0`, matching the Java constructor's hardcoded
    /// value.
    pub fn new(meta_data: &HashMap<String, String>) -> Self {
        let age = meta_data
            .get("PDB Age")
            .and_then(|s| s.parse::<i32>().ok());
        Self {
            guid: meta_data.get("PDB GUID").cloned(),
            age,
            database: meta_data.get("PDB File").cloned(),
            machine_type: 0,
        }
    }
}

impl IsfObject for IsfWinPDB {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn fields_extracted_from_metadata() {
        let meta = make_map(&[
            ("PDB GUID", "A1B2C3D4-1234-5678-ABCD-EF0123456789"),
            ("PDB Age", "3"),
            ("PDB File", "ntdll.pdb"),
        ]);
        let pdb = IsfWinPDB::new(&meta);
        assert_eq!(pdb.guid.as_deref(), Some("A1B2C3D4-1234-5678-ABCD-EF0123456789"));
        assert_eq!(pdb.age, Some(3));
        assert_eq!(pdb.database.as_deref(), Some("ntdll.pdb"));
    }

    #[test]
    fn machine_type_is_always_zero() {
        let meta = make_map(&[
            ("PDB GUID", "guid"),
            ("PDB Age", "1"),
            ("PDB File", "foo.pdb"),
        ]);
        let pdb = IsfWinPDB::new(&meta);
        assert_eq!(pdb.machine_type, 0);
    }

    #[test]
    fn missing_keys_yield_none() {
        let meta = HashMap::new();
        let pdb = IsfWinPDB::new(&meta);
        assert_eq!(pdb.guid, None);
        assert_eq!(pdb.age, None);
        assert_eq!(pdb.database, None);
        assert_eq!(pdb.machine_type, 0);
    }

    #[test]
    fn invalid_age_yields_none() {
        let meta = make_map(&[("PDB Age", "not_a_number")]);
        let pdb = IsfWinPDB::new(&meta);
        assert_eq!(pdb.age, None);
    }

    #[test]
    fn age_zero_is_valid() {
        let meta = make_map(&[("PDB Age", "0")]);
        let pdb = IsfWinPDB::new(&meta);
        assert_eq!(pdb.age, Some(0));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let meta = HashMap::new();
        let pdb = IsfWinPDB::new(&meta);
        accepts_isf_object(&pdb);
    }
}
