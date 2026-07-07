use std::collections::HashMap;

use super::{IsfObject, IsfWinPDB, IsfWinPE};

/// Represents an ISF Windows OS descriptor.
///
/// Mirrors `IsfWinOS` from Ghidra's `Debugger-isf` module. Aggregates a
/// [`IsfWinPE`] and [`IsfWinPDB`] constructed from the same metadata map.
pub struct IsfWinOS {
    pub pe: IsfWinPE,
    pub pdb: IsfWinPDB,
}

impl IsfWinOS {
    /// Creates a new `IsfWinOS` from the provided metadata map.
    ///
    /// Delegates directly to [`IsfWinPE::new`] and [`IsfWinPDB::new`].
    pub fn new(meta_data: &HashMap<String, String>) -> Self {
        Self {
            pe: IsfWinPE::new(meta_data),
            pdb: IsfWinPDB::new(meta_data),
        }
    }
}

impl IsfObject for IsfWinOS {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn constructs_pe_and_pdb_from_metadata() {
        let meta = make_map(&[
            ("PE Property[ProductVersion]", "10.0.19041.1"),
            ("PDB GUID", "A1B2C3D4-1234-5678-ABCD-EF0123456789"),
            ("PDB Age", "3"),
            ("PDB File", "ntdll.pdb"),
        ]);
        let os = IsfWinOS::new(&meta);
        assert_eq!(os.pe.major, Some(10));
        assert_eq!(os.pe.minor, Some(0));
        assert_eq!(os.pe.revision, Some(19041));
        assert_eq!(os.pe.build, Some(1));
        assert_eq!(os.pdb.guid.as_deref(), Some("A1B2C3D4-1234-5678-ABCD-EF0123456789"));
        assert_eq!(os.pdb.age, Some(3));
        assert_eq!(os.pdb.database.as_deref(), Some("ntdll.pdb"));
        assert_eq!(os.pdb.machine_type, 0);
    }

    #[test]
    fn empty_metadata_yields_none_fields() {
        let meta = HashMap::new();
        let os = IsfWinOS::new(&meta);
        assert_eq!(os.pe.major, None);
        assert_eq!(os.pe.minor, None);
        assert_eq!(os.pe.revision, None);
        assert_eq!(os.pe.build, None);
        assert_eq!(os.pdb.guid, None);
        assert_eq!(os.pdb.age, None);
        assert_eq!(os.pdb.database, None);
        assert_eq!(os.pdb.machine_type, 0);
    }

    #[test]
    fn partial_metadata_pe_only() {
        let meta = make_map(&[("PE Property[ProductVersion]", "6.1.7601.0")]);
        let os = IsfWinOS::new(&meta);
        assert_eq!(os.pe.major, Some(6));
        assert_eq!(os.pdb.guid, None);
    }

    #[test]
    fn partial_metadata_pdb_only() {
        let meta = make_map(&[("PDB GUID", "some-guid"), ("PDB Age", "1")]);
        let os = IsfWinOS::new(&meta);
        assert_eq!(os.pe.major, None);
        assert_eq!(os.pdb.guid.as_deref(), Some("some-guid"));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let meta = HashMap::new();
        let os = IsfWinOS::new(&meta);
        accepts_isf_object(&os);
    }
}
