use crate::program::model::data::isf::IsfObject;
use crate::program::model::reloc::Relocation;

/// Represents an extended relocation for SARIF export.
///
/// Mirrors `ExtRelocation` from Ghidra's `sarif.export.relocs` package. Fields are
/// extracted from a [`Relocation`] with non-empty values populated as `Option<String>`.
pub struct ExtRelocation {
    pub name: Option<String>,
    pub kind: String,
    pub value: String,
    pub bytes: Option<String>,
}

impl ExtRelocation {
    /// Creates a new `ExtRelocation` from a [`Relocation`].
    ///
    /// The `kind` field is always populated from the relocation's type as a string.
    /// The `value` field contains packed relocation values (empty string if none).
    /// The `bytes` field is populated from packed bytes if present.
    /// The `name` field is populated from the symbol name if not empty.
    pub fn new(reloc: &Relocation) -> Self {
        let kind = reloc.type_().to_string();
        let value = Self::pack_values(reloc.values());
        let bytes = reloc.bytes().and_then(Self::pack_bytes);
        let name = reloc.symbol_name().and_then(|sym| {
            if !sym.is_empty() {
                Some(sym.to_string())
            } else {
                None
            }
        });

        Self { name, kind, value, bytes }
    }

    fn pack_values(values: &[i64]) -> String {
        if values.is_empty() {
            return String::new();
        }
        values
            .iter()
            .map(|v| format!("0x{:x}", v))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn pack_bytes(bytes: &[u8]) -> Option<String> {
        if bytes.is_empty() {
            return None;
        }
        let packed = bytes
            .iter()
            .map(|b| format!("0x{:x}", b))
            .collect::<Vec<_>>()
            .join(",");
        Some(packed)
    }
}

impl IsfObject for ExtRelocation {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::reloc::RelocationStatus;

    fn test_address(offset: i64) -> crate::program::model::address::Address {
        let space = AddressSpace::new("RAM", 32, 1, AddressSpaceType::Ram, 0);
        space.address(offset)
    }

    #[test]
    fn extracts_type_as_kind() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            42,
            vec![],
            None,
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.kind, "42");
    }

    #[test]
    fn packs_values_with_hex_format() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![0x1000, 0x2000, 0xffff],
            None,
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.value, "0x1000,0x2000,0xffff");
    }

    #[test]
    fn empty_values_yields_empty_string() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            None,
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.value, "");
    }

    #[test]
    fn packs_bytes_with_hex_format() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            Some(vec![0xde, 0xad, 0xbe, 0xef]),
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.bytes, Some("0xde,0xad,0xbe,0xef".to_string()));
    }

    #[test]
    fn empty_bytes_yields_none() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            Some(vec![]),
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.bytes, None);
    }

    #[test]
    fn no_bytes_yields_none() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            None,
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.bytes, None);
    }

    #[test]
    fn extracts_symbol_name() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            None,
            Some("main".to_string()),
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.name, Some("main".to_string()));
    }

    #[test]
    fn empty_symbol_name_yields_none() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            None,
            Some("".to_string()),
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.name, None);
    }

    #[test]
    fn no_symbol_name_yields_none() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            None,
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.name, None);
    }

    #[test]
    fn all_fields_populated() {
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            5,
            vec![0x100, 0x200],
            Some(vec![0x01, 0x02, 0x03]),
            Some("symbol".to_string()),
        );
        let ext = ExtRelocation::new(&reloc);
        assert_eq!(ext.kind, "5");
        assert_eq!(ext.value, "0x100,0x200");
        assert_eq!(ext.bytes, Some("0x1,0x2,0x3".to_string()));
        assert_eq!(ext.name, Some("symbol".to_string()));
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let reloc = Relocation::new(
            test_address(0x1000),
            RelocationStatus::Applied,
            1,
            vec![],
            None,
            None,
        );
        let ext = ExtRelocation::new(&reloc);
        accepts_isf_object(&ext);
    }
}
