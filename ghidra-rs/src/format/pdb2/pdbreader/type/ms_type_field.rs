use crate::format::pdb2::pdbreader::id_ms_parsable::IdMsParsable;

/// Trait for PDB type field items.
///
/// Corresponds to the Java interface
/// `ghidra.app.util.bin.format.pdb2.pdbreader.type.MsTypeField`.
pub trait MsTypeField: IdMsParsable {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTypeField;
    impl IdMsParsable for MockTypeField {
        fn pdb_id(&self) -> i32 {
            0x1234
        }
    }
    impl MsTypeField for MockTypeField {}

    #[test]
    fn type_field_can_be_implemented() {
        let field = MockTypeField;
        assert_eq!(field.pdb_id(), 0x1234);
    }
}
