/// CLI metadata table types from ECMA-335 §II.22.
///
/// Mirrors `ghidra.app.util.bin.format.pe.cli.tables.CliTypeTable`.
/// Each variant carries its numeric table index as the discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CliTypeTable {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    Field = 0x04,
    MethodDef = 0x06,
    Param = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0a,
    Constant = 0x0b,
    CustomAttribute = 0x0c,
    FieldMarshal = 0x0d,
    DeclSecurity = 0x0e,
    ClassLayout = 0x0f,
    FieldLayout = 0x10,
    StandAloneSig = 0x11,
    EventMap = 0x12,
    Event = 0x14,
    PropertyMap = 0x15,
    Property = 0x17,
    MethodSemantics = 0x18,
    MethodImpl = 0x19,
    ModuleRef = 0x1a,
    TypeSpec = 0x1b,
    ImplMap = 0x1c,
    FieldRva = 0x1d,
    Assembly = 0x20,
    AssemblyProcessor = 0x21,
    AssemblyOs = 0x22,
    AssemblyRef = 0x23,
    AssemblyRefProcessor = 0x24,
    AssemblyRefOs = 0x25,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    NestedClass = 0x29,
    GenericParam = 0x2a,
    MethodSpec = 0x2b,
    GenericParamConstraint = 0x2c,
}

impl CliTypeTable {
    /// Returns the numeric table index associated with this table type.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Returns the [`CliTypeTable`] for the given numeric table index, or
    /// `None` if no table type with that index exists.
    pub fn from_id(id: u8) -> Option<CliTypeTable> {
        match id {
            0x00 => Some(CliTypeTable::Module),
            0x01 => Some(CliTypeTable::TypeRef),
            0x02 => Some(CliTypeTable::TypeDef),
            0x04 => Some(CliTypeTable::Field),
            0x06 => Some(CliTypeTable::MethodDef),
            0x08 => Some(CliTypeTable::Param),
            0x09 => Some(CliTypeTable::InterfaceImpl),
            0x0a => Some(CliTypeTable::MemberRef),
            0x0b => Some(CliTypeTable::Constant),
            0x0c => Some(CliTypeTable::CustomAttribute),
            0x0d => Some(CliTypeTable::FieldMarshal),
            0x0e => Some(CliTypeTable::DeclSecurity),
            0x0f => Some(CliTypeTable::ClassLayout),
            0x10 => Some(CliTypeTable::FieldLayout),
            0x11 => Some(CliTypeTable::StandAloneSig),
            0x12 => Some(CliTypeTable::EventMap),
            0x14 => Some(CliTypeTable::Event),
            0x15 => Some(CliTypeTable::PropertyMap),
            0x17 => Some(CliTypeTable::Property),
            0x18 => Some(CliTypeTable::MethodSemantics),
            0x19 => Some(CliTypeTable::MethodImpl),
            0x1a => Some(CliTypeTable::ModuleRef),
            0x1b => Some(CliTypeTable::TypeSpec),
            0x1c => Some(CliTypeTable::ImplMap),
            0x1d => Some(CliTypeTable::FieldRva),
            0x20 => Some(CliTypeTable::Assembly),
            0x21 => Some(CliTypeTable::AssemblyProcessor),
            0x22 => Some(CliTypeTable::AssemblyOs),
            0x23 => Some(CliTypeTable::AssemblyRef),
            0x24 => Some(CliTypeTable::AssemblyRefProcessor),
            0x25 => Some(CliTypeTable::AssemblyRefOs),
            0x26 => Some(CliTypeTable::File),
            0x27 => Some(CliTypeTable::ExportedType),
            0x28 => Some(CliTypeTable::ManifestResource),
            0x29 => Some(CliTypeTable::NestedClass),
            0x2a => Some(CliTypeTable::GenericParam),
            0x2b => Some(CliTypeTable::MethodSpec),
            0x2c => Some(CliTypeTable::GenericParamConstraint),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_round_trip() {
        let all = [
            CliTypeTable::Module,
            CliTypeTable::TypeRef,
            CliTypeTable::TypeDef,
            CliTypeTable::Field,
            CliTypeTable::MethodDef,
            CliTypeTable::Param,
            CliTypeTable::InterfaceImpl,
            CliTypeTable::MemberRef,
            CliTypeTable::Constant,
            CliTypeTable::CustomAttribute,
            CliTypeTable::FieldMarshal,
            CliTypeTable::DeclSecurity,
            CliTypeTable::ClassLayout,
            CliTypeTable::FieldLayout,
            CliTypeTable::StandAloneSig,
            CliTypeTable::EventMap,
            CliTypeTable::Event,
            CliTypeTable::PropertyMap,
            CliTypeTable::Property,
            CliTypeTable::MethodSemantics,
            CliTypeTable::MethodImpl,
            CliTypeTable::ModuleRef,
            CliTypeTable::TypeSpec,
            CliTypeTable::ImplMap,
            CliTypeTable::FieldRva,
            CliTypeTable::Assembly,
            CliTypeTable::AssemblyProcessor,
            CliTypeTable::AssemblyOs,
            CliTypeTable::AssemblyRef,
            CliTypeTable::AssemblyRefProcessor,
            CliTypeTable::AssemblyRefOs,
            CliTypeTable::File,
            CliTypeTable::ExportedType,
            CliTypeTable::ManifestResource,
            CliTypeTable::NestedClass,
            CliTypeTable::GenericParam,
            CliTypeTable::MethodSpec,
            CliTypeTable::GenericParamConstraint,
        ];
        for variant in all {
            assert_eq!(CliTypeTable::from_id(variant.id()), Some(variant));
        }
    }

    #[test]
    fn id_spot_checks() {
        assert_eq!(CliTypeTable::Module.id(), 0x00);
        assert_eq!(CliTypeTable::TypeRef.id(), 0x01);
        assert_eq!(CliTypeTable::Field.id(), 0x04);
        assert_eq!(CliTypeTable::MethodDef.id(), 0x06);
        assert_eq!(CliTypeTable::Assembly.id(), 0x20);
        assert_eq!(CliTypeTable::GenericParamConstraint.id(), 0x2c);
    }

    #[test]
    fn gap_ids_return_none() {
        // Gaps in the table: 0x03, 0x05, 0x07, 0x13, 0x16, 0x1e, 0x1f
        for &gap in &[0x03u8, 0x05, 0x07, 0x13, 0x16, 0x1e, 0x1f] {
            assert_eq!(CliTypeTable::from_id(gap), None, "expected None for id {gap:#04x}");
        }
    }

    #[test]
    fn out_of_range_returns_none() {
        assert_eq!(CliTypeTable::from_id(0x2d), None);
        assert_eq!(CliTypeTable::from_id(0xff), None);
    }

    #[test]
    fn from_id_known_values() {
        assert_eq!(CliTypeTable::from_id(0x00), Some(CliTypeTable::Module));
        assert_eq!(CliTypeTable::from_id(0x2c), Some(CliTypeTable::GenericParamConstraint));
        assert_eq!(CliTypeTable::from_id(0x26), Some(CliTypeTable::File));
        assert_eq!(CliTypeTable::from_id(0x1d), Some(CliTypeTable::FieldRva));
    }
}
