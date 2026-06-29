/// Kinds of symbols that can appear in a PDB file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdbKind {
    Structure,
    Union,
    Member,
    StaticLocal,
    StaticMember,
    ObjectPointer,
    Parameter,
    Local,
    Unknown,
}

impl PdbKind {
    /// Returns the name in UpperCamelCase form (e.g. `StaticLocal` for [`PdbKind::StaticLocal`]).
    pub fn camel_name(&self) -> &'static str {
        match self {
            PdbKind::Structure => "Structure",
            PdbKind::Union => "Union",
            PdbKind::Member => "Member",
            PdbKind::StaticLocal => "StaticLocal",
            PdbKind::StaticMember => "StaticMember",
            PdbKind::ObjectPointer => "ObjectPointer",
            PdbKind::Parameter => "Parameter",
            PdbKind::Local => "Local",
            PdbKind::Unknown => "Unknown",
        }
    }

    /// Parses a case-insensitive camel-form kind string and returns the corresponding
    /// [`PdbKind`]. Returns [`PdbKind::Unknown`] when the string is not recognized.
    ///
    /// Input is expected in camel notation (e.g. `"ObjectPointer"` for
    /// `OBJECT_POINTER`). Underscores in the input are not permitted.
    pub fn parse(kind: &str) -> Self {
        for variant in Self::all() {
            if variant.camel_name().eq_ignore_ascii_case(kind) {
                return *variant;
            }
        }
        PdbKind::Unknown
    }

    fn all() -> &'static [PdbKind] {
        &[
            PdbKind::Structure,
            PdbKind::Union,
            PdbKind::Member,
            PdbKind::StaticLocal,
            PdbKind::StaticMember,
            PdbKind::ObjectPointer,
            PdbKind::Parameter,
            PdbKind::Local,
            PdbKind::Unknown,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_names_are_correct() {
        assert_eq!(PdbKind::Structure.camel_name(), "Structure");
        assert_eq!(PdbKind::Union.camel_name(), "Union");
        assert_eq!(PdbKind::Member.camel_name(), "Member");
        assert_eq!(PdbKind::StaticLocal.camel_name(), "StaticLocal");
        assert_eq!(PdbKind::StaticMember.camel_name(), "StaticMember");
        assert_eq!(PdbKind::ObjectPointer.camel_name(), "ObjectPointer");
        assert_eq!(PdbKind::Parameter.camel_name(), "Parameter");
        assert_eq!(PdbKind::Local.camel_name(), "Local");
        assert_eq!(PdbKind::Unknown.camel_name(), "Unknown");
    }

    #[test]
    fn parse_exact_camel() {
        assert_eq!(PdbKind::parse("Structure"), PdbKind::Structure);
        assert_eq!(PdbKind::parse("Union"), PdbKind::Union);
        assert_eq!(PdbKind::parse("Member"), PdbKind::Member);
        assert_eq!(PdbKind::parse("StaticLocal"), PdbKind::StaticLocal);
        assert_eq!(PdbKind::parse("StaticMember"), PdbKind::StaticMember);
        assert_eq!(PdbKind::parse("ObjectPointer"), PdbKind::ObjectPointer);
        assert_eq!(PdbKind::parse("Parameter"), PdbKind::Parameter);
        assert_eq!(PdbKind::parse("Local"), PdbKind::Local);
        assert_eq!(PdbKind::parse("Unknown"), PdbKind::Unknown);
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(PdbKind::parse("structure"), PdbKind::Structure);
        assert_eq!(PdbKind::parse("STRUCTURE"), PdbKind::Structure);
        assert_eq!(PdbKind::parse("oBjEcTpOiNtEr"), PdbKind::ObjectPointer);
        assert_eq!(PdbKind::parse("staticlocal"), PdbKind::StaticLocal);
    }

    #[test]
    fn parse_unknown_for_unrecognized() {
        assert_eq!(PdbKind::parse(""), PdbKind::Unknown);
        assert_eq!(PdbKind::parse("STATIC_LOCAL"), PdbKind::Unknown);
        assert_eq!(PdbKind::parse("garbage"), PdbKind::Unknown);
    }

    #[test]
    fn parse_unknown_literal_returns_unknown_variant() {
        assert_eq!(PdbKind::parse("unknown"), PdbKind::Unknown);
    }
}
