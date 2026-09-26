use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;
use crate::format::pdb2::pdbreader::r#type::ms_type::MsType;

/// Bind ordinal used for determining when parentheses should surround components during
/// [`AbstractMsType::emit`].
///
/// Corresponds to the nested Java enum
/// `ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType.Bind`. Order matters, matching
/// the Java declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bind {
    Ptr,
    Array,
    Proc,
    None,
}

/// Base trait for PDB Data Type units.
///
/// Corresponds to the Java abstract class
/// `ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractMsType`, which extends
/// `AbstractParsableItem` and implements `MsType`. This was selected as a dependency-cycle
/// cut-point, so it is ported as a trait rather than a struct: the Java `pdb`/`recordNumber`
/// fields have no home on a trait, so implementors are expected to track that state themselves
/// and surface it through [`MsType::record_number`] (already declared on the supertrait) the
/// same way the existing leaf traits (e.g.
/// [`AbstractCobol0MsType`](crate::format::pdb2::pdbreader::r#type::abstract_cobol0_ms_type::AbstractCobol0MsType))
/// do.
pub trait AbstractMsType: MsType + AbstractParsableItem {
    /// Emits string output of this class into `builder`, matching the Java override
    /// `emit(StringBuilder, Bind)`.
    ///
    /// Named `emit_with_bind` (rather than `emit`) because Rust does not support overloading:
    /// [`AbstractParsableItem::emit`] already claims that name on the supertrait, and Java's
    /// single-argument `emit(StringBuilder)` override (which just forwards to this method with
    /// `Bind.NONE`) is likewise already covered by `AbstractParsableItem::emit`'s default.
    ///
    /// The default mirrors Java's default body, which produces a placeholder string for leaf
    /// types that have not overridden this method: `"IncompleteImpl(<SimpleClassName>)"`.
    fn emit_with_bind(&self, builder: &mut String, _bind: Bind) {
        let full = std::any::type_name::<Self>();
        let simple = full.rsplit("::").next().unwrap_or(full);
        builder.push_str(&format!("IncompleteImpl({simple})"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::id_ms_parsable::IdMsParsable;

    struct DefaultType;
    impl AbstractParsableItem for DefaultType {}
    impl IdMsParsable for DefaultType {
        fn pdb_id(&self) -> i32 {
            0x1001
        }
    }
    impl MsType for DefaultType {}
    impl AbstractMsType for DefaultType {}

    struct NamedType;
    impl AbstractParsableItem for NamedType {}
    impl IdMsParsable for NamedType {
        fn pdb_id(&self) -> i32 {
            0x1002
        }
    }
    impl MsType for NamedType {
        fn name(&self) -> String {
            "Foo".to_string()
        }
    }
    impl AbstractMsType for NamedType {
        fn emit_with_bind(&self, builder: &mut String, _bind: Bind) {
            builder.push_str(&self.name());
        }
    }

    #[test]
    fn default_emit_produces_incomplete_impl_marker() {
        let t = DefaultType;
        let mut builder = String::new();
        t.emit_with_bind(&mut builder, Bind::None);
        assert!(builder.starts_with("IncompleteImpl("));
        assert!(builder.contains("DefaultType"));
    }

    #[test]
    fn overridden_emit_replaces_default() {
        let t = NamedType;
        let mut builder = String::new();
        t.emit_with_bind(&mut builder, Bind::Ptr);
        assert_eq!(builder, "Foo");
    }

    #[test]
    fn inherits_ms_type_and_parsable_item_defaults() {
        let t = DefaultType;
        assert_eq!(t.pdb_id(), 0x1001);
        assert_eq!(t.name(), "");
        assert_eq!(t.to_display_string(), "DefaultType");
    }

    #[test]
    fn is_object_safe() {
        let boxed: Box<dyn AbstractMsType> = Box::new(NamedType);
        assert_eq!(boxed.pdb_id(), 0x1002);
        let mut builder = String::new();
        boxed.emit_with_bind(&mut builder, Bind::None);
        assert_eq!(builder, "Foo");
    }
}
