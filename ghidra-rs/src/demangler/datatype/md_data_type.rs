use crate::demangler::seam_stubs::MdMangLike;

/// Base trait of a number of data types within a Microsoft mangled symbol.
///
/// Mirrors `mdemangler.datatype.MDDataType`, cut to a trait to break a dependency cycle
/// with `MDType`/`MDMang` (neither is ported yet). `insert`/`insert_as_arg` and the default
/// `is_signed` are given trait-default bodies since they only depend on the other trait
/// methods, mirroring the concrete logic `MDDataType` itself provides on top of the still
/// unported `MDType`/`MDParsableItem` chain.
pub trait MdDataType {
    /// Sets the type name text inserted ahead of any signedness keyword.
    ///
    /// Mirrors `setTypeName(String)`.
    fn set_type_name(&mut self, name: String);

    /// Returns the type name text, if any has been set.
    ///
    /// Mirrors `getTypeName()`; modeled as `Option` rather than a nullable `String` since the
    /// Java field defaults to `null` until `setTypeName` (or a `typeName`-taking constructor)
    /// runs.
    fn type_name(&self) -> Option<&str>;

    /// Marks the type as explicitly `signed`, distinct from the implicit default signedness.
    ///
    /// Mirrors `setSigned()`.
    fn set_signed(&mut self);

    /// Marks the type as `unsigned`.
    ///
    /// Mirrors `setUnsigned()`.
    fn set_unsigned(&mut self);

    /// True once [`MdDataType::set_signed`] was explicitly called.
    ///
    /// Mirrors `isSpecifiedSigned()`.
    fn is_specified_signed(&self) -> bool;

    /// True once [`MdDataType::set_unsigned`] was called.
    ///
    /// Mirrors `isUnsigned()`.
    fn is_unsigned(&self) -> bool;

    /// True unless the type has been marked `unsigned` (the default, and the explicitly-signed
    /// case, both count as signed).
    ///
    /// Mirrors `isSigned()`.
    fn is_signed(&self) -> bool {
        !self.is_unsigned()
    }

    /// Inserts the type name (space-separated ahead of any existing content) followed by a
    /// `signed `/`unsigned ` keyword when the signedness was set explicitly.
    ///
    /// Mirrors `insert(StringBuilder)`.
    fn insert(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        if let Some(name) = self.type_name() {
            if !name.is_empty() {
                if !builder.is_empty() {
                    dmang.insert_string(builder, " ");
                }
                dmang.insert_string(builder, name);
            }
        }

        if self.is_specified_signed() {
            dmang.insert_spaced_string(builder, "signed ");
        }
        if self.is_unsigned() {
            dmang.insert_spaced_string(builder, "unsigned ");
        }
    }

    /// Inserts this type as though it is a template or function argument.
    ///
    /// Mirrors `insertAsArg(StringBuilder)`, which just delegates to `insert` in the original.
    fn insert_as_arg(&self, dmang: &dyn MdMangLike, builder: &mut String) {
        self.insert(dmang, builder);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MockDataType {
        type_name: Option<String>,
        specified_signed: bool,
        unsigned: bool,
    }

    impl MdDataType for MockDataType {
        fn set_type_name(&mut self, name: String) {
            self.type_name = Some(name);
        }

        fn type_name(&self) -> Option<&str> {
            self.type_name.as_deref()
        }

        fn set_signed(&mut self) {
            self.specified_signed = true;
            self.unsigned = false;
        }

        fn set_unsigned(&mut self) {
            self.unsigned = true;
            self.specified_signed = false;
        }

        fn is_specified_signed(&self) -> bool {
            self.specified_signed
        }

        fn is_unsigned(&self) -> bool {
            self.unsigned
        }
    }

    struct MockMdMang;

    impl MdMangLike for MockMdMang {
        fn insert_string(&self, builder: &mut String, s: &str) {
            builder.insert_str(0, s);
        }

        fn insert_spaced_string(&self, builder: &mut String, s: &str) {
            if builder.is_empty() || s.is_empty() {
                builder.insert_str(0, s);
                return;
            }
            if builder.starts_with(' ') {
                if s.ends_with(' ') {
                    builder.remove(0);
                }
            } else if !s.ends_with(' ') {
                builder.insert(0, ' ');
            }
            builder.insert_str(0, s);
        }
    }

    #[test]
    fn default_signedness_is_signed_and_not_specified() {
        let dt = MockDataType::default();

        assert!(dt.is_signed());
        assert!(!dt.is_unsigned());
        assert!(!dt.is_specified_signed());
    }

    #[test]
    fn set_unsigned_flips_signedness() {
        let mut dt = MockDataType::default();
        dt.set_unsigned();

        assert!(!dt.is_signed());
        assert!(dt.is_unsigned());
        assert!(!dt.is_specified_signed());
    }

    #[test]
    fn set_signed_marks_specified_without_unsigned() {
        let mut dt = MockDataType::default();
        dt.set_signed();

        assert!(dt.is_signed());
        assert!(!dt.is_unsigned());
        assert!(dt.is_specified_signed());
    }

    #[test]
    fn insert_prepends_type_name_and_unsigned_keyword() {
        let mut dt = MockDataType::default();
        dt.set_type_name("int".to_string());
        dt.set_unsigned();
        let dmang = MockMdMang;
        let mut builder = String::new();

        dt.insert(&dmang, &mut builder);

        assert_eq!(builder, "unsigned int");
    }

    #[test]
    fn insert_as_arg_matches_insert() {
        let mut dt = MockDataType::default();
        dt.set_type_name("char".to_string());
        dt.set_signed();
        let dmang = MockMdMang;

        let mut via_insert = String::new();
        dt.insert(&dmang, &mut via_insert);

        let mut via_arg = String::new();
        dt.insert_as_arg(&dmang, &mut via_arg);

        assert_eq!(via_insert, via_arg);
        assert_eq!(via_insert, "signed char");
    }

    #[test]
    fn insert_with_no_type_name_only_emits_signedness() {
        let mut dt = MockDataType::default();
        dt.set_unsigned();
        let dmang = MockMdMang;
        let mut builder = String::new();

        dt.insert(&dmang, &mut builder);

        assert_eq!(builder, "unsigned ");
    }
}
