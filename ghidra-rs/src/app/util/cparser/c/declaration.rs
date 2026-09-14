//! Port of `ghidra.app.util.cparser.C.Declaration`.
//!
//! Container for information about a Declaration that is accumulated during parsing (by the
//! JavaCC-generated C grammar, not itself ported -- see [`super::parse_exception`]'s doc comment).
//!
//! # Reference vs. value semantics for the held [`DataType`]
//!
//! Every Java constructor here that copies from another `Declaration` (or receives a `DataType`
//! directly) just copies the *reference* -- `this.dt = dec.getDataType();` shares the same
//! object, it does not clone it. This port stores `dt` as `Option<Arc<dyn DataType>>` (rather
//! than `Box<dyn DataType>`, which would force an actual deep clone on every copy-construction,
//! something Java never does here) so that cloning an `Arc` reproduces the same cheap
//! reference-sharing behavior.

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;

use super::parse_exception::ParseException;

/// Container for information about a Declaration that is accumulated during parsing.
///
/// Port of `ghidra.app.util.cparser.C.Declaration`.
pub struct Declaration {
    qualifier_list: Option<Vec<i32>>,
    dt: Option<Arc<dyn DataType>>,
    name: Option<String>,
    comment: Option<String>,
    bit_size: i32,
}

impl Default for Declaration {
    fn default() -> Self {
        Self::new()
    }
}

impl Declaration {
    /// Port of `Declaration()`.
    pub fn new() -> Self {
        Declaration { qualifier_list: None, dt: None, name: None, comment: None, bit_size: -1 }
    }

    /// Port of `Declaration(Declaration dec)`. See the module docs for why this shares `dec`'s
    /// data type rather than cloning it.
    pub fn from_declaration(dec: &Declaration) -> Self {
        let mut result = Self::new();
        result.dt = dec.dt.clone();
        if let Some(qualifiers) = &dec.qualifier_list {
            result.qualifier_list = Some(qualifiers.clone());
        }
        result
    }

    /// Port of `Declaration(Declaration dec, String name) throws ParseException`. `dec` is
    /// `Option` in place of Java's nullable reference: passing `None` mirrors constructing with a
    /// `null` `dec`, which throws immediately.
    pub fn from_declaration_and_name(dec: Option<&Declaration>, name: impl Into<String>) -> Result<Self, ParseException> {
        let name = name.into();
        let Some(dec) = dec
        else {
            return Err(ParseException::new(format!("Undefined data type \"{name}\"")));
        };
        let mut result = Self::new();
        result.dt = dec.dt.clone();
        result.name = Some(name);
        Ok(result)
    }

    /// Port of `Declaration(String name)`.
    pub fn from_name(name: impl Into<String>) -> Self {
        let mut result = Self::new();
        result.name = Some(name.into());
        result
    }

    /// Port of `Declaration(DataType dt)`.
    pub fn from_data_type(dt: Arc<dyn DataType>) -> Self {
        let mut result = Self::new();
        result.dt = Some(dt);
        result
    }

    /// Port of `Declaration(Declaration subDecl, DataType dt)`. `sub_decl` is `Option` in place
    /// of Java's nullable reference; when `None`, only `dt` is stored (matching the Java `if
    /// (subDecl == null) { return; }` early return).
    ///
    /// `dt` is `Box`-owned (rather than `Arc`, like the field itself) because this constructor may
    /// need to consume it to build a *new* pointer data type wrapping it (mirroring `new
    /// PointerDataType(dt)`) when `sub_decl`'s own data type was itself a pointer -- see
    /// [`Pointer::new_pointer`](crate::program::model::data::pointer::Pointer::new_pointer).
    pub fn from_sub_decl_and_data_type(sub_decl: Option<&Declaration>, dt: Box<dyn DataType>) -> Self {
        let mut result = Self::new();

        let wrapping_pointer =
            sub_decl.and_then(|s| s.dt.as_ref()).and_then(|sub_dt| sub_dt.as_pointer());
        result.dt = Some(match wrapping_pointer {
            Some(ptr) => Arc::from(ptr.new_pointer(dt) as Box<dyn DataType>),
            None => Arc::from(dt),
        });

        let Some(sub_decl) = sub_decl
        else {
            return result;
        };
        result.name = sub_decl.name.clone();
        result.comment = sub_decl.comment.clone();
        if let Some(qualifiers) = &sub_decl.qualifier_list {
            result.qualifier_list = Some(qualifiers.clone());
        }
        result
    }

    /// Port of `Declaration(DataType dt, String name)`.
    pub fn from_data_type_and_name(dt: Arc<dyn DataType>, name: impl Into<String>) -> Self {
        let mut result = Self::new();
        result.dt = Some(dt);
        result.name = Some(name.into());
        result
    }

    /// Port of `Declaration(DataType dt, String name, String comment)`.
    pub fn from_data_type_name_and_comment(
        dt: Arc<dyn DataType>,
        name: impl Into<String>,
        comment: impl Into<String>,
    ) -> Self {
        let mut result = Self::new();
        result.dt = Some(dt);
        result.name = Some(name.into());
        result.comment = Some(comment.into());
        result
    }

    /// Port of `getComment()`. Unlike [`get_name`](Self::get_name), a missing comment stays
    /// `None` rather than defaulting to an empty string -- matching Java's asymmetric treatment
    /// (`getComment` returns the raw, possibly-`null`, `comment` field; `getName` special-cases
    /// `null` into `""`).
    pub fn get_comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Port of `getQualifiers()`.
    ///
    /// Java returns the live, mutable backing `ArrayList` directly (or `List.of()` when unset),
    /// so external mutation of the returned list would alias back into this `Declaration`. That
    /// aliasing has no Rust equivalent without borrowing `self` mutably from a `&self` method, and
    /// no caller in this crate (the C grammar that would exercise it is not ported) observes the
    /// difference, so this returns an owned copy instead.
    pub fn get_qualifiers(&self) -> Vec<i32> {
        self.qualifier_list.clone().unwrap_or_default()
    }

    /// Port of `getDataType()`. Returns a cheap `Arc` clone (see the module docs), not a deep
    /// copy.
    pub fn get_data_type(&self) -> Option<Arc<dyn DataType>> {
        self.dt.clone()
    }

    /// Port of `getName()`.
    pub fn get_name(&self) -> String {
        self.name.clone().unwrap_or_default()
    }

    /// Port of `setComment(String)`.
    pub fn set_comment(&mut self, comment: Option<String>) {
        self.comment = comment;
    }

    /// Port of `addQualifier(int)`.
    pub fn add_qualifier(&mut self, qualifier: i32) {
        self.qualifier_list.get_or_insert_with(Vec::new).push(qualifier);
    }

    /// Port of `addQualifiers(Declaration)`.
    pub fn add_qualifiers(&mut self, dec: &Declaration) {
        let Some(other_qualifiers) = &dec.qualifier_list
        else {
            return;
        };
        self.qualifier_list.get_or_insert_with(Vec::new).extend(other_qualifiers.iter().copied());
    }

    /// Port of `setDataType(DataType)`.
    ///
    /// # `unsigned`-before-a-signed-type promotion
    ///
    /// Mirrors the Java quirk: if the data type already held is an unsigned
    /// [`AbstractIntegerDataType`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType)
    /// (e.g. from an earlier `unsigned` qualifier token) and `new_type` is itself a *signed*
    /// integer type, the signed `new_type` is swapped for its
    /// [`get_opposite_signedness_data_type`](crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType::get_opposite_signedness_data_type)
    /// instead of being stored directly -- so `unsigned int` (parsed as `unsigned` then `int`)
    /// ends up as the unsigned-int type, not signed `int`.
    pub fn set_data_type(&mut self, new_type: Arc<dyn DataType>) {
        let promoted = match (
            self.dt.as_ref().and_then(|d| d.as_abstract_integer()),
            new_type.as_abstract_integer(),
        ) {
            (Some(current), Some(new_as_int)) if !current.is_signed() && new_as_int.is_signed() => {
                Some(Arc::from(new_as_int.get_opposite_signedness_data_type() as Box<dyn DataType>))
            }
            _ => None,
        };
        self.dt = Some(promoted.unwrap_or(new_type));
    }

    /// Port of `setName(String)`.
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Returns true if a bitfield size has been set.
    ///
    /// Port of the package-private `isBitField()`.
    pub(crate) fn is_bit_field(&self) -> bool {
        self.bit_size >= 0
    }

    /// Returns the currently set bitfield size.
    ///
    /// Port of `getBitFieldSize()`.
    pub fn get_bit_field_size(&self) -> i32 {
        self.bit_size
    }

    /// Set the bitfield size for this data type. More checking could be done here if the
    /// bitfield is set on something that isn't a bitfield, but that probably isn't necessary.
    ///
    /// Port of the package-private `setBitFieldSize(int) throws ParseException`.
    ///
    /// # Panics
    /// Java's error-message path dereferences `dt.getName()` unconditionally
    /// (`throw new ParseException("Negative bitfield size not permitted: " + dt.getName());`),
    /// which throws a `NullPointerException` if no data type has been set yet -- this port
    /// reproduces that as a panic rather than silently substituting a placeholder name.
    pub(crate) fn set_bit_field_size(&mut self, bits: i32) -> Result<(), ParseException> {
        if bits < 0 {
            let dt_name = self
                .dt
                .as_ref()
                .expect(
                    "Declaration::set_bit_field_size: dt is None (mirrors a Java \
                     NullPointerException from dt.getName() in the error-message path)",
                )
                .get_name();
            return Err(ParseException::new(format!("Negative bitfield size not permitted: {dt_name}")));
        }
        self.bit_size = bits;
        Ok(())
    }
}

impl std::fmt::Debug for Declaration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Declaration")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("qualifier_list", &self.qualifier_list)
            .field("bit_size", &self.bit_size)
            .field("dt", &self.dt.as_ref().map(|d| d.get_name()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::data::abstract_integer_data_type::AbstractIntegerDataType;
    use crate::program::model::data::array_stringable::ArrayStringable;
    use crate::program::model::data::built_in_data_type::BuiltInDataType;
    use crate::program::model::data::data_organization::DataOrganization;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::data::pointer::Pointer;
    use crate::program::model::mem::MemBuffer;
    use crate::program::model::data::string_data_instance::StringDataInstance;

    #[derive(Clone)]
    struct MockDataType {
        name: &'static str,
    }
    impl DataType for MockDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
    }

    fn dt(name: &'static str) -> Arc<dyn DataType> {
        Arc::new(MockDataType { name })
    }

    #[test]
    fn default_constructor_has_no_bit_field_and_empty_name() {
        let d = Declaration::new();
        assert_eq!(d.get_name(), "");
        assert_eq!(d.get_comment(), None);
        assert!(d.get_data_type().is_none());
        assert!(d.get_qualifiers().is_empty());
        assert!(!d.is_bit_field());
        assert_eq!(d.get_bit_field_size(), -1);
    }

    #[test]
    fn from_data_type_and_name_stores_both() {
        let d = Declaration::from_data_type_and_name(dt("int"), "x");
        assert_eq!(d.get_name(), "x");
        assert_eq!(d.get_data_type().unwrap().get_name(), "int");
    }

    #[test]
    fn from_data_type_name_and_comment_stores_all_three() {
        let d = Declaration::from_data_type_name_and_comment(dt("int"), "x", "the x field");
        assert_eq!(d.get_name(), "x");
        assert_eq!(d.get_comment(), Some("the x field"));
    }

    #[test]
    fn from_declaration_shares_the_same_data_type_instance() {
        let original = Declaration::from_data_type(dt("int"));
        let copy = Declaration::from_declaration(&original);
        // Same Arc contents (reference-shared, not deep-cloned -- see the module docs).
        assert!(Arc::ptr_eq(&original.get_data_type().unwrap(), &copy.get_data_type().unwrap()));
    }

    #[test]
    fn from_declaration_copies_qualifiers() {
        let mut original = Declaration::from_data_type(dt("int"));
        original.add_qualifier(7);
        let copy = Declaration::from_declaration(&original);
        assert_eq!(copy.get_qualifiers(), vec![7]);
    }

    #[test]
    fn from_declaration_and_name_with_some_dec_succeeds() {
        let base = Declaration::from_data_type(dt("int"));
        let d = Declaration::from_declaration_and_name(Some(&base), "count").unwrap();
        assert_eq!(d.get_name(), "count");
        assert_eq!(d.get_data_type().unwrap().get_name(), "int");
    }

    #[test]
    fn from_declaration_and_name_with_none_dec_errors() {
        let err = Declaration::from_declaration_and_name(None, "count").unwrap_err();
        assert_eq!(err.to_string(), "Undefined data type \"count\"");
    }

    #[test]
    fn from_name_only_sets_name() {
        let d = Declaration::from_name("y");
        assert_eq!(d.get_name(), "y");
        assert!(d.get_data_type().is_none());
    }

    #[test]
    fn getters_and_setters_roundtrip() {
        let mut d = Declaration::new();
        d.set_name(Some("z".to_string()));
        d.set_comment(Some("a comment".to_string()));
        d.set_data_type(dt("char"));
        assert_eq!(d.get_name(), "z");
        assert_eq!(d.get_comment(), Some("a comment"));
        assert_eq!(d.get_data_type().unwrap().get_name(), "char");
    }

    #[test]
    fn set_name_to_none_clears_it_and_get_name_defaults_to_empty() {
        let mut d = Declaration::from_name("z");
        d.set_name(None);
        assert_eq!(d.get_name(), "");
    }

    #[test]
    fn add_qualifier_accumulates() {
        let mut d = Declaration::new();
        d.add_qualifier(1);
        d.add_qualifier(2);
        assert_eq!(d.get_qualifiers(), vec![1, 2]);
    }

    #[test]
    fn add_qualifiers_from_another_declaration_appends() {
        let mut source = Declaration::new();
        source.add_qualifier(10);
        source.add_qualifier(20);

        let mut target = Declaration::new();
        target.add_qualifier(1);
        target.add_qualifiers(&source);

        assert_eq!(target.get_qualifiers(), vec![1, 10, 20]);
    }

    #[test]
    fn add_qualifiers_from_a_declaration_with_none_is_a_no_op() {
        let source = Declaration::new();
        let mut target = Declaration::new();
        target.add_qualifier(1);
        target.add_qualifiers(&source);
        assert_eq!(target.get_qualifiers(), vec![1]);
    }

    #[test]
    fn bit_field_size_roundtrip() {
        let mut d = Declaration::from_data_type(dt("int"));
        assert!(!d.is_bit_field());
        d.set_bit_field_size(4).unwrap();
        assert!(d.is_bit_field());
        assert_eq!(d.get_bit_field_size(), 4);
    }

    #[test]
    fn negative_bit_field_size_is_rejected() {
        let mut d = Declaration::from_data_type(dt("int"));
        let err = d.set_bit_field_size(-1).unwrap_err();
        assert_eq!(err.to_string(), "Negative bitfield size not permitted: int");
        // Rejected sizes must not stick.
        assert!(!d.is_bit_field());
    }

    #[test]
    #[should_panic(expected = "dt is None")]
    fn negative_bit_field_size_with_no_data_type_panics_mirroring_a_java_npe() {
        let mut d = Declaration::new();
        let _ = d.set_bit_field_size(-1);
    }

    // --- Pointer-wrapping constructor ---------------------------------------------------

    struct MockPointer {
        name: &'static str,
        referenced_name: &'static str,
    }
    impl DataType for MockPointer {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn as_pointer(&self) -> Option<&dyn Pointer> {
            Some(self)
        }
    }
    impl Pointer for MockPointer {
        fn get_data_type(&self) -> Option<Box<dyn DataType>> {
            Some(Box::new(MockDataType { name: self.referenced_name }))
        }
        fn new_pointer(&self, data_type: Box<dyn DataType>) -> Box<dyn Pointer> {
            // Static-str-only mock: leak the (test-only, bounded) name so `referenced_name` can
            // stay `&'static str` like the rest of this file's mocks.
            let name: &'static str = Box::leak(data_type.get_name().into_boxed_str());
            Box::new(MockPointer { name: "PTR", referenced_name: name })
        }
        fn typedef_builder(&self) -> Box<dyn crate::program::model::data::pointer_typedef_builder::PointerTypedefBuilder> {
            unreachable!("not exercised by this test")
        }
    }

    #[test]
    fn from_sub_decl_and_data_type_wraps_in_a_pointer_when_sub_decl_was_a_pointer() {
        let ptr_decl = Declaration::from_data_type(Arc::new(MockPointer { name: "PTR(int)", referenced_name: "int" }));

        let result = Declaration::from_sub_decl_and_data_type(Some(&ptr_decl), Box::new(MockDataType { name: "char" }));

        let result_dt = result.get_data_type().unwrap();
        assert_eq!(result_dt.get_name(), "PTR");
        let referenced = result_dt.as_pointer().unwrap().get_data_type().unwrap();
        assert_eq!(referenced.get_name(), "char");
    }

    #[test]
    fn from_sub_decl_and_data_type_stores_dt_directly_when_sub_decl_was_not_a_pointer() {
        let sub_decl = Declaration::from_data_type_and_name(dt("int"), "field");
        let result = Declaration::from_sub_decl_and_data_type(Some(&sub_decl), Box::new(MockDataType { name: "char" }));
        assert_eq!(result.get_data_type().unwrap().get_name(), "char");
        assert_eq!(result.get_name(), "field");
    }

    #[test]
    fn from_sub_decl_and_data_type_with_none_sub_decl_just_stores_dt() {
        let result = Declaration::from_sub_decl_and_data_type(None, Box::new(MockDataType { name: "char" }));
        assert_eq!(result.get_data_type().unwrap().get_name(), "char");
        assert_eq!(result.get_name(), "");
    }

    #[test]
    fn from_sub_decl_and_data_type_copies_sub_decl_comment_and_qualifiers() {
        let mut sub_decl = Declaration::from_data_type_name_and_comment(dt("int"), "field", "a comment");
        sub_decl.add_qualifier(3);
        let result = Declaration::from_sub_decl_and_data_type(Some(&sub_decl), Box::new(MockDataType { name: "char" }));
        assert_eq!(result.get_comment(), Some("a comment"));
        assert_eq!(result.get_qualifiers(), vec![3]);
    }

    // --- setDataType's unsigned-then-signed promotion quirk -----------------------------

    struct MockOppositeSignedness;
    impl DataType for MockOppositeSignedness {
        fn get_name(&self) -> String {
            "unsigned int".to_string()
        }
        fn as_abstract_integer(&self) -> Option<&dyn AbstractIntegerDataType> {
            Some(self)
        }
    }
    impl BuiltInDataType for MockOppositeSignedness {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl ArrayStringable for MockOppositeSignedness {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            false
        }
        fn string_data_instance(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }
    impl AbstractIntegerDataType for MockOppositeSignedness {
        fn is_signed(&self) -> bool {
            false
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            unreachable!("not exercised by this test")
        }
    }

    struct MockIntDataType {
        name: &'static str,
        signed: bool,
    }
    impl DataType for MockIntDataType {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn as_abstract_integer(&self) -> Option<&dyn AbstractIntegerDataType> {
            Some(self)
        }
    }
    impl BuiltInDataType for MockIntDataType {
        fn get_c_type_declaration(&self, _data_organization: Option<&dyn DataOrganization>) -> Option<String> {
            None
        }
        fn set_default_settings(&mut self, _settings: &dyn Settings) {}
    }
    impl ArrayStringable for MockIntDataType {
        fn has_string_value(&self, _settings: &dyn Settings) -> bool {
            false
        }
        fn string_data_instance(&self, _buf: &dyn MemBuffer, _settings: &dyn Settings, _length: i32) -> Box<dyn StringDataInstance> {
            Box::new(crate::program::model::data::string_data_instance::null_instance())
        }
        fn get_array_default_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
        ) -> Option<String> {
            None
        }
        fn get_array_default_offcut_label_prefix(
            &self,
            _buf: &dyn MemBuffer,
            _settings: &dyn Settings,
            _len: i32,
            _options: &dyn DataTypeDisplayOptions,
            _offcut_length: i32,
        ) -> Option<String> {
            None
        }
    }
    impl AbstractIntegerDataType for MockIntDataType {
        fn is_signed(&self) -> bool {
            self.signed
        }
        fn get_opposite_signedness_data_type(&self) -> Box<dyn AbstractIntegerDataType> {
            Box::new(MockOppositeSignedness)
        }
    }

    #[test]
    fn set_data_type_promotes_signed_to_unsigned_when_current_is_unsigned() {
        // Simulates parsing `unsigned int`: the `unsigned` keyword first sets an unsigned
        // placeholder type, then the `int` token calls setDataType with a *signed* int -- Java
        // swaps in the opposite-signedness (unsigned) type instead of overwriting with the
        // signed one.
        let mut d = Declaration::new();
        d.set_data_type(Arc::new(MockOppositeSignedness));
        assert!(!d.get_data_type().unwrap().as_abstract_integer().unwrap().is_signed());

        d.set_data_type(Arc::new(MockIntDataType { name: "int", signed: true }));

        assert_eq!(d.get_data_type().unwrap().get_name(), "unsigned int");
    }

    #[test]
    fn set_data_type_does_not_promote_when_current_is_not_an_integer_type() {
        let mut d = Declaration::from_data_type(dt("float"));
        d.set_data_type(Arc::new(MockIntDataType { name: "int", signed: true }));
        assert_eq!(d.get_data_type().unwrap().get_name(), "int");
    }

    #[test]
    fn set_data_type_does_not_promote_when_new_type_is_already_unsigned() {
        let mut d = Declaration::new();
        d.set_data_type(Arc::new(MockOppositeSignedness));
        d.set_data_type(Arc::new(MockIntDataType { name: "unsigned char", signed: false }));
        assert_eq!(d.get_data_type().unwrap().get_name(), "unsigned char");
    }
}
