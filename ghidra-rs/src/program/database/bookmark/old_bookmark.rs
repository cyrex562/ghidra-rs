use crate::program::model::address::Address;
use crate::program::model::listing::{Program, NOTE};
use crate::util::{ObjectStorage, ObjectStorageFieldType, Saveable};

/// Legacy bookmark record, retained for reading/upgrading old database property values.
///
/// Port of `ghidra.program.database.bookmark.OldBookmark`.
#[derive(Debug, Clone)]
pub struct OldBookmark {
    r#type: String,
    category: String,
    comment: String,
    addr: Option<Address>,
    addr_string: Option<String>,
}

impl OldBookmark {
    /// Constructs a copy of a bookmark at a new address.
    pub(crate) fn with_address(info: &OldBookmark, addr: Address) -> Self {
        OldBookmark {
            r#type: info.get_type().to_string(),
            category: info.get_category().to_string(),
            comment: info.get_comment().to_string(),
            addr: Some(addr),
            addr_string: None,
        }
    }

    /// Constructs a bookmark.
    ///
    /// # Panics
    /// Panics if `addr` is not provided, mirroring the Java constructor's
    /// `IllegalArgumentException("Bookmark address required")`.
    pub fn new(r#type: Option<&str>, category: Option<&str>, comment: Option<&str>, addr: Address) -> Self {
        OldBookmark {
            r#type: r#type.unwrap_or(NOTE).to_string(),
            category: category.unwrap_or_default().to_string(),
            comment: comment.unwrap_or_default().to_string(),
            addr: Some(addr),
            addr_string: None,
        }
    }

    /// Constructs a Note bookmark (required for Saveable property objects). Contains no
    /// address.
    pub fn empty() -> Self {
        OldBookmark {
            r#type: String::new(),
            category: String::new(),
            comment: String::new(),
            addr: None,
            addr_string: None,
        }
    }

    pub(crate) fn set_context(&mut self, program: &dyn Program, r#type: &str) {
        self.r#type = r#type.to_string();
        if let Some(addr_string) = self.addr_string.take() {
            self.addr = program
                .get_address_factory()
                .and_then(|factory| factory.get_address(&addr_string));
        }
    }

    pub fn get_type(&self) -> &str {
        &self.r#type
    }

    pub fn get_category(&self) -> &str {
        &self.category
    }

    pub fn set_category(&mut self, category: &str) {
        self.category = category.to_string();
    }

    pub fn get_comment(&self) -> &str {
        &self.comment
    }

    pub fn set_comment(&mut self, comment: &str) {
        self.comment = comment.to_string();
    }

    /// Get the address of this bookmark info.
    pub fn get_address(&self) -> Option<&Address> {
        self.addr.as_ref()
    }
}

impl PartialEq for OldBookmark {
    fn eq(&self, other: &Self) -> bool {
        let addrs_equal = match (&self.addr, &other.addr) {
            (Some(a), Some(b)) => a == b,
            _ => self.addr_string == other.addr_string,
        };

        addrs_equal
            && self.comment == other.comment
            && self.category == other.category
            && self.r#type == other.r#type
    }
}

impl Saveable for OldBookmark {
    fn get_object_storage_fields(&self) -> Vec<ObjectStorageFieldType> {
        vec![
            ObjectStorageFieldType::String,
            ObjectStorageFieldType::String,
            ObjectStorageFieldType::String,
        ]
    }

    fn save(&self, obj_storage: &mut dyn ObjectStorage) {
        obj_storage.put_string(&self.category);
        obj_storage.put_string(&self.comment);
        let addr_string = self
            .addr
            .as_ref()
            .map(|addr| addr.to_string())
            .or_else(|| self.addr_string.clone())
            .unwrap_or_default();
        obj_storage.put_string(&addr_string);
    }

    fn restore(&mut self, obj_storage: &mut dyn ObjectStorage) {
        self.category = obj_storage.get_string();
        self.comment = obj_storage.get_string();
        self.addr_string = Some(obj_storage.get_string());
    }

    fn get_schema_version(&self) -> i32 {
        0
    }

    fn is_upgradeable(&self, _old_schema_version: i32) -> bool {
        false
    }

    fn upgrade(
        &mut self,
        _old_obj_storage: &mut dyn ObjectStorage,
        _old_schema_version: i32,
        _current_obj_storage: &mut dyn ObjectStorage,
    ) -> bool {
        false
    }

    fn is_private(&self) -> bool {
        false
    }
}

impl std::fmt::Display for OldBookmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.category, self.comment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Minimal FIFO [`ObjectStorage`] supporting only strings, sufficient for exercising
    /// [`OldBookmark::save`]/[`OldBookmark::restore`].
    struct StringStorage {
        queue: VecDeque<String>,
    }

    impl StringStorage {
        fn new(values: Vec<String>) -> Self {
            Self { queue: VecDeque::from(values) }
        }
    }

    impl ObjectStorage for StringStorage {
        fn put_int(&mut self, _value: i32) {
            unimplemented!()
        }
        fn put_byte(&mut self, _value: i8) {
            unimplemented!()
        }
        fn put_short(&mut self, _value: i16) {
            unimplemented!()
        }
        fn put_long(&mut self, _value: i64) {
            unimplemented!()
        }
        fn put_string(&mut self, value: &str) {
            self.queue.push_back(value.to_string());
        }
        fn put_boolean(&mut self, _value: bool) {
            unimplemented!()
        }
        fn put_float(&mut self, _value: f32) {
            unimplemented!()
        }
        fn put_double(&mut self, _value: f64) {
            unimplemented!()
        }

        fn get_int(&mut self) -> i32 {
            unimplemented!()
        }
        fn get_byte(&mut self) -> i8 {
            unimplemented!()
        }
        fn get_short(&mut self) -> i16 {
            unimplemented!()
        }
        fn get_long(&mut self) -> i64 {
            unimplemented!()
        }
        fn get_boolean(&mut self) -> bool {
            unimplemented!()
        }
        fn get_string(&mut self) -> String {
            self.queue.pop_front().expect("storage underflow")
        }
        fn get_float(&mut self) -> f32 {
            unimplemented!()
        }
        fn get_double(&mut self) -> f64 {
            unimplemented!()
        }

        fn put_ints(&mut self, _value: &[i32]) {
            unimplemented!()
        }
        fn put_bytes(&mut self, _value: &[i8]) {
            unimplemented!()
        }
        fn put_shorts(&mut self, _value: &[i16]) {
            unimplemented!()
        }
        fn put_longs(&mut self, _value: &[i64]) {
            unimplemented!()
        }
        fn put_floats(&mut self, _value: &[f32]) {
            unimplemented!()
        }
        fn put_doubles(&mut self, _value: &[f64]) {
            unimplemented!()
        }
        fn put_strings(&mut self, _value: &[&str]) {
            unimplemented!()
        }

        fn get_ints(&mut self) -> Vec<i32> {
            unimplemented!()
        }
        fn get_bytes(&mut self) -> Vec<i8> {
            unimplemented!()
        }
        fn get_shorts(&mut self) -> Vec<i16> {
            unimplemented!()
        }
        fn get_longs(&mut self) -> Vec<i64> {
            unimplemented!()
        }
        fn get_floats(&mut self) -> Vec<f32> {
            unimplemented!()
        }
        fn get_doubles(&mut self) -> Vec<f64> {
            unimplemented!()
        }
        fn get_strings(&mut self) -> Vec<String> {
            unimplemented!()
        }
    }

    struct TestProgram {
        factory: Arc<DefaultAddressFactory>,
    }

    impl DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "test".to_string()
        }

        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    fn test_program() -> TestProgram {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        TestProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![ram])),
        }
    }

    fn test_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(ram, offset)
    }

    #[test]
    fn new_with_defaults_uses_note_type() {
        let bookmark = OldBookmark::new(None, None, None, test_address(0x100));
        assert_eq!(bookmark.get_type(), NOTE);
        assert_eq!(bookmark.get_category(), "");
        assert_eq!(bookmark.get_comment(), "");
        assert_eq!(bookmark.get_address(), Some(&test_address(0x100)));
    }

    #[test]
    fn new_with_explicit_values() {
        let bookmark = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x200));
        assert_eq!(bookmark.get_type(), "Info");
        assert_eq!(bookmark.get_category(), "cat");
        assert_eq!(bookmark.get_comment(), "hi");
    }

    #[test]
    fn empty_has_no_address() {
        let bookmark = OldBookmark::empty();
        assert_eq!(bookmark.get_type(), "");
        assert_eq!(bookmark.get_category(), "");
        assert_eq!(bookmark.get_comment(), "");
        assert_eq!(bookmark.get_address(), None);
    }

    #[test]
    fn with_address_copies_fields_at_new_address() {
        let original = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x100));
        let copy = OldBookmark::with_address(&original, test_address(0x200));
        assert_eq!(copy.get_type(), "Info");
        assert_eq!(copy.get_category(), "cat");
        assert_eq!(copy.get_comment(), "hi");
        assert_eq!(copy.get_address(), Some(&test_address(0x200)));
    }

    #[test]
    fn setters_update_category_and_comment() {
        let mut bookmark = OldBookmark::new(None, None, None, test_address(0x100));
        bookmark.set_category("cat2");
        bookmark.set_comment("comment2");
        assert_eq!(bookmark.get_category(), "cat2");
        assert_eq!(bookmark.get_comment(), "comment2");
    }

    #[test]
    fn set_context_resolves_pending_address_string() {
        let mut bookmark = OldBookmark::empty();
        let mut storage = StringStorage::new(vec![
            "cat".to_string(),
            "hi".to_string(),
            test_address(0x300).to_string(),
        ]);
        bookmark.restore(&mut storage);
        assert_eq!(bookmark.get_address(), None);

        let program = test_program();
        bookmark.set_context(&program, "Info");
        assert_eq!(bookmark.get_type(), "Info");
        assert_eq!(bookmark.get_address(), Some(&test_address(0x300)));
    }

    #[test]
    fn save_and_restore_round_trip() {
        let bookmark = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x400));

        let mut storage = StringStorage::new(Vec::new());
        bookmark.save(&mut storage);

        let mut restored = OldBookmark::empty();
        restored.restore(&mut storage);
        assert_eq!(restored.get_category(), "cat");
        assert_eq!(restored.get_comment(), "hi");
        assert_eq!(restored.get_address(), None);

        let program = test_program();
        restored.set_context(&program, "Info");
        assert_eq!(restored.get_address(), Some(&test_address(0x400)));
    }

    #[test]
    fn equals_compares_type_category_comment_and_address() {
        let a = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x100));
        let b = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x100));
        let c = OldBookmark::new(Some("Info"), Some("cat"), Some("bye"), test_address(0x100));
        let d = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x200));

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn get_schema_version_and_upgrade_are_fixed() {
        let mut bookmark = OldBookmark::empty();
        assert_eq!(bookmark.get_schema_version(), 0);
        assert!(!bookmark.is_upgradeable(0));
        assert!(!bookmark.is_private());

        let mut a = StringStorage::new(Vec::new());
        let mut b = StringStorage::new(Vec::new());
        assert!(!bookmark.upgrade(&mut a, 0, &mut b));
    }

    #[test]
    fn to_string_joins_category_and_comment() {
        let bookmark = OldBookmark::new(Some("Info"), Some("cat"), Some("hi"), test_address(0x100));
        assert_eq!(bookmark.to_string(), "cat/hi");
    }
}
