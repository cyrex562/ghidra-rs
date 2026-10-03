//! Port of `sarif.export.dd.ExtCommentSet`.

use std::any::Any;
use std::collections::HashMap;

use crate::program::model::data::isf::{IsfObject, IsfSetting, IsfSettingValue};
use crate::program::model::listing::{CommentType, Data};
use crate::sarif::export::dd::ext_comment::ExtComment;

/// The five [`CommentType`] variants, in the same order Java's `CommentType.values()` iterates
/// them (declaration order; see [`CommentType`]'s own docs for why the ordinals must never
/// change).
const COMMENT_TYPES: [CommentType; 5] = [
    CommentType::Eol,
    CommentType::Pre,
    CommentType::Post,
    CommentType::Plate,
    CommentType::Repeatable,
];

/// A recursive collection of a [`Data`] value's comments and settings, plus (if any of its
/// sub-components have comments/settings/embedded sets of their own) a map of component index to
/// the same collection for that component.
///
/// Port of `sarif.export.dd.ExtCommentSet`.
///
/// # Deviations from Java
///
/// Java's `IsfSetting(String name, Object value)` constructor accepts an arbitrary `Object`,
/// `.toString()`s it for the stored value, and labels the `kind` `"string"` only when the runtime
/// value `instanceof String` (labeling everything else, even a `Boolean` or some other unrelated
/// type, `"long"` -- a real Java mislabeling quirk). This crate's already-ported [`IsfSetting`]
/// instead takes a pre-classified [`IsfSettingValue`] (`Str` or `Long`), which does not admit
/// arbitrary Object types. Since `Data`'s settings values realistically are only ever `String` or
/// `i64` in this crate's model (the same two kinds [`crate::docking::settings::settings::Settings`]
/// itself documents accessors for -- `get_string`/`get_long`), this port classifies a settings
/// value by downcasting to `String` then `i64`, and silently skips any value that's neither. A
/// value that arrives as some third type could not be faithfully mislabeled `"long"` (with its own
/// `toString()`) under the existing `IsfSetting` port's API shape without changing that already-
/// ported type, so this narrowing is the pragmatic choice; nothing in this crate's `Settings`
/// implementations currently stores a third kind of value here.
pub struct ExtCommentSet {
    pub comment: Option<Vec<ExtComment>>,
    pub setting: Option<Vec<IsfSetting>>,
    pub embedded: Option<HashMap<i32, ExtCommentSet>>,
}

impl ExtCommentSet {
    /// Java: `ExtCommentSet(Data data)`.
    pub fn new(data: &dyn Data) -> Self {
        let mut result = Self { comment: None, setting: None, embedded: None };
        result.export_comments(data);

        let n = data.get_num_components();
        if n > 0 {
            for i in 0..n {
                // Java's `data.getComponent(i)` for `i < n` is contractually never `null`; if this
                // crate's `get_component` ever returns `None` here regardless, this simply skips
                // that (contractually impossible) index rather than panicking.
                if let Some(component) = data.get_component(i) {
                    let cs = ExtCommentSet::new(component.as_ref());
                    if cs.comment.is_some() || cs.setting.is_some() || cs.embedded.is_some() {
                        result.embedded.get_or_insert_with(HashMap::new).insert(i, cs);
                    }
                }
            }
        }
        result
    }

    /// Java: private `void exportComments(Data data)`.
    fn export_comments(&mut self, data: &dyn Data) {
        for &comment_type in &COMMENT_TYPES {
            if data.get_comment(comment_type).is_some() {
                // Matches Java's own redundant re-fetch: `ExtComment`'s constructor calls
                // `data.getComment(type)` again internally.
                let isf = ExtComment::new(data, comment_type);
                self.comment.get_or_insert_with(Vec::new).push(isf);
            }
        }

        for name in data.get_names() {
            // Disambiguated: `Data` requires `Settings` as a supertrait, and both declare a
            // `get_value` method, so plain dot-call syntax is ambiguous.
            if let Some(value) = crate::docking::settings::settings::Settings::get_value(data, &name) {
                if let Some(setting_value) = classify_setting_value(value) {
                    let isf = IsfSetting::new(name, setting_value);
                    self.setting.get_or_insert_with(Vec::new).push(isf);
                }
            }
        }
    }
}

impl IsfObject for ExtCommentSet {}

/// Classifies a `Settings` value as an [`IsfSettingValue`]. See the struct docs for why this only
/// recognizes `String`/`i64`.
fn classify_setting_value(value: Box<dyn Any>) -> Option<IsfSettingValue> {
    match value.downcast::<String>() {
        Ok(s) => Some(IsfSettingValue::Str(*s)),
        Err(v) => v.downcast::<i64>().ok().map(|n| IsfSettingValue::Long(*n)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docking::settings::settings::Settings;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::register::Register;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::{MemBuffer, MemoryAccessException};
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType as SymRefType, Reference as SymReference, ReferenceIterator,
        SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{RefType, Reference};
    use std::any::TypeId;
    use std::sync::Arc;

    struct MockDataType;
    impl DataType for MockDataType {}

    fn mock_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    /// A configurable [`Data`] mock: fixed comments (by [`CommentType`]), fixed named settings
    /// values, and a list of child components (for recursion), enough to exercise
    /// [`ExtCommentSet::new`]'s full behavior without pulling in a real database. Follows the same
    /// approach as `ext_comment.rs`'s own `MockData` (each file in this crate defines its own,
    /// per this codebase's established convention), generalized to support multiple comments,
    /// settings, and children.
    struct MockData {
        comments: Vec<(CommentType, String)>,
        settings: Vec<(String, MockSettingValue)>,
        children: Vec<MockData>,
    }

    #[derive(Clone)]
    enum MockSettingValue {
        Str(String),
        Long(i64),
        Other,
    }

    impl MockData {
        fn empty() -> Self {
            Self { comments: Vec::new(), settings: Vec::new(), children: Vec::new() }
        }
    }

    impl MemBuffer for MockData {
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            mock_address(0)
        }
    }
    impl PropertySet for MockData {}

    impl CodeUnit for MockData {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            "00000000".to_string()
        }
        fn get_label(&self) -> Option<String> {
            None
        }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }
        fn get_min_address(&self) -> Address {
            mock_address(0)
        }
        fn get_max_address(&self) -> Address {
            mock_address(0)
        }
        fn get_mnemonic_string(&self) -> String {
            String::new()
        }
        fn get_comment(&self, comment_type: CommentType) -> Option<String> {
            self.comments.iter().find(|(t, _)| *t == comment_type).map(|(_, v)| v.clone())
        }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}
        fn get_length(&self) -> i32 {
            1
        }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(Vec::new())
        }
        fn get_bytes_in_code_unit(
            &self,
            _buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            Ok(())
        }
        fn contains(&self, _test_addr: &Address) -> bool {
            false
        }
        fn compare_to(&self, _addr: &Address) -> i32 {
            0
        }
        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn SymReference>> {
            None
        }
        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: SymRefType,
            _source_type: SourceType,
        ) {
        }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}
        fn get_references_from(&self) -> Vec<Arc<dyn SymReference>> {
            Vec::new()
        }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(crate::program::model::symbol::EmptyReferenceIterator)
        }
        fn get_program(&self) -> Arc<dyn Program> {
            struct MockProgram;
            impl crate::framework::model::DomainObject for MockProgram {}
            impl Program for MockProgram {
                fn get_name(&self) -> String {
                    "mock.bin".to_string()
                }
                fn get_language_id(&self) -> String {
                    "test:LE:32:default".to_string()
                }
            }
            Arc::new(MockProgram)
        }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }
        fn remove_external_reference(&mut self, _op_index: i32) {}
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn SymReference>) {}
        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &Register,
            _source_type: SourceType,
            _ref_type: SymRefType,
        ) {
        }
        fn get_num_operands(&self) -> i32 {
            1
        }
        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl Settings for MockData {
        fn get_value(&self, name: &str) -> Option<Box<dyn Any>> {
            self.settings.iter().find(|(n, _)| n == name).map(|(_, v)| match v {
                MockSettingValue::Str(s) => Box::new(s.clone()) as Box<dyn Any>,
                MockSettingValue::Long(n) => Box::new(*n) as Box<dyn Any>,
                MockSettingValue::Other => Box::new(3.14_f64) as Box<dyn Any>,
            })
        }

        fn get_names(&self) -> Vec<String> {
            self.settings.iter().map(|(n, _)| n.clone()).collect()
        }
    }

    impl Data for MockData {
        fn get_value(&self) -> Option<Box<dyn Any>> {
            None
        }
        fn get_value_class(&self) -> Option<TypeId> {
            None
        }
        fn has_string_value(&self) -> bool {
            false
        }
        fn is_constant(&self) -> bool {
            false
        }
        fn is_writable(&self) -> bool {
            true
        }
        fn is_volatile(&self) -> bool {
            false
        }
        fn is_defined(&self) -> bool {
            true
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_base_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn get_value_references(&self) -> Vec<Box<dyn Reference>> {
            Vec::new()
        }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn RefType>) {}
        fn remove_value_reference(&mut self, _ref_addr: Address) {}
        fn get_field_name(&self) -> Option<String> {
            None
        }
        fn get_path_name(&self) -> String {
            "mock".to_string()
        }
        fn get_component_path_name(&self) -> String {
            String::new()
        }
        fn is_pointer(&self) -> bool {
            false
        }
        fn is_union(&self) -> bool {
            false
        }
        fn is_structure(&self) -> bool {
            false
        }
        fn is_array(&self) -> bool {
            false
        }
        fn is_dynamic(&self) -> bool {
            false
        }
        fn get_parent(&self) -> Option<Box<dyn Data>> {
            None
        }
        fn get_root(&self) -> Box<dyn Data> {
            Box::new(MockData::empty())
        }
        fn get_root_offset(&self) -> i32 {
            0
        }
        fn get_parent_offset(&self) -> i32 {
            0
        }
        fn get_component(&self, index: i32) -> Option<Box<dyn Data>> {
            self.children.get(index as usize).map(|c| {
                Box::new(MockData {
                    comments: c.comments.clone(),
                    settings: c.settings.clone(),
                    children: c.children.iter().map(|gc| MockData {
                        comments: gc.comments.clone(),
                        settings: gc.settings.clone(),
                        children: Vec::new(),
                    }).collect(),
                }) as Box<dyn Data>
            })
        }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_path(&self) -> Vec<i32> {
            Vec::new()
        }
        fn get_num_components(&self) -> i32 {
            self.children.len() as i32
        }
        #[allow(deprecated)]
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> {
            None
        }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> {
            None
        }
        fn get_component_index(&self) -> i32 {
            -1
        }
        fn get_component_level(&self) -> i32 {
            0
        }
        fn get_default_value_representation(&self) -> String {
            String::new()
        }
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> {
            None
        }
    }

    impl Clone for MockData {
        fn clone(&self) -> Self {
            MockData {
                comments: self.comments.clone(),
                settings: self.settings.clone(),
                children: self.children.iter().map(|c| MockData {
                    comments: c.comments.clone(),
                    settings: c.settings.clone(),
                    children: Vec::new(),
                }).collect(),
            }
        }
    }

    #[test]
    fn no_comments_settings_or_components_yields_all_none() {
        let data = MockData::empty();
        let set = ExtCommentSet::new(&data);
        assert!(set.comment.is_none());
        assert!(set.setting.is_none());
        assert!(set.embedded.is_none());
    }

    #[test]
    fn collects_every_present_comment_type() {
        let data = MockData {
            comments: vec![
                (CommentType::Eol, "eol".to_string()),
                (CommentType::Plate, "plate".to_string()),
            ],
            settings: Vec::new(),
            children: Vec::new(),
        };
        let set = ExtCommentSet::new(&data);
        let comments = set.comment.expect("expected comments");
        assert_eq!(comments.len(), 2);
        // `comment_type` is `CommentsSarifMgr::get_comment_type_string`'s short SARIF tag
        // ("end-of-line"/"plate"), not an English display label.
        assert_eq!(comments[0].comment_type, "end-of-line");
        assert_eq!(comments[0].comment.as_deref(), Some("eol"));
        assert_eq!(comments[1].comment_type, "plate");
        assert_eq!(comments[1].comment.as_deref(), Some("plate"));
    }

    #[test]
    fn collects_string_and_long_settings() {
        let data = MockData {
            comments: Vec::new(),
            settings: vec![
                ("arch".to_string(), MockSettingValue::Str("x86_64".to_string())),
                ("base".to_string(), MockSettingValue::Long(42)),
            ],
            children: Vec::new(),
        };
        let set = ExtCommentSet::new(&data);
        let settings = set.setting.expect("expected settings");
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].name, "arch");
        assert_eq!(settings[0].kind, "string");
        assert_eq!(settings[0].value, "x86_64");
        assert_eq!(settings[1].name, "base");
        assert_eq!(settings[1].kind, "long");
        assert_eq!(settings[1].value, "42");
    }

    #[test]
    fn unrecognized_setting_value_type_is_skipped() {
        let data = MockData {
            comments: Vec::new(),
            settings: vec![("weird".to_string(), MockSettingValue::Other)],
            children: Vec::new(),
        };
        let set = ExtCommentSet::new(&data);
        assert!(set.setting.is_none());
    }

    #[test]
    fn embedded_only_includes_components_with_content() {
        let empty_child = MockData::empty();
        let commented_child = MockData {
            comments: vec![(CommentType::Eol, "child eol".to_string())],
            settings: Vec::new(),
            children: Vec::new(),
        };
        let data = MockData {
            comments: Vec::new(),
            settings: Vec::new(),
            children: vec![empty_child, commented_child],
        };

        let set = ExtCommentSet::new(&data);
        let embedded = set.embedded.expect("expected an embedded map");

        // Only index 1 (the commented child) is present -- index 0 (empty) is skipped.
        assert_eq!(embedded.len(), 1);
        assert!(!embedded.contains_key(&0));
        let child_set = embedded.get(&1).expect("index 1 present");
        let child_comments = child_set.comment.as_ref().expect("child has comments");
        assert_eq!(child_comments[0].comment.as_deref(), Some("child eol"));
    }

    #[test]
    fn no_components_have_content_yields_no_embedded_map() {
        let data = MockData {
            comments: Vec::new(),
            settings: Vec::new(),
            children: vec![MockData::empty(), MockData::empty()],
        };
        let set = ExtCommentSet::new(&data);
        assert!(set.embedded.is_none());
    }

    #[test]
    fn implements_isf_object() {
        fn accepts_isf_object<T: IsfObject>(_: &T) {}
        let data = MockData::empty();
        let set = ExtCommentSet::new(&data);
        accepts_isf_object(&set);
    }
}
