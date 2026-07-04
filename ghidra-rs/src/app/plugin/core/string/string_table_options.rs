use std::sync::Arc;

use crate::program::model::address::AddressSetView;

/// Options controlling how the string table search collects and filters
/// candidate strings.
pub struct StringTableOptions {
    min_string_size: i32,
    alignment: i32,
    include_all_char_sizes: bool,
    null_termination_required: bool,
    include_undefined_strings: bool,
    include_defined_strings: bool,
    only_show_word_strings: bool,
    address_set: Option<Arc<dyn AddressSetView>>,
    require_pascal: bool,
    include_partially_defined_strings: bool,
    include_conflicting_strings: bool,
    word_model_file: String,
    word_model_initialized: bool,
    loaded_blocks_only: bool,
}

impl Default for StringTableOptions {
    fn default() -> Self {
        StringTableOptions {
            min_string_size: 5,
            alignment: 1,
            include_all_char_sizes: true,
            null_termination_required: true,
            include_undefined_strings: true,
            include_defined_strings: true,
            only_show_word_strings: false,
            address_set: None,
            require_pascal: false,
            include_partially_defined_strings: true,
            include_conflicting_strings: true,
            word_model_file: String::new(),
            word_model_initialized: false,
            loaded_blocks_only: false,
        }
    }
}

impl StringTableOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn use_loaded_blocks_only(&self) -> bool {
        self.loaded_blocks_only
    }

    pub fn set_use_loaded_blocks_only(&mut self, loaded_blocks_only: bool) {
        self.loaded_blocks_only = loaded_blocks_only;
    }

    pub fn get_min_string_size(&self) -> i32 {
        self.min_string_size
    }

    pub fn get_alignment(&self) -> i32 {
        self.alignment
    }

    pub fn get_include_all_char_sizes(&self) -> bool {
        self.include_all_char_sizes
    }

    pub fn get_word_model_file(&self) -> &str {
        &self.word_model_file
    }

    pub fn get_word_model_initialized(&self) -> bool {
        self.word_model_initialized
    }

    pub fn is_null_termination_required(&self) -> bool {
        self.null_termination_required
    }

    pub fn include_undefined_strings(&self) -> bool {
        self.include_undefined_strings
    }

    pub fn include_defined_strings(&self) -> bool {
        self.include_defined_strings
    }

    pub fn include_partially_defined_strings(&self) -> bool {
        self.include_partially_defined_strings
    }

    pub fn include_conflicting_strings(&self) -> bool {
        self.include_conflicting_strings
    }

    pub fn only_show_word_strings(&self) -> bool {
        self.only_show_word_strings
    }

    pub fn set_null_termination_required(&mut self, required: bool) {
        self.null_termination_required = required;
    }

    pub fn set_min_string_size(&mut self, min_string_size: i32) {
        self.min_string_size = min_string_size;
    }

    pub fn set_alignment(&mut self, alignment: i32) {
        self.alignment = alignment;
    }

    pub fn set_include_all_char_sizes(&mut self, include_all_char_sizes: bool) {
        self.include_all_char_sizes = include_all_char_sizes;
    }

    pub fn set_include_undefined_strings(&mut self, include_undefined_strings: bool) {
        self.include_undefined_strings = include_undefined_strings;
    }

    pub fn set_include_defined_strings(&mut self, include_defined_strings: bool) {
        self.include_defined_strings = include_defined_strings;
    }

    pub fn set_only_show_word_strings(&mut self, only_show_word_strings: bool) {
        self.only_show_word_strings = only_show_word_strings;
    }

    pub fn get_address_set(&self) -> Option<Arc<dyn AddressSetView>> {
        self.address_set.clone()
    }

    pub fn set_address_set(&mut self, address_set: Option<Arc<dyn AddressSetView>>) {
        self.address_set = address_set;
    }

    pub fn set_require_pascal(&mut self, require_pascal: bool) {
        self.require_pascal = require_pascal;
    }

    pub fn is_pascal_required(&self) -> bool {
        self.require_pascal
    }

    pub fn set_include_partially_defined_strings(
        &mut self,
        include_partially_defined_strings: bool,
    ) {
        self.include_partially_defined_strings = include_partially_defined_strings;
    }

    pub fn set_include_conflicting_strings(&mut self, include_conflicting_strings: bool) {
        self.include_conflicting_strings = include_conflicting_strings;
    }

    pub fn set_word_model_file(&mut self, word_model_file: String) {
        self.word_model_file = word_model_file;
    }

    pub fn set_word_model_initialized(&mut self, word_model_initialized: bool) {
        self.word_model_initialized = word_model_initialized;
    }

    pub fn copy(&self) -> StringTableOptions {
        let mut options = StringTableOptions::new();
        options.set_min_string_size(self.min_string_size);
        options.set_address_set(self.address_set.clone());
        options.set_alignment(self.alignment);
        options.set_require_pascal(self.require_pascal);
        options.set_null_termination_required(self.null_termination_required);
        options.set_include_all_char_sizes(self.include_all_char_sizes);
        options.set_include_conflicting_strings(self.include_conflicting_strings);
        options.set_include_undefined_strings(self.include_undefined_strings);
        options.set_include_defined_strings(self.include_defined_strings);
        options.set_include_partially_defined_strings(self.include_partially_defined_strings);
        options.set_only_show_word_strings(self.only_show_word_strings);
        options.set_word_model_file(self.word_model_file.clone());
        options.set_word_model_initialized(self.word_model_initialized);

        options
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let options = StringTableOptions::new();
        assert_eq!(options.get_min_string_size(), 5);
        assert_eq!(options.get_alignment(), 1);
        assert!(options.get_include_all_char_sizes());
        assert!(options.is_null_termination_required());
        assert!(options.include_undefined_strings());
        assert!(options.include_defined_strings());
        assert!(!options.only_show_word_strings());
        assert!(options.get_address_set().is_none());
        assert!(!options.is_pascal_required());
        assert!(options.include_partially_defined_strings());
        assert!(options.include_conflicting_strings());
        assert_eq!(options.get_word_model_file(), "");
        assert!(!options.get_word_model_initialized());
        assert!(!options.use_loaded_blocks_only());
    }

    #[test]
    fn test_setters_and_getters() {
        let mut options = StringTableOptions::new();
        options.set_min_string_size(10);
        options.set_alignment(4);
        options.set_include_all_char_sizes(false);
        options.set_null_termination_required(false);
        options.set_include_undefined_strings(false);
        options.set_include_defined_strings(false);
        options.set_only_show_word_strings(true);
        options.set_require_pascal(true);
        options.set_include_partially_defined_strings(false);
        options.set_include_conflicting_strings(false);
        options.set_word_model_file("model.txt".to_string());
        options.set_word_model_initialized(true);
        options.set_use_loaded_blocks_only(true);

        assert_eq!(options.get_min_string_size(), 10);
        assert_eq!(options.get_alignment(), 4);
        assert!(!options.get_include_all_char_sizes());
        assert!(!options.is_null_termination_required());
        assert!(!options.include_undefined_strings());
        assert!(!options.include_defined_strings());
        assert!(options.only_show_word_strings());
        assert!(options.is_pascal_required());
        assert!(!options.include_partially_defined_strings());
        assert!(!options.include_conflicting_strings());
        assert_eq!(options.get_word_model_file(), "model.txt");
        assert!(options.get_word_model_initialized());
        assert!(options.use_loaded_blocks_only());
    }

    #[test]
    fn test_copy_produces_independent_equivalent_instance() {
        let mut options = StringTableOptions::new();
        options.set_min_string_size(20);
        options.set_alignment(2);
        options.set_word_model_file("trained.model".to_string());
        options.set_word_model_initialized(true);
        options.set_only_show_word_strings(true);

        let copy = options.copy();
        assert_eq!(copy.get_min_string_size(), 20);
        assert_eq!(copy.get_alignment(), 2);
        assert_eq!(copy.get_word_model_file(), "trained.model");
        assert!(copy.get_word_model_initialized());
        assert!(copy.only_show_word_strings());

        // Mutating the copy should not affect the original.
        let mut copy = copy;
        copy.set_min_string_size(99);
        assert_eq!(options.get_min_string_size(), 20);
        assert_eq!(copy.get_min_string_size(), 99);
    }
}
