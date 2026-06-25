/// Simple class to hold options for searching the text in Program.
#[derive(Clone, Debug)]
pub struct SearchOptions {
    text: String,
    functions: bool,
    comments: bool,
    labels: bool,
    instruction_mnemonics: bool,
    instruction_operands: bool,
    data_mnemonics: bool,
    data_operands: bool,
    case_sensitive: bool,
    direction: bool, // true --> Forward; false --> Backward
    search_all: bool, // true --> search all the fields
    include_non_loaded_blocks: bool,
    /// true --> do the search of the program database, vs. a string search of the fields
    database_search: bool,
    progress: i32, // state information for progress
}

impl SearchOptions {
    /// Constructor
    ///
    /// # Arguments
    ///
    /// * `text` - string to match
    /// * `database_search` - true to do database search (quick search)
    /// * `functions` - true to search for function text
    /// * `comments` - true to search comments
    /// * `labels` - true to search labels
    /// * `instruction_mnemonics` - true to search instruction mnemonics
    /// * `instruction_operands` - true to search instruction operands
    /// * `data_mnemonics` - true to search data mnemonics
    /// * `data_operands` - true to search data values
    /// * `case_sensitive` - true if search is to be case sensitive
    /// * `direction` - true means forward, false means backward search
    /// * `include_non_loaded_blocks` - true to include non-loaded memory blocks
    /// * `search_all` - true to search all the fields
    pub fn new(
        text: String,
        database_search: bool,
        functions: bool,
        comments: bool,
        labels: bool,
        instruction_mnemonics: bool,
        instruction_operands: bool,
        data_mnemonics: bool,
        data_operands: bool,
        case_sensitive: bool,
        direction: bool,
        include_non_loaded_blocks: bool,
        search_all: bool,
    ) -> Self {
        SearchOptions {
            text,
            functions,
            comments,
            labels,
            instruction_mnemonics,
            instruction_operands,
            data_mnemonics,
            data_operands,
            case_sensitive,
            direction,
            search_all,
            include_non_loaded_blocks,
            database_search,
            progress: 0,
        }
    }

    /// Constructor used when all fields should be searched. The direction is forward.
    ///
    /// # Arguments
    ///
    /// * `text` - string to match
    /// * `case_sensitive` - true if search is to be case sensitive
    /// * `direction` - true means forward, false means backward search
    /// * `include_non_loaded_blocks` - true to include non-loaded memory blocks
    pub fn new_search_all_fields(
        text: String,
        case_sensitive: bool,
        direction: bool,
        include_non_loaded_blocks: bool,
    ) -> Self {
        SearchOptions::new(
            text,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            case_sensitive,
            direction,
            include_non_loaded_blocks,
            true,
        )
    }

    /// Get the text that is the pattern to search for.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Return true if functions should be searched.
    pub fn search_functions(&self) -> bool {
        self.functions
    }

    /// Return true if labels should be searched.
    pub fn search_labels(&self) -> bool {
        self.labels
    }

    /// Return true if comments should be searched.
    pub fn search_comments(&self) -> bool {
        self.comments
    }

    /// Return true if both instruction mnemonics and operands should be searched.
    pub fn search_both_instruction_mnemonic_and_operands(&self) -> bool {
        self.instruction_mnemonics && self.instruction_operands
    }

    /// Return true if instruction mnemonics should be searched.
    pub fn search_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics
    }

    /// Return true if instruction operands should be searched.
    pub fn search_instruction_operands(&self) -> bool {
        self.instruction_operands
    }

    /// Return true if only instruction mnemonics (not operands) should be searched.
    pub fn search_only_instruction_mnemonics(&self) -> bool {
        self.instruction_mnemonics && !self.instruction_operands
    }

    /// Return true if only instruction operands (not mnemonics) should be searched.
    pub fn search_only_instruction_operands(&self) -> bool {
        self.instruction_operands && !self.instruction_mnemonics
    }

    /// Return true if both data mnemonics and operands should be searched.
    pub fn search_both_data_mnemonics_and_operands(&self) -> bool {
        self.data_mnemonics && self.data_operands
    }

    /// Return true if data mnemonics should be searched.
    pub fn search_data_mnemonics(&self) -> bool {
        self.data_mnemonics
    }

    /// Return true if data operands should be searched.
    pub fn search_data_operands(&self) -> bool {
        self.data_operands
    }

    /// Return true if only data mnemonics (not operands) should be searched.
    pub fn search_only_data_mnemonics(&self) -> bool {
        self.data_mnemonics && !self.data_operands
    }

    /// Return true if only data operands (not mnemonics) should be searched.
    pub fn search_only_data_operands(&self) -> bool {
        self.data_operands && !self.data_mnemonics
    }

    /// Return true if search should be case sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Return true if search is being done in the forward direction.
    pub fn is_forward(&self) -> bool {
        self.direction
    }

    /// Return true if all fields should be searched.
    pub fn search_all_fields(&self) -> bool {
        self.search_all
    }

    /// Return true if non-loaded memory blocks should be included.
    pub fn include_non_loaded_memory_blocks(&self) -> bool {
        self.include_non_loaded_blocks
    }

    /// Return whether the quick search option is on (database search).
    pub fn is_program_database_search(&self) -> bool {
        self.database_search
    }

    /// Set the progress value; used in subsequent searches to update the monitor.
    pub fn set_progress(&mut self, progress: i32) {
        self.progress = progress;
    }

    /// Get the progress value to add on to it for updating the progress in the search monitor.
    pub fn progress(&self) -> i32 {
        self.progress
    }
}

impl PartialEq for SearchOptions {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
            && self.case_sensitive == other.case_sensitive
            && self.comments == other.comments
            && self.data_mnemonics == other.data_mnemonics
            && self.data_operands == other.data_operands
            && self.direction == other.direction
            && self.functions == other.functions
            && self.instruction_mnemonics == other.instruction_mnemonics
            && self.instruction_operands == other.instruction_operands
            && self.labels == other.labels
            && self.database_search == other.database_search
            && self.search_all == other.search_all
            && self.include_non_loaded_blocks == other.include_non_loaded_blocks
    }
}

impl Eq for SearchOptions {}

impl std::hash::Hash for SearchOptions {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.text.hash(state);
        self.case_sensitive.hash(state);
        self.comments.hash(state);
        self.data_mnemonics.hash(state);
        self.data_operands.hash(state);
        self.direction.hash(state);
        self.functions.hash(state);
        self.instruction_mnemonics.hash(state);
        self.instruction_operands.hash(state);
        self.labels.hash(state);
        self.database_search.hash(state);
        self.search_all.hash(state);
        self.include_non_loaded_blocks.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_constructor() {
        let opts = SearchOptions::new(
            "test".to_string(),
            true,
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
        );

        assert_eq!(opts.text(), "test");
        assert!(opts.search_functions());
        assert!(!opts.search_comments());
        assert!(opts.search_labels());
        assert!(!opts.is_case_sensitive());
        assert!(opts.is_forward());
        assert!(!opts.include_non_loaded_memory_blocks());
        assert!(!opts.search_all_fields());
        assert!(opts.is_program_database_search());
    }

    #[test]
    fn test_new_search_all_fields() {
        let opts = SearchOptions::new_search_all_fields(
            "pattern".to_string(),
            true,
            false,
            true,
        );

        assert_eq!(opts.text(), "pattern");
        assert!(opts.is_case_sensitive());
        assert!(!opts.is_forward());
        assert!(opts.include_non_loaded_memory_blocks());
        assert!(opts.search_all_fields());
        assert!(!opts.is_program_database_search());
        assert!(!opts.search_functions());
        assert!(!opts.search_comments());
        assert!(!opts.search_labels());
    }

    #[test]
    fn test_instruction_search_combinations() {
        let both = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
        );
        assert!(both.search_both_instruction_mnemonic_and_operands());
        assert!(both.search_instruction_mnemonics());
        assert!(both.search_instruction_operands());
        assert!(!both.search_only_instruction_mnemonics());
        assert!(!both.search_only_instruction_operands());

        let mnemonics_only = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
        );
        assert!(!mnemonics_only.search_both_instruction_mnemonic_and_operands());
        assert!(mnemonics_only.search_instruction_mnemonics());
        assert!(!mnemonics_only.search_instruction_operands());
        assert!(mnemonics_only.search_only_instruction_mnemonics());
        assert!(!mnemonics_only.search_only_instruction_operands());

        let operands_only = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
        );
        assert!(!operands_only.search_both_instruction_mnemonic_and_operands());
        assert!(!operands_only.search_instruction_mnemonics());
        assert!(operands_only.search_instruction_operands());
        assert!(!operands_only.search_only_instruction_mnemonics());
        assert!(operands_only.search_only_instruction_operands());
    }

    #[test]
    fn test_data_search_combinations() {
        let both = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            true,
            false,
            true,
            false,
            false,
        );
        assert!(both.search_both_data_mnemonics_and_operands());
        assert!(both.search_data_mnemonics());
        assert!(both.search_data_operands());
        assert!(!both.search_only_data_mnemonics());
        assert!(!both.search_only_data_operands());

        let mnemonics_only = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
        );
        assert!(!mnemonics_only.search_both_data_mnemonics_and_operands());
        assert!(mnemonics_only.search_data_mnemonics());
        assert!(!mnemonics_only.search_data_operands());
        assert!(mnemonics_only.search_only_data_mnemonics());
        assert!(!mnemonics_only.search_only_data_operands());

        let operands_only = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
        );
        assert!(!operands_only.search_both_data_mnemonics_and_operands());
        assert!(!operands_only.search_data_mnemonics());
        assert!(operands_only.search_data_operands());
        assert!(!operands_only.search_only_data_mnemonics());
        assert!(operands_only.search_only_data_operands());
    }

    #[test]
    fn test_progress_methods() {
        let mut opts = SearchOptions::new(
            "test".to_string(),
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
        );

        assert_eq!(opts.progress(), 0);
        opts.set_progress(42);
        assert_eq!(opts.progress(), 42);
    }

    #[test]
    fn test_equality() {
        let opts1 = SearchOptions::new(
            "test".to_string(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
        );

        let opts2 = SearchOptions::new(
            "test".to_string(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
        );

        assert_eq!(opts1, opts2);
    }

    #[test]
    fn test_inequality() {
        let opts1 = SearchOptions::new(
            "test".to_string(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
        );

        let opts2 = SearchOptions::new(
            "test2".to_string(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
        );

        assert_ne!(opts1, opts2);
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;

        let opts1 = SearchOptions::new(
            "test".to_string(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
        );

        let opts2 = SearchOptions::new(
            "test".to_string(),
            true,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            false,
        );

        let mut set = HashSet::new();
        set.insert(opts1);
        assert!(set.contains(&opts2));
    }

    #[test]
    fn test_clone() {
        let original = SearchOptions::new(
            "test".to_string(),
            true,
            true,
            false,
            true,
            false,
            true,
            false,
            true,
            true,
            false,
            true,
            false,
        );

        let cloned = original.clone();
        assert_eq!(original, cloned);
    }
}
