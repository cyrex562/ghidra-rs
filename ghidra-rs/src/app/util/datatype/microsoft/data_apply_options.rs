/// Options controlling how data structures are applied to a program.
///
/// Mirrors `ghidra.app.util.datatype.microsoft.DataApplyOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataApplyOptions {
    pub follow_data: bool,
    pub clear_instructions: bool,
    pub clear_defined_data: bool,
    pub create_label: bool,
    pub create_function: bool,
    pub create_bookmarks: bool,
    pub create_comments: bool,
}

impl Default for DataApplyOptions {
    fn default() -> Self {
        Self {
            follow_data: true,
            clear_instructions: false,
            clear_defined_data: true,
            create_label: true,
            create_function: true,
            create_bookmarks: true,
            create_comments: true,
        }
    }
}

impl DataApplyOptions {
    /// Creates a `DataApplyOptions` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if data referred to by a structure should also be created.
    pub fn should_follow_data(&self) -> bool {
        self.follow_data
    }

    /// Sets whether follow-on data referred to by the structure should be created.
    pub fn set_follow_data(&mut self, follow_data: bool) {
        self.follow_data = follow_data;
    }

    /// Returns `true` if existing instructions should be cleared to make room for new data.
    pub fn should_clear_instructions(&self) -> bool {
        self.clear_instructions
    }

    /// Sets whether existing instructions should be cleared to create new data.
    pub fn set_clear_instructions(&mut self, clear_instructions: bool) {
        self.clear_instructions = clear_instructions;
    }

    /// Returns `true` if existing defined data should be cleared to create new data.
    pub fn should_clear_defined_data(&self) -> bool {
        self.clear_defined_data
    }

    /// Sets whether existing defined data should be cleared to create new data.
    pub fn set_clear_defined_data(&mut self, clear_defined_data: bool) {
        self.clear_defined_data = clear_defined_data;
    }

    /// Returns `true` if a label should be created for new data or referred-to structures.
    pub fn should_create_label(&self) -> bool {
        self.create_label
    }

    /// Sets whether labels should be created for new data or referred-to structures.
    pub fn set_create_label(&mut self, create_label: bool) {
        self.create_label = create_label;
    }

    /// Returns `true` if referred-to functions should be disassembled and created.
    pub fn should_create_function(&self) -> bool {
        self.create_function
    }

    /// Sets whether referred-to functions should be disassembled and created.
    pub fn set_create_function(&mut self, create_function: bool) {
        self.create_function = create_function;
    }

    /// Returns `true` if bookmarks should be created for problems encountered during creation.
    pub fn should_create_bookmarks(&self) -> bool {
        self.create_bookmarks
    }

    /// Sets whether error bookmarks should be created during structure creation.
    pub fn set_create_bookmarks(&mut self, create_bookmarks: bool) {
        self.create_bookmarks = create_bookmarks;
    }

    /// Returns `true` if comments should be created for problems encountered during creation.
    pub fn should_create_comments(&self) -> bool {
        self.create_comments
    }

    /// Sets whether error comments should be created during structure creation.
    pub fn set_create_comments(&mut self, create_comments: bool) {
        self.create_comments = create_comments;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_values() {
        let opts = DataApplyOptions::new();
        assert!(opts.should_follow_data());
        assert!(!opts.should_clear_instructions());
        assert!(opts.should_clear_defined_data());
        assert!(opts.should_create_label());
        assert!(opts.should_create_function());
        assert!(opts.should_create_bookmarks());
        assert!(opts.should_create_comments());
    }

    #[test]
    fn test_clone_is_equal() {
        let opts = DataApplyOptions::new();
        let cloned = opts.clone();
        assert_eq!(opts, cloned);
    }

    #[test]
    fn test_setters() {
        let mut opts = DataApplyOptions::new();

        opts.set_follow_data(false);
        assert!(!opts.should_follow_data());

        opts.set_clear_instructions(true);
        assert!(opts.should_clear_instructions());

        opts.set_clear_defined_data(false);
        assert!(!opts.should_clear_defined_data());

        opts.set_create_label(false);
        assert!(!opts.should_create_label());

        opts.set_create_function(false);
        assert!(!opts.should_create_function());

        opts.set_create_bookmarks(false);
        assert!(!opts.should_create_bookmarks());

        opts.set_create_comments(false);
        assert!(!opts.should_create_comments());
    }

    #[test]
    fn test_clone_is_independent() {
        let original = DataApplyOptions::new();
        let mut copy = original.clone();
        copy.set_follow_data(false);
        assert!(original.should_follow_data());
        assert!(!copy.should_follow_data());
    }

    #[test]
    fn test_debug() {
        let opts = DataApplyOptions::new();
        let s = format!("{:?}", opts);
        assert!(s.contains("DataApplyOptions"));
    }
}
