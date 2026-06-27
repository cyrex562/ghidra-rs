/// Options for the DyldCacheLoader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DyldCacheOptions {
    /// True if slide pointers should be fixed up.
    pub fixup_slide_pointers: bool,
    /// True if slide pointers should be marked up.
    pub markup_slide_pointers: bool,
    /// True if slide pointers should be added to the relocation table.
    pub add_slide_pointer_relocations: bool,
    /// True if local symbols should be processed.
    pub process_local_symbols: bool,
    /// True if local symbols should be marked up.
    pub markup_local_symbols: bool,
    /// True if individual dylib memory should be processed.
    pub process_dylib_memory: bool,
    /// True if individual dylib symbols should be processed.
    pub process_dylib_symbols: bool,
    /// True if individual dylib exports should be processed.
    pub process_dylib_exports: bool,
    /// True if individual dylib load command data blocks should be marked up.
    pub markup_dylib_load_command_data: bool,
    /// True if special libobjc processing should occur.
    pub process_libobjc: bool,
}

impl DyldCacheOptions {
    pub fn new(
        fixup_slide_pointers: bool,
        markup_slide_pointers: bool,
        add_slide_pointer_relocations: bool,
        process_local_symbols: bool,
        markup_local_symbols: bool,
        process_dylib_memory: bool,
        process_dylib_symbols: bool,
        process_dylib_exports: bool,
        markup_dylib_load_command_data: bool,
        process_libobjc: bool,
    ) -> Self {
        Self {
            fixup_slide_pointers,
            markup_slide_pointers,
            add_slide_pointer_relocations,
            process_local_symbols,
            markup_local_symbols,
            process_dylib_memory,
            process_dylib_symbols,
            process_dylib_exports,
            markup_dylib_load_command_data,
            process_libobjc,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_true() {
        let opts = DyldCacheOptions::new(true, true, true, true, true, true, true, true, true, true);
        assert!(opts.fixup_slide_pointers);
        assert!(opts.markup_slide_pointers);
        assert!(opts.add_slide_pointer_relocations);
        assert!(opts.process_local_symbols);
        assert!(opts.markup_local_symbols);
        assert!(opts.process_dylib_memory);
        assert!(opts.process_dylib_symbols);
        assert!(opts.process_dylib_exports);
        assert!(opts.markup_dylib_load_command_data);
        assert!(opts.process_libobjc);
    }

    #[test]
    fn test_all_false() {
        let opts =
            DyldCacheOptions::new(false, false, false, false, false, false, false, false, false, false);
        assert!(!opts.fixup_slide_pointers);
        assert!(!opts.markup_slide_pointers);
        assert!(!opts.add_slide_pointer_relocations);
        assert!(!opts.process_local_symbols);
        assert!(!opts.markup_local_symbols);
        assert!(!opts.process_dylib_memory);
        assert!(!opts.process_dylib_symbols);
        assert!(!opts.process_dylib_exports);
        assert!(!opts.markup_dylib_load_command_data);
        assert!(!opts.process_libobjc);
    }

    #[test]
    fn test_mixed_flags() {
        let opts =
            DyldCacheOptions::new(true, false, true, false, true, false, true, false, true, false);
        assert!(opts.fixup_slide_pointers);
        assert!(!opts.markup_slide_pointers);
        assert!(opts.add_slide_pointer_relocations);
        assert!(!opts.process_local_symbols);
        assert!(opts.markup_local_symbols);
        assert!(!opts.process_dylib_memory);
        assert!(opts.process_dylib_symbols);
        assert!(!opts.process_dylib_exports);
        assert!(opts.markup_dylib_load_command_data);
        assert!(!opts.process_libobjc);
    }

    #[test]
    fn test_clone_and_equality() {
        let opts = DyldCacheOptions::new(true, false, true, false, true, false, true, false, true, false);
        let cloned = opts;
        assert_eq!(opts, cloned);
    }
}
