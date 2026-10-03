use crate::app::plugin::core::searchtext::search_options::SearchOptions;
use crate::program::util::program_location::ProgramLocation;
use crate::util::task::TaskMonitor;

/// A record object that represents a single search result.
///
/// Port of `ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult`.
pub struct TextSearchResult {
    /// The program location of the search result.
    pub program_location: Box<dyn ProgramLocation>,
    /// The offset in the *model*'s text of the search result; this value will be from 0 to
    /// `text.length()`, where text is a single string for all text in the given field.
    pub offset: i32,
}

impl TextSearchResult {
    /// Creates a new `TextSearchResult`.
    pub fn new(program_location: Box<dyn ProgramLocation>, offset: i32) -> Self {
        Self { program_location, offset }
    }

    /// Returns the program location of the search result. Mirrors the record accessor
    /// `programLocation()`.
    pub fn program_location(&self) -> &dyn ProgramLocation {
        self.program_location.as_ref()
    }

    /// Returns the offset in the model's text of the search result. Mirrors the record accessor
    /// `offset()`.
    pub fn offset(&self) -> i32 {
        self.offset
    }
}

/// Search the program text.
///
/// Port of `ghidra.app.plugin.core.searchtext.Searcher`.
pub trait Searcher {
    /// Get the next program location, or `None` if there is no next program location. Mirrors
    /// `search()`.
    fn search(&mut self) -> Option<TextSearchResult>;

    /// Set the task monitor that allows the search to be canceled. Mirrors `setMonitor
    /// (TaskMonitor)`.
    fn set_monitor(&mut self, monitor: Box<dyn TaskMonitor>);

    /// Return the search options associated with this Searcher. Mirrors `getSearchOptions()`.
    fn get_search_options(&self) -> SearchOptions;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::Program;
    use crate::util::task::DummyMonitor;
    use std::sync::Arc;

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    struct FixedLocation {
        address: Address,
    }

    impl ProgramLocation for FixedLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
    }

    fn test_address(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    /// Searcher over a fixed list of addresses, each reported once with an incrementing offset.
    struct ListSearcher {
        remaining: Vec<i64>,
        options: SearchOptions,
        monitor: Option<Box<dyn TaskMonitor>>,
        next_offset: i32,
    }

    impl ListSearcher {
        fn new(addresses: Vec<i64>, options: SearchOptions) -> Self {
            Self { remaining: addresses, options, monitor: None, next_offset: 0 }
        }
    }

    impl Searcher for ListSearcher {
        fn search(&mut self) -> Option<TextSearchResult> {
            if self.remaining.is_empty() {
                return None;
            }
            let offset_val = self.remaining.remove(0);
            let result = TextSearchResult::new(
                Box::new(FixedLocation { address: test_address(offset_val) }),
                self.next_offset,
            );
            self.next_offset += 1;
            Some(result)
        }

        fn set_monitor(&mut self, monitor: Box<dyn TaskMonitor>) {
            self.monitor = Some(monitor);
        }

        fn get_search_options(&self) -> SearchOptions {
            self.options.clone()
        }
    }

    fn options() -> SearchOptions {
        SearchOptions::new(
            "needle".to_string(),
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
        )
    }

    #[test]
    fn text_search_result_accessors() {
        let result = TextSearchResult::new(
            Box::new(FixedLocation { address: test_address(0x100) }),
            7,
        );
        assert_eq!(result.offset(), 7);
        assert_eq!(result.program_location().get_address(), test_address(0x100));
    }

    #[test]
    fn search_returns_results_then_none() {
        let mut searcher = ListSearcher::new(vec![0x10, 0x20], options());
        let first = searcher.search().expect("first result");
        assert_eq!(first.offset(), 0);
        assert_eq!(first.program_location().get_address(), test_address(0x10));

        let second = searcher.search().expect("second result");
        assert_eq!(second.offset(), 1);
        assert_eq!(second.program_location().get_address(), test_address(0x20));

        assert!(searcher.search().is_none());
    }

    #[test]
    fn set_monitor_stores_monitor() {
        let mut searcher = ListSearcher::new(vec![], options());
        searcher.set_monitor(Box::new(DummyMonitor));
        assert!(searcher.monitor.is_some());
    }

    #[test]
    fn get_search_options_returns_configured_options() {
        let searcher = ListSearcher::new(vec![], options());
        let opts = searcher.get_search_options();
        assert_eq!(opts.text(), "needle");
        assert!(opts.is_case_sensitive());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mut searcher: Box<dyn Searcher> = Box::new(ListSearcher::new(vec![0x1], options()));
        assert!(searcher.search().is_some());
    }
}
