use crate::app::plugin::core::analysis::analysis_options_updater::AnalysisOptionsUpdater;
use crate::app::seam_stubs::MessageLog;
use crate::app::services::analysis_priority::AnalysisPriority;
use crate::app::services::analyzer_type::AnalyzerType;
use crate::framework::options::Options;
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Interface to perform automatic analysis.
///
/// NOTE: In the Java original, all analyzer implementation class names must end in "Analyzer",
/// or the `ClassSearcher` will not find them via classpath scanning. That constraint doesn't
/// apply here since Rust analyzers are registered explicitly rather than discovered by name.
///
/// Port of `ghidra.app.services.Analyzer`. The Java interface also extends `ExtensionPoint`, a
/// marker interface with no methods that exists solely to aid Ghidra's classpath scanner; it has
/// no Rust equivalent and is omitted.
pub trait Analyzer {
    /// Get the name of this analyzer.
    fn get_name(&self) -> String;

    /// Get the type of analysis this analyzer performs.
    fn get_analysis_type(&self) -> AnalyzerType;

    /// Returns true if this analyzer should be enabled by default. Generally useful analyzers
    /// should return true. Specialized analyzers should return false.
    fn get_default_enablement(&self, program: &dyn Program) -> bool;

    /// Returns true if it makes sense for this analyzer to be directly invoked on an address or
    /// address set. The AutoAnalyzer plug-in will automatically create an action for each
    /// analyzer that returns true.
    fn supports_one_time_analysis(&self) -> bool;

    /// Get a longer description of what this analyzer does.
    fn get_description(&self) -> String;

    /// Get the priority that this analyzer should run at.
    fn get_priority(&self) -> AnalysisPriority;

    /// Can this analyzer work on this program.
    fn can_analyze(&self, program: &dyn Program) -> bool;

    /// Called when the requested information type has been added, for example, when a function
    /// is added.
    ///
    /// Returns `Ok(true)` if the analysis succeeded, or `Err(CancelledException)` if the user
    /// cancelled the analysis.
    fn added(
        &mut self,
        program: &mut dyn Program,
        set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
        log: &mut dyn MessageLog,
    ) -> Result<bool, CancelledException>;

    /// Called when the requested information type has been removed, for example, when a function
    /// is removed.
    ///
    /// Returns `Ok(true)` if the analysis succeeded, or `Err(CancelledException)` if the user
    /// cancelled the analysis.
    fn removed(
        &mut self,
        program: &mut dyn Program,
        set: &dyn AddressSetView,
        monitor: &dyn TaskMonitor,
        log: &mut dyn MessageLog,
    ) -> Result<bool, CancelledException>;

    /// Analyzers should register their options with associated default value, help content and
    /// description.
    fn register_options(&self, options: &mut dyn Options, program: &dyn Program);

    /// Returns an optional options updater that allows clients to migrate old options to new
    /// options. Defaults to `None`, mirroring the Java default method's `null` return.
    fn get_options_updater(&self) -> Option<AnalysisOptionsUpdater> {
        None
    }

    /// Analyzers should initialize their options from the values in the given Options, providing
    /// appropriate default values.
    fn options_changed(&mut self, options: &dyn Options, program: &dyn Program);

    /// Called when an auto-analysis session ends. This notifies the analyzer so it can clean up
    /// any resources that only needed to be maintained during a single auto-analysis session.
    fn analysis_ended(&mut self, program: &dyn Program);

    /// Returns true if this analyzer is a prototype.
    fn is_prototype(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockProgram;

    impl crate::framework::model::DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    struct MockAddressSetView;

    impl AddressSetView for MockAddressSetView {
        fn contains(&self, _address: &crate::program::model::address::Address) -> bool {
            false
        }
        fn contains_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }
        fn is_empty(&self) -> bool {
            true
        }
        fn min_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn max_address(&self) -> Option<crate::program::model::address::Address> {
            None
        }
        fn num_address_ranges(&self) -> usize {
            0
        }
        fn address_ranges(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn address_ranges_ordered(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn address_ranges_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            Box::new(crate::program::model::address::EmptyAddressRangeIterator)
        }
        fn num_addresses(&self) -> u64 {
            0
        }
        fn addresses(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }
        fn addresses_from(
            &self,
            _start: &crate::program::model::address::Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressIterator> {
            Box::new(crate::program::model::address::EmptyAddressIterator)
        }
        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            false
        }
        fn intersects_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> bool {
            false
        }
        fn intersect(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn intersect_range(
            &self,
            _start: &crate::program::model::address::Address,
            _end: &crate::program::model::address::Address,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn union(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn subtract(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn xor(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            crate::program::model::address::AddressSet::new()
        }
        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            true
        }
        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }
        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            None
        }
        fn range_containing(
            &self,
            _address: &crate::program::model::address::Address,
        ) -> Option<crate::program::model::address::AddressRange> {
            None
        }
        fn find_first_address_in_common(
            &self,
            _set: &dyn AddressSetView,
        ) -> Option<crate::program::model::address::Address> {
            None
        }
    }

    struct MockMessageLog;

    impl MessageLog for MockMessageLog {}

    /// Minimal mock analyzer proving the trait is object-safe and usable via `Box<dyn Analyzer>`.
    struct MockAnalyzer {
        ended: bool,
    }

    impl Analyzer for MockAnalyzer {
        fn get_name(&self) -> String {
            "Mock Analyzer".to_string()
        }

        fn get_analysis_type(&self) -> AnalyzerType {
            AnalyzerType::FunctionAnalyzer
        }

        fn get_default_enablement(&self, _program: &dyn Program) -> bool {
            true
        }

        fn supports_one_time_analysis(&self) -> bool {
            false
        }

        fn get_description(&self) -> String {
            "A mock analyzer used for testing.".to_string()
        }

        fn get_priority(&self) -> AnalysisPriority {
            AnalysisPriority::function_analysis()
        }

        fn can_analyze(&self, _program: &dyn Program) -> bool {
            true
        }

        fn added(
            &mut self,
            _program: &mut dyn Program,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
            _log: &mut dyn MessageLog,
        ) -> Result<bool, CancelledException> {
            Ok(true)
        }

        fn removed(
            &mut self,
            _program: &mut dyn Program,
            _set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
            _log: &mut dyn MessageLog,
        ) -> Result<bool, CancelledException> {
            Ok(true)
        }

        fn register_options(&self, _options: &mut dyn Options, _program: &dyn Program) {}

        fn options_changed(&mut self, _options: &dyn Options, _program: &dyn Program) {}

        fn analysis_ended(&mut self, _program: &dyn Program) {
            self.ended = true;
        }

        fn is_prototype(&self) -> bool {
            false
        }
    }

    #[test]
    fn mock_analyzer_is_usable_as_trait_object() {
        let mut program = MockProgram;
        let set = MockAddressSetView;
        let mut log = MockMessageLog;

        let mut analyzer: Box<dyn Analyzer> = Box::new(MockAnalyzer { ended: false });

        assert_eq!(analyzer.get_name(), "Mock Analyzer");
        assert_eq!(analyzer.get_analysis_type(), AnalyzerType::FunctionAnalyzer);
        assert!(analyzer.get_default_enablement(&program));
        assert!(!analyzer.supports_one_time_analysis());
        assert_eq!(analyzer.get_priority(), AnalysisPriority::function_analysis());
        assert!(analyzer.can_analyze(&program));
        assert!(analyzer.get_options_updater().is_none());
        assert!(!analyzer.is_prototype());

        let monitor = crate::util::task::DummyMonitor;
        let added = analyzer.added(&mut program, &set, &monitor, &mut log);
        assert_eq!(added, Ok(true));

        analyzer.analysis_ended(&mut program);
    }
}
