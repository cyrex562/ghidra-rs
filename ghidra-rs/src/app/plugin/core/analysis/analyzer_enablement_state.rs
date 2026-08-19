use crate::app::services::Analyzer;

/// Row objects for the analyzer enablement table.
///
/// Maps to `ghidra.app.plugin.core.analysis.AnalyzerEnablementState`.
pub struct AnalyzerEnablementState {
    name: String,
    enabled: bool,
    default_enabled: bool,
    is_prototype: bool,
}

impl AnalyzerEnablementState {
    /// Creates a new analyzer enablement state from an analyzer and its current/default states.
    ///
    /// # Arguments
    ///
    /// * `analyzer` - The analyzer to extract name and prototype status from.
    /// * `enabled` - The current enablement state.
    /// * `default_enablement` - The default enablement state for this analyzer.
    pub fn new(analyzer: &dyn Analyzer, enabled: bool, default_enablement: bool) -> Self {
        Self {
            name: analyzer.get_name(),
            enabled,
            default_enabled: default_enablement,
            is_prototype: analyzer.is_prototype(),
        }
    }

    /// Returns the analyzer name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns if the analyzer is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns if the analyzer's enablement is the default enablement state.
    pub fn is_default_enablement(&self) -> bool {
        self.enabled == self.default_enabled
    }

    /// Returns true if the analyzer is a prototype.
    pub fn is_prototype(&self) -> bool {
        self.is_prototype
    }

    /// Sets the enablement state for the analyzer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::services::AnalyzerType;
    use crate::app::services::AnalysisPriority;
    use crate::util::exception::CancelledException;

    struct TestAnalyzer {
        name: String,
        is_prototype: bool,
    }

    impl Analyzer for TestAnalyzer {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_analysis_type(&self) -> AnalyzerType {
            AnalyzerType::FunctionAnalyzer
        }

        fn get_default_enablement(&self, _program: &dyn crate::program::model::listing::Program) -> bool {
            true
        }

        fn supports_one_time_analysis(&self) -> bool {
            false
        }

        fn get_description(&self) -> String {
            "Test analyzer".to_string()
        }

        fn get_priority(&self) -> AnalysisPriority {
            AnalysisPriority::function_analysis()
        }

        fn can_analyze(&self, _program: &dyn crate::program::model::listing::Program) -> bool {
            true
        }

        fn added(
            &mut self,
            _program: &mut dyn crate::program::model::listing::Program,
            _set: &dyn crate::program::model::address::AddressSetView,
            _monitor: &dyn crate::util::task::TaskMonitor,
            _log: &mut dyn crate::app::seam_stubs::MessageLog,
        ) -> Result<bool, CancelledException> {
            Ok(true)
        }

        fn removed(
            &mut self,
            _program: &mut dyn crate::program::model::listing::Program,
            _set: &dyn crate::program::model::address::AddressSetView,
            _monitor: &dyn crate::util::task::TaskMonitor,
            _log: &mut dyn crate::app::seam_stubs::MessageLog,
        ) -> Result<bool, CancelledException> {
            Ok(true)
        }

        fn register_options(&self, _options: &mut dyn crate::framework::options::Options, _program: &dyn crate::program::model::listing::Program) {}

        fn options_changed(&mut self, _options: &dyn crate::framework::options::Options, _program: &dyn crate::program::model::listing::Program) {}

        fn analysis_ended(&mut self, _program: &dyn crate::program::model::listing::Program) {}

        fn is_prototype(&self) -> bool {
            self.is_prototype
        }
    }

    fn make_analyzer(name: &str, is_prototype: bool) -> TestAnalyzer {
        TestAnalyzer {
            name: name.to_string(),
            is_prototype,
        }
    }

    #[test]
    fn constructor_captures_name_from_analyzer() {
        let analyzer = make_analyzer("TestAnalyzer", false);
        let state = AnalyzerEnablementState::new(&analyzer, true, true);
        assert_eq!(state.get_name(), "TestAnalyzer");
    }

    #[test]
    fn constructor_captures_is_prototype_from_analyzer() {
        let analyzer = make_analyzer("ProtoAnalyzer", true);
        let state = AnalyzerEnablementState::new(&analyzer, false, false);
        assert!(state.is_prototype());
    }

    #[test]
    fn is_enabled_returns_current_state() {
        let analyzer = make_analyzer("Analyzer", false);
        let state = AnalyzerEnablementState::new(&analyzer, true, false);
        assert!(state.is_enabled());

        let state2 = AnalyzerEnablementState::new(&analyzer, false, true);
        assert!(!state2.is_enabled());
    }

    #[test]
    fn is_default_enablement_when_current_equals_default() {
        let analyzer = make_analyzer("Analyzer", false);
        let state = AnalyzerEnablementState::new(&analyzer, true, true);
        assert!(state.is_default_enablement());
    }

    #[test]
    fn not_default_enablement_when_current_differs_from_default() {
        let analyzer = make_analyzer("Analyzer", false);
        let state = AnalyzerEnablementState::new(&analyzer, true, false);
        assert!(!state.is_default_enablement());

        let state2 = AnalyzerEnablementState::new(&analyzer, false, true);
        assert!(!state2.is_default_enablement());
    }

    #[test]
    fn set_enabled_updates_enabled_state() {
        let analyzer = make_analyzer("Analyzer", false);
        let mut state = AnalyzerEnablementState::new(&analyzer, false, true);
        assert!(!state.is_enabled());

        state.set_enabled(true);
        assert!(state.is_enabled());
    }

    #[test]
    fn set_enabled_affects_is_default_enablement() {
        let analyzer = make_analyzer("Analyzer", false);
        let mut state = AnalyzerEnablementState::new(&analyzer, false, true);
        assert!(!state.is_default_enablement());

        state.set_enabled(true);
        assert!(state.is_default_enablement());
    }

    #[test]
    fn prototype_analyzer() {
        let analyzer = make_analyzer("ProtoAnalyzer", true);
        let state = AnalyzerEnablementState::new(&analyzer, true, false);
        assert!(state.is_prototype());
        assert_eq!(state.get_name(), "ProtoAnalyzer");
        assert!(state.is_enabled());
        assert!(!state.is_default_enablement());
    }

    #[test]
    fn non_prototype_analyzer() {
        let analyzer = make_analyzer("StandardAnalyzer", false);
        let state = AnalyzerEnablementState::new(&analyzer, true, true);
        assert!(!state.is_prototype());
        assert_eq!(state.get_name(), "StandardAnalyzer");
        assert!(state.is_enabled());
        assert!(state.is_default_enablement());
    }
}
