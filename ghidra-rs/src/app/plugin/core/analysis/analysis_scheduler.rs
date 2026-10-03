//! Port of `ghidra.app.plugin.core.analysis.AnalysisScheduler`: accumulates the address sets an
//! analyzer has been told about and schedules an [`AnalysisTask`] to run it.
//!
//! # Ownership
//!
//! Java's scheduler holds its `AutoAnalysisManager` and hands `this` to each `AnalysisTask` it
//! schedules. Here the manager owns its schedulers in an arena keyed by [`SchedulerId`]; a task
//! carries the id, and the manager passes the scheduler (and the program) in when the task runs.
//! Where Java calls `analysisMgr.schedule(...)` from inside the scheduler, the scheduler returns
//! the task to schedule and the manager queues it. The program the Java scheduler reached through
//! its manager is a call-time argument.
use slotmap::new_key_type;

use crate::app::plugin::core::analysis::analysis_task::AnalysisTask;
use crate::app::services::analyzer::Analyzer;
use crate::app::util::importer::message_log::MessageLog;
use crate::framework::options::Options;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::Program;
use crate::util::exception::CancelledException;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

new_key_type! {
    /// Identifies an [`AnalysisScheduler`] in its manager's arena.
    pub struct SchedulerId;
}

/// Error constructing a scheduler. Mirrors the constructor's `IllegalArgumentException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAnalyzerName(pub String);

impl std::fmt::Display for InvalidAnalyzerName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Analyzer name may not contain a period: {}", self.0)
    }
}

impl std::error::Error for InvalidAnalyzerName {}

/// Schedules one analyzer. Mirrors `AnalysisScheduler`.
pub struct AnalysisScheduler {
    analyzer: Box<dyn Analyzer>,
    remove_set: AddressSet,
    add_set: AddressSet,
    default_enablement: bool,
    enabled: bool,
    scheduled: bool,
}

impl AnalysisScheduler {
    /// Mirrors the constructor: fails for an analyzer whose name contains a period (it would not
    /// appear in the options panel); starts enabled per the analyzer's default enablement for
    /// `program`, as overridden by the language's properties.
    pub fn new(
        analyzer: Box<dyn Analyzer>,
        program: &dyn Program,
    ) -> Result<Self, InvalidAnalyzerName> {
        let name = analyzer.get_name();
        if name.contains('.') {
            // Use of period will cause analyzer not to appear in options panel
            return Err(InvalidAnalyzerName(name));
        }
        let default_enablement = Self::compute_default_enablement(analyzer.as_ref(), program);
        Ok(AnalysisScheduler {
            analyzer,
            remove_set: AddressSet::new(),
            add_set: AddressSet::new(),
            default_enablement,
            enabled: default_enablement,
            scheduled: false,
        })
    }

    /// Mirrors the private `getDefaultEnablement()`.
    fn compute_default_enablement(analyzer: &dyn Analyzer, program: &dyn Program) -> bool {
        let mut default_enable = analyzer.get_default_enablement(program);
        let override_enable = Self::get_enable_override(analyzer, program, default_enable);
        if default_enable != override_enable {
            Msg::warn(
                "AnalysisScheduler",
                &format!(
                    "Analyzer '{}' for {} {} by PSPEC file override",
                    analyzer.get_name(),
                    Program::get_name(program),
                    if override_enable { "enabled" } else { "disabled" }
                ),
            );
            default_enable = override_enable;
        }
        default_enable
    }

    /// Mirrors the private `getEnableOverride(boolean)`: the language property
    /// `Analyzers.<name>` wins; otherwise `DisableAllAnalyzers` disables.
    fn get_enable_override(analyzer: &dyn Analyzer, program: &dyn Program, default_enable: bool) -> bool {
        let Some(language) = program.get_language() else {
            return default_enable;
        };
        // get the overall disable property
        let all_overridden = language.has_property("DisableAllAnalyzers");
        // let individual analyzers be turned off or on
        let property_name = format!("Analyzers.{}", analyzer.get_name());
        if language.has_property(&property_name) {
            language.get_property_as_boolean(&property_name, default_enable)
        } else if all_overridden {
            false
        } else {
            default_enable
        }
    }

    /// Whether the analyzer is enabled by default (after overrides).
    pub fn get_default_enablement(&self) -> bool {
        self.default_enablement
    }

    /// Whether the analyzer is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a task for this scheduler is queued.
    pub fn is_scheduled(&self) -> bool {
        self.scheduled
    }

    /// Mirrors `schedule()`: if not already scheduled and there is work, mark scheduled and
    /// return the task (and its priority) for the manager to queue.
    pub fn schedule(&mut self, id: SchedulerId) -> Option<(AnalysisTask, i32)> {
        // if not scheduled right now, schedule it
        if !self.scheduled && (!self.add_set.is_empty() || !self.remove_set.is_empty()) {
            self.scheduled = true;
            return Some((AnalysisTask::new(id, self.get_name()), self.get_priority()));
        }
        None
    }

    /// Mirrors `added(AddressSetView)`.
    pub fn added(&mut self, id: SchedulerId, set: &dyn AddressSetView) -> Option<(AnalysisTask, i32)> {
        if !self.enabled {
            return None;
        }
        self.add_set.add_set(set);
        self.schedule(id)
    }

    /// Mirrors `added(Address)`.
    pub fn added_address(&mut self, id: SchedulerId, addr: &Address) -> Option<(AnalysisTask, i32)> {
        if !self.enabled {
            return None;
        }
        self.add_set.add_address(addr);
        self.schedule(id)
    }

    /// Mirrors `removed(AddressSetView)`.
    pub fn removed(&mut self, id: SchedulerId, set: &dyn AddressSetView) -> Option<(AnalysisTask, i32)> {
        if !self.enabled {
            return None;
        }
        self.remove_set.add_set(set);
        self.schedule(id)
    }

    /// Mirrors `removed(Address)`.
    pub fn removed_address(&mut self, id: SchedulerId, addr: &Address) -> Option<(AnalysisTask, i32)> {
        if !self.enabled {
            return None;
        }
        self.remove_set.add_address(addr);
        self.schedule(id)
    }

    /// Mirrors `getAnalyzer()`.
    pub fn get_analyzer(&self) -> &dyn Analyzer {
        self.analyzer.as_ref()
    }

    /// Mutable access to the analyzer.
    pub fn get_analyzer_mut(&mut self) -> &mut dyn Analyzer {
        self.analyzer.as_mut()
    }

    /// Mirrors `optionsChanged(Options)`.
    pub fn options_changed(&mut self, options: &dyn Options, program: &dyn Program) {
        let name = self.analyzer.get_name();
        self.enabled = options.get_boolean(&name, self.default_enablement);
        let analyzer_options = options.get_options(&name);
        self.analyzer.options_changed(analyzer_options.as_ref(), program);
    }

    /// Mirrors `registerOptions(Options)`.
    pub fn register_options(&self, options: &mut dyn Options, program: &dyn Program) {
        let name = self.analyzer.get_name();
        let mut analyzer_options = options.get_options(&name);
        options.register_option(
            &name,
            Box::new(self.default_enablement),
            None,
            &self.analyzer.get_description(),
        );
        self.analyzer.register_options(analyzer_options.as_mut(), program);
    }

    /// Mirrors `getPriority()`.
    pub fn get_priority(&self) -> i32 {
        self.analyzer.get_priority().priority()
    }

    /// Mirrors `getName()`.
    pub fn get_name(&self) -> String {
        self.analyzer.get_name()
    }

    /// Run the analyzer over the accumulated sets, which are cleared (and the scheduler marked
    /// unscheduled) first. Mirrors `runAnalyzer(Program, TaskMonitor, MessageLog)`.
    pub fn run_analyzer(
        &mut self,
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledException> {
        let save_add_set = std::mem::take(&mut self.add_set);
        let save_remove_set = std::mem::take(&mut self.remove_set);
        self.scheduled = false;

        monitor.set_message(&self.analyzer.get_name());
        monitor.set_progress(0);

        let mut result = false;
        if !save_add_set.is_empty() {
            result |= self.analyzer.added(program, &save_add_set, monitor, log)?;
        }
        if !save_remove_set.is_empty() {
            result |= self.analyzer.removed(program, &save_remove_set, monitor, log)?;
        }
        Ok(result)
    }

    /// Throw away the saved-up address sets. Mirrors `runCanceled()`.
    pub fn run_canceled(&mut self) {
        self.add_set = AddressSet::new();
        self.remove_set = AddressSet::new();
        self.scheduled = false;
    }

    /// The addresses waiting to be reported as added.
    pub fn pending_added(&self) -> &AddressSet {
        &self.add_set
    }

    /// The addresses waiting to be reported as removed.
    pub fn pending_removed(&self) -> &AddressSet {
        &self.remove_set
    }
}

impl std::fmt::Display for AnalysisScheduler {
    /// Mirrors `toString()`: the analyzer's name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.analyzer.get_name())
    }
}
