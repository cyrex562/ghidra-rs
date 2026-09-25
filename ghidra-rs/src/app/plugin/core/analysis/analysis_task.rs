//! Port of `ghidra.app.plugin.core.analysis.AnalysisTask`: the background command that runs one
//! scheduler's analyzer.
//!
//! Java's task holds its `AnalysisScheduler` and the manager's `MessageLog`. Here it holds the
//! scheduler's [`SchedulerId`]; the manager supplies the scheduler and its log when it runs or
//! disposes the task (see [`analysis_scheduler`](super::analysis_scheduler) for why).
use crate::app::plugin::core::analysis::analysis_scheduler::{AnalysisScheduler, SchedulerId};
use crate::app::util::importer::message_log::MessageLog;
use crate::framework::cmd::background_command::BackgroundCommandBase;
use crate::program::model::listing::Program;
use crate::util::task::TaskMonitor;

/// Runs a scheduler's analyzer. Mirrors `AnalysisTask extends BackgroundCommand<Program>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisTask {
    base: BackgroundCommandBase,
    scheduler: SchedulerId,
}

impl AnalysisTask {
    /// Mirrors `AnalysisTask(AnalysisScheduler, MessageLog)`: named after the scheduler, with
    /// progress, cancellable, not modal.
    pub fn new(scheduler: SchedulerId, scheduler_name: impl Into<String>) -> Self {
        AnalysisTask {
            base: BackgroundCommandBase::new(scheduler_name, true, true, false),
            scheduler,
        }
    }

    /// The scheduler this task runs.
    pub fn scheduler(&self) -> SchedulerId {
        self.scheduler
    }

    /// The inherited command state (name, flags, status).
    pub fn base(&self) -> &BackgroundCommandBase {
        &self.base
    }

    /// Mirrors `applyTo(Program, TaskMonitor)`: run the scheduler's analyzer; cancellation
    /// yields `false`.
    pub fn apply_to(
        &mut self,
        scheduler: &mut AnalysisScheduler,
        program: &mut dyn Program,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> bool {
        scheduler.run_analyzer(program, monitor, log).unwrap_or(false)
    }

    /// Mirrors `dispose()`: the scheduler throws away its saved-up address sets.
    pub fn dispose(&mut self, scheduler: &mut AnalysisScheduler) {
        scheduler.run_canceled();
    }
}
