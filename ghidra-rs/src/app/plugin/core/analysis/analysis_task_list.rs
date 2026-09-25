//! Port of `ghidra.app.plugin.core.analysis.AnalysisTaskList`: the schedulers for one kind of
//! analyzer, ordered by priority then name.
//!
//! The schedulers live in the manager's arena; the list holds their ids and takes the arena as
//! an argument. Notifications return the tasks the schedulers asked to have queued (Java's
//! schedulers queue them on the manager themselves).
use std::cmp::Ordering;

use slotmap::SlotMap;

use crate::app::plugin::core::analysis::analysis_scheduler::{AnalysisScheduler, SchedulerId};
use crate::app::plugin::core::analysis::analysis_task::AnalysisTask;
use crate::framework::options::Options;
use crate::program::model::address::{Address, AddressSetView};
use crate::program::model::listing::Program;

/// The scheduler arena a manager owns.
pub type SchedulerArena = SlotMap<SchedulerId, AnalysisScheduler>;

/// Tasks a notification asked to have scheduled, with their priorities.
pub type ScheduleRequests = Vec<(AnalysisTask, i32)>;

/// Mirrors `priorityComparator`: by priority, then (for determinism) by name.
fn priority_compare(a: &AnalysisScheduler, b: &AnalysisScheduler) -> Ordering {
    a.get_priority()
        .cmp(&b.get_priority())
        .then_with(|| a.get_name().cmp(&b.get_name()))
}

/// One kind of analyzer's schedulers. Mirrors `AnalysisTaskList`.
#[derive(Debug, Clone, Default)]
pub struct AnalysisTaskList {
    tasks: Vec<SchedulerId>,
    name: String,
}

impl AnalysisTaskList {
    /// Mirrors `AnalysisTaskList(AutoAnalysisManager, String)`.
    pub fn new(name: impl Into<String>) -> Self {
        AnalysisTaskList { tasks: Vec::new(), name: name.into() }
    }

    /// The list's name (the analyzer type's name).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Mirrors `clear()`.
    pub fn clear(&mut self) {
        self.tasks.clear();
    }

    /// The scheduler ids in order. Mirrors `iterator()`.
    pub fn iter(&self) -> impl Iterator<Item = SchedulerId> + '_ {
        self.tasks.iter().copied()
    }

    /// Insert a scheduler (already in `arena`) at its priority position. Mirrors
    /// `add(Analyzer)`, whose scheduler construction is the caller's (it needs the program).
    pub fn add(&mut self, arena: &SchedulerArena, id: SchedulerId) {
        let new = &arena[id];
        let index = self
            .tasks
            .partition_point(|t| priority_compare(&arena[*t], new) == Ordering::Less);
        self.tasks.insert(index, id);
    }

    /// Mirrors `notifyResume()`.
    pub fn notify_resume(&self, arena: &mut SchedulerArena) -> ScheduleRequests {
        self.tasks.iter().filter_map(|id| arena[*id].schedule(*id)).collect()
    }

    /// Mirrors `notifyAdded(Address)`.
    pub fn notify_added_address(&self, arena: &mut SchedulerArena, addr: &Address) -> ScheduleRequests {
        self.tasks.iter().filter_map(|id| arena[*id].added_address(*id, addr)).collect()
    }

    /// Mirrors `notifyAdded(AddressSetView)`.
    pub fn notify_added(&self, arena: &mut SchedulerArena, set: &dyn AddressSetView) -> ScheduleRequests {
        self.tasks.iter().filter_map(|id| arena[*id].added(*id, set)).collect()
    }

    /// Mirrors `notifyRemoved(AddressSetView)`.
    pub fn notify_removed(&self, arena: &mut SchedulerArena, set: &dyn AddressSetView) -> ScheduleRequests {
        self.tasks.iter().filter_map(|id| arena[*id].removed(*id, set)).collect()
    }

    /// Mirrors `notifyRemoved(Address)`.
    pub fn notify_removed_address(
        &self,
        arena: &mut SchedulerArena,
        addr: &Address,
    ) -> ScheduleRequests {
        self.tasks.iter().filter_map(|id| arena[*id].removed_address(*id, addr)).collect()
    }

    /// Mirrors `optionsChanged(Options)`.
    pub fn options_changed(&self, arena: &mut SchedulerArena, options: &dyn Options, program: &dyn Program) {
        for id in &self.tasks {
            arena[*id].options_changed(options, program);
        }
    }

    /// Mirrors `registerOptions(Options)`.
    pub fn register_options(&self, arena: &SchedulerArena, options: &mut dyn Options, program: &dyn Program) {
        for id in &self.tasks {
            arena[*id].register_options(options, program);
        }
    }

    /// Mirrors `notifyAnalysisEnded(Program)`.
    pub fn notify_analysis_ended(&self, arena: &mut SchedulerArena, program: &dyn Program) {
        for id in &self.tasks {
            arena[*id].get_analyzer_mut().analysis_ended(program);
        }
    }
}
