//! Partial port of `ghidra.app.plugin.core.analysis.AutoAnalysisManager`: the analyzer registry,
//! change notifications, the priority queue of analysis commands, and the analysis loop.
//!
//! # Ownership
//!
//! The manager owns its [`AnalysisScheduler`]s in an arena ([`SchedulerArena`]); the six
//! [`AnalysisTaskList`]s hold their ids and queued [`AnalysisTask`]s carry one. When a task runs,
//! the manager hands it the scheduler, the program and the message log. The program is not
//! stored: every operation that needs it takes it as an argument (Java keeps one manager per
//! program in a static `WeakHashMap`).
//!
//! # Not ported (row stays TODO)
//!
//! * The per-program registry (`getAnalysisManager`/`hasAutoAnalysisManager`), the
//!   domain-object listener and private event queue, and `dispose`.
//! * Analyzer discovery through `ClassSearcher` (`initializeAnalyzers`); analyzers are added with
//!   [`AutoAnalysisManager::add_analyzer`], which applies the same routing.
//! * Everything tool- or thread-bound: `startBackgroundAnalysis`'s follow-on command,
//!   `getAnalysisTool`/`addTool`/`removeTool`, `askToAnalyze`, the shared thread pool,
//!   `scheduleWorker`/`AnalysisWorkerCommand`/`JointTaskMonitor`, `yield`/`waitForAnalysis`, and
//!   re-entrant scheduling from a running analyzer (analyzers do not receive the manager).
//! * `scheduleOneTimeAnalysis` (needs `OneShotAnalysisCommand`), `disassemble`/`createFunction`
//!   (need `DisassembleCommand`/`CreateFunctionCmd` as background commands), `externalAdded`
//!   (needs the external address space), `reAnalyzeAll` (needs listing/function-manager counts),
//!   `restoreDefaultOptions`, `registerGlobalAnalyisOptions`, `saveTaskTimes`, and
//!   `getDataTypeManagerService`.
//! * `AnalysisTaskWrapper.run`'s catch of analyzer `RuntimeException`s (a panicking analyzer
//!   propagates).
use std::collections::HashMap;
use std::time::Instant;

use crate::app::plugin::core::analysis::analysis_scheduler::{
    AnalysisScheduler, InvalidAnalyzerName, SchedulerId,
};
use crate::app::plugin::core::analysis::analysis_task::AnalysisTask;
use crate::app::plugin::core::analysis::analysis_task_list::{
    AnalysisTaskList, ScheduleRequests, SchedulerArena,
};
use crate::app::plugin::core::analysis::auto_analysis_manager_listener::AutoAnalysisManagerListener;
use crate::app::services::analysis_priority::AnalysisPriority;
use crate::app::services::analyzer::Analyzer;
use crate::app::services::analyzer_type::AnalyzerType;
use crate::app::util::importer::message_log::MessageLog;
use crate::framework::cmd::background_command::BackgroundCommand;
use crate::framework::options::Options;
use crate::program::model::address::{Address, AddressSet, AddressSetView};
use crate::program::model::listing::Program;
use crate::util::datastruct::priority_queue::PriorityQueue;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// A command in the analysis queue: an analyzer's task, or any other background command
/// scheduled on the manager (Java's `PriorityQueue<BackgroundCommand<Program>>`).
pub enum ScheduledCommand {
    /// A scheduler's analysis task.
    Analysis(AnalysisTask),
    /// Any other background command.
    Command(Box<dyn BackgroundCommand<dyn Program>>),
}

impl ScheduledCommand {
    /// The command's name.
    pub fn get_name(&self) -> String {
        match self {
            ScheduledCommand::Analysis(t) => t.base().get_name().to_string(),
            ScheduledCommand::Command(c) => c.get_name(),
        }
    }
}

/// A listener for the end of an analysis run.
pub type AnalysisListener = Box<dyn AutoAnalysisManagerListener<AutoAnalysisManager>>;

/// Drives auto-analysis of a program. Mirrors `AutoAnalysisManager` (see the module docs for
/// what is not ported).
pub struct AutoAnalysisManager {
    schedulers: SchedulerArena,
    byte_tasks: AnalysisTaskList,
    function_tasks: AnalysisTaskList,
    function_modifier_changed_tasks: AnalysisTaskList,
    function_signature_changed_tasks: AnalysisTaskList,
    instruction_tasks: AnalysisTaskList,
    data_tasks: AnalysisTaskList,
    protected_locations: AddressSet,
    queue: PriorityQueue<ScheduledCommand>,
    timed_tasks: HashMap<String, i64>,
    cumulative_tasks: HashMap<String, i64>,
    background_analysis_pending: bool,
    /// Java's `analysisThread != null`.
    analyzing: bool,
    /// Java's `activeTask.taskPriority`.
    active_task_priority: Option<i32>,
    total_task_time: i64,
    ignore_changes: bool,
    is_enabled: bool,
    log: MessageLog,
    listeners: Vec<AnalysisListener>,
}

impl Default for AutoAnalysisManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoAnalysisManager {
    /// A manager with no analyzers. Mirrors the constructor's task-list setup in
    /// `initializeAnalyzers()`.
    pub fn new() -> Self {
        AutoAnalysisManager {
            schedulers: SchedulerArena::with_key(),
            byte_tasks: AnalysisTaskList::new(AnalyzerType::ByteAnalyzer.name()),
            function_tasks: AnalysisTaskList::new(AnalyzerType::FunctionAnalyzer.name()),
            function_modifier_changed_tasks: AnalysisTaskList::new(
                AnalyzerType::FunctionModifiersAnalyzer.name(),
            ),
            function_signature_changed_tasks: AnalysisTaskList::new(
                AnalyzerType::FunctionSignaturesAnalyzer.name(),
            ),
            instruction_tasks: AnalysisTaskList::new(AnalyzerType::InstructionAnalyzer.name()),
            data_tasks: AnalysisTaskList::new(AnalyzerType::DataAnalyzer.name()),
            protected_locations: AddressSet::new(),
            queue: PriorityQueue::new(),
            timed_tasks: HashMap::new(),
            cumulative_tasks: HashMap::new(),
            background_analysis_pending: false,
            analyzing: false,
            active_task_priority: None,
            total_task_time: 0,
            ignore_changes: false,
            is_enabled: true,
            log: MessageLog::new(),
            listeners: Vec::new(),
        }
    }

    /// Java's `taskArray` order.
    fn task_lists(&self) -> [&AnalysisTaskList; 6] {
        [
            &self.byte_tasks,
            &self.instruction_tasks,
            &self.function_tasks,
            &self.function_modifier_changed_tasks,
            &self.function_signature_changed_tasks,
            &self.data_tasks,
        ]
    }

    /// Register an analyzer, routed to the task list for its type. Mirrors the body of
    /// `initializeAnalyzers()`'s loop: an analyzer that cannot analyze `program` is skipped
    /// (`Ok(None)`).
    pub fn add_analyzer(
        &mut self,
        analyzer: Box<dyn Analyzer>,
        program: &dyn Program,
    ) -> Result<Option<SchedulerId>, InvalidAnalyzerName> {
        if !analyzer.can_analyze(program) {
            return Ok(None);
        }
        let ty = analyzer.get_analysis_type();
        let scheduler = AnalysisScheduler::new(analyzer, program)?;
        let id = self.schedulers.insert(scheduler);
        let list = match ty {
            AnalyzerType::ByteAnalyzer => &mut self.byte_tasks,
            AnalyzerType::DataAnalyzer => &mut self.data_tasks,
            AnalyzerType::FunctionAnalyzer => &mut self.function_tasks,
            AnalyzerType::FunctionModifiersAnalyzer => &mut self.function_modifier_changed_tasks,
            AnalyzerType::FunctionSignaturesAnalyzer => &mut self.function_signature_changed_tasks,
            AnalyzerType::InstructionAnalyzer => &mut self.instruction_tasks,
        };
        list.add(&self.schedulers, id);
        Ok(Some(id))
    }

    /// The scheduler with the given id.
    pub fn get_scheduler(&self, id: SchedulerId) -> Option<&AnalysisScheduler> {
        self.schedulers.get(id)
    }

    /// The schedulers of the given analyzer type, in priority order.
    pub fn get_schedulers(&self, ty: AnalyzerType) -> Vec<SchedulerId> {
        let list = match ty {
            AnalyzerType::ByteAnalyzer => &self.byte_tasks,
            AnalyzerType::DataAnalyzer => &self.data_tasks,
            AnalyzerType::FunctionAnalyzer => &self.function_tasks,
            AnalyzerType::FunctionModifiersAnalyzer => &self.function_modifier_changed_tasks,
            AnalyzerType::FunctionSignaturesAnalyzer => &self.function_signature_changed_tasks,
            AnalyzerType::InstructionAnalyzer => &self.instruction_tasks,
        };
        list.iter().collect()
    }

    /// Mirrors `getMessageLog()`.
    pub fn get_message_log(&self) -> &MessageLog {
        &self.log
    }

    /// Mirrors `getAnalyzer(String)`.
    pub fn get_analyzer(&self, analyzer_name: &str) -> Option<&dyn Analyzer> {
        for list in self.task_lists() {
            for id in list.iter() {
                let analyzer = self.schedulers[id].get_analyzer();
                if analyzer.get_name() == analyzer_name {
                    return Some(analyzer);
                }
            }
        }
        None
    }

    fn schedule_all(&mut self, requests: ScheduleRequests) {
        for (task, priority) in requests {
            self.schedule(ScheduledCommand::Analysis(task), priority);
        }
    }

    /// Mirrors `blockAdded(AddressSetView)`.
    pub fn block_added(&mut self, set: &dyn AddressSetView) {
        if !self.ignore_changes && !set.is_empty() {
            let r = self.byte_tasks.notify_added(&mut self.schedulers, set);
            self.schedule_all(r);
        }
    }

    /// Mirrors `codeDefined(Address)`.
    pub fn code_defined_address(&mut self, addr: &Address) {
        if !self.ignore_changes {
            let r = self.instruction_tasks.notify_added_address(&mut self.schedulers, addr);
            self.schedule_all(r);
        }
    }

    /// Mirrors `codeDefined(AddressSetView)`.
    pub fn code_defined(&mut self, set: &dyn AddressSetView) {
        if !self.ignore_changes && !set.is_empty() {
            let r = self.instruction_tasks.notify_added(&mut self.schedulers, set);
            self.schedule_all(r);
        }
    }

    /// Mirrors `dataDefined(AddressSetView)`.
    pub fn data_defined(&mut self, set: &dyn AddressSetView) {
        if !self.ignore_changes && !set.is_empty() {
            let r = self.data_tasks.notify_added(&mut self.schedulers, set);
            self.schedule_all(r);
        }
    }

    /// Mirrors `functionDefined(Address)`.
    pub fn function_defined_address(&mut self, addr: &Address) {
        if !self.ignore_changes {
            let r = self.function_tasks.notify_added_address(&mut self.schedulers, addr);
            self.schedule_all(r);
        }
    }

    /// Mirrors `functionDefined(AddressSetView)`.
    pub fn function_defined(&mut self, set: &dyn AddressSetView) {
        if !self.ignore_changes && !set.is_empty() {
            let r = self.function_tasks.notify_added(&mut self.schedulers, set);
            self.schedule_all(r);
        }
    }

    /// Mirrors `functionModifierChanged(Address)`.
    pub fn function_modifier_changed_address(&mut self, addr: &Address) {
        if !self.ignore_changes {
            let r = self
                .function_modifier_changed_tasks
                .notify_added_address(&mut self.schedulers, addr);
            self.schedule_all(r);
        }
    }

    /// Mirrors `functionModifierChanged(AddressSetView)`.
    pub fn function_modifier_changed(&mut self, set: &dyn AddressSetView) {
        if !self.ignore_changes && !set.is_empty() {
            let r = self.function_modifier_changed_tasks.notify_added(&mut self.schedulers, set);
            self.schedule_all(r);
        }
    }

    /// Mirrors `functionSignatureChanged(Address)`.
    pub fn function_signature_changed_address(&mut self, addr: &Address) {
        if !self.ignore_changes {
            let r = self
                .function_signature_changed_tasks
                .notify_added_address(&mut self.schedulers, addr);
            self.schedule_all(r);
        }
    }

    /// Mirrors `functionSignatureChanged(AddressSetView)`.
    pub fn function_signature_changed(&mut self, set: &dyn AddressSetView) {
        if !self.ignore_changes && !set.is_empty() {
            let r = self.function_signature_changed_tasks.notify_added(&mut self.schedulers, set);
            self.schedule_all(r);
        }
    }

    /// Mirrors `setIgnoreChanges(boolean)` (without the event-queue flush, see the module docs):
    /// returns the previous state.
    pub fn set_ignore_changes(&mut self, state: bool) -> bool {
        std::mem::replace(&mut self.ignore_changes, state)
    }

    /// Enable or disable the manager (Java's test-only `isEnabled` field).
    pub fn set_enabled(&mut self, enabled: bool) {
        self.is_enabled = enabled;
    }

    /// Mirrors `registerAnalyzerOptions()`, given the program's analysis options.
    pub fn register_analyzer_options(&self, options: &mut dyn Options, program: &dyn Program) {
        for list in self.task_lists() {
            list.register_options(&self.schedulers, options, program);
        }
    }

    /// Mirrors `initializeOptions(Options)`.
    pub fn initialize_options(&mut self, options: &dyn Options, program: &dyn Program) {
        // Java's order: byte, function, modifiers, signatures, instruction, data.
        let lists = [
            &self.byte_tasks,
            &self.function_tasks,
            &self.function_modifier_changed_tasks,
            &self.function_signature_changed_tasks,
            &self.instruction_tasks,
            &self.data_tasks,
        ];
        for list in lists {
            list.options_changed(&mut self.schedulers, options, program);
        }
    }

    /// Mirrors `addListener(AutoAnalysisManagerListener)`.
    pub fn add_listener(&mut self, listener: AnalysisListener) {
        self.listeners.push(listener);
    }

    /// Queue a command. Mirrors `schedule(BackgroundCommand, int)`: returns whether analysis is
    /// (or will be) running -- with no tool to run it in the background, only when a run is
    /// already in progress.
    pub fn schedule(&mut self, cmd: ScheduledCommand, priority: i32) -> bool {
        self.queue.add(cmd, priority);
        self.start_background_analysis()
    }

    /// Mirrors `startBackgroundAnalysis()`. There is no tool to schedule the follow-on command
    /// on, which is Java's headless result: `false` unless analysis is already running.
    pub fn start_background_analysis(&mut self) -> bool {
        if !self.is_enabled {
            return false;
        }
        self.analyzing || self.background_analysis_pending
    }

    /// Mirrors `isAnalyzing()`.
    pub fn is_analyzing(&self) -> bool {
        self.analyzing || self.background_analysis_pending
    }

    /// The number of queued commands.
    pub fn queued_count(&self) -> usize {
        self.queue.size()
    }

    /// Mirrors `cancelQueuedTasks()`: dispose every queued command.
    pub fn cancel_queued_tasks(&mut self) {
        while let Some(cmd) = self.queue.remove_first() {
            match cmd {
                ScheduledCommand::Analysis(mut task) => {
                    if let Some(s) = self.schedulers.get_mut(task.scheduler()) {
                        task.dispose(s);
                    }
                }
                ScheduledCommand::Command(mut c) => c.dispose(),
            }
        }
    }

    /// Mirrors `getNextTask(Integer, TaskMonitor)`.
    fn get_next_task(
        &mut self,
        limit_priority: Option<i32>,
        monitor: &dyn TaskMonitor,
    ) -> Option<(ScheduledCommand, i32)> {
        if monitor.is_cancelled() {
            self.cancel_queued_tasks();
        }
        let first = self.queue.get_first_priority()?;
        if !self.is_enabled || limit_priority.is_some_and(|limit| first >= limit) {
            return None;
        }
        let cmd = self.queue.remove_first()?;
        Some((cmd, first))
    }

    /// Mirrors `AnalysisTaskWrapper.run(Program, TaskMonitor)`.
    fn run_task(
        &mut self,
        cmd: &mut ScheduledCommand,
        program: &mut (dyn Program + 'static),
        monitor: &dyn TaskMonitor,
    ) {
        let start = Instant::now();
        match cmd {
            ScheduledCommand::Analysis(task) => {
                if let Some(scheduler) = self.schedulers.get_mut(task.scheduler()) {
                    task.apply_to(scheduler, program, monitor, &mut self.log);
                }
            }
            ScheduledCommand::Command(c) => {
                c.apply_to(program, monitor);
            }
        }
        let time_diff = start.elapsed().as_millis() as i64;
        self.total_task_time += time_diff;
        self.add_to_task_time(&cmd.get_name(), time_diff);
    }

    /// Run queued analysis until the queue is empty. Mirrors `startAnalysis(TaskMonitor,
    /// boolean)` on a thread with no tool (Java's non-yielding
    /// `startAnalysis(monitor, false, null, printTaskTimes)`): does nothing if analysis is already
    /// running or the manager is disabled; at the end, notifies analyzers and listeners and
    /// clears the log and the protected locations.
    pub fn start_analysis(
        &mut self,
        program: &mut (dyn Program + 'static),
        monitor: &dyn TaskMonitor,
        print_task_times: bool,
    ) {
        if self.analyzing || !self.is_enabled {
            return;
        }
        let next = self.get_next_task(None, monitor);
        self.background_analysis_pending = false;
        let Some((mut cmd, mut priority)) = next else {
            return;
        };
        self.analyzing = true;
        if print_task_times {
            self.clear_timed_tasks();
        }
        loop {
            self.active_task_priority = Some(priority);
            self.run_task(&mut cmd, program, monitor);
            match self.get_next_task(None, monitor) {
                Some((c, p)) => {
                    cmd = c;
                    priority = p;
                }
                None => break,
            }
        }
        self.notify_analysis_ended(program, monitor.is_cancelled());
        if print_task_times {
            self.print_timed_tasks();
        }
        self.analyzing = false;
        self.active_task_priority = None;
        self.protected_locations = AddressSet::new();
    }

    /// Mirrors `notifyAnalysisEnded(boolean)`.
    fn notify_analysis_ended(&mut self, program: &dyn Program, is_cancelled: bool) {
        let lists = [
            self.byte_tasks.clone(),
            self.instruction_tasks.clone(),
            self.function_tasks.clone(),
            self.function_modifier_changed_tasks.clone(),
            self.function_signature_changed_tasks.clone(),
            self.data_tasks.clone(),
        ];
        for list in &lists {
            list.notify_analysis_ended(&mut self.schedulers, program);
        }
        let mut listeners = std::mem::take(&mut self.listeners);
        for listener in &mut listeners {
            listener.analysis_ended(self, is_cancelled);
        }
        listeners.append(&mut self.listeners);
        self.listeners = listeners;
        self.log.clear();
    }

    /// Mirrors the private `getDisassemblyPriority()`: two better than the running task, or
    /// `DISASSEMBLY` when idle.
    pub fn get_disassembly_priority(&self) -> i32 {
        match self.active_task_priority {
            None => AnalysisPriority::disassembly().priority(),
            Some(p) => p - 2,
        }
    }

    /// Mirrors the private `getFunctionPriority()`.
    pub fn get_function_priority(&self) -> i32 {
        self.get_disassembly_priority() + 1
    }

    /// Mirrors `getProtectedLocations()`.
    pub fn get_protected_locations(&self) -> &dyn AddressSetView {
        &self.protected_locations
    }

    /// Mirrors `setProtectedLocation(Address)`.
    pub fn set_protected_location(&mut self, addr: &Address) {
        self.protected_locations.add_address(addr);
    }

    /// Mirrors `setProtectedLocations(AddressSet)`.
    pub fn set_protected_locations(&mut self, set: &AddressSet) {
        self.protected_locations.add_set(set);
    }

    /// Mirrors `getTimedTasks()`: the timed task names, sorted.
    pub fn get_timed_tasks(&self) -> Vec<String> {
        let mut names: Vec<String> = self.timed_tasks.keys().cloned().collect();
        names.sort();
        names
    }

    /// Mirrors `getTaskTime(Map, String)` for the current run's times: `-1` if never timed.
    pub fn get_task_time(&self, task_name: &str) -> i64 {
        self.timed_tasks.get(task_name).copied().unwrap_or(-1)
    }

    /// The accumulated time across runs (Java's `cumulativeTasks`), `-1` if never timed.
    pub fn get_cumulative_task_time(&self, task_name: &str) -> i64 {
        self.cumulative_tasks.get(task_name).copied().unwrap_or(-1)
    }

    fn clear_timed_tasks(&mut self) {
        self.timed_tasks.clear();
        self.total_task_time = 0;
    }

    fn updated_task_time(map: &HashMap<String, i64>, task_name: &str, new_time: i64) -> i64 {
        let current = map.get(task_name).copied().unwrap_or(-1);
        if current > 0 {
            new_time + current
        } else {
            new_time
        }
    }

    /// Mirrors the private `addToTaskTime(String, long)`.
    fn add_to_task_time(&mut self, task_name: &str, time: i64) {
        let l = Self::updated_task_time(&self.timed_tasks, task_name, time);
        self.timed_tasks.insert(task_name.to_string(), l);
        let l = Self::updated_task_time(&self.cumulative_tasks, task_name, time);
        self.cumulative_tasks.insert(task_name.to_string(), l);
    }

    /// Mirrors `getTotalTimeInMillis()`.
    pub fn get_total_time_in_millis(&self) -> i64 {
        self.total_task_time
    }

    /// Mirrors `getTaskTimesString()`.
    pub fn get_task_times_string(&self) -> String {
        const SPACER: &str = "                                                     ";
        const RULE: &str = "-----------------------------------------------------\n";
        let mut buf = String::new();
        buf.push_str(RULE);
        for element in self.get_timed_tasks() {
            let task_time = self.get_task_time(&element);
            let total_time = task_time as f64 / 1000.00;
            let sec_string = format!("{total_time:.3} secs");
            let mut test_len = element.chars().count() + sec_string.len();
            if test_len > SPACER.len() {
                test_len = SPACER.len() - 5;
            }
            buf.push_str(&format!("    {element}{}{sec_string}\n", &SPACER[test_len..]));
        }
        buf.push_str(RULE);
        buf.push_str(&format!(
            "     Total Time   {} secs\n",
            (self.total_task_time as f64 / 1000.00) as i32
        ));
        buf.push_str(RULE);
        buf
    }

    /// Mirrors the private `printTimedTasks()`: only runs of a second or more.
    fn print_timed_tasks(&self) {
        if self.total_task_time < 1000 {
            return;
        }
        Msg::info("AutoAnalysisManager", &self.get_task_times_string());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::app::services::analysis_priority::AnalysisPriority;
    use crate::framework::cmd::background_command::BackgroundCommandBase;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::util::exception::CancelledException;
    use crate::util::task::DummyMonitor;

    struct TestProgram;
    impl crate::framework::model::DomainObject for TestProgram {}
    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "prog".to_string()
        }
        fn get_language_id(&self) -> String {
            "x86:LE:64:default".to_string()
        }
    }

    type Events = Arc<Mutex<Vec<String>>>;

    /// An analyzer (the extension point) that records what it is told.
    struct Recorder {
        name: &'static str,
        ty: AnalyzerType,
        priority: i32,
        enabled: bool,
        events: Events,
    }

    impl Analyzer for Recorder {
        fn get_name(&self) -> String {
            self.name.to_string()
        }
        fn get_analysis_type(&self) -> AnalyzerType {
            self.ty
        }
        fn get_default_enablement(&self, _program: &dyn Program) -> bool {
            self.enabled
        }
        fn supports_one_time_analysis(&self) -> bool {
            false
        }
        fn get_description(&self) -> String {
            format!("{} description", self.name)
        }
        fn get_priority(&self) -> AnalysisPriority {
            AnalysisPriority::new(self.priority)
        }
        fn can_analyze(&self, _program: &dyn Program) -> bool {
            self.name != "Unsupported"
        }
        fn added(
            &mut self,
            _program: &mut dyn Program,
            set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
            log: &mut MessageLog,
        ) -> Result<bool, CancelledException> {
            log.append_msg(format!("{} ran", self.name));
            self.events.lock().unwrap().push(format!("{}:added:{}", self.name, set.num_addresses()));
            Ok(true)
        }
        fn removed(
            &mut self,
            _program: &mut dyn Program,
            set: &dyn AddressSetView,
            _monitor: &dyn TaskMonitor,
            _log: &mut MessageLog,
        ) -> Result<bool, CancelledException> {
            self.events.lock().unwrap().push(format!("{}:removed:{}", self.name, set.num_addresses()));
            Ok(true)
        }
        fn register_options(&self, _options: &mut dyn Options, _program: &dyn Program) {}
        fn options_changed(&mut self, _options: &dyn Options, _program: &dyn Program) {}
        fn analysis_ended(&mut self, _program: &dyn Program) {
            self.events.lock().unwrap().push(format!("{}:ended", self.name));
        }
        fn is_prototype(&self) -> bool {
            false
        }
    }

    fn recorder(name: &'static str, ty: AnalyzerType, priority: i32, events: &Events) -> Box<dyn Analyzer> {
        Box::new(Recorder { name, ty, priority, enabled: true, events: events.clone() })
    }

    fn range(start: i64, end: i64) -> AddressSet {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let mut set = AddressSet::new();
        set.add_range(&Address::new(space.clone(), start), &Address::new(space, end));
        set
    }

    #[test]
    fn analyzers_are_routed_by_type_and_ordered_by_priority_then_name() {
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let p = TestProgram;
        mgr.add_analyzer(recorder("Late", AnalyzerType::ByteAnalyzer, 500, &events), &p).unwrap();
        mgr.add_analyzer(recorder("Bravo", AnalyzerType::ByteAnalyzer, 100, &events), &p).unwrap();
        mgr.add_analyzer(recorder("Alpha", AnalyzerType::ByteAnalyzer, 100, &events), &p).unwrap();
        mgr.add_analyzer(recorder("Data", AnalyzerType::DataAnalyzer, 50, &events), &p).unwrap();
        assert_eq!(
            mgr.add_analyzer(recorder("Unsupported", AnalyzerType::DataAnalyzer, 1, &events), &p),
            Ok(None)
        );
        let names: Vec<String> = mgr
            .get_schedulers(AnalyzerType::ByteAnalyzer)
            .into_iter()
            .map(|id| mgr.get_scheduler(id).unwrap().get_name())
            .collect();
        assert_eq!(names, vec!["Alpha", "Bravo", "Late"]);
        assert_eq!(mgr.get_schedulers(AnalyzerType::DataAnalyzer).len(), 1);
        assert_eq!(mgr.get_analyzer("Data").unwrap().get_priority().priority(), 50);
        assert!(mgr.get_analyzer("Nope").is_none());
    }

    #[test]
    fn analyzer_names_with_periods_are_rejected() {
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let err = mgr
            .add_analyzer(recorder("Bad.Name", AnalyzerType::ByteAnalyzer, 1, &events), &TestProgram)
            .unwrap_err();
        assert_eq!(err.to_string(), "Analyzer name may not contain a period: Bad.Name");
    }

    #[test]
    fn notifications_schedule_each_analyzer_once_and_accumulate_sets() {
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let p = TestProgram;
        let id = mgr
            .add_analyzer(recorder("Code", AnalyzerType::InstructionAnalyzer, 10, &events), &p)
            .unwrap()
            .unwrap();
        mgr.code_defined(&range(0x1000, 0x100f));
        mgr.code_defined(&range(0x2000, 0x2003));
        assert_eq!(mgr.queued_count(), 1);
        assert!(mgr.get_scheduler(id).unwrap().is_scheduled());
        assert_eq!(mgr.get_scheduler(id).unwrap().pending_added().num_addresses(), 20);
        // Other lists are not notified.
        mgr.data_defined(&range(0, 4));
        assert_eq!(mgr.queued_count(), 1);
        // Ignored changes schedule nothing.
        mgr.set_ignore_changes(true);
        mgr.block_added(&range(0, 4));
        assert!(mgr.set_ignore_changes(false));
    }

    #[test]
    fn start_analysis_runs_tasks_in_priority_order_then_notifies() {
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let mut p = TestProgram;
        mgr.add_analyzer(recorder("Func", AnalyzerType::FunctionAnalyzer, 300, &events), &p).unwrap();
        mgr.add_analyzer(recorder("Bytes", AnalyzerType::ByteAnalyzer, 100, &events), &p).unwrap();

        struct Ended(Arc<Mutex<Vec<bool>>>);
        impl AutoAnalysisManagerListener<AutoAnalysisManager> for Ended {
            fn analysis_ended(&mut self, manager: &AutoAnalysisManager, is_cancelled: bool) {
                assert!(manager.is_analyzing());
                self.0.lock().unwrap().push(is_cancelled);
            }
        }
        let ended = Arc::new(Mutex::new(Vec::new()));
        mgr.add_listener(Box::new(Ended(ended.clone())));

        mgr.function_defined(&range(0x10, 0x11));
        mgr.block_added(&range(0, 0xff));
        assert!(!mgr.is_analyzing());
        mgr.start_analysis(&mut p, &DummyMonitor, false);
        assert_eq!(
            *events.lock().unwrap(),
            vec!["Bytes:added:256", "Func:added:2", "Bytes:ended", "Func:ended"]
        );
        assert_eq!(*ended.lock().unwrap(), vec![false]);
        assert_eq!(mgr.queued_count(), 0);
        assert!(!mgr.is_analyzing());
        // The log is cleared once analysis ends.
        assert!(!mgr.get_message_log().has_messages());
        assert_eq!(mgr.get_timed_tasks(), vec!["Bytes", "Func"]);
        assert!(mgr.get_task_time("Bytes") >= 0);
        assert_eq!(mgr.get_task_time("Nope"), -1);
    }

    #[test]
    fn cancelled_monitor_disposes_queued_tasks() {
        /// A monitor whose user has already cancelled.
        struct Cancelled;
        impl TaskMonitor for Cancelled {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException("cancelled".into()))
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let mut p = TestProgram;
        let id = mgr
            .add_analyzer(recorder("Bytes", AnalyzerType::ByteAnalyzer, 100, &events), &p)
            .unwrap()
            .unwrap();
        mgr.block_added(&range(0, 0xf));
        mgr.start_analysis(&mut p, &Cancelled, false);
        assert!(events.lock().unwrap().is_empty());
        let s = mgr.get_scheduler(id).unwrap();
        assert!(!s.is_scheduled());
        assert!(s.pending_added().is_empty());
        assert_eq!(mgr.queued_count(), 0);
    }

    #[test]
    fn disabled_analyzers_ignore_notifications() {
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let p = TestProgram;
        let analyzer =
            Box::new(Recorder { name: "Off", ty: AnalyzerType::DataAnalyzer, priority: 1, enabled: false, events });
        let id = mgr.add_analyzer(analyzer, &p).unwrap().unwrap();
        assert!(!mgr.get_scheduler(id).unwrap().get_default_enablement());
        mgr.data_defined(&range(0, 3));
        assert_eq!(mgr.queued_count(), 0);
    }

    #[test]
    fn other_commands_run_in_the_same_queue() {
        struct Marker {
            base: BackgroundCommandBase,
            events: Events,
        }
        impl BackgroundCommand<dyn Program> for Marker {
            fn base(&self) -> &BackgroundCommandBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut BackgroundCommandBase {
                &mut self.base
            }
            fn apply_to(
                &mut self,
                obj: &mut (dyn Program + 'static),
                _monitor: &dyn TaskMonitor,
            ) -> bool {
                self.events.lock().unwrap().push(format!("marker on {}", Program::get_name(obj)));
                true
            }
        }
        let events = Events::default();
        let mut mgr = AutoAnalysisManager::new();
        let mut p = TestProgram;
        mgr.add_analyzer(recorder("Bytes", AnalyzerType::ByteAnalyzer, 100, &events), &p).unwrap();
        mgr.block_added(&range(0, 1));
        let marker = Marker { base: BackgroundCommandBase::new("Marker", false, true, false), events: events.clone() };
        // Idle with no tool: scheduling reports that analysis is not running.
        assert!(!mgr.schedule(ScheduledCommand::Command(Box::new(marker)), 50));
        mgr.start_analysis(&mut p, &DummyMonitor, false);
        assert_eq!(events.lock().unwrap()[..2], ["marker on prog", "Bytes:added:2"]);
    }

    #[test]
    fn disassembly_priority_and_task_times_string() {
        let mut mgr = AutoAnalysisManager::new();
        assert_eq!(mgr.get_disassembly_priority(), AnalysisPriority::disassembly().priority());
        assert_eq!(mgr.get_function_priority(), AnalysisPriority::disassembly().priority() + 1);
        mgr.add_to_task_time("Stack", 1500);
        mgr.add_to_task_time("Stack", 500);
        mgr.total_task_time = 2000;
        assert_eq!(mgr.get_task_time("Stack"), 2000);
        assert_eq!(mgr.get_cumulative_task_time("Stack"), 2000);
        let rule = "-----------------------------------------------------\n";
        let line = format!("    Stack{}2.000 secs\n", " ".repeat(53 - 15));
        assert_eq!(
            mgr.get_task_times_string(),
            format!("{rule}{line}{rule}     Total Time   2 secs\n{rule}")
        );
    }

    #[test]
    fn protected_locations_accumulate() {
        let mut mgr = AutoAnalysisManager::new();
        mgr.set_protected_locations(&range(0, 3));
        mgr.set_protected_locations(&range(8, 9));
        assert_eq!(mgr.get_protected_locations().num_addresses(), 6);
    }
}
