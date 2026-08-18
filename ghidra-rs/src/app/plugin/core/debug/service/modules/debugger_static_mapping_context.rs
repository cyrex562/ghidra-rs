//! The bookkeeping core of the static-mapping service: which programs and traces are open, and
//! how addresses translate between them.
//!
//! Port of `ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingContext`.
//!
//! # Divergences from the Java
//!
//! * Java's nested `record ChangeCollector(ctx, traces, programs) implements AutoCloseable`
//!   becomes the plain [`ChangeCollector`] struct below. It does not hold a back-reference to its
//!   context: Rust's [`Drop`] cannot be handed the context, so the `try`-with-resources close is
//!   spelled explicitly as [`ChangeCollector::close`], which takes the context it notifies. This
//!   also keeps ownership acyclic (the context owns the per-program/per-trace info; nothing owns
//!   the context).
//! * Java's `final Object lock` monitor is dropped. Every mutator here takes `&mut self` and every
//!   observer takes `&self`, so the borrow checker already provides the mutual exclusion the
//!   monitor was there to provide.
//! * Traces and programs are keyed by reference identity, matching Java (neither `Trace` nor
//!   `Program` overrides `equals`/`hashCode`). The [`Hash`](std::hash::Hash)/[`Eq`] impls on
//!   `dyn Trace`/`dyn Program` used for that live with their traits. Where the
//!   [`DebuggerAddressTranslator`] signatures hand us a borrowed `&dyn Trace` rather than an
//!   `Arc`, the matching key is recovered by comparing trait-object data pointers.
//! * `InfoPerTrace` is not ported yet, so the context cannot construct one:
//!   [`add_trace`](DebuggerStaticMappingContext::add_trace) and
//!   [`set_traces`](DebuggerStaticMappingContext::set_traces) take the info alongside the trace
//!   instead of doing `new InfoPerTrace(this, trace)` themselves.
//! * `InfoPerProgram.domainObjectChanged` needs its owning context to re-register a renamed
//!   program, which in Rust would mean a back-reference from an owned value into its owner. That
//!   handler moves here as
//!   [`program_object_changed`](DebuggerStaticMappingContext::program_object_changed); it runs
//!   synchronously rather than on `ctx.executor`, matching the note already recorded in
//!   [`InfoPerProgram`].
//! * `getStaticLocationFromDynamic` and `getDynamicLocationFromStatic` are not implemented; both
//!   are blocked, and each logs a debug message rather than failing silently. The former needs to
//!   downcast `ProgramLocation.getProgram()` to a [`TraceProgramView`], which the ported `Program`
//!   trait has no facility for; the latter must build a `ProgramLocation` over the given view,
//!   which needs an owned `Arc<dyn Program>` that a borrowed `&dyn TraceProgramView` parameter
//!   cannot yield. Both unblock when `TraceProgramView` gains its decided concrete type.
//! * Java returns `null` from several accessors when the trace/program is not tracked; the `Vec`-
//!   and `Option`-returning Rust signatures express that as an empty `Vec`/`None`.
//! * `noProject()` is dropped: it is an unused protected helper here that forwards to the unported
//!   `DebuggerStaticMappingUtils`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::app::plugin::core::debug::service::modules::InfoPerProgram;
use crate::app::seam_stubs::{InfoPerTrace, MappingEntry};
use crate::debug::api::modules::debugger_address_translator::DebuggerAddressTranslator;
use crate::debug::api::modules::debugger_static_mapping_change_listener::DebuggerStaticMappingChangeListener;
use crate::debug::seam_stubs::MappedAddressRange;
use crate::framework::model::{DomainObjectChangedEvent, DomainObjectEvent};
use crate::program::model::address::AddressSetView;
use crate::program::model::listing::Program;
use crate::program::util::program_location::ProgramLocation;
use crate::trace::model::default_trace_span::DefaultTraceSpan;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::program::TraceProgramView;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_location::TraceLocation;
use crate::util::async_utils::{AsyncExecutor, DirectExecutor};
use crate::util::Msg;

/// The trait-object data pointer of a trace, used as its identity.
fn trace_id(trace: &dyn Trace) -> *const () {
    trace as *const dyn Trace as *const ()
}

/// The trait-object data pointer of a program, used as its identity.
fn program_id(program: &dyn Program) -> *const () {
    program as *const dyn Program as *const ()
}

/// A batch of mapping changes, reported to the context's listeners when it is
/// [`close`](ChangeCollector::close)d.
///
/// Port of the nested record `DebuggerStaticMappingContext.ChangeCollector`.
#[derive(Default)]
pub struct ChangeCollector {
    traces: HashSet<Arc<dyn Trace>>,
    programs: HashSet<Arc<dyn Program>>,
}

impl ChangeCollector {
    /// Port of `new ChangeCollector(ctx)`.
    pub fn new() -> Self {
        ChangeCollector {
            traces: HashSet::new(),
            programs: HashSet::new(),
        }
    }

    /// Port of `ChangeCollector.traceAffected(Trace)`.
    pub fn trace_affected(&mut self, trace: Arc<dyn Trace>) {
        self.traces.insert(trace);
    }

    /// Port of `ChangeCollector.programAffected(Program)`.
    ///
    /// Java tolerates a null program; the `Option` says the same thing.
    pub fn program_affected(&mut self, program: Option<Arc<dyn Program>>) {
        if let Some(program) = program {
            self.programs.insert(program);
        }
    }

    /// The traces affected by this batch.
    pub fn traces(&self) -> &HashSet<Arc<dyn Trace>> {
        &self.traces
    }

    /// The programs affected by this batch.
    pub fn programs(&self) -> &HashSet<Arc<dyn Program>> {
        &self.programs
    }

    /// Port of `ChangeCollector.close()`: notify `ctx`'s listeners of everything collected.
    pub fn close(self, ctx: &DebuggerStaticMappingContext) {
        for listener in ctx.change_listeners() {
            listener.mappings_changed(&self.traces, &self.programs);
        }
    }
}

/// Tracks the open traces and programs, and the mappings between them.
///
/// Port of `ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingContext`.
pub struct DebuggerStaticMappingContext {
    trace_info_by_trace: HashMap<Arc<dyn Trace>, Arc<Mutex<dyn InfoPerTrace>>>,
    /// The same [`InfoPerProgram`] instance appears in both program maps, exactly as in Java, so
    /// it is shared (and individually locked) rather than duplicated.
    program_info_by_program: HashMap<Arc<dyn Program>, Arc<Mutex<InfoPerProgram>>>,
    program_info_by_url: HashMap<String, Arc<Mutex<InfoPerProgram>>>,
    /// Where this context's asynchronous work is dispatched.
    ///
    /// Port of the `executor` field; defaults to `AsyncUtils.DIRECT_EXECUTOR`.
    pub executor: Arc<dyn AsyncExecutor>,
    change_listeners: Vec<Arc<dyn DebuggerStaticMappingChangeListener>>,
}

impl Default for DebuggerStaticMappingContext {
    fn default() -> Self {
        Self::new()
    }
}

impl DebuggerStaticMappingContext {
    /// Port of `DebuggerStaticMappingContext()`.
    pub fn new() -> Self {
        Self::with_executor(Arc::new(DirectExecutor))
    }

    /// Port of `DebuggerStaticMappingContext(Executor)`.
    pub fn with_executor(executor: Arc<dyn AsyncExecutor>) -> Self {
        DebuggerStaticMappingContext {
            trace_info_by_trace: HashMap::new(),
            program_info_by_program: HashMap::new(),
            program_info_by_url: HashMap::new(),
            executor,
            change_listeners: Vec::new(),
        }
    }

    /// Port of `DebuggerStaticMappingContext.addChangeListener(DebuggerStaticMappingChangeListener)`.
    pub fn add_change_listener(&mut self, l: Arc<dyn DebuggerStaticMappingChangeListener>) {
        if self.change_listeners.iter().any(|e| Arc::ptr_eq(e, &l)) {
            return;
        }
        self.change_listeners.push(l);
    }

    /// Port of `DebuggerStaticMappingContext.removeChangeListener(DebuggerStaticMappingChangeListener)`.
    pub fn remove_change_listener(&mut self, l: &Arc<dyn DebuggerStaticMappingChangeListener>) {
        self.change_listeners.retain(|e| !Arc::ptr_eq(e, l));
    }

    /// The registered change listeners, in registration order.
    pub fn change_listeners(&self) -> &[Arc<dyn DebuggerStaticMappingChangeListener>] {
        &self.change_listeners
    }

    /// Port of `DebuggerStaticMappingContext.collectChanges()`.
    pub fn collect_changes(&self) -> ChangeCollector {
        ChangeCollector::new()
    }

    /// Port of `DebuggerStaticMappingContext.addProgram(ChangeCollector, Program)`.
    pub fn add_program(&mut self, cc: &mut ChangeCollector, program: Arc<dyn Program>) {
        self.process_added_program(cc, program);
    }

    /// Port of `DebuggerStaticMappingContext.removeProgram(ChangeCollector, Program)`.
    pub fn remove_program(&mut self, cc: &mut ChangeCollector, program: &Arc<dyn Program>) {
        let Some(info) = self.require_program_info(program.as_ref()) else {
            return;
        };
        self.process_removed_program_info(cc, &info);
    }

    /// Port of `DebuggerStaticMappingContext.setPrograms(ChangeCollector, Set<Program>)`.
    pub fn set_programs(&mut self, cc: &mut ChangeCollector, programs: Vec<Arc<dyn Program>>) {
        let programs: HashSet<Arc<dyn Program>> = programs.into_iter().collect();
        let removed: Vec<Arc<Mutex<InfoPerProgram>>> = self
            .program_info_by_program
            .values()
            .filter(|i| {
                let info = i.lock().unwrap();
                !programs.contains(&info.program) || !info.url_matches()
            })
            .map(Arc::clone)
            .collect();
        self.process_removed_program_infos(cc, &removed);
        let added: Vec<Arc<dyn Program>> = programs
            .into_iter()
            .filter(|p| !self.program_info_by_program.contains_key(p))
            .collect();
        self.process_added_programs(cc, added);
    }

    /// Port of `DebuggerStaticMappingContext.addTrace(ChangeCollector, Trace)`.
    ///
    /// Takes the trace's info, which the context cannot construct itself (see the module
    /// divergence note).
    pub fn add_trace(
        &mut self,
        cc: &mut ChangeCollector,
        trace: Arc<dyn Trace>,
        info: Arc<Mutex<dyn InfoPerTrace>>,
    ) {
        self.process_added_trace(cc, trace, info);
    }

    /// Port of `DebuggerStaticMappingContext.removeTrace(ChangeCollector, Trace)`.
    pub fn remove_trace(&mut self, cc: &mut ChangeCollector, trace: &Arc<dyn Trace>) {
        self.process_removed_trace(cc, trace);
    }

    /// Port of `DebuggerStaticMappingContext.setTraces(ChangeCollector, Set<Trace>)`.
    ///
    /// Takes each trace's info, which the context cannot construct itself (see the module
    /// divergence note).
    pub fn set_traces(
        &mut self,
        cc: &mut ChangeCollector,
        traces: Vec<(Arc<dyn Trace>, Arc<Mutex<dyn InfoPerTrace>>)>,
    ) {
        let new_keys: HashSet<Arc<dyn Trace>> = traces.iter().map(|(t, _)| Arc::clone(t)).collect();
        let removed: Vec<Arc<dyn Trace>> = self
            .trace_info_by_trace
            .keys()
            .filter(|t| !new_keys.contains(*t))
            .map(Arc::clone)
            .collect();
        let added: Vec<(Arc<dyn Trace>, Arc<Mutex<dyn InfoPerTrace>>)> = traces
            .into_iter()
            .filter(|(t, _)| !self.trace_info_by_trace.contains_key(t))
            .collect();

        self.process_removed_traces(cc, &removed);
        self.process_added_traces(cc, added);
    }

    /// Port of `DebuggerStaticMappingContext.noTraceInfo()`.
    fn no_trace_info<T>(&self) -> Option<T> {
        Msg::debug(
            "DebuggerStaticMappingContext",
            &"The given trace is not open in this tool (or the service hasn't received and \
              processed the open-trace event, yet)",
        );
        None
    }

    /// Port of `DebuggerStaticMappingContext.noProgramInfo()`.
    fn no_program_info<T>(&self) -> Option<T> {
        Msg::debug(
            "DebuggerStaticMappingContext",
            &"The given program is not open in this tool (or the service hasn't received and \
              processed the open-program event, yet)",
        );
        None
    }

    /// Port of `DebuggerStaticMappingContext.checkAndClearProgram(ChangeCollector, MappingEntry)`.
    pub fn check_and_clear_program(
        &self,
        cc: &mut ChangeCollector,
        me: &Arc<Mutex<dyn MappingEntry>>,
    ) {
        let url = me.lock().unwrap().get_static_program_url();
        let Some(info) = url.and_then(|u| self.program_info_by_url.get(&u)) else {
            return;
        };
        info.lock().unwrap().clear_program(cc, Arc::clone(me));
    }

    /// Port of `DebuggerStaticMappingContext.checkAndFillProgram(ChangeCollector, MappingEntry)`.
    pub fn check_and_fill_program(
        &self,
        cc: &mut ChangeCollector,
        me: &Arc<Mutex<dyn MappingEntry>>,
    ) {
        let url = me.lock().unwrap().get_static_program_url();
        let Some(info) = url.and_then(|u| self.program_info_by_url.get(&u)) else {
            return;
        };
        info.lock().unwrap().fill_program(cc, Arc::clone(me));
    }

    /// Port of `DebuggerStaticMappingContext.processRemovedProgramInfos(ChangeCollector, Set)`.
    fn process_removed_program_infos(
        &mut self,
        cc: &mut ChangeCollector,
        removed: &[Arc<Mutex<InfoPerProgram>>],
    ) {
        for info in removed {
            self.process_removed_program_info(cc, info);
        }
    }

    /// Port of `DebuggerStaticMappingContext.processRemovedProgramInfo(ChangeCollector, InfoPerProgram)`.
    pub fn process_removed_program_info(
        &mut self,
        cc: &mut ChangeCollector,
        info: &Arc<Mutex<InfoPerProgram>>,
    ) {
        let (program, url) = {
            let info = info.lock().unwrap();
            (Arc::clone(&info.program), info.url.clone())
        };
        self.program_info_by_program.remove(&program);
        if let Some(url) = url {
            self.program_info_by_url.remove(&url);
        }
        let trace_infos = self.trace_infos();
        info.lock().unwrap().clear_entries(cc, &trace_infos);
    }

    /// Port of `DebuggerStaticMappingContext.processAddedPrograms(ChangeCollector, Set<Program>)`.
    fn process_added_programs(&mut self, cc: &mut ChangeCollector, added: Vec<Arc<dyn Program>>) {
        for program in added {
            self.process_added_program(cc, program);
        }
    }

    /// Port of `DebuggerStaticMappingContext.processAddedProgram(ChangeCollector, Program)`.
    pub fn process_added_program(&mut self, cc: &mut ChangeCollector, program: Arc<dyn Program>) {
        let info = Arc::new(Mutex::new(InfoPerProgram::new(Arc::clone(&program))));
        self.program_info_by_program
            .insert(program, Arc::clone(&info));
        if let Some(url) = info.lock().unwrap().url.clone() {
            self.program_info_by_url.insert(url, Arc::clone(&info));
        }
        let trace_infos = self.trace_infos();
        info.lock().unwrap().fill_entries(cc, &trace_infos);
    }

    /// Port of `DebuggerStaticMappingContext.processRemovedTraces(ChangeCollector, Set<Trace>)`.
    fn process_removed_traces(&mut self, cc: &mut ChangeCollector, removed: &[Arc<dyn Trace>]) {
        for trace in removed {
            self.process_removed_trace(cc, trace);
        }
    }

    /// Port of `DebuggerStaticMappingContext.processRemovedTrace(ChangeCollector, Trace)`.
    fn process_removed_trace(&mut self, cc: &mut ChangeCollector, trace: &Arc<dyn Trace>) {
        let Some(info) = self.trace_info_by_trace.remove(trace) else {
            let _: Option<()> = self.no_trace_info();
            return;
        };
        info.lock().unwrap().remove_entries(cc);
    }

    /// Port of `DebuggerStaticMappingContext.processAddedTraces(ChangeCollector, Set<Trace>)`.
    fn process_added_traces(
        &mut self,
        cc: &mut ChangeCollector,
        added: Vec<(Arc<dyn Trace>, Arc<Mutex<dyn InfoPerTrace>>)>,
    ) {
        for (trace, info) in added {
            self.process_added_trace(cc, trace, info);
        }
    }

    /// Port of `DebuggerStaticMappingContext.processAddedTrace(ChangeCollector, Trace)`.
    fn process_added_trace(
        &mut self,
        cc: &mut ChangeCollector,
        trace: Arc<dyn Trace>,
        info: Arc<Mutex<dyn InfoPerTrace>>,
    ) {
        self.trace_info_by_trace.insert(trace, Arc::clone(&info));
        info.lock().unwrap().resync_entries(cc);
    }

    /// The per-trace infos this context tracks (Java's `traceInfoByTrace.values()`).
    pub fn trace_infos(&self) -> Vec<Arc<Mutex<dyn InfoPerTrace>>> {
        self.trace_info_by_trace.values().map(Arc::clone).collect()
    }

    /// Port of `DebuggerStaticMappingContext.requireTrackedInfo(Trace)`.
    fn require_trace_info(&self, trace: &dyn Trace) -> Option<Arc<Mutex<dyn InfoPerTrace>>> {
        match self
            .trace_info_by_trace
            .iter()
            .find(|(t, _)| trace_id(t.as_ref()) == trace_id(trace))
        {
            Some((_, info)) => Some(Arc::clone(info)),
            None => self.no_trace_info(),
        }
    }

    /// The tracked key equal (by identity) to `trace`, if this context tracks it.
    ///
    /// Needed because [`DebuggerAddressTranslator`] hands traces over as `&dyn Trace`, while the
    /// per-program lookups need the shared `Arc` handle.
    fn require_trace_key(&self, trace: &dyn Trace) -> Option<Arc<dyn Trace>> {
        match self
            .trace_info_by_trace
            .keys()
            .find(|t| trace_id(t.as_ref()) == trace_id(trace))
        {
            Some(t) => Some(Arc::clone(t)),
            None => self.no_trace_info(),
        }
    }

    /// Port of `DebuggerStaticMappingContext.requireTrackedInfo(Program)`.
    fn require_program_info(&self, program: &dyn Program) -> Option<Arc<Mutex<InfoPerProgram>>> {
        match self
            .program_info_by_program
            .iter()
            .find(|(p, _)| program_id(p.as_ref()) == program_id(program))
        {
            Some((_, info)) => Some(Arc::clone(info)),
            None => self.no_program_info(),
        }
    }

    /// Port of `InfoPerProgram.domainObjectChanged(DomainObjectChangedEvent)`, relocated here (see
    /// the module divergence note): when a tracked program is renamed or its file changes, its URL
    /// may no longer match, in which case it is re-registered under the new URL.
    pub fn program_object_changed(
        &mut self,
        ev: &DomainObjectChangedEvent<'_>,
        program: &Arc<dyn Program>,
    ) {
        if !ev.contains(&DomainObjectEvent::FileChanged) && !ev.contains(&DomainObjectEvent::Renamed)
        {
            return;
        }
        let Some(info) = self.require_program_info(program.as_ref()) else {
            return;
        };
        if info.lock().unwrap().url_matches() {
            return;
        }
        let mut cc = self.collect_changes();
        self.process_removed_program_info(&mut cc, &info);
        self.process_added_program(&mut cc, Arc::clone(program));
        cc.close(self);
    }

    /// Port of `DebuggerStaticMappingContext.getNonScratchSnap(TraceProgramView)`.
    fn get_non_scratch_snap(&self, view: &dyn TraceProgramView) -> Option<i64> {
        let top = view
            .get_viewport()
            .get_top(&|s| if s >= 0 { Some(Box::new(s)) } else { None });
        top.and_then(|t| t.downcast_ref::<i64>().copied())
    }
}

impl DebuggerAddressTranslator for DebuggerStaticMappingContext {
    /// Port of `DebuggerStaticMappingContext.getOpenMappedProgramsAtSnap(Trace, long)`.
    fn get_open_mapped_programs_at_snap(
        &self,
        trace: &dyn Trace,
        snap: i64,
    ) -> Vec<Box<dyn Program>> {
        let Some(info) = self.require_trace_info(trace) else {
            return Vec::new();
        };
        let info = info.lock().unwrap();
        info.get_open_mapped_programs_at_snap(snap)
    }

    /// Port of `DebuggerStaticMappingContext.getOpenMappedLocation(TraceLocation)`.
    fn get_open_mapped_location(
        &self,
        loc: &dyn TraceLocation,
    ) -> Option<Box<dyn ProgramLocation>> {
        let trace = loc.get_trace();
        let info = self.require_trace_info(trace.as_ref())?;
        let info = info.lock().unwrap();
        info.get_open_mapped_program_location(&loc.get_address(), loc.get_lifespan())
    }

    /// Port of `DebuggerStaticMappingContext.getStaticLocationFromDynamic(ProgramLocation)`.
    ///
    /// Not implemented: see the module divergence note.
    fn get_static_location_from_dynamic(
        &self,
        _loc: &dyn ProgramLocation,
    ) -> Option<Box<dyn ProgramLocation>> {
        Msg::debug(
            "DebuggerStaticMappingContext",
            &"getStaticLocationFromDynamic requires downcasting the location's program to a \
              TraceProgramView, which is not yet possible in this port",
        );
        None
    }

    /// Port of `DebuggerStaticMappingContext.getOpenMappedLocations(ProgramLocation)`.
    fn get_open_mapped_locations(&self, loc: &dyn ProgramLocation) -> Vec<Box<dyn TraceLocation>> {
        let Some(info) = self.require_program_info(loc.get_program().as_ref()) else {
            return Vec::new();
        };
        let info = info.lock().unwrap();
        info.get_open_mapped_trace_locations(&loc.get_byte_address())
    }

    /// Port of `DebuggerStaticMappingContext.getOpenMappedLocation(Trace, ProgramLocation, long)`.
    fn get_open_mapped_trace_location(
        &self,
        trace: &dyn Trace,
        loc: &dyn ProgramLocation,
        snap: i64,
    ) -> Option<Box<dyn TraceLocation>> {
        let info = self.require_program_info(loc.get_program().as_ref())?;
        let trace = self.require_trace_key(trace)?;
        let info = info.lock().unwrap();
        info.get_open_mapped_trace_location(&trace, &loc.get_byte_address(), snap)
    }

    /// Port of `DebuggerStaticMappingContext.getDynamicLocationFromStatic(TraceProgramView,
    /// ProgramLocation)`.
    ///
    /// Not implemented: see the module divergence note.
    fn get_dynamic_location_from_static(
        &self,
        _view: &dyn TraceProgramView,
        _loc: &dyn ProgramLocation,
    ) -> Option<Box<dyn ProgramLocation>> {
        Msg::debug(
            "DebuggerStaticMappingContext",
            &"getDynamicLocationFromStatic requires an owned handle to the given view to build \
              the resulting location, which is not yet possible in this port",
        );
        None
    }

    /// Port of `DebuggerStaticMappingContext.getOpenMappedViews(Trace, AddressSetView, long)`.
    fn get_open_mapped_views(
        &self,
        trace: &dyn Trace,
        set: &dyn AddressSetView,
        snap: i64,
    ) -> Vec<(Box<dyn Program>, Vec<MappedAddressRange>)> {
        let Some(info) = self.require_trace_info(trace) else {
            return Vec::new();
        };
        let info = info.lock().unwrap();
        info.get_open_mapped_views(set, Lifespan::at(snap))
    }

    /// Port of `DebuggerStaticMappingContext.getOpenMappedViews(Program, AddressSetView)`.
    fn get_open_mapped_views_for_program(
        &self,
        program: &dyn Program,
        set: &dyn AddressSetView,
    ) -> Vec<(DefaultTraceSpan, Vec<MappedAddressRange>)> {
        let Some(info) = self.require_program_info(program) else {
            return Vec::new();
        };
        let info = info.lock().unwrap();
        info.get_open_mapped_views(set).into_iter().collect()
    }

    /// Port of `DebuggerStaticMappingContext.getMappedProgramUrlsInView(Trace, AddressSetView,
    /// long)`.
    fn get_mapped_program_urls_in_view(
        &self,
        trace: &dyn Trace,
        set: &dyn AddressSetView,
        snap: i64,
    ) -> Vec<String> {
        let Some(info) = self.require_trace_info(trace) else {
            return Vec::new();
        };
        let info = info.lock().unwrap();
        info.get_mapped_program_urls_in_view(set, Lifespan::at(snap))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::domain_file::DomainFile;
    use crate::framework::model::domain_object::DomainObject;
    use crate::framework::model::domain_object_change_record::DomainObjectChangeRecord;
    use crate::program::model::address::{
        Address, AddressRange, AddressSet, AddressSpace, AddressSpaceType,
    };
    use crate::trace::model::thread::trace_thread::TraceThread;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(space(), offset)
    }

    struct MockDomainFile {
        url: Option<String>,
    }

    impl DomainFile for MockDomainFile {
        fn get_shared_project_url(&self, _reference: Option<&str>) -> Option<String> {
            self.url.clone()
        }
    }

    struct MockProgram {
        url: Mutex<Option<String>>,
    }

    impl DomainObject for MockProgram {
        fn get_domain_file(&self) -> Option<Box<dyn DomainFile>> {
            Some(Box::new(MockDomainFile {
                url: self.url.lock().unwrap().clone(),
            }))
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:64:default".to_string()
        }
    }

    fn make_program(url: &str) -> Arc<MockProgram> {
        Arc::new(MockProgram {
            url: Mutex::new(Some(url.to_string())),
        })
    }

    struct MockTrace;
    impl DomainObject for MockTrace {
        fn get_name(&self) -> String {
            "mock-trace".to_string()
        }
    }
    impl crate::program::model::data::data_type_manager_domain_object::DataTypeManagerDomainObject
        for MockTrace
    {
    }
    impl crate::app::merge::DataTypeManagerOwner for MockTrace {
        fn get_data_type_manager(
            &self,
        ) -> &dyn crate::program::model::data::data_type_manager::DataTypeManager {
            unimplemented!("not exercised by this smoke test")
        }
    }
    impl Trace for MockTrace {
        fn get_base_language(&self) -> Box<dyn crate::program::model::lang::Language> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_compiler_spec(&self) -> Box<dyn crate::program::model::lang::CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn set_emulator_cache_version(&mut self, _version: i64) {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_emulator_cache_version(&self) -> i64 {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_address_factory(
            &self,
        ) -> Box<dyn crate::program::model::address::AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_address_property_manager(
            &self,
        ) -> Box<dyn crate::trace::model::property::TraceAddressPropertyManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_bookmark_manager(&self) -> Box<dyn crate::trace::seam_stubs::TraceBookmarkManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_breakpoint_manager(
            &self,
        ) -> Box<
            dyn crate::trace::model::breakpoint::trace_breakpoint_manager::TraceBreakpointManager,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_code_manager(&self) -> Box<dyn crate::trace::model::listing::TraceCodeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_base_data_type_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceBasedDataTypeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_equate_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_equate_manager::TraceEquateManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_platform_manager(
            &self,
        ) -> Box<dyn crate::trace::model::guest::trace_platform_manager::TracePlatformManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_memory_manager(
            &self,
        ) -> Box<dyn crate::trace::model::memory::trace_memory_manager::TraceMemoryManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_module_manager(&self) -> Box<dyn crate::trace::model::modules::TraceModuleManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_object_manager(
            &self,
        ) -> Box<dyn crate::trace::model::target::trace_object_manager::TraceObjectManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_reference_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_reference_manager::TraceReferenceManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_register_context_manager(
            &self,
        ) -> Box<dyn crate::trace::seam_stubs::TraceRegisterContextManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_stack_manager(
            &self,
        ) -> Box<dyn crate::trace::model::stack::trace_stack_manager::TraceStackManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_static_mapping_manager(
            &self,
        ) -> Box<dyn crate::trace::model::modules::TraceStaticMappingManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_symbol_manager(
            &self,
        ) -> Box<dyn crate::trace::model::symbol::trace_symbol_manager::TraceSymbolManager>
        {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread_manager(&self) -> Box<dyn crate::trace::model::thread::TraceThreadManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_time_manager(
            &self,
        ) -> Box<dyn crate::trace::model::time::trace_time_manager::TraceTimeManager> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_fixed_program_view(&self, _snap: i64) -> Box<dyn TraceProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_program_view(
            &self,
            _snap: i64,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_all_program_views(&self) -> Vec<Box<dyn TraceProgramView>> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_program_view(
            &self,
        ) -> Box<dyn crate::trace::model::program::TraceVariableSnapProgramView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn create_time_viewport(
            &self,
        ) -> Box<dyn crate::trace::model::trace_time_viewport::TraceTimeViewport> {
            unimplemented!("not exercised by this smoke test")
        }
        fn add_program_view_listener(
            &mut self,
            _listener: Box<dyn crate::trace::model::trace::TraceProgramViewListener>,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn remove_program_view_listener(
            &mut self,
            _listener: &dyn crate::trace::model::trace::TraceProgramViewListener,
        ) {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_read(
            &self,
        ) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
        fn lock_write(
            &self,
        ) -> crate::util::lock_hold::LockHold<'_, dyn crate::util::lock_hold::Lock> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    /// Records the calls the context makes on a per-trace info, and answers the translator's
    /// trace-side queries with fixed data.
    struct MockInfoPerTrace {
        program: Arc<dyn Program>,
        url: String,
        removed: Arc<AtomicUsize>,
        resynced: Arc<AtomicUsize>,
        cleared_for_program: Arc<AtomicUsize>,
        filled_for_program: Arc<AtomicUsize>,
    }

    impl MockInfoPerTrace {
        fn new(program: Arc<dyn Program>, url: &str) -> Self {
            MockInfoPerTrace {
                program,
                url: url.to_string(),
                removed: Arc::new(AtomicUsize::new(0)),
                resynced: Arc::new(AtomicUsize::new(0)),
                cleared_for_program: Arc::new(AtomicUsize::new(0)),
                filled_for_program: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl InfoPerTrace for MockInfoPerTrace {
        fn clear_entries_for_program(&mut self, _cc: &mut ChangeCollector, _info: &InfoPerProgram) {
            self.cleared_for_program.fetch_add(1, Ordering::SeqCst);
        }

        fn fill_entries_for_program(&mut self, _cc: &mut ChangeCollector, _info: &InfoPerProgram) {
            self.filled_for_program.fetch_add(1, Ordering::SeqCst);
        }

        fn remove_entries(&mut self, _cc: &mut ChangeCollector) {
            self.removed.fetch_add(1, Ordering::SeqCst);
        }

        fn resync_entries(&mut self, _cc: &mut ChangeCollector) {
            self.resynced.fetch_add(1, Ordering::SeqCst);
        }

        fn get_open_mapped_programs_at_snap(&self, snap: i64) -> Vec<Box<dyn Program>> {
            if snap < 0 {
                return Vec::new();
            }
            vec![Box::new(MockProgram {
                url: Mutex::new(Some(self.url.clone())),
            })]
        }

        fn get_open_mapped_program_location(
            &self,
            address: &Address,
            _lifespan: Lifespan,
        ) -> Option<Box<dyn ProgramLocation>> {
            Some(
                crate::feature::base::memsearch::bytesource::addressable_byte_source::generate_program_location(
                    Arc::clone(&self.program),
                    address,
                ),
            )
        }

        fn get_open_mapped_views(
            &self,
            _set: &dyn AddressSetView,
            _lifespan: Lifespan,
        ) -> Vec<(Box<dyn Program>, Vec<MappedAddressRange>)> {
            Vec::new()
        }

        fn get_mapped_program_urls_in_view(
            &self,
            _set: &dyn AddressSetView,
            _lifespan: Lifespan,
        ) -> Vec<String> {
            vec![self.url.clone()]
        }
    }

    struct MockMappingEntry {
        trace: Arc<dyn Trace>,
        static_range: Mutex<Option<AddressRange>>,
        target_static_range: AddressRange,
        static_program_url: String,
    }

    impl MockMappingEntry {
        fn new(trace: Arc<dyn Trace>, url: &str, range: AddressRange) -> Self {
            MockMappingEntry {
                trace,
                static_range: Mutex::new(None),
                target_static_range: range,
                static_program_url: url.to_string(),
            }
        }
    }

    impl MappingEntry for MockMappingEntry {
        fn get_trace(&self) -> Arc<dyn Trace> {
            Arc::clone(&self.trace)
        }

        fn get_static_range(&self) -> Option<AddressRange> {
            self.static_range.lock().unwrap().clone()
        }

        fn get_static_address(&self) -> Option<Address> {
            self.static_range
                .lock()
                .unwrap()
                .as_ref()
                .map(|r| r.min_address().clone())
        }

        fn get_trace_span(&self) -> DefaultTraceSpan {
            DefaultTraceSpan::new(Arc::clone(&self.trace), Lifespan::span(0, 10))
        }

        fn is_in_trace_lifespan(&self, snap: i64) -> bool {
            (0..=10).contains(&snap)
        }

        fn is_in_program_range(&self, address: &Address) -> bool {
            self.static_range
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|r| r.contains(address))
        }

        fn is_in_program_range_for_range(&self, rng: &AddressRange) -> bool {
            self.static_range
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|r| r.intersects(rng))
        }

        fn map_program_address_to_trace_location(
            &self,
            _address: &Address,
        ) -> Box<dyn TraceLocation> {
            Box::new(MockTraceLocation)
        }

        fn map_program_range_to_trace(&self, rng: &AddressRange) -> AddressRange {
            rng.clone()
        }

        fn get_static_program_url(&self) -> Option<String> {
            Some(self.static_program_url.clone())
        }

        fn is_mapping_deleted(&self) -> bool {
            false
        }

        fn clear_program(&mut self, _cc: &mut ChangeCollector, _program: &dyn Program) {
            *self.static_range.lock().unwrap() = None;
        }

        fn fill_program(&mut self, _cc: &mut ChangeCollector, _program: &dyn Program) {
            *self.static_range.lock().unwrap() = Some(self.target_static_range.clone());
        }
    }

    struct MockTraceLocation;
    impl TraceLocation for MockTraceLocation {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_lifespan(&self) -> Lifespan {
            Lifespan::at(0)
        }
        fn get_address(&self) -> Address {
            addr(0x400)
        }
    }

    struct MockProgramLocation {
        program: Arc<dyn Program>,
        address: Address,
    }

    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::clone(&self.program)
        }
        fn get_address(&self) -> Address {
            self.address.clone()
        }
        fn get_byte_address(&self) -> Address {
            self.address.clone()
        }
    }

    struct RecordingListener {
        calls: Mutex<Vec<(usize, usize)>>,
    }

    impl DebuggerStaticMappingChangeListener for RecordingListener {
        fn mappings_changed(
            &self,
            affected_traces: &HashSet<Arc<dyn Trace>>,
            affected_programs: &HashSet<Arc<dyn Program>>,
        ) {
            self.calls
                .lock()
                .unwrap()
                .push((affected_traces.len(), affected_programs.len()));
        }
    }

    /// Registers `program`, then hands the context a mapping entry naming that program's URL, as
    /// `InfoPerTrace` would once a trace's static-mapping table is read.
    fn ctx_with_mapped_program(
        program: &Arc<dyn Program>,
        trace: &Arc<dyn Trace>,
        url: &str,
    ) -> DebuggerStaticMappingContext {
        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_program(&mut cc, Arc::clone(program));
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry::new(
            Arc::clone(trace),
            url,
            AddressRange::new(addr(0x1000), addr(0x1fff)),
        )));
        ctx.check_and_fill_program(&mut cc, &me);
        cc.close(&ctx);
        ctx
    }

    #[test]
    fn mapping_entry_is_routed_to_the_program_info_matching_its_url() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let ctx = ctx_with_mapped_program(&program, &trace, "ghidra://repo/a");

        let loc = MockProgramLocation {
            program: Arc::clone(&program),
            address: addr(0x1800),
        };
        // Java: getOpenMappedLocations returns the trace locations for the filled entry.
        assert_eq!(ctx.get_open_mapped_locations(&loc).len(), 1);

        // An entry naming an unknown URL is dropped on the floor (Java: info == null -> return).
        let mut cc = ctx.collect_changes();
        let other: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry::new(
            Arc::clone(&trace),
            "ghidra://repo/unknown",
            AddressRange::new(addr(0x3000), addr(0x3fff)),
        )));
        ctx.check_and_fill_program(&mut cc, &other);
        assert!(other.lock().unwrap().get_static_range().is_none());
        assert_eq!(ctx.get_open_mapped_locations(&loc).len(), 1);
    }

    #[test]
    fn check_and_clear_program_undoes_check_and_fill_program() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_program(&mut cc, Arc::clone(&program));
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry::new(
            Arc::clone(&trace),
            "ghidra://repo/a",
            AddressRange::new(addr(0x1000), addr(0x1fff)),
        )));
        ctx.check_and_fill_program(&mut cc, &me);

        let loc = MockProgramLocation {
            program: Arc::clone(&program),
            address: addr(0x1800),
        };
        assert_eq!(ctx.get_open_mapped_locations(&loc).len(), 1);

        ctx.check_and_clear_program(&mut cc, &me);
        assert!(ctx.get_open_mapped_locations(&loc).is_empty());
        assert!(me.lock().unwrap().get_static_range().is_none());
    }

    #[test]
    fn removing_a_program_untracks_it() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mut ctx = ctx_with_mapped_program(&program, &trace, "ghidra://repo/a");
        let loc = MockProgramLocation {
            program: Arc::clone(&program),
            address: addr(0x1800),
        };
        assert_eq!(ctx.get_open_mapped_locations(&loc).len(), 1);

        let mut cc = ctx.collect_changes();
        ctx.remove_program(&mut cc, &program);
        cc.close(&ctx);

        // Untracked: Java logs "not open in this tool" and returns null.
        assert!(ctx.get_open_mapped_locations(&loc).is_empty());
        // ...and the URL index dropped with it, so entries no longer resolve.
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry::new(
            Arc::clone(&trace),
            "ghidra://repo/a",
            AddressRange::new(addr(0x1000), addr(0x1fff)),
        )));
        let mut cc = ctx.collect_changes();
        ctx.check_and_fill_program(&mut cc, &me);
        assert!(me.lock().unwrap().get_static_range().is_none());
    }

    #[test]
    fn set_programs_drops_untracked_and_adds_new() {
        let kept: Arc<dyn Program> = make_program("ghidra://repo/kept");
        let dropped: Arc<dyn Program> = make_program("ghidra://repo/dropped");
        let fresh: Arc<dyn Program> = make_program("ghidra://repo/fresh");

        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_program(&mut cc, Arc::clone(&kept));
        ctx.add_program(&mut cc, Arc::clone(&dropped));
        ctx.set_programs(&mut cc, vec![Arc::clone(&kept), Arc::clone(&fresh)]);
        cc.close(&ctx);

        let empty = AddressSet::new();
        assert!(ctx
            .require_program_info(kept.as_ref())
            .is_some());
        assert!(ctx.require_program_info(dropped.as_ref()).is_none());
        assert!(ctx.require_program_info(fresh.as_ref()).is_some());
        // The surviving infos answer queries; the dropped one does not.
        assert!(ctx
            .get_open_mapped_views_for_program(fresh.as_ref(), &empty)
            .is_empty());
    }

    #[test]
    fn set_programs_re_registers_a_program_whose_url_changed() {
        let program = make_program("ghidra://repo/a");
        let as_program: Arc<dyn Program> = Arc::clone(&program) as Arc<dyn Program>;
        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_program(&mut cc, Arc::clone(&as_program));

        *program.url.lock().unwrap() = Some("ghidra://repo/b".to_string());
        ctx.set_programs(&mut cc, vec![Arc::clone(&as_program)]);
        cc.close(&ctx);

        // Re-indexed under the new URL: an entry naming it now fills.
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry::new(
            trace,
            "ghidra://repo/b",
            AddressRange::new(addr(0x1000), addr(0x1fff)),
        )));
        let mut cc = ctx.collect_changes();
        ctx.check_and_fill_program(&mut cc, &me);
        assert!(me.lock().unwrap().get_static_range().is_some());
    }

    #[test]
    fn program_object_changed_re_registers_a_renamed_program() {
        let program = make_program("ghidra://repo/a");
        let as_program: Arc<dyn Program> = Arc::clone(&program) as Arc<dyn Program>;
        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_program(&mut cc, Arc::clone(&as_program));
        cc.close(&ctx);

        *program.url.lock().unwrap() = Some("ghidra://repo/renamed".to_string());
        let ev = DomainObjectChangedEvent::new(
            as_program.as_ref(),
            vec![DomainObjectChangeRecord::new(Box::new(
                DomainObjectEvent::Renamed,
            ))],
        );
        ctx.program_object_changed(&ev, &as_program);

        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let me: Arc<Mutex<dyn MappingEntry>> = Arc::new(Mutex::new(MockMappingEntry::new(
            trace,
            "ghidra://repo/renamed",
            AddressRange::new(addr(0x1000), addr(0x1fff)),
        )));
        let mut cc = ctx.collect_changes();
        ctx.check_and_fill_program(&mut cc, &me);
        assert!(me.lock().unwrap().get_static_range().is_some());
    }

    #[test]
    fn trace_lifecycle_drives_the_per_trace_info() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mock = MockInfoPerTrace::new(Arc::clone(&program), "ghidra://repo/a");
        let (removed, resynced) = (Arc::clone(&mock.removed), Arc::clone(&mock.resynced));
        let info: Arc<Mutex<dyn InfoPerTrace>> = Arc::new(Mutex::new(mock));

        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_trace(&mut cc, Arc::clone(&trace), Arc::clone(&info));
        assert_eq!(resynced.load(Ordering::SeqCst), 1);

        // Trace-side queries now route to that info.
        assert_eq!(
            ctx.get_open_mapped_programs_at_snap(trace.as_ref(), 0).len(),
            1
        );
        assert_eq!(
            ctx.get_mapped_program_urls_in_view(trace.as_ref(), &AddressSet::new(), 0),
            vec!["ghidra://repo/a".to_string()]
        );

        ctx.remove_trace(&mut cc, &trace);
        assert_eq!(removed.load(Ordering::SeqCst), 1);
        assert!(ctx
            .get_open_mapped_programs_at_snap(trace.as_ref(), 0)
            .is_empty());
        cc.close(&ctx);
    }

    #[test]
    fn set_traces_removes_absent_and_adds_present() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let old_trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let new_trace: Arc<dyn Trace> = Arc::new(MockTrace);

        let old_mock = MockInfoPerTrace::new(Arc::clone(&program), "ghidra://repo/old");
        let old_removed = Arc::clone(&old_mock.removed);
        let old_info: Arc<Mutex<dyn InfoPerTrace>> = Arc::new(Mutex::new(old_mock));
        let new_mock = MockInfoPerTrace::new(Arc::clone(&program), "ghidra://repo/new");
        let new_resynced = Arc::clone(&new_mock.resynced);
        let new_info: Arc<Mutex<dyn InfoPerTrace>> = Arc::new(Mutex::new(new_mock));

        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_trace(&mut cc, Arc::clone(&old_trace), old_info);
        ctx.set_traces(
            &mut cc,
            vec![(Arc::clone(&new_trace), Arc::clone(&new_info))],
        );
        cc.close(&ctx);

        assert_eq!(old_removed.load(Ordering::SeqCst), 1);
        assert_eq!(new_resynced.load(Ordering::SeqCst), 1);
        assert!(ctx
            .get_open_mapped_programs_at_snap(old_trace.as_ref(), 0)
            .is_empty());
        assert_eq!(
            ctx.get_mapped_program_urls_in_view(new_trace.as_ref(), &AddressSet::new(), 0),
            vec!["ghidra://repo/new".to_string()]
        );
    }

    #[test]
    fn adding_a_program_fills_entries_on_every_open_trace() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mock = MockInfoPerTrace::new(Arc::clone(&program), "ghidra://repo/a");
        let (filled, cleared) = (
            Arc::clone(&mock.filled_for_program),
            Arc::clone(&mock.cleared_for_program),
        );
        let info: Arc<Mutex<dyn InfoPerTrace>> = Arc::new(Mutex::new(mock));

        let mut ctx = DebuggerStaticMappingContext::new();
        let mut cc = ctx.collect_changes();
        ctx.add_trace(&mut cc, Arc::clone(&trace), info);
        ctx.add_program(&mut cc, Arc::clone(&program));
        assert_eq!(filled.load(Ordering::SeqCst), 1);
        assert_eq!(cleared.load(Ordering::SeqCst), 0);

        ctx.remove_program(&mut cc, &program);
        assert_eq!(cleared.load(Ordering::SeqCst), 1);
        cc.close(&ctx);
    }

    #[test]
    fn change_collector_reports_affected_traces_and_programs_on_close() {
        let listener = Arc::new(RecordingListener {
            calls: Mutex::new(Vec::new()),
        });
        let mut ctx = DebuggerStaticMappingContext::new();
        ctx.add_change_listener(Arc::clone(&listener) as Arc<dyn DebuggerStaticMappingChangeListener>);

        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mut cc = ctx.collect_changes();
        cc.trace_affected(Arc::clone(&trace));
        cc.trace_affected(Arc::clone(&trace)); // Java: a Set, so the repeat collapses.
        cc.program_affected(Some(Arc::clone(&program)));
        cc.program_affected(None); // Java: null programs are ignored.
        assert_eq!(cc.traces().len(), 1);
        assert_eq!(cc.programs().len(), 1);
        cc.close(&ctx);

        assert_eq!(*listener.calls.lock().unwrap(), vec![(1, 1)]);

        // Removed listeners stop hearing about changes.
        let as_listener: Arc<dyn DebuggerStaticMappingChangeListener> =
            Arc::clone(&listener) as Arc<dyn DebuggerStaticMappingChangeListener>;
        ctx.remove_change_listener(&as_listener);
        let mut cc = ctx.collect_changes();
        cc.trace_affected(Arc::clone(&trace));
        cc.close(&ctx);
        assert_eq!(listener.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn open_mapped_views_for_program_maps_the_static_range() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let ctx = ctx_with_mapped_program(&program, &trace, "ghidra://repo/a");

        let mut set = AddressSet::new();
        set.add_range(&addr(0x1000), &addr(0x1fff));
        let views = ctx.get_open_mapped_views_for_program(program.as_ref(), &set);
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].1.len(), 1);
        assert_eq!(
            *views[0].1[0].source_address_range(),
            AddressRange::new(addr(0x1000), addr(0x1fff))
        );

        // An untracked program yields nothing rather than panicking.
        let other: Arc<dyn Program> = make_program("ghidra://repo/other");
        assert!(ctx
            .get_open_mapped_views_for_program(other.as_ref(), &set)
            .is_empty());
    }

    #[test]
    fn open_mapped_trace_location_requires_a_tracked_trace() {
        let program: Arc<dyn Program> = make_program("ghidra://repo/a");
        let trace: Arc<dyn Trace> = Arc::new(MockTrace);
        let mut ctx = ctx_with_mapped_program(&program, &trace, "ghidra://repo/a");
        let mock = MockInfoPerTrace::new(Arc::clone(&program), "ghidra://repo/a");
        let info: Arc<Mutex<dyn InfoPerTrace>> = Arc::new(Mutex::new(mock));
        let mut cc = ctx.collect_changes();
        ctx.add_trace(&mut cc, Arc::clone(&trace), info);
        cc.close(&ctx);

        let loc = MockProgramLocation {
            program: Arc::clone(&program),
            address: addr(0x1800),
        };
        assert!(ctx
            .get_open_mapped_trace_location(trace.as_ref(), &loc, 5)
            .is_some());
        // Snap outside the entry's lifespan.
        assert!(ctx
            .get_open_mapped_trace_location(trace.as_ref(), &loc, 50)
            .is_none());
        // An untracked trace has no shared handle to match entries against.
        let untracked: Arc<dyn Trace> = Arc::new(MockTrace);
        assert!(ctx
            .get_open_mapped_trace_location(untracked.as_ref(), &loc, 5)
            .is_none());
    }
}
