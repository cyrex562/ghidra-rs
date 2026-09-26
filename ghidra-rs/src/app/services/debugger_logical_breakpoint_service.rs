//! Aggregates breakpoints for programs and traces into "logical" breakpoints.
//!
//! Port of `ghidra.app.services.DebuggerLogicalBreakpointService`. The Java `@ServiceInfo`
//! annotation (default provider `DebuggerLogicalBreakpointServicePlugin`) is metadata rather than a
//! runtime type, so it has no Rust equivalent and is omitted.
//!
//! Several Java methods are overloaded on parameter type alone, which Rust traits cannot express;
//! each overload is given a distinct name, keeping the `ProgramLocation` form (the one the default
//! methods build on) at the base name:
//! - `getBreakpoints(Program)`/`getBreakpoints(Trace)` become
//!   [`get_breakpoints_for_program`](DebuggerLogicalBreakpointService::get_breakpoints_for_program)
//!   and [`get_breakpoints_for_trace`](DebuggerLogicalBreakpointService::get_breakpoints_for_trace).
//! - `getBreakpointsAt(ProgramLocation)` stays [`get_breakpoints_at`](DebuggerLogicalBreakpointService::get_breakpoints_at);
//!   the `(Program, Address)` and `(Trace, Address)` forms become
//!   [`get_breakpoints_at_in_program`](DebuggerLogicalBreakpointService::get_breakpoints_at_in_program)
//!   and [`get_breakpoints_at_in_trace`](DebuggerLogicalBreakpointService::get_breakpoints_at_in_trace).
//! - `placeBreakpointAt(ProgramLocation, ...)` stays [`place_breakpoint_at`](DebuggerLogicalBreakpointService::place_breakpoint_at);
//!   the `Program`/`Trace` forms gain `_in_program`/`_in_trace` suffixes.
//! - The five `computeState` overloads become
//!   [`compute_state`](DebuggerLogicalBreakpointService::compute_state),
//!   [`compute_state_for_program`](DebuggerLogicalBreakpointService::compute_state_for_program),
//!   [`compute_state_for_trace`](DebuggerLogicalBreakpointService::compute_state_for_trace),
//!   [`compute_state_at`](DebuggerLogicalBreakpointService::compute_state_at), and
//!   [`compute_state_at_location`](DebuggerLogicalBreakpointService::compute_state_at_location).
//! - `anyMapped(Collection, Trace)`/`anyMapped(Collection)` become
//!   [`any_mapped_to_trace`](DebuggerLogicalBreakpointService::any_mapped_to_trace) and
//!   [`any_mapped`](DebuggerLogicalBreakpointService::any_mapped); Java's `trace == null` fallback
//!   from the former to the latter is expressed by an `Option<&dyn Trace>` parameter.
//! - `generateStatusToggleAt`/`toggleBreakpointsAt` keep their explicit-set forms at the base name;
//!   the defaults that first look the set up become `..._at_location`.
//!
//! Java's `null` returns (`getBreakpoint`, `generateStatusEnable`, `generateStatusToggleAt`) become
//! `Option`. Java's `CompletableFuture<...>` returns become boxed futures, as in
//! [`DebuggerStaticMappingService`](crate::app::services::DebuggerStaticMappingService).
//!
//! Java's `Set<LogicalBreakpoint>` becomes `Vec<Arc<dyn LogicalBreakpoint>>`: `LogicalBreakpoint` is
//! a trait object with no `Hash`/`Eq`, so it cannot key a `HashSet`. `NavigableMap<Address, ...>`
//! becomes a [`BTreeMap`], which is Rust's sorted-map equivalent.
//!
//! `LogicalBreakpoint` and its nested `State` enum are not yet ported; they are represented by
//! [`crate::debug::seam_stubs::LogicalBreakpoint`] and
//! [`crate::debug::seam_stubs::LogicalBreakpointState`]. See `STUBS.tsv` for provenance.
//!
//! Java's two static helpers, `addressFromLocation` and `programOrTrace`, both branch on
//! `instanceof`, which Rust cannot do through a trait object. Each is ported as a free function
//! that takes the discriminating information explicitly: see [`address_from_location`] /
//! [`address_from_code_unit_location`] and [`program_or_trace`].

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::debug::api::breakpoint::LogicalBreakpointsChangeListener;
use crate::debug::seam_stubs::{LogicalBreakpoint, LogicalBreakpointState};
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::util::{CodeUnitLocation, ProgramLocation};
use crate::trace::model::breakpoint::trace_breakpoint_kind::TraceBreakpointKind;
use crate::trace::model::breakpoint::trace_breakpoint_location::TraceBreakpointLocation;
use crate::trace::model::program::TraceProgramView;
use crate::trace::model::trace::Trace;

/// A future representing an asynchronous breakpoint command that produces no value.
///
/// Port of the `CompletableFuture<Void>` returned by most of this service's commands.
pub type BreakpointCommandFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// A future producing a set of logical breakpoints.
///
/// Port of the `CompletableFuture<Set<LogicalBreakpoint>>` returned by
/// [`DebuggerLogicalBreakpointService::toggle_breakpoints_at`].
pub type BreakpointSetFuture =
    Pin<Box<dyn Future<Output = Vec<Arc<dyn LogicalBreakpoint>>> + Send>>;

/// A routine that places a breakpoint when there is none to toggle.
///
/// Port of Java's `Supplier<CompletableFuture<Set<LogicalBreakpoint>>>` parameter to
/// `toggleBreakpointsAt`. It is called at most once, hence `FnOnce`.
pub type BreakpointPlacer = Box<dyn FnOnce() -> BreakpointSetFuture + Send>;

/// The static image or the trace behind a [`ProgramLocation`], as resolved by
/// [`program_or_trace`].
///
/// Port of the `Program`-versus-`Trace` branch of Java's
/// `DebuggerLogicalBreakpointService.programOrTrace`.
pub enum LocationTarget {
    /// The location refers to a program database (static image).
    Program(Arc<dyn Program>),
    /// The location refers to a view of a trace.
    Trace(Box<dyn Trace>),
}

/// Get the address most likely intended by the user for a location that is *not* a code unit
/// location.
///
/// Program locations always have addresses at the start of a code unit, no matter how the location
/// was produced. Java's `addressFromLocation` interprets the context a bit deeper: if the location
/// is a `CodeUnitLocation` it takes the location's address, otherwise its byte address. Rust cannot
/// perform that `instanceof` test through a `&dyn ProgramLocation`, so the two branches are split
/// into this function and [`address_from_code_unit_location`], and the caller — which knows the
/// concrete location type — picks.
///
/// Port of the `else` branch of `DebuggerLogicalBreakpointService.addressFromLocation`.
pub fn address_from_location(loc: &dyn ProgramLocation) -> Address {
    loc.get_byte_address()
}

/// Get the address most likely intended by the user for a code unit location, namely the code
/// unit's minimum address.
///
/// Port of the `instanceof CodeUnitLocation` branch of
/// `DebuggerLogicalBreakpointService.addressFromLocation`. See [`address_from_location`] for why
/// the two branches are separate functions.
pub fn address_from_code_unit_location(loc: &dyn CodeUnitLocation) -> Address {
    loc.get_address()
}

/// Resolve a location to either its static image or, if the location's program is a view of a
/// trace, that trace.
///
/// Java tests `loc.getProgram() instanceof TraceProgramView`, which Rust cannot do through a
/// `&dyn Program`; the caller passes `view` when it knows the location's program is a trace view,
/// and `None` when it is a program database.
///
/// Port of `DebuggerLogicalBreakpointService.programOrTrace`, minus the address the Java version
/// bundles into its callbacks — compute that with [`address_from_location`] or
/// [`address_from_code_unit_location`] as appropriate.
pub fn program_or_trace(
    loc: &dyn ProgramLocation,
    view: Option<&dyn TraceProgramView>,
) -> LocationTarget {
    match view {
        Some(view) => LocationTarget::Trace(view.get_trace()),
        None => LocationTarget::Program(loc.get_program()),
    }
}

/// Aggregates breakpoints for programs and traces.
///
/// Port of `ghidra.app.services.DebuggerLogicalBreakpointService`.
pub trait DebuggerLogicalBreakpointService {
    /// Get all logical breakpoints known to the tool.
    fn get_all_breakpoints(&self) -> Vec<Arc<dyn LogicalBreakpoint>>;

    /// Get a map of addresses to collected logical breakpoints for a given program.
    ///
    /// The program ought to be a program database, not a view of a trace.
    fn get_breakpoints_for_program(
        &self,
        program: &dyn Program,
    ) -> BTreeMap<Address, Vec<Arc<dyn LogicalBreakpoint>>>;

    /// Get a map of addresses to collected logical breakpoints for a given trace.
    ///
    /// The map only includes breakpoints visible in the trace's primary view. Visibility depends
    /// on the view's snapshot.
    fn get_breakpoints_for_trace(
        &self,
        trace: &dyn Trace,
    ) -> BTreeMap<Address, Vec<Arc<dyn LogicalBreakpoint>>>;

    /// Get the collected logical breakpoints at the given program location.
    ///
    /// The program ought to be a program database, not a view of a trace.
    fn get_breakpoints_at_in_program(
        &self,
        program: &dyn Program,
        address: &Address,
    ) -> Vec<Arc<dyn LogicalBreakpoint>>;

    /// Get the collected logical breakpoints at the given trace location.
    ///
    /// The result only includes breakpoints visible in the trace's primary view. Visibility depends
    /// on the view's snapshot.
    fn get_breakpoints_at_in_trace(
        &self,
        trace: &dyn Trace,
        address: &Address,
    ) -> Vec<Arc<dyn LogicalBreakpoint>>;

    /// Get the logical breakpoint of which the given trace breakpoint location is a part.
    ///
    /// Returns `None` if the location is not part of any logical breakpoint, e.g., because the
    /// trace is not opened in the tool or events are still being processed.
    fn get_breakpoint(
        &self,
        loc: &dyn TraceBreakpointLocation,
    ) -> Option<Arc<dyn LogicalBreakpoint>>;

    /// Get the collected logical breakpoints (at present) at the given location.
    ///
    /// The location's program may be either a program database (static image) or a view for a
    /// trace. If it is the latter, the view's snapshot is ignored in favor of the trace's primary
    /// view's snapshot. That is, this is equivalent to
    /// [`get_breakpoints_at_in_program`](Self::get_breakpoints_at_in_program) for a static image
    /// and [`get_breakpoints_at_in_trace`](Self::get_breakpoints_at_in_trace) for a trace view.
    fn get_breakpoints_at(&self, loc: &dyn ProgramLocation) -> Vec<Arc<dyn LogicalBreakpoint>>;

    /// Add a listener for logical breakpoint changes.
    ///
    /// Logical breakpoints may change from time to time for a variety of reasons: a new trace is
    /// started; a static image is opened; the user adds or removes breakpoints; mappings change;
    /// etc. The service reacts to these events, reconciles the breakpoints, and invokes callbacks
    /// for the changes, allowing other UI components and services to update accordingly.
    fn add_change_listener(&mut self, l: Box<dyn LogicalBreakpointsChangeListener>);

    /// Remove a listener for logical breakpoint changes.
    fn remove_change_listener(&mut self, l: &dyn LogicalBreakpointsChangeListener);

    /// Get a future which completes after pending changes have been processed.
    ///
    /// The returned future completes after all change listeners have been invoked.
    fn changes_settled(&self) -> BreakpointCommandFuture;

    /// Create an enabled breakpoint at the given program location and each mapped trace location.
    ///
    /// The implementation should take care not to create the same breakpoint multiple times. The
    /// risk of this happening derives from the possibility of one module mapped to multiple targets
    /// which are all managed by the same debugger, having a single breakpoint container.
    ///
    /// `length` is the size of the breakpoint, which the debugger may ignore. For no name, use the
    /// empty string.
    fn place_breakpoint_at_in_program(
        &self,
        program: &dyn Program,
        address: &Address,
        length: i64,
        kinds: &[TraceBreakpointKind],
        name: &str,
    ) -> BreakpointCommandFuture;

    /// Create an enabled breakpoint at the given trace location and its mapped program location.
    ///
    /// If the breakpoint has no static location, then only the trace location is placed; note that
    /// in that case the breakpoint will have no name.
    ///
    /// For live targets the debugger ultimately determines the placement behavior. If it is
    /// managing multiple targets, the breakpoint may end up effective in another trace; that is
    /// reflected in the resulting logical markings once all resulting events have been processed.
    ///
    /// `address` is the address in the trace as viewed in the present.
    fn place_breakpoint_at_in_trace(
        &self,
        trace: &dyn Trace,
        address: &Address,
        length: i64,
        kinds: &[TraceBreakpointKind],
        name: &str,
    ) -> BreakpointCommandFuture;

    /// Create an enabled breakpoint at the given location.
    ///
    /// If the location refers to a static image, this behaves as
    /// [`place_breakpoint_at_in_program`](Self::place_breakpoint_at_in_program); if it refers to a
    /// trace view, as [`place_breakpoint_at_in_trace`](Self::place_breakpoint_at_in_trace),
    /// ignoring the view's current snapshot in favor of the present. The name is only saved for a
    /// program breakpoint; `None` (Java's `null`) becomes the empty string.
    fn place_breakpoint_at(
        &self,
        loc: &dyn ProgramLocation,
        length: i64,
        kinds: &[TraceBreakpointKind],
        name: Option<&str>,
    ) -> BreakpointCommandFuture;

    /// Generate an informational status message when enabling the selected breakpoints.
    ///
    /// Breakpoint enabling may fail for a variety of reasons, some of which deal with the trace
    /// database and GUI rather than with the target. When enabling will not likely behave in the
    /// manner expected by the user, this explains why — for example, that a breakpoint has no
    /// locations on a target. Returns `None` if enabling is expected to work.
    ///
    /// `trace` limits the command to a single trace when `Some`.
    fn generate_status_enable(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        trace: Option<&dyn Trace>,
    ) -> Option<String>;

    /// Enable a collection of logical breakpoints on target, if applicable.
    ///
    /// This is preferable to enabling each logical breakpoint individually: depending on the
    /// debugger, a single breakpoint specification may produce several effective breakpoints,
    /// perhaps spanning multiple targets. This prevents multiple requests (which a debugger may
    /// consider erroneous) to enable the same specification when that specification is involved in
    /// more than one logical breakpoint in the given collection.
    fn enable_all(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        trace: Option<&dyn Trace>,
    ) -> BreakpointCommandFuture;

    /// Disable a collection of logical breakpoints on target, if applicable.
    ///
    /// See [`enable_all`](Self::enable_all).
    fn disable_all(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        trace: Option<&dyn Trace>,
    ) -> BreakpointCommandFuture;

    /// Delete, if possible, a collection of logical breakpoints on target, if applicable.
    ///
    /// See [`enable_all`](Self::enable_all).
    fn delete_all(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        trace: Option<&dyn Trace>,
    ) -> BreakpointCommandFuture;

    /// Enable the given trace breakpoint locations.
    fn enable_locs(&self, col: &[&dyn TraceBreakpointLocation]) -> BreakpointCommandFuture;

    /// Disable the given trace breakpoint locations.
    fn disable_locs(&self, col: &[&dyn TraceBreakpointLocation]) -> BreakpointCommandFuture;

    /// Delete the given trace breakpoint locations.
    fn delete_locs(&self, col: &[&dyn TraceBreakpointLocation]) -> BreakpointCommandFuture;

    /// Generate an informational message when toggling the given breakpoints.
    ///
    /// This works like [`generate_status_enable`](Self::generate_status_enable), except it is for
    /// toggling. If the breakpoint set is empty this returns `None`, since the usual behavior in
    /// that case is to prompt to place a new breakpoint.
    fn generate_status_toggle_at(
        &self,
        bs: &[Arc<dyn LogicalBreakpoint>],
        loc: &dyn ProgramLocation,
    ) -> Option<String>;

    /// Generate an informational message when toggling the breakpoints at the given location.
    ///
    /// See [`generate_status_toggle_at`](Self::generate_status_toggle_at).
    fn generate_status_toggle_at_location(&self, loc: &dyn ProgramLocation) -> Option<String> {
        self.generate_status_toggle_at(&self.get_breakpoints_at(loc), loc)
    }

    /// Toggle the given breakpoints at the given location.
    ///
    /// `placer` is invoked to place a breakpoint if the breakpoint set is empty.
    fn toggle_breakpoints_at(
        &self,
        bs: &[Arc<dyn LogicalBreakpoint>],
        location: &dyn ProgramLocation,
        placer: BreakpointPlacer,
    ) -> BreakpointSetFuture;

    /// Toggle the breakpoints at the given location.
    ///
    /// `placer` is invoked to place a breakpoint if there are no breakpoints there.
    fn toggle_breakpoints_at_location(
        &self,
        location: &dyn ProgramLocation,
        placer: BreakpointPlacer,
    ) -> BreakpointSetFuture {
        self.toggle_breakpoints_at(&self.get_breakpoints_at(location), location, placer)
    }

    /// Compose the states of the given logical breakpoints, which are assumed to share an address.
    fn compute_state(&self, col: &[Arc<dyn LogicalBreakpoint>]) -> LogicalBreakpointState {
        col.iter().fold(LogicalBreakpointState::None, |state, lb| {
            state.same_address(lb.compute_state())
        })
    }

    /// Compose the states of the given logical breakpoints as they apply to the given program.
    fn compute_state_for_program(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        program: &dyn Program,
    ) -> LogicalBreakpointState {
        col.iter().fold(LogicalBreakpointState::None, |state, lb| {
            state.same_address(lb.compute_state_for_program(program))
        })
    }

    /// Compose the states of the given logical breakpoints as they apply to the given trace.
    fn compute_state_for_trace(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        trace: &dyn Trace,
    ) -> LogicalBreakpointState {
        col.iter().fold(LogicalBreakpointState::None, |state, lb| {
            state.same_address(lb.compute_state_for_trace(trace))
        })
    }

    /// Compose the states of the given logical breakpoints as they apply to the given location's
    /// program or trace.
    ///
    /// `view` distinguishes a trace view from a static image; see [`program_or_trace`].
    fn compute_state_at(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        loc: &dyn ProgramLocation,
        view: Option<&dyn TraceProgramView>,
    ) -> LogicalBreakpointState {
        match program_or_trace(loc, view) {
            LocationTarget::Program(program) => self.compute_state_for_program(col, &*program),
            LocationTarget::Trace(trace) => self.compute_state_for_trace(col, &*trace),
        }
    }

    /// Compute the state of the breakpoints at the given location.
    ///
    /// `view` distinguishes a trace view from a static image; see [`program_or_trace`].
    fn compute_state_at_location(
        &self,
        loc: &dyn ProgramLocation,
        view: Option<&dyn TraceProgramView>,
    ) -> LogicalBreakpointState {
        self.compute_state_at(&self.get_breakpoints_at(loc), loc, view)
    }

    /// True if any of the given breakpoints maps into the given trace, or — when `trace` is `None`,
    /// mirroring Java's `null` check — into any trace at all.
    fn any_mapped_to_trace(
        &self,
        col: &[Arc<dyn LogicalBreakpoint>],
        trace: Option<&dyn Trace>,
    ) -> bool {
        match trace {
            None => self.any_mapped(col),
            Some(trace) => col.iter().any(|lb| lb.is_mapped_to_trace(trace)),
        }
    }

    /// True if any of the given breakpoints maps into at least one trace.
    fn any_mapped(&self, col: &[Arc<dyn LogicalBreakpoint>]) -> bool {
        col.iter().any(|lb| lb.has_mapped_traces())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::seam_stubs::{LogicalBreakpointConsistency, LogicalBreakpointMode};
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    /// A breakpoint that reports fixed states and mappings, with per-trace mapping keyed by the
    /// caller not caring which trace is passed (the mock is only ever asked about `MockTrace`).
    struct MockBreakpoint {
        state: LogicalBreakpointState,
        mapped: bool,
    }

    impl LogicalBreakpoint for MockBreakpoint {
        fn compute_state(&self) -> LogicalBreakpointState {
            self.state
        }

        fn compute_state_for_program(&self, _program: &dyn Program) -> LogicalBreakpointState {
            self.state
        }

        fn compute_state_for_trace(&self, _trace: &dyn Trace) -> LogicalBreakpointState {
            self.state
        }

        fn is_mapped_to_trace(&self, _trace: &dyn Trace) -> bool {
            self.mapped
        }

        fn has_mapped_traces(&self) -> bool {
            self.mapped
        }
    }

    fn bp(state: LogicalBreakpointState, mapped: bool) -> Arc<dyn LogicalBreakpoint> {
        Arc::new(MockBreakpoint { state, mapped })
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }
        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }
    }

    struct MockProgramLocation;
    impl ProgramLocation for MockProgramLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_address(&self) -> Address {
            Address::new(ram(), 0x1000)
        }

        fn get_byte_address(&self) -> Address {
            Address::new(ram(), 0x1004)
        }
    }

    /// A location that Java would match with `instanceof CodeUnitLocation`.
    struct MockCodeUnitLocation;
    impl ProgramLocation for MockCodeUnitLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_address(&self) -> Address {
            Address::new(ram(), 0x1000)
        }

        fn get_byte_address(&self) -> Address {
            Address::new(ram(), 0x1004)
        }
    }
    impl CodeUnitLocation for MockCodeUnitLocation {}

    /// A service that only answers `get_breakpoints_at`; every default method under test is built
    /// on that plus the breakpoints' own states.
    struct MockService {
        at_location: Vec<Arc<dyn LogicalBreakpoint>>,
        listener_count: usize,
    }

    impl DebuggerLogicalBreakpointService for MockService {
        fn get_all_breakpoints(&self) -> Vec<Arc<dyn LogicalBreakpoint>> {
            self.at_location.clone()
        }

        fn get_breakpoints_for_program(
            &self,
            _program: &dyn Program,
        ) -> BTreeMap<Address, Vec<Arc<dyn LogicalBreakpoint>>> {
            BTreeMap::from([(Address::new(ram(), 0x1000), self.at_location.clone())])
        }

        fn get_breakpoints_for_trace(
            &self,
            _trace: &dyn Trace,
        ) -> BTreeMap<Address, Vec<Arc<dyn LogicalBreakpoint>>> {
            BTreeMap::new()
        }

        fn get_breakpoints_at_in_program(
            &self,
            _program: &dyn Program,
            _address: &Address,
        ) -> Vec<Arc<dyn LogicalBreakpoint>> {
            self.at_location.clone()
        }

        fn get_breakpoints_at_in_trace(
            &self,
            _trace: &dyn Trace,
            _address: &Address,
        ) -> Vec<Arc<dyn LogicalBreakpoint>> {
            Vec::new()
        }

        fn get_breakpoint(
            &self,
            _loc: &dyn TraceBreakpointLocation,
        ) -> Option<Arc<dyn LogicalBreakpoint>> {
            None
        }

        fn get_breakpoints_at(&self, _loc: &dyn ProgramLocation) -> Vec<Arc<dyn LogicalBreakpoint>> {
            self.at_location.clone()
        }

        fn add_change_listener(&mut self, _l: Box<dyn LogicalBreakpointsChangeListener>) {
            self.listener_count += 1;
        }

        fn remove_change_listener(&mut self, _l: &dyn LogicalBreakpointsChangeListener) {
            self.listener_count -= 1;
        }

        fn changes_settled(&self) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn place_breakpoint_at_in_program(
            &self,
            _program: &dyn Program,
            _address: &Address,
            _length: i64,
            _kinds: &[TraceBreakpointKind],
            _name: &str,
        ) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn place_breakpoint_at_in_trace(
            &self,
            _trace: &dyn Trace,
            _address: &Address,
            _length: i64,
            _kinds: &[TraceBreakpointKind],
            _name: &str,
        ) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn place_breakpoint_at(
            &self,
            _loc: &dyn ProgramLocation,
            _length: i64,
            _kinds: &[TraceBreakpointKind],
            _name: Option<&str>,
        ) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn generate_status_enable(
            &self,
            col: &[Arc<dyn LogicalBreakpoint>],
            _trace: Option<&dyn Trace>,
        ) -> Option<String> {
            if col.is_empty() {
                None
            } else {
                Some(format!("{} breakpoint(s)", col.len()))
            }
        }

        fn enable_all(
            &self,
            _col: &[Arc<dyn LogicalBreakpoint>],
            _trace: Option<&dyn Trace>,
        ) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn disable_all(
            &self,
            _col: &[Arc<dyn LogicalBreakpoint>],
            _trace: Option<&dyn Trace>,
        ) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn delete_all(
            &self,
            _col: &[Arc<dyn LogicalBreakpoint>],
            _trace: Option<&dyn Trace>,
        ) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn enable_locs(&self, _col: &[&dyn TraceBreakpointLocation]) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn disable_locs(&self, _col: &[&dyn TraceBreakpointLocation]) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn delete_locs(&self, _col: &[&dyn TraceBreakpointLocation]) -> BreakpointCommandFuture {
            Box::pin(async {})
        }

        fn generate_status_toggle_at(
            &self,
            bs: &[Arc<dyn LogicalBreakpoint>],
            _loc: &dyn ProgramLocation,
        ) -> Option<String> {
            if bs.is_empty() {
                None
            } else {
                Some(format!("toggling {}", bs.len()))
            }
        }

        fn toggle_breakpoints_at(
            &self,
            bs: &[Arc<dyn LogicalBreakpoint>],
            _location: &dyn ProgramLocation,
            placer: BreakpointPlacer,
        ) -> BreakpointSetFuture {
            if bs.is_empty() {
                placer()
            } else {
                let bs = bs.to_vec();
                Box::pin(async move { bs })
            }
        }
    }

    fn service_with(bps: Vec<Arc<dyn LogicalBreakpoint>>) -> MockService {
        MockService {
            at_location: bps,
            listener_count: 0,
        }
    }

    /// `State.NONE` is the identity of `sameAdddress`, so an empty collection composes to `NONE`
    /// and a singleton composes to that breakpoint's own state.
    #[test]
    fn compute_state_folds_from_none() {
        let empty = service_with(Vec::new());
        assert_eq!(empty.compute_state(&[]), LogicalBreakpointState::None);

        let one = service_with(vec![bp(LogicalBreakpointState::Enabled, true)]);
        let col = one.get_breakpoints_at(&MockProgramLocation);
        assert_eq!(one.compute_state(&col), LogicalBreakpointState::Enabled);
    }

    /// Java: ENABLED.sameAdddress(DISABLED) == MIXED, since the modes disagree and both are NORMAL.
    #[test]
    fn compute_state_mixes_disagreeing_modes() {
        let svc = service_with(vec![
            bp(LogicalBreakpointState::Enabled, true),
            bp(LogicalBreakpointState::Disabled, true),
        ]);
        let col = svc.get_breakpoints_at(&MockProgramLocation);
        assert_eq!(svc.compute_state(&col), LogicalBreakpointState::Mixed);
    }

    /// Consistency composes by taking the higher priority, so ENABLED with INCONSISTENT_ENABLED
    /// stays enabled but becomes inconsistent.
    #[test]
    fn compute_state_takes_worst_consistency() {
        let svc = service_with(vec![
            bp(LogicalBreakpointState::Enabled, true),
            bp(LogicalBreakpointState::InconsistentEnabled, true),
        ]);
        let col = svc.get_breakpoints_at(&MockProgramLocation);
        assert_eq!(
            svc.compute_state(&col),
            LogicalBreakpointState::InconsistentEnabled
        );
        assert_eq!(
            svc.compute_state(&col).mode(),
            Some(LogicalBreakpointMode::Enabled)
        );
        assert_eq!(
            svc.compute_state(&col).consistency(),
            Some(LogicalBreakpointConsistency::Inconsistent)
        );
    }

    /// `computeState(ProgramLocation)` looks the breakpoints up, then dispatches on program-or-
    /// trace. With no trace view, the program branch is taken.
    #[test]
    fn compute_state_at_location_uses_program_branch() {
        let svc = service_with(vec![
            bp(LogicalBreakpointState::IneffectiveEnabled, true),
            bp(LogicalBreakpointState::Enabled, true),
        ]);
        assert_eq!(
            svc.compute_state_at_location(&MockProgramLocation, None),
            LogicalBreakpointState::IneffectiveEnabled
        );
    }

    /// `anyMapped(col, null)` falls back to `anyMapped(col)`; `anyMapped` is false only when every
    /// breakpoint has an empty mapped-trace set.
    #[test]
    fn any_mapped_falls_back_when_no_trace_given() {
        let none_mapped = service_with(vec![bp(LogicalBreakpointState::Enabled, false)]);
        let col = none_mapped.get_breakpoints_at(&MockProgramLocation);
        assert!(!none_mapped.any_mapped(&col));
        assert!(!none_mapped.any_mapped_to_trace(&col, None));

        let some_mapped = service_with(vec![
            bp(LogicalBreakpointState::Enabled, false),
            bp(LogicalBreakpointState::Disabled, true),
        ]);
        let col = some_mapped.get_breakpoints_at(&MockProgramLocation);
        assert!(some_mapped.any_mapped(&col));
        assert!(some_mapped.any_mapped_to_trace(&col, None));
    }

    /// The `ProgramLocation`-only overloads look the set up first and then delegate.
    #[test]
    fn location_overloads_look_up_the_breakpoint_set() {
        let empty = service_with(Vec::new());
        assert_eq!(
            empty.generate_status_toggle_at_location(&MockProgramLocation),
            None
        );

        let svc = service_with(vec![
            bp(LogicalBreakpointState::Enabled, true),
            bp(LogicalBreakpointState::Enabled, true),
        ]);
        assert_eq!(
            svc.generate_status_toggle_at_location(&MockProgramLocation),
            Some("toggling 2".to_string())
        );
    }

    /// An empty toggle falls through to the placer; a non-empty one does not.
    #[tokio::test]
    async fn toggle_at_location_invokes_placer_only_when_empty() {
        let empty = service_with(Vec::new());
        let placed = empty
            .toggle_breakpoints_at_location(
                &MockProgramLocation,
                Box::new(|| Box::pin(async { vec![bp(LogicalBreakpointState::Enabled, true)] })),
            )
            .await;
        assert_eq!(placed.len(), 1);
        assert_eq!(placed[0].compute_state(), LogicalBreakpointState::Enabled);

        let svc = service_with(vec![bp(LogicalBreakpointState::Disabled, true)]);
        let toggled = svc
            .toggle_breakpoints_at_location(
                &MockProgramLocation,
                Box::new(|| Box::pin(async { Vec::new() })),
            )
            .await;
        assert_eq!(toggled.len(), 1);
        assert_eq!(toggled[0].compute_state(), LogicalBreakpointState::Disabled);
    }

    /// Java's `addressFromLocation` returns the location's address for a `CodeUnitLocation` and its
    /// byte address otherwise.
    #[test]
    fn address_from_location_picks_byte_or_code_unit_address() {
        assert_eq!(
            address_from_location(&MockProgramLocation),
            Address::new(ram(), 0x1004)
        );
        assert_eq!(
            address_from_code_unit_location(&MockCodeUnitLocation),
            Address::new(ram(), 0x1000)
        );
    }

    /// With no trace view, `programOrTrace` resolves to the location's own program.
    #[test]
    fn program_or_trace_resolves_static_image() {
        match program_or_trace(&MockProgramLocation, None) {
            LocationTarget::Program(p) => assert_eq!(Program::get_name(&*p), "mock"),
            LocationTarget::Trace(_) => panic!("expected the static-image branch"),
        }
    }

    struct NoopListener;
    impl LogicalBreakpointsChangeListener for NoopListener {}

    #[test]
    fn is_object_safe_as_boxed_trait() {
        let mut service: Box<dyn DebuggerLogicalBreakpointService> =
            Box::new(service_with(vec![bp(LogicalBreakpointState::Enabled, true)]));
        assert_eq!(service.get_all_breakpoints().len(), 1);
        assert_eq!(
            service
                .get_breakpoints_for_program(&MockProgram)
                .into_keys()
                .collect::<Vec<_>>(),
            vec![Address::new(ram(), 0x1000)]
        );
        let all = service.get_all_breakpoints();
        assert_eq!(
            service.generate_status_enable(&all, None),
            Some("1 breakpoint(s)".to_string())
        );
        service.add_change_listener(Box::new(NoopListener));
        service.remove_change_listener(&NoopListener);
        let _ = service.changes_settled();
    }
}
