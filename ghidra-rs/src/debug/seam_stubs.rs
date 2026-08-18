//! Minimal placeholder traits for core types that a ported interface references before the real
//! Rust port of that type exists yet. Each stub exposes only the members needed by the
//! interface(s) that currently reference it, and is expected to be replaced (or grown into a
//! supertrait of) the real port once that Java class is ported. See `STUBS.tsv` for provenance.

use crate::program::model::listing::Program;
use crate::trace::model::trace::Trace;

/// Placeholder for `ghidra.debug.api.action.LocationTrackingSpec`, referenced by
/// [`DebuggerListing`](crate::debug::api::listing::DebuggerListing) before the real class is
/// ported. `DebuggerListing` only ever passes this type through as a parameter (`setTrackingSpec`),
/// so no members are needed yet.
pub trait LocationTrackingSpec {}

/// Placeholder for `ghidra.debug.api.modules.MappedAddressRange`, referenced by
/// [`DebuggerAddressTranslator`](crate::debug::api::modules::DebuggerAddressTranslator) before the
/// real class is ported. In Java this is a concrete class (not an interface), so it becomes a
/// concrete struct here rather than a trait; `DebuggerAddressTranslator` only ever passes it
/// through as a collection element in return values, so no members are needed yet.
pub struct MappedAddressRange;

/// Placeholder for `LogicalBreakpoint.Mode`, the mode of a logical breakpoint's trace locations.
///
/// Ported ahead of the rest of `LogicalBreakpoint` because
/// [`LogicalBreakpointState::same_address`] is defined in terms of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogicalBreakpointMode {
    /// All locations are enabled.
    Enabled,
    /// All locations are disabled.
    Disabled,
    /// Has both enabled and disabled trace locations.
    Mixed,
}

impl LogicalBreakpointMode {
    /// Compose the modes of two logical breakpoints that appear at the same address: agreement
    /// keeps the mode, disagreement yields [`Mixed`](Self::Mixed).
    ///
    /// Port of `LogicalBreakpoint.Mode.sameAddress`.
    pub fn same_address(self, that: Self) -> Self {
        if self == that {
            self
        } else {
            Self::Mixed
        }
    }
}

/// Placeholder for `LogicalBreakpoint.Consistency`, describing how well a logical breakpoint's
/// bookmark and trace locations agree.
///
/// Ported ahead of the rest of `LogicalBreakpoint` because
/// [`LogicalBreakpointState::same_address`] is defined in terms of it. The variants are ordered by
/// priority, highest last, since `sameAddress` composes by taking the higher ordinal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LogicalBreakpointConsistency {
    /// The bookmark and locations all agree.
    Normal,
    /// Has a bookmark but one or more trace locations is missing.
    Ineffective,
    /// Has a trace location but is not bookmarked, or the bookmark disagrees.
    Inconsistent,
}

impl LogicalBreakpointConsistency {
    /// Compose the consistencies of two logical breakpoints at the same address by taking the
    /// higher-priority (later-declared) of the two.
    ///
    /// Port of `LogicalBreakpoint.Consistency.sameAddress`, which indexes `values()` by
    /// `Math.max(ordinal, ordinal)`.
    pub fn same_address(self, that: Self) -> Self {
        self.max(that)
    }
}

/// Placeholder for `LogicalBreakpoint.State`, the state of a logical breakpoint.
///
/// In essence this is the cross product of [`LogicalBreakpointMode`] and
/// [`LogicalBreakpointConsistency`], plus a [`None`](Self::None) placeholder. It is ported ahead of
/// the rest of `LogicalBreakpoint` because
/// [`DebuggerLogicalBreakpointService`](crate::app::services::DebuggerLogicalBreakpointService)
/// computes with it in default methods. The `display`/`icon` fields of the Java enum are Swing
/// presentation data and are omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogicalBreakpointState {
    /// A placeholder state, usually indicating the logical breakpoint should not exist. It is the
    /// identity element of [`same_address`](Self::same_address).
    None,
    /// The breakpoint is enabled, and all locations and its bookmark agree.
    Enabled,
    /// The breakpoint is disabled, and all locations and its bookmark agree.
    Disabled,
    /// Multiple logical breakpoints at this address are all saved and effective, but some are
    /// enabled and some are disabled.
    Mixed,
    /// The breakpoint is saved as enabled, but one or more trace locations are absent.
    IneffectiveEnabled,
    /// The breakpoint is saved as disabled, and one or more trace locations are absent.
    IneffectiveDisabled,
    /// Multiple saved logical breakpoints at this address, at least one ineffective, and some
    /// enabled and some disabled.
    IneffectiveMixed,
    /// The breakpoint is enabled and all locations agree, but the bookmark is absent or disagrees.
    InconsistentEnabled,
    /// The breakpoint is disabled and all locations agree, but the bookmark is absent or disagrees.
    InconsistentDisabled,
    /// The breakpoint's locations disagree, and the bookmark may be absent.
    InconsistentMixed,
}

impl LogicalBreakpointState {
    /// The mode of this state, or `None` for [`LogicalBreakpointState::None`].
    pub fn mode(self) -> Option<LogicalBreakpointMode> {
        match self {
            Self::None => Option::None,
            Self::Enabled | Self::IneffectiveEnabled | Self::InconsistentEnabled => {
                Some(LogicalBreakpointMode::Enabled)
            }
            Self::Disabled | Self::IneffectiveDisabled | Self::InconsistentDisabled => {
                Some(LogicalBreakpointMode::Disabled)
            }
            Self::Mixed | Self::IneffectiveMixed | Self::InconsistentMixed => {
                Some(LogicalBreakpointMode::Mixed)
            }
        }
    }

    /// The consistency of this state, or `None` for [`LogicalBreakpointState::None`].
    pub fn consistency(self) -> Option<LogicalBreakpointConsistency> {
        match self {
            Self::None => Option::None,
            Self::Enabled | Self::Disabled | Self::Mixed => {
                Some(LogicalBreakpointConsistency::Normal)
            }
            Self::IneffectiveEnabled | Self::IneffectiveDisabled | Self::IneffectiveMixed => {
                Some(LogicalBreakpointConsistency::Ineffective)
            }
            Self::InconsistentEnabled | Self::InconsistentDisabled | Self::InconsistentMixed => {
                Some(LogicalBreakpointConsistency::Inconsistent)
            }
        }
    }

    /// Recompose a state from its mode and consistency.
    ///
    /// Port of `LogicalBreakpoint.State.fromFields`, whose `(null, null)` case maps to
    /// [`LogicalBreakpointState::None`] here.
    pub fn from_fields(
        mode: Option<LogicalBreakpointMode>,
        consistency: Option<LogicalBreakpointConsistency>,
    ) -> Self {
        let (Some(mode), Some(consistency)) = (mode, consistency) else {
            return Self::None;
        };
        match (mode, consistency) {
            (LogicalBreakpointMode::Enabled, LogicalBreakpointConsistency::Normal) => Self::Enabled,
            (LogicalBreakpointMode::Enabled, LogicalBreakpointConsistency::Ineffective) => {
                Self::IneffectiveEnabled
            }
            (LogicalBreakpointMode::Enabled, LogicalBreakpointConsistency::Inconsistent) => {
                Self::InconsistentEnabled
            }
            (LogicalBreakpointMode::Disabled, LogicalBreakpointConsistency::Normal) => {
                Self::Disabled
            }
            (LogicalBreakpointMode::Disabled, LogicalBreakpointConsistency::Ineffective) => {
                Self::IneffectiveDisabled
            }
            (LogicalBreakpointMode::Disabled, LogicalBreakpointConsistency::Inconsistent) => {
                Self::InconsistentDisabled
            }
            (LogicalBreakpointMode::Mixed, LogicalBreakpointConsistency::Normal) => Self::Mixed,
            (LogicalBreakpointMode::Mixed, LogicalBreakpointConsistency::Ineffective) => {
                Self::IneffectiveMixed
            }
            (LogicalBreakpointMode::Mixed, LogicalBreakpointConsistency::Inconsistent) => {
                Self::InconsistentMixed
            }
        }
    }

    /// Compose the states of two logical breakpoints that appear at the same address.
    ///
    /// This can happen when two logical breakpoints having different attributes (size, kinds,
    /// etc.) coincide at the same address. Use it only when deciding how to mark or choose actions
    /// for the address. [`None`](Self::None) acts as the identity.
    ///
    /// Port of `LogicalBreakpoint.State.sameAdddress` (the Java method name is misspelled).
    pub fn same_address(self, that: Self) -> Self {
        if self == Self::None {
            return that;
        }
        if that == Self::None {
            return self;
        }
        Self::from_fields(
            match (self.mode(), that.mode()) {
                (Some(a), Some(b)) => Some(a.same_address(b)),
                _ => Option::None,
            },
            match (self.consistency(), that.consistency()) {
                (Some(a), Some(b)) => Some(a.same_address(b)),
                _ => Option::None,
            },
        )
    }
}

/// Placeholder for `ghidra.debug.api.breakpoint.LogicalBreakpoint`, referenced by
/// [`LogicalBreakpointsChangeListener`](crate::debug::api::breakpoint::LogicalBreakpointsChangeListener)
/// and [`DebuggerLogicalBreakpointService`](crate::app::services::DebuggerLogicalBreakpointService)
/// before the real class is ported. Only the members those two need are exposed.
pub trait LogicalBreakpoint: Send + Sync {
    /// Compute the state of this breakpoint in the abstract, i.e., across all its traces.
    ///
    /// Port of `LogicalBreakpoint.computeState()`.
    fn compute_state(&self) -> LogicalBreakpointState;

    /// Compute the state of this breakpoint as it applies to the given program.
    ///
    /// Port of `LogicalBreakpoint.computeStateForProgram(Program)`.
    fn compute_state_for_program(&self, program: &dyn Program) -> LogicalBreakpointState;

    /// Compute the state of this breakpoint as it applies to the given trace.
    ///
    /// Port of `LogicalBreakpoint.computeStateForTrace(Trace)`.
    fn compute_state_for_trace(&self, trace: &dyn Trace) -> LogicalBreakpointState;

    /// True if this breakpoint's static address maps into the given trace.
    ///
    /// Stands in for `LogicalBreakpoint.getMappedTraces().contains(trace)`. The Java `Set<Trace>`
    /// is compared by object identity, which a `&dyn Trace` cannot reproduce, and membership is
    /// the only thing
    /// [`DebuggerLogicalBreakpointService::any_mapped_to_trace`](crate::app::services::DebuggerLogicalBreakpointService::any_mapped_to_trace)
    /// asks of it.
    fn is_mapped_to_trace(&self, trace: &dyn Trace) -> bool;

    /// True if this breakpoint's static address maps into at least one trace.
    ///
    /// Stands in for `!LogicalBreakpoint.getMappedTraces().isEmpty()`.
    fn has_mapped_traces(&self) -> bool;
}

/// Placeholder for `ghidra.debug.api.action.ActionContext`, referenced by `ActionName`.
pub trait ActionContext: Send + Sync {}

/// Placeholder for `ghidra.debug.api.target.TraceObject`, referenced by `ActionName`.
pub trait TraceObject: Send + Sync {}

/// Placeholder for the unported Java type `ActionName`, referenced by `RemoteMethodRegistry`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait ActionName: Send + Sync {
    fn is_showing(&self, context: &dyn ActionContext) -> bool;
    fn is_enabled(&self, obj: &dyn TraceObject, snap: i64) -> bool;
    fn name(&self, name: &str) -> Box<dyn ActionName>;
}

/// Placeholder for the unported Java type `RemoteMethod`, referenced by `RemoteMethodRegistry`.
/// Generated stub: only a shape hint. Receivers default to `&self` (some may need `&mut self`);
/// unknown in-repo types map to trait objects. Replace with the real port when available.
pub trait RemoteMethod: Send + Sync {
    // (no public methods parsed from the Java source)
}

/// Placeholder for the unported Java type `ghidra.debug.api.target.Target`, referenced by
/// [`TraceRmiConnection`](crate::debug::api::tracermi::TraceRmiConnection).
/// `TraceRmiConnection` only ever passes this type through (as a collection element or by-value
/// parameter), so no members are needed yet.
pub trait Target: Send + Sync {}
