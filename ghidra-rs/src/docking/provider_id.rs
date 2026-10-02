//! Stable handle for a component provider registered with a tool.

/// Identifies a [`ComponentProvider`](crate::docking) within its tool. Assigned
/// by the tool when the provider is added; `Copy` so contexts and actions can
/// refer to providers without back-pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderId(pub u64);
