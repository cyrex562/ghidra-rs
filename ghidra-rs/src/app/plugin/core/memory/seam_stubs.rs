//! Minimal placeholder traits for core types that [`MemoryMapPlugin`](super::MemoryMapPlugin)
//! references before the real Rust port of that type exists yet. Each stub exposes only the
//! members [`MemoryMapPlugin`](super::MemoryMapPlugin) needs; see `STUBS.tsv` for provenance.

use std::sync::Arc;

use crate::program::model::listing::Program;
use crate::program::util::ProgramLocation;

/// Placeholder for `ghidra.app.plugin.core.memory.MemoryMapManager` (a concrete class, not an
/// interface), referenced by [`MemoryMapPlugin`](super::MemoryMapPlugin) before the real class is
/// ported.
///
/// Java's constructor takes a back-reference to the plugin (`new MemoryMapManager(this)`); that
/// cycle is broken by having the plugin's constructor take an already-built manager instead (see
/// [`MemoryMapPlugin::new`](super::MemoryMapPlugin::new)).
pub trait MemoryMapManager: Send + Sync {
    /// Port of the package-private `setProgram(Program)`. `None` mirrors Java's `null`, used when
    /// no program is active.
    fn set_program(&self, program: Option<Arc<dyn Program>>);
}

/// Placeholder for `ghidra.app.plugin.core.memory.MemoryMapProvider` (a concrete class, not an
/// interface), referenced by [`MemoryMapPlugin`](super::MemoryMapPlugin) before the real class is
/// ported.
///
/// Java's constructor takes a back-reference to the plugin (`new MemoryMapProvider(this)`); that
/// cycle is broken the same way as [`MemoryMapManager`] (see
/// [`MemoryMapPlugin::new`](super::MemoryMapPlugin::new)). Only the members
/// [`MemoryMapPlugin`](super::MemoryMapPlugin) calls directly are included here; the many
/// UI-facing methods on the real (`ComponentProviderAdapter`-derived) class are not needed.
pub trait MemoryMapProvider: Send + Sync {
    /// Port of `dispose()`.
    fn dispose(&self);

    /// Port of the inherited `ComponentProvider.isVisible()`, used to skip UI refreshes while the
    /// window is not showing.
    fn is_visible(&self) -> bool;

    /// Port of the package-private `updateMap()`.
    fn update_map(&self);

    /// Port of the package-private `updateData()`.
    fn update_data(&self);

    /// Port of the package-private `setProgram(Program)`. `None` mirrors Java's `null`.
    fn set_program(&self, program: Option<Arc<dyn Program>>);

    /// Port of the package-private `locationChanged(ProgramLocation)`.
    fn location_changed(&self, location: &dyn ProgramLocation);
}
