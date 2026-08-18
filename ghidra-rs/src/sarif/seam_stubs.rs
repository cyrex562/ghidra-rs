//! Minimal placeholder types for core types that `sarif` code references before the real Rust
//! port of that type exists yet. Each stub exposes only the members needed by the type(s) that
//! currently reference it, and is expected to be replaced (or grown into a full port) once that
//! Java class is ported. See `STUBS.tsv` for provenance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::program::model::address::Address;
use crate::program::model::address::address_overflow_exception::AddressOverflowException;
use crate::program::model::listing::Bookmark;
use crate::util::task::TaskMonitor;

/// Placeholder for the abstract Java base class `sarif.managers.SarifMgr`, which every
/// `*SarifMgr` (including [`BookmarksSarifMgr`](crate::sarif::managers::BookmarksSarifMgr))
/// extends. Java's version is an abstract class, not an interface, so this is a plain struct
/// composed into the leaf manager rather than a `dyn`-dispatched trait or an inheritance
/// relationship (Rust has neither).
///
/// Only the members `BookmarksSarifMgr` uses are modeled: the `key` field and the `getLocation`
/// helper. `getLocation` defers to `sarif.SarifUtils.getLocations`
/// (`Ghidra/Features/Sarif/src/main/java/sarif/SarifUtils.java`), which is not ported yet, so it
/// always reports "no location found" -- the same thing an empty `AddressSet.getMinAddress()`
/// returns in Java.
pub struct SarifMgr {
    key: String,
}

impl SarifMgr {
    /// `new SarifMgr(String key, Program program, MessageLog log)`, minus the `program`/`log`
    /// fields the base class also stores: `BookmarksSarifMgr` keeps its own `log` and derives
    /// what it needs from `program` directly instead of caching them a second time here.
    pub fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }

    /// `SarifMgr.getKey()`.
    pub fn get_key(&self) -> &str {
        &self.key
    }

    /// `SarifMgr.getLocation(Map<String, Object>)`. Placeholder pending the `SarifUtils` port.
    pub fn get_location(
        &self,
        _result: &HashMap<String, serde_json::Value>,
    ) -> Result<Option<Address>, AddressOverflowException> {
        Ok(None)
    }
}

/// Placeholder for `sarif.SarifProgramOptions`, referenced by
/// [`BookmarksSarifMgr::read`](crate::sarif::managers::BookmarksSarifMgr::read). Java's version
/// is a concrete class, not an interface, so this is a plain struct. Only the one flag
/// `BookmarksSarifMgr` reads (`isOverwriteBookmarkConflicts`) is modeled.
#[derive(Debug, Clone, Copy, Default)]
pub struct SarifProgramOptions {
    pub overwrite_bookmark_conflicts: bool,
}

impl SarifProgramOptions {
    /// `SarifProgramOptions.isOverwriteBookmarkConflicts()`.
    pub fn is_overwrite_bookmark_conflicts(&self) -> bool {
        self.overwrite_bookmark_conflicts
    }
}

/// Placeholder for `ghidra.app.util.importer.MessageLog`, referenced by `sarif` managers.
/// Concrete stub, since there is nothing to dispatch over (Java's version is a concrete class):
/// a real, if minimal, in-memory log rather than an `unimplemented!()` placeholder. Only the two
/// methods `BookmarksSarifMgr` calls (`appendMsg`, `appendException`) are modeled.
#[derive(Debug, Default)]
pub struct MessageLog {
    messages: Mutex<Vec<String>>,
}

impl MessageLog {
    /// `new MessageLog()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// `MessageLog.appendMsg(String)`.
    pub fn append_msg(&self, message: impl Into<String>) {
        self.messages.lock().unwrap().push(message.into());
    }

    /// `MessageLog.appendException(Throwable)`.
    pub fn append_exception(&self, err: &dyn std::error::Error) {
        self.messages.lock().unwrap().push(err.to_string());
    }

    /// The messages recorded so far, in append order.
    pub fn messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }
}

/// Placeholder for `sarif.export.bkmk.SarifBookmarkWriter`, referenced by
/// [`BookmarksSarifMgr::write_as_sarif`](crate::sarif::managers::BookmarksSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor is modeled; the `genRoot`/`AbstractExtWriter` machinery that turns the bookmarks
/// into SARIF JSON is pending that class's own port.
pub struct SarifBookmarkWriter {
    pub bookmarks: Vec<Arc<dyn Bookmark>>,
}

impl SarifBookmarkWriter {
    /// `new SarifBookmarkWriter(List<Bookmark> target, Writer baseWriter)`, minus the (always
    /// `null`, here) base writer.
    pub fn new(bookmarks: Vec<Arc<dyn Bookmark>>) -> Self {
        Self { bookmarks }
    }
}

/// Placeholder for `sarif.export.SarifWriterTask`, referenced by
/// [`BookmarksSarifMgr::write_as_sarif`](crate::sarif::managers::BookmarksSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// constructor and `run` are modeled; `run`'s real behavior (flushing the writer's results into
/// the shared `JsonArray`) is pending `SarifBookmarkWriter`'s and `TaskLauncher`'s own ports, so
/// this is a no-op for now.
pub struct SarifWriterTask {
    pub tag: String,
    pub writer: SarifBookmarkWriter,
}

impl SarifWriterTask {
    /// `new SarifWriterTask(String tag, AbstractIsfWriter writer, JsonArray results)`, minus the
    /// `results` array (passed to [`run`](Self::run) instead, matching `Task.run(TaskMonitor)`'s
    /// signature).
    pub fn new(tag: impl Into<String>, writer: SarifBookmarkWriter) -> Self {
        Self { tag: tag.into(), writer }
    }

    /// `SarifWriterTask.run(TaskMonitor)`.
    pub fn run(&self, _monitor: &dyn TaskMonitor, _results: &mut Vec<serde_json::Value>) {}
}

/// Placeholder for `ghidra.util.task.TaskLauncher`, referenced by
/// [`BookmarksSarifMgr::write_as_sarif`](crate::sarif::managers::BookmarksSarifMgr::write_as_sarif).
/// Java's version is a concrete class, not an interface, so this is a plain struct. Only the
/// modal two-argument constructor `writeAsSARIF` uses (`new TaskLauncher(task, null)`) is
/// modeled, and since there is no GUI here it just runs the task synchronously.
pub struct TaskLauncher;

impl TaskLauncher {
    /// `new TaskLauncher(Task task, Component parent)`, minus the (always `null`, here) parent
    /// component.
    pub fn launch(task: &SarifWriterTask, monitor: &dyn TaskMonitor, results: &mut Vec<serde_json::Value>) {
        task.run(monitor, results);
    }
}
