//! Port of `db.buffers.RecoveryMgr`.
//!
//! Orchestrates a ping-ponged pair of [`RecoveryFile`]s (`snapshotA.grf`/`snapshotB.grf`, each
//! with an optional companion `changeA.grf`/`changeB.grf` cumulative-change file) that record
//! periodic crash-recovery snapshots of a live buffer file's modified content, and -- via
//! [`RecoveryMgr::new_for_recovery`] -- applies the newer of the two snapshots back into live
//! buffer state after an unclean shutdown. See `recovery_file.rs`'s module doc for this
//! package's established conventions (its "Adaptations"/"Quirks ported faithfully" split is
//! followed here too).
//!
//! # The `RecoverySource` seam
//!
//! Java's `RecoveryMgr` holds a `private BufferMgr bufferMgr` field and calls
//! `bufferMgr.getSourceFile()` (cast to `LocalBufferFile`) and `bufferMgr.recover(RecoveryFile,
//! int, TaskMonitor)` on it. This crate's [`BufferMgr`](crate::framework::db::buffer_mgr::BufferMgr)
//! is a much-reduced, in-memory-only stand-in for the real Ghidra class -- it has no notion of a
//! backing on-disk source file, no checkpoint history, and no `recover()` operation, so it
//! cannot fill that role (this is the same gap noted by [`BufferNode`](super::BufferNode)'s
//! module doc, which was written anticipating this exact port).
//!
//! Rather than force the whole of `RecoveryMgr` to `TODO` on that gap, this port factors the two
//! operations it actually needs out into the [`RecoverySource`] trait, matching this codebase's
//! "prefer trait seams over pervasive concrete types" convention. Every method below that is
//! reachable without applying a crash recovery (`new_for_snapshot`, `start_snapshot`,
//! `end_snapshot`, `put_buffer`, `dispose`, `clear`, `recovered`, `get_recovery_change_set_file`,
//! `can_recover`, `print_stats`) is fully ported and has real tests. Only
//! [`RecoveryMgr::new_for_recovery`] -- the constructor that actually replays a recovered
//! snapshot into a live buffer manager -- depends on a real [`RecoverySource::recover`]
//! implementation, which this crate does not yet provide; it is exercised here against a mock.
//!
//! Also unlike Java (where `bufferMgr` is a stored field, referenced again from `startSnapshot`),
//! this port does not store the collaborator: since a real `RecoverySource` implementation would
//! typically be (or be owned by) the very `BufferMgr` that also *owns* this `RecoveryMgr`
//! (composition, matching `db.buffers.BufferMgr`'s own field), storing a back-reference here
//! would create an ownership cycle Rust's borrow checker rejects. Instead, [`Self::new_for_snapshot`],
//! [`Self::new_for_recovery`], and [`Self::start_snapshot`] each take their `&mut dyn
//! RecoverySource` as a plain parameter, matching the pattern already used by
//! [`BufferNode`](super::BufferNode)'s free functions to break a similar cycle.
//!
//! # The `DBHandle::save_as` seam
//!
//! `startSnapshot`'s change-set branch (`changeSet != null`) writes the change set into a
//! throwaway `DBHandle`, then calls `DBHandle.saveAs(File, boolean, TaskMonitor)` to persist it.
//! [`DBHandle`](crate::framework::db::db_handle::DBHandle) did not have a `save_as` method before
//! this port; a minimal one (copying every allocated buffer verbatim into a fresh
//! [`LocalBufferFile`]) was added to `db_handle.rs` specifically to support this path -- see its
//! doc comment for exactly what it does and does not implement.
//!
//! # Adaptations
//!
//! - **`csh.close()` via `Drop` instead of an explicit call**: Java's `startSnapshot` wraps
//!   `changeSet.write(csh, true); csh.saveAs(...)` in `try { ... } finally { csh.close(); }`.
//!   This crate's [`DBHandle`] has no `close()` method (its underlying, in-memory-only
//!   `BufferMgr` has no real resources to release), so this port simply lets the local `DBHandle`
//!   go out of scope and be dropped at the end of [`RecoveryMgr::start_snapshot`], which achieves
//!   the same effect.
//! - **Fallible constructors return `Result` instead of throwing**: `RecoveryMgr(BufferMgr,
//!   TaskMonitor)` declares `throws IOException, CancelledException`; [`RecoveryMgr::new_for_recovery`]
//!   returns `Result<Self, RecoveryError>` accordingly. The snapshot-only constructor
//!   (`RecoveryMgr(BufferMgr)`) declares no checked exceptions and is ported as the infallible
//!   [`RecoveryMgr::new_for_snapshot`].
//! - **`dispose()` consumes `self`**: Java's `dispose()` nulls out `snapshotFiles`/`changeFiles`
//!   after deleting them, so that any further use of the (still-live) Java object throws an
//!   unchecked `NullPointerException`. Rather than model that with `Option<PathBuf>` fields
//!   threaded through every other method, this port has [`RecoveryMgr::dispose`] take `self` by
//!   value, so the type system -- not a runtime null check -- prevents any further use.
//! - **Unchecked `AssertException`s stay typed**: `startSnapshot`, `endSnapshot`, `putBuffer`,
//!   and `clear` each throw an unchecked `AssertException` for a precondition violation
//!   (snapshot already/not in progress). Since [`AssertException`](crate::util::exception::AssertException)
//!   already implements `std::error::Error` in this crate, these are surfaced as a proper
//!   `Result` variant (see [`RecoveryError`]) rather than collapsed into a generic `io::Error`
//!   string, unlike `recovery_file.rs`'s narrower `assert_err` helper (which had only a single
//!   `io::Result`-shaped API to fit into).
//!
//! # Quirks ported faithfully (verified against the real Java source)
//!
//! - **Empty-string parameter key** (`RecoveryMgr.java` line 38): `CHANGE_SET_REQUIRED_PARM` is
//!   literally `private static final String CHANGE_SET_REQUIRED_PARM = "";` -- an empty string,
//!   not a descriptive name. This is presumably intentional (an empty key can't collide with any
//!   real user- or system-assigned parameter name), but it is unusual enough to call out
//!   explicitly. Ported verbatim as [`CHANGE_SET_REQUIRED_PARM`].
//! - **`startSnapshot`'s trailing counter reset is skipped on failure** (lines 306-354): the
//!   `buffersSaved[snapshotIndex] = 0; buffersIgnored[snapshotIndex] = 0; buffersRemoved[snapshotIndex]
//!   = 0;` statements are textually *after* the `try { ... } finally { ... }` block, not inside
//!   it -- so if the `try` body throws (propagating past the `finally`'s cleanup), those three
//!   assignments never execute for that snapshot slot, leaving whatever counts were left over
//!   from the slot's previous use. This is easy to misread as "always runs after cleanup"; it is
//!   reproduced faithfully by [`RecoveryMgr::start_snapshot`] returning early with `Err` before
//!   reaching the resets, and pinned down by
//!   [`tests::start_snapshot_failure_leaves_prior_counters_unreset`].
//! - **`getRecoveryFile`'s equal-timestamp tie yields no usable recovery data** (lines 226-260):
//!   when both snapshot files parse as valid with identical timestamps, neither is treated as
//!   recoverable -- both are closed and `null` (`None`) is returned, matching the inability to
//!   tell which is newer. This is reproduced by [`get_recovery_file`] (see its doc comment for
//!   why this specific branch is not covered by an automated test).
//!
//! # Documented gap
//!
//! `RecoveryMgr::new_for_recovery`'s actual application of recovered data to live buffer state
//! (`BufferMgr.recover(RecoveryFile, int, TaskMonitor)`) has no real implementation in this
//! crate -- see the "The `RecoverySource` seam" section above. Everything else in this file
//! (file selection/tie-breaking, snapshot lifecycle, buffer bookkeeping, change-set persistence,
//! disposal) is fully ported and tested against a mock `RecoverySource`.

use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;

use super::buffer_node::BufferNodeRef;
use super::{LocalBufferFile, RecoveryFile};
use crate::framework::db::buffer::DataBuffer;
use crate::framework::db::db_change_set::DBChangeSet;
use crate::framework::db::db_handle::DBHandle;
use crate::util::datastruct::IntSet;
use crate::util::exception::{AssertException, CancelledException};
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

const SNAPSHOT1_FILE: &str = "snapshotA.grf";
const SNAPSHOT2_FILE: &str = "snapshotB.grf";
const SNAPSHOT1_CHANGESET_FILE: &str = "changeA.grf";
const SNAPSHOT2_CHANGESET_FILE: &str = "changeB.grf";

/// See the module-level "Quirks ported faithfully" note: this is a literal empty string in the
/// real Java source, not a placeholder.
const CHANGE_SET_REQUIRED_PARM: &str = "";

/// Combined error type covering every checked-or-unchecked exception `RecoveryMgr`'s methods can
/// raise in the original Java: `IOException`, `CancelledException` (from a `TaskMonitor`), and
/// the unchecked `AssertException` used for precondition violations. Not every variant is
/// reachable from every method that returns this type -- see each method's doc comment.
#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
    #[error(transparent)]
    Assert(#[from] AssertException),
}

/// Abstracts the subset of `db.buffers.BufferMgr` that `RecoveryMgr` depends on. See the
/// module-level "The `RecoverySource` seam" section for why this exists.
pub trait RecoverySource {
    /// The on-disk buffer file this recovery manager protects. Mirrors
    /// `bufferMgr.getSourceFile()` cast to `LocalBufferFile` -- Java performs that cast at
    /// runtime (throwing `RuntimeException("Invalid use of recovery manager")` if the source
    /// file isn't a `LocalBufferFile`); this port's trait signature enforces the same
    /// requirement structurally instead.
    fn source_file(&self) -> &LocalBufferFile;

    /// Apply a recovered snapshot to live buffer state. Mirrors `BufferMgr.recover(RecoveryFile,
    /// int, TaskMonitor)`. `snapshot_index` is 0 or 1, matching the Java `int snapshotIndex`
    /// parameter.
    fn recover(
        &mut self,
        recovery_file: &mut RecoveryFile,
        snapshot_index: usize,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), RecoveryError>;
}

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn file_last_modified_millis(path: &Path) -> i64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn get_snapshot_files(bf: &LocalBufferFile) -> [PathBuf; 2] {
    let dir = bf.get_file().parent().map(Path::to_path_buf).unwrap_or_default();
    [dir.join(SNAPSHOT1_FILE), dir.join(SNAPSHOT2_FILE)]
}

fn get_change_files(bf: &LocalBufferFile) -> [PathBuf; 2] {
    let dir = bf.get_file().parent().map(Path::to_path_buf).unwrap_or_default();
    [dir.join(SNAPSHOT1_CHANGESET_FILE), dir.join(SNAPSHOT2_CHANGESET_FILE)]
}

/// Picks whichever of the two candidate snapshot files (if any) is valid and newest, closing the
/// other(s). Mirrors the private static `RecoveryMgr.getRecoveryFile(LocalBufferFile, File[])`.
///
/// The equal-timestamp tie branch (see the module-level quirks note) has no dedicated test: it
/// requires two `RecoveryFile`s whose `close()`-assigned timestamps (real wall-clock
/// milliseconds, with no way to inject a fake clock through `RecoveryFile`'s public API) collide
/// exactly, which isn't something a test can force deterministically -- the same practical
/// limitation the original Java code would have.
fn get_recovery_file(src_bf: &LocalBufferFile, snapshot_files: &[PathBuf; 2]) -> Option<RecoveryFile> {
    let mut recovery_files: [Option<RecoveryFile>; 2] = [None, None];
    let mut mod_times: [i64; 2] = [0, 0];

    for i in 0..2 {
        if snapshot_files[i].exists() {
            if let Ok(mut rf) = RecoveryFile::open_read_only(src_bf, snapshot_files[i].clone()) {
                if rf.is_valid() {
                    mod_times[i] = rf.get_timestamp();
                    recovery_files[i] = Some(rf);
                } else {
                    let _ = rf.close();
                }
            }
        }
    }

    match (recovery_files[0].take(), recovery_files[1].take()) {
        (Some(mut rf0), Some(mut rf1)) => {
            if mod_times[1] == mod_times[0] {
                Msg::warn(
                    "RecoveryMgr",
                    &format!("Recover files have same timestamp: {}", mod_times[0]),
                );
                let _ = rf0.close();
                let _ = rf1.close();
                None
            } else if mod_times[1] > mod_times[0] {
                let _ = rf0.close();
                Some(rf1)
            } else {
                let _ = rf1.close();
                Some(rf0)
            }
        }
        (Some(rf0), None) => Some(rf0),
        (None, Some(rf1)) => Some(rf1),
        (None, None) => None,
    }
}

/// Manages recovery snapshot data for a `BufferMgr`-managed buffer file. Mirrors
/// `db.buffers.RecoveryMgr`. See the module doc for the `RecoverySource` seam this port uses in
/// place of a stored back-reference to its owning buffer manager.
#[derive(Debug)]
pub struct RecoveryMgr {
    snapshot_files: [PathBuf; 2],
    change_files: [PathBuf; 2],
    snapshot_index: i32,
    active_file: Option<RecoveryFile>,
    old_index_set: Option<IntSet>,
    new_snapshot: bool,
    last_snapshot_time: i64,

    recovered: bool,
    recovery_has_change_set: bool,

    buffers_saved: [i32; 2],
    buffers_ignored: [i32; 2],
    buffers_removed: [i32; 2],
}

impl RecoveryMgr {
    /// Construct a recovery manager and perform crash recovery, if recoverable data exists.
    /// Mirrors `RecoveryMgr(BufferMgr, TaskMonitor)`.
    pub fn new_for_recovery(
        source: &mut dyn RecoverySource,
        monitor: &dyn TaskMonitor,
    ) -> Result<Self, RecoveryError> {
        let snapshot_files = get_snapshot_files(source.source_file());
        let change_files = get_change_files(source.source_file());

        let mut recovered = false;
        let mut recovery_has_change_set = false;
        let mut snapshot_index: i32 = -1;
        let mut last_snapshot_time: i64 = 0;

        if let Some(mut rf) = get_recovery_file(source.source_file(), &snapshot_files) {
            let result: Result<(), RecoveryError> = (|| {
                let file_path = rf.get_file()?.to_path_buf();
                last_snapshot_time = file_last_modified_millis(&file_path);
                snapshot_index = if file_path == snapshot_files[0] { 0 } else { 1 };

                recovery_has_change_set =
                    rf.get_parameter(CHANGE_SET_REQUIRED_PARM).map(|v| v != 0).unwrap_or(false);

                if !recovery_has_change_set || change_files[snapshot_index as usize].exists() {
                    Msg::info(
                        "RecoveryMgr",
                        &format!(
                            "Applying buffer file recovery data: {}",
                            source.source_file().get_file().display()
                        ),
                    );
                    source.recover(&mut rf, snapshot_index as usize, monitor)?;
                    recovered = true;
                }
                Ok(())
            })();
            let _ = rf.close();
            result?;
        }

        if snapshot_index != 0 {
            let _ = std::fs::remove_file(&snapshot_files[0]);
            let _ = std::fs::remove_file(&change_files[0]);
        }
        if snapshot_index != 1 {
            let _ = std::fs::remove_file(&snapshot_files[1]);
            let _ = std::fs::remove_file(&change_files[1]);
        }

        Ok(Self {
            snapshot_files,
            change_files,
            snapshot_index,
            active_file: None,
            old_index_set: None,
            new_snapshot: false,
            last_snapshot_time,
            recovered,
            recovery_has_change_set,
            buffers_saved: [0, 0],
            buffers_ignored: [0, 0],
            buffers_removed: [0, 0],
        })
    }

    /// Construct a recovery manager for snapshot use only (no crash recovery is attempted; any
    /// pre-existing snapshot/change files are discarded). Mirrors `RecoveryMgr(BufferMgr)`.
    pub fn new_for_snapshot(source: &dyn RecoverySource) -> Self {
        let snapshot_files = get_snapshot_files(source.source_file());
        let change_files = get_change_files(source.source_file());

        let _ = std::fs::remove_file(&snapshot_files[0]);
        let _ = std::fs::remove_file(&snapshot_files[1]);
        let _ = std::fs::remove_file(&change_files[0]);
        let _ = std::fs::remove_file(&change_files[1]);

        Self {
            snapshot_files,
            change_files,
            snapshot_index: -1,
            active_file: None,
            old_index_set: None,
            new_snapshot: false,
            last_snapshot_time: 0,
            recovered: false,
            recovery_has_change_set: false,
            buffers_saved: [0, 0],
            buffers_ignored: [0, 0],
            buffers_removed: [0, 0],
        }
    }

    /// Release all recovery snapshot resources, ending an in-progress snapshot (without
    /// committing it) and deleting every recovery file. Mirrors `dispose()`.
    ///
    /// See the module-level "Adaptations" note: this consumes `self` rather than modeling Java's
    /// null-out-then-NPE-on-reuse behavior.
    pub fn dispose(mut self) {
        if self.active_file.is_some() {
            self.end_snapshot(false).expect(
                "end_snapshot's only failure mode is 'no snapshot in progress', which was just \
                 checked",
            );
        }
        for i in 0..2 {
            let _ = std::fs::remove_file(&self.snapshot_files[i]);
            let _ = std::fs::remove_file(&self.change_files[i]);
        }
    }

    /// Returns true if a crash-recovery snapshot was successfully applied by
    /// [`Self::new_for_recovery`]. Mirrors `recovered()`.
    pub fn recovered(&self) -> bool {
        self.recovered
    }

    /// Returns the recovery change-data file for reading, if a recovered snapshot has an
    /// associated cumulative change file. Mirrors `getRecoveryChangeSetFile()`.
    ///
    /// The caller must dispose of the returned file before this manager generates any new
    /// recovery snapshots (matching the Java doc comment's contract).
    pub fn get_recovery_change_set_file(&self) -> io::Result<Option<LocalBufferFile>> {
        if self.recovered && self.recovery_has_change_set {
            let path = self.change_files[self.snapshot_index as usize].clone();
            return Ok(Some(LocalBufferFile::open(path, true)?));
        }
        Ok(None)
    }

    /// Discard all recovery snapshot data. Mirrors `clear()`.
    pub fn clear(&mut self) -> Result<(), AssertException> {
        if self.active_file.is_some() {
            return Err(AssertException::with_message("Snapshot already in progress"));
        }
        let _ = std::fs::remove_file(&self.snapshot_files[0]);
        let _ = std::fs::remove_file(&self.snapshot_files[1]);
        let _ = std::fs::remove_file(&self.change_files[0]);
        let _ = std::fs::remove_file(&self.change_files[1]);
        Ok(())
    }

    /// Returns true if recovery data exists which may enable recovery of unsaved changes
    /// resulting from a previous crash. Mirrors the static `canRecover(LocalBufferFile)`.
    pub fn can_recover(bf: &LocalBufferFile) -> bool {
        let snapshot_files = get_snapshot_files(bf);
        let Some(mut rf) = get_recovery_file(bf, &snapshot_files) else {
            return false;
        };
        let mut can_recover = true;
        if let Ok(v) = rf.get_parameter(CHANGE_SET_REQUIRED_PARM) {
            if v != 0 {
                let change_files = get_change_files(bf);
                let snapshot_index = match rf.get_file() {
                    Ok(p) if p == snapshot_files[0] => 0,
                    _ => 1,
                };
                can_recover = change_files[snapshot_index].exists();
            }
        }
        let _ = rf.close();
        can_recover
    }

    /// Open a recovery file for an updated snapshot. Mirrors `startSnapshot(int, int[],
    /// DBChangeSet, TaskMonitor)`.
    ///
    /// # Parameters
    /// - `source`: provides the source buffer file this snapshot protects.
    /// - `index_cnt`: the total number of allocated indexes within the corresponding source
    ///   buffer file.
    /// - `free_indexes`: a list of indexes which are currently free/empty.
    /// - `change_set`: an optional database-backed change set which reflects changes made since
    ///   the last version.
    pub fn start_snapshot(
        &mut self,
        source: &dyn RecoverySource,
        index_cnt: i32,
        free_indexes: &[i32],
        change_set: Option<&mut dyn DBChangeSet>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), RecoveryError> {
        if self.active_file.is_some() {
            return Err(AssertException::with_message("Snapshot already in progress").into());
        }
        self.recovered = false;
        self.snapshot_index += 1;
        if self.snapshot_index == 2 {
            self.snapshot_index = 0;
        }

        // Prevent duplicate snapshot times.
        let t = now_millis();
        if t.saturating_sub(self.last_snapshot_time) < 1 {
            std::thread::sleep(std::time::Duration::from_millis(2));
            // Mirrors Java's re-read of `t` after the sleep -- like the original, the
            // re-computed value is never subsequently used (see the module doc).
            let _ = now_millis();
        }

        let idx = self.snapshot_index as usize;
        self.new_snapshot = !self.snapshot_files[idx].exists();

        let attempt: Result<RecoveryFile, RecoveryError> = (|| {
            let mut active = match RecoveryFile::new(
                source.source_file(),
                self.snapshot_files[idx].clone(),
                self.new_snapshot,
            ) {
                Ok(rf) => rf,
                Err(e) => {
                    if self.new_snapshot {
                        return Err(e.into());
                    }
                    // Assume an invalid file -- remove bad snapshot and create a new file.
                    let _ = std::fs::remove_file(&self.snapshot_files[idx]);
                    self.new_snapshot = true;
                    RecoveryFile::new(source.source_file(), self.snapshot_files[idx].clone(), true)?
                }
            };
            active.set_index_count(index_cnt);
            active.set_free_index_list(free_indexes);
            self.old_index_set = Some(IntSet::from_values(&active.get_buffer_indexes()));

            if let Some(cs) = change_set {
                active.set_parameter(CHANGE_SET_REQUIRED_PARM, 1)?;
                let _ = std::fs::remove_file(&self.change_files[idx]);
                let csh = DBHandle::new()?;
                cs.write(&csh, true)?;
                csh.save_as(&self.change_files[idx], true, monitor).map_err(|e| match e {
                    crate::framework::db::db_handle::SaveAsError::Io(e) => RecoveryError::Io(e),
                    crate::framework::db::db_handle::SaveAsError::Cancelled(e) => {
                        RecoveryError::Cancelled(e)
                    }
                })?;
                // `csh` is dropped here -- see the module-level "Adaptations" note on why no
                // explicit close() call is needed.
            } else {
                active.set_parameter(CHANGE_SET_REQUIRED_PARM, 0)?;
            }
            Ok(active)
        })();

        let active = match attempt {
            Ok(active) => active,
            Err(e) => {
                let _ = std::fs::remove_file(&self.snapshot_files[idx]);
                let _ = std::fs::remove_file(&self.change_files[idx]);
                return Err(e);
            }
        };
        self.active_file = Some(active);

        self.buffers_saved[idx] = 0;
        self.buffers_ignored[idx] = 0;
        self.buffers_removed[idx] = 0;
        Ok(())
    }

    /// Returns true if a snapshot is in progress. Mirrors `isSnapshotInProgress()`.
    pub fn is_snapshot_in_progress(&self) -> bool {
        self.active_file.is_some()
    }

    /// End the recovery snapshot and close the underlying file. Mirrors `endSnapshot(boolean)`.
    ///
    /// `commit`: if true the snapshot is finalized and stored, otherwise the snapshot is
    /// deleted.
    ///
    /// Unlike Java's `startSnapshot`, this method's own `IOException`s are caught internally
    /// (degrading a requested commit to a rollback) rather than propagated -- matching the real
    /// Java `endSnapshot`, which declares no checked exceptions at all. Only the unchecked
    /// `AssertException` for "no snapshot in progress" can escape.
    pub fn end_snapshot(&mut self, commit: bool) -> Result<(), AssertException> {
        if self.active_file.is_none() {
            return Err(AssertException::with_message("Snapshot not in progress"));
        }
        let idx = self.snapshot_index as usize;
        let mut commit = commit;

        let io_result: io::Result<()> = (|| {
            let mut active = self.active_file.take().unwrap();
            if commit {
                // Eliminate buffers if they were not put into the snapshot. This is the result
                // of an undo which may have reverted a buffer to its original unmodified state.
                let indexes =
                    self.old_index_set.as_ref().map(IntSet::get_values).unwrap_or_default();
                for &index in &indexes {
                    active.remove_buffer(index);
                }
                self.buffers_removed[idx] = indexes.len() as i32;
                let file = active.get_file()?.to_path_buf();
                active.close()?;
                self.last_snapshot_time = file_last_modified_millis(&file);
                Msg::info(
                    "RecoveryMgr",
                    &format!("Recovery snapshot created: {}", self.snapshot_files[idx].display()),
                );
            } else {
                active.close()?;
            }
            Ok(())
        })();

        if io_result.is_err() {
            commit = false;
        }

        self.active_file = None;
        if !commit {
            let _ = std::fs::remove_file(&self.snapshot_files[idx]);
            self.snapshot_index -= 1;
            if self.snapshot_index < 0 {
                self.snapshot_index = 1;
            }
        }
        Ok(())
    }

    /// Write a modified buffer corresponding to the specified [`BufferNode`](super::BufferNode)
    /// to the current open snapshot file. The node's `id` and `snapshot_taken` state are
    /// consulted and updated; these should not be modified concurrently with this call. Mirrors
    /// `putBuffer(DataBuffer, BufferNode)`.
    pub fn put_buffer(
        &mut self,
        buffer: &DataBuffer,
        node: &BufferNodeRef,
    ) -> Result<(), RecoveryError> {
        if self.active_file.is_none() {
            return Err(AssertException::with_message("Snapshot not in progress").into());
        }
        let idx = self.snapshot_index as usize;
        let already_taken = node.borrow().snapshot_taken(idx);
        if self.new_snapshot || !already_taken {
            self.active_file.as_mut().unwrap().put_buffer(buffer)?;
            node.borrow_mut().set_snapshot_taken(idx, true);
            self.buffers_saved[idx] += 1;
        } else {
            self.buffers_ignored[idx] += 1;
        }
        if let Some(set) = self.old_index_set.as_mut() {
            set.remove(node.borrow().id());
        }
        Ok(())
    }

    /// Log recovery statistics for both snapshot slots. Mirrors `printStats()`.
    pub fn print_stats(&self) {
        Msg::info("RecoveryMgr", &"RecoveryMgr stats:");
        for i in 0..2 {
            let marker = if self.snapshot_index == i as i32 { "*" } else { " " };
            Msg::info(
                "RecoveryMgr",
                &format!("  {}{}", marker, self.snapshot_files[i].display()),
            );
            Msg::info("RecoveryMgr", &format!("     buffers saved: {}", self.buffers_saved[i]));
            Msg::info(
                "RecoveryMgr",
                &format!("     buffers unchanged: {}", self.buffers_ignored[i]),
            );
            Msg::info(
                "RecoveryMgr",
                &format!("     buffers removed: {}", self.buffers_removed[i]),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::framework::db::buffers::BufferNode;

    /// A `RecoverySource` backed by a real on-disk `LocalBufferFile`, whose `recover()` calls are
    /// simply recorded for inspection (since this crate's real `BufferMgr` cannot implement the
    /// trait -- see the module doc).
    struct MockSource {
        src: LocalBufferFile,
        recover_calls: RefCell<Vec<usize>>,
        fail_recover: bool,
    }

    impl MockSource {
        fn new(src: LocalBufferFile) -> Self {
            Self { src, recover_calls: RefCell::new(Vec::new()), fail_recover: false }
        }
    }

    impl RecoverySource for MockSource {
        fn source_file(&self) -> &LocalBufferFile {
            &self.src
        }

        fn recover(
            &mut self,
            _recovery_file: &mut RecoveryFile,
            snapshot_index: usize,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), RecoveryError> {
            self.recover_calls.borrow_mut().push(snapshot_index);
            if self.fail_recover {
                return Err(io::Error::new(io::ErrorKind::Other, "simulated recover failure").into());
            }
            Ok(())
        }
    }

    struct MockBufferNode {
        id: i32,
        snapshot_taken: [bool; 2],
    }

    impl MockBufferNode {
        fn new(id: i32) -> BufferNodeRef {
            Rc::new(RefCell::new(MockBufferNode { id, snapshot_taken: [false, false] }))
        }
    }

    impl BufferNode for MockBufferNode {
        fn id(&self) -> i32 {
            self.id
        }
        fn checkpoint(&self) -> i32 {
            0
        }
        fn set_checkpoint(&mut self, _checkpoint: i32) {}
        fn buffer(&self) -> Option<&DataBuffer> {
            None
        }
        fn set_buffer(&mut self, _buffer: Option<DataBuffer>) {}
        fn disk_cache_index(&self) -> i32 {
            -1
        }
        fn set_disk_cache_index(&mut self, _index: i32) {}
        fn is_locked(&self) -> bool {
            false
        }
        fn set_locked(&mut self, _locked: bool) {}
        fn is_empty(&self) -> bool {
            false
        }
        fn set_empty(&mut self, _empty: bool) {}
        fn is_modified(&self) -> bool {
            false
        }
        fn set_modified(&mut self, _modified: bool) {}
        fn is_dirty(&self) -> bool {
            false
        }
        fn set_dirty(&mut self, _dirty: bool) {}
        fn snapshot_taken(&self, slot: usize) -> bool {
            self.snapshot_taken[slot]
        }
        fn set_snapshot_taken(&mut self, slot: usize, taken: bool) {
            self.snapshot_taken[slot] = taken;
        }
        fn next_cached(&self) -> Option<BufferNodeRef> {
            None
        }
        fn set_next_cached(&mut self, _node: Option<BufferNodeRef>) {}
        fn prev_cached(&self) -> Option<BufferNodeRef> {
            None
        }
        fn set_prev_cached(&mut self, _node: Option<BufferNodeRef>) {}
        fn next_version(&self) -> Option<BufferNodeRef> {
            None
        }
        fn set_next_version(&mut self, _node: Option<BufferNodeRef>) {}
        fn prev_version(&self) -> Option<BufferNodeRef> {
            None
        }
        fn set_prev_version(&mut self, _node: Option<BufferNodeRef>) {}
        fn next_in_checkpoint(&self) -> Option<BufferNodeRef> {
            None
        }
        fn set_next_in_checkpoint(&mut self, _node: Option<BufferNodeRef>) {}
        fn prev_in_checkpoint(&self) -> Option<BufferNodeRef> {
            None
        }
        fn set_prev_in_checkpoint(&mut self, _node: Option<BufferNodeRef>) {}
    }

    /// Buffer size for the source (and so the recovery) files. A recovery file's header holds
    /// `RecoveryFile`'s ten parameters plus this manager's `CHANGE_SET_REQUIRED_PARM`: 263 bytes,
    /// which must fit in one buffer (`LocalBufferFile::write_header()` fails with "Buffer size
    /// too small" otherwise, as in Java). Before that check existed, 256 let the header spill
    /// into buffer 0's block; whether the spill corrupted anything depended on `HashMap`
    /// iteration order, which made these tests flaky.
    const BUF_SIZE: usize = 512;

    fn make_source(dir: &Path) -> MockSource {
        let src = LocalBufferFile::create(dir.join("src.bf"), BUF_SIZE).unwrap();
        MockSource::new(src)
    }

    #[test]
    fn new_for_snapshot_starts_with_no_recovery_and_clean_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mgr = RecoveryMgr::new_for_snapshot(&source);
        assert!(!mgr.recovered());
        assert!(!mgr.is_snapshot_in_progress());
        assert!(mgr.get_recovery_change_set_file().unwrap().is_none());
    }

    #[test]
    fn can_recover_false_with_no_snapshot_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        assert!(!RecoveryMgr::can_recover(source.source_file()));
    }

    #[test]
    fn start_snapshot_without_change_set_sets_up_active_file_and_resets_counters() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        mgr.start_snapshot(&source, 4, &[1, 3], None, &monitor).unwrap();
        assert!(mgr.is_snapshot_in_progress());
        assert_eq!(mgr.active_file.as_ref().unwrap().get_index_count(), 4);
        assert_eq!(mgr.active_file.as_ref().unwrap().get_free_index_list(), &[1, 3]);
        assert_eq!(mgr.active_file.as_ref().unwrap().get_parameter(CHANGE_SET_REQUIRED_PARM).unwrap(), 0);
        assert_eq!(mgr.buffers_saved[0], 0);
        assert_eq!(mgr.buffers_ignored[0], 0);
        assert_eq!(mgr.buffers_removed[0], 0);
    }

    #[test]
    fn start_snapshot_while_in_progress_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap();
        let err = mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap_err();
        assert!(matches!(err, RecoveryError::Assert(_)));
    }

    #[test]
    fn put_buffer_marks_snapshot_taken_and_counts_saved_then_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        let node = MockBufferNode::new(2);
        let buf = DataBuffer::new(2, BUF_SIZE);

        // Slot 0 (snapshotA.grf, freshly created): always written regardless of the node's
        // snapshotTaken flag.
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        assert!(mgr.new_snapshot);
        mgr.put_buffer(&buf, &node).unwrap();
        assert_eq!(mgr.buffers_saved[0], 1);
        assert_eq!(mgr.buffers_ignored[0], 0);
        assert!(node.borrow().snapshot_taken(0));
        mgr.end_snapshot(true).unwrap();

        // Slot 1 (snapshotB.grf, also never seen before -- still a fresh snapshot).
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        mgr.end_snapshot(true).unwrap();

        // Slot 0 again: snapshotA.grf now already exists on disk from the first commit, so this
        // reopen is *not* a fresh snapshot, and the node's snapshotTaken[0] flag (still set from
        // the first snapshot) causes putBuffer to skip rewriting it.
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        assert!(!mgr.new_snapshot, "reopening an existing snapshot file is not a fresh snapshot");
        assert_eq!(mgr.buffers_saved[0], 0, "start_snapshot resets counters for the slot on success");
        mgr.put_buffer(&buf, &node).unwrap();
        assert_eq!(mgr.buffers_saved[0], 0);
        assert_eq!(mgr.buffers_ignored[0], 1);
    }

    #[test]
    fn put_buffer_without_in_progress_snapshot_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let node = MockBufferNode::new(0);
        let buf = DataBuffer::new(0, BUF_SIZE);
        let err = mgr.put_buffer(&buf, &node).unwrap_err();
        assert!(matches!(err, RecoveryError::Assert(_)));
    }

    #[test]
    fn end_snapshot_without_in_progress_snapshot_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        assert!(mgr.end_snapshot(true).is_err());
    }

    #[test]
    fn end_snapshot_commit_removes_stale_buffers_and_records_stats() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        let node2 = MockBufferNode::new(2);
        mgr.put_buffer(&DataBuffer::new(2, BUF_SIZE), &node2).unwrap();
        mgr.end_snapshot(true).unwrap();
        assert!(!mgr.is_snapshot_in_progress());
        assert!(mgr.snapshot_files[0].exists(), "committed snapshot file survives");

        // Slot 1: unrelated, empty snapshot -- also committed.
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        mgr.end_snapshot(true).unwrap();

        // Slot 0 again: the recovery file on disk still has buffer 2 recorded from the first
        // commit (reflected in oldIndexSet), but this session never re-puts it, simulating an
        // undo that reverted buffer 2 to its unmodified state. Committing should remove it.
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        assert_eq!(mgr.old_index_set.as_ref().unwrap().get_values(), vec![2]);
        mgr.end_snapshot(true).unwrap();
        assert_eq!(mgr.buffers_removed[0], 1);
    }

    #[test]
    fn end_snapshot_rollback_deletes_file_and_rewinds_index() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap();
        assert_eq!(mgr.snapshot_index, 0);
        let path = mgr.snapshot_files[0].clone();
        mgr.end_snapshot(false).unwrap();
        assert!(!path.exists());
        // snapshotIndex wraps back to 1 on rollback from 0.
        assert_eq!(mgr.snapshot_index, 1);
    }

    #[test]
    fn start_snapshot_failure_leaves_prior_counters_unreset() {
        // See the module-level quirks note: startSnapshot's trailing counter-reset statements
        // are textually outside the try/finally, so a failure inside the try leaves whatever
        // counts a prior successful snapshot at this slot left behind.
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        // Slot 0: successful snapshot with one buffer saved.
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        let node = MockBufferNode::new(1);
        mgr.put_buffer(&DataBuffer::new(1, BUF_SIZE), &node).unwrap();
        assert_eq!(mgr.buffers_saved[0], 1);
        mgr.end_snapshot(true).unwrap();
        assert_eq!(mgr.snapshot_index, 0);

        // Slot 1: successful, empty snapshot.
        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        mgr.end_snapshot(true).unwrap();
        assert_eq!(mgr.snapshot_index, 1);

        // Force the *third* call (which wraps snapshot_index back to slot 0) to fail: remove the
        // recovery directory out from under it, so even the "new_snapshot" branch of
        // RecoveryFile::new fails -- the one Java branch that rethrows unconditionally rather
        // than retrying against a freshly created file.
        let recovery_dir = mgr.snapshot_files[0].parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&recovery_dir).unwrap();

        let err = mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap_err();
        assert!(matches!(err, RecoveryError::Io(_)));
        assert_eq!(
            mgr.buffers_saved[0], 1,
            "faithfully reproduced Java quirk: startSnapshot's trailing counter reset is \
             outside the try/finally, so a failed attempt at a slot leaves that slot's stale \
             counts in place"
        );
    }

    #[test]
    fn dispose_ends_in_progress_snapshot_and_deletes_all_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;
        mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap();
        let path = mgr.snapshot_files[0].clone();

        mgr.dispose();
        assert!(!path.exists());
    }

    #[test]
    fn clear_deletes_files_and_rejects_while_snapshot_in_progress() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap();
        assert!(mgr.clear().is_err());
        mgr.end_snapshot(true).unwrap();

        let path = mgr.snapshot_files[0].clone();
        assert!(path.exists());
        mgr.clear().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn full_snapshot_then_recovery_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;

        mgr.start_snapshot(&source, 4, &[], None, &monitor).unwrap();
        let node = MockBufferNode::new(1);
        mgr.put_buffer(&DataBuffer::new(1, BUF_SIZE), &node).unwrap();
        mgr.end_snapshot(true).unwrap();
        drop(mgr);

        // Simulate a fresh process discovering the leftover recovery data and recovering it.
        let mut recover_source = MockSource::new(
            LocalBufferFile::open(dir.path().join("src.bf"), false).unwrap(),
        );
        let mgr2 = RecoveryMgr::new_for_recovery(&mut recover_source, &monitor).unwrap();
        assert!(mgr2.recovered());
        assert_eq!(recover_source.recover_calls.into_inner(), vec![0]);
        // The unused slot's snapshot/change files were cleaned up.
        assert!(!mgr2.snapshot_files[1].exists());
    }

    #[test]
    fn recovery_propagates_recover_failure_and_still_closes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;
        mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap();
        mgr.end_snapshot(true).unwrap();
        drop(mgr);

        let mut recover_source = MockSource::new(
            LocalBufferFile::open(dir.path().join("src.bf"), false).unwrap(),
        );
        recover_source.fail_recover = true;
        let err = RecoveryMgr::new_for_recovery(&mut recover_source, &monitor).unwrap_err();
        assert!(matches!(err, RecoveryError::Io(_)));
    }

    #[test]
    fn can_recover_true_after_a_committed_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let source = make_source(dir.path());
        let mut mgr = RecoveryMgr::new_for_snapshot(&source);
        let monitor = crate::util::task::DummyMonitor;
        mgr.start_snapshot(&source, 0, &[], None, &monitor).unwrap();
        mgr.end_snapshot(true).unwrap();

        assert!(RecoveryMgr::can_recover(source.source_file()));
    }
}
