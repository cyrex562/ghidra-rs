//! Port of `db.buffers.RecoveryFile`.
//!
//! Records buffer changes and parameters necessary to reconstruct a `LocalBufferFile` after a
//! crash without an explicit save -- the on-disk format backing `RecoveryMgr`'s periodic
//! snapshots. A recovery file stores: the source file's ID, its current buffer/index count and
//! free-index list, plus a map from source-file buffer index to a buffer (stored within this
//! file) holding that buffer's *new* contents as of the last snapshot -- i.e. only buffers
//! modified since the source file was last saved are actually stored here.
//!
//! Architecturally this is extremely close to [`super::version_file::VersionFile`] in the same
//! package: both are chained-block on-disk records built on `IndexProvider` for their own
//! internal block allocation, and both encode a buffer-index map and a free-index list as linked
//! chains of fixed-size blocks with a `NEXT_BUFFER_INDEX_OFFSET`/`FIRST_ENTRY_OFFSET` sentinel
//! convention. Unlike `VersionFile` (which updates its buffer-index map incrementally, appending
//! new entries as `putOldBuffer` is called), `RecoveryFile` rewrites its *entire* buffer-index
//! map and free-index list from scratch every time it is closed (`saveBufferMap`/
//! `saveFreeIndexList`), reusing the existing on-disk block chain in place when one already
//! exists (the "update" constructor path, `create == false`).
//!
//! The Java class is package-private, concrete, and has no `extends` clause -- like
//! `VersionFile`, it is a plain data holder with no inheritance to decouple via composition.
//! Unlike `VersionFile` (whose field is `BufferFile version_file`, an interface type), this
//! class's Java field is the concrete type `LocalBufferFile recoveryFile`, so this port's field
//! is likewise a concrete `Option<LocalBufferFile>` rather than a `Box<dyn BufferFile>` trait
//! object.
//!
//! # Adaptations
//!
//! - **Empty-buffer signalling**: as in `VersionFile` (see that module's doc comment), Java's
//!   `BufferFile.get(DataBuffer, int)` fills a buffer in place and signals corruption via
//!   `buf.isEmpty()` rather than throwing; this port's [`super::BufferFile::get`] returns
//!   `io::Result<DataBuffer>` instead, with an empty/absent block surfacing as `Err`. Since
//!   `read_buffer_map`/`read_free_index_list` are the only callers that ever cared about this
//!   distinction (and only to detect corruption), collapsing the two cases into `Err` there,
//!   translated to `BAD_BUFFER_MAP`/`BAD_FREE_LIST`, is behaviorally equivalent.
//! - **Uniform "closed" errors**: Java guards some methods that dereference `recoveryFile`
//!   explicitly (`putBuffer`, `getBuffer`, `getUserParameterNames`, `getParameter`, each throwing
//!   `IOException("Version file is closed")` -- see the quirk below) but leaves others unguarded
//!   (`clearParameters`, `setParameter`, `getFile`), where a call after `close()` would throw an
//!   unchecked `NullPointerException` in Java. This port guards *every* method that touches
//!   `recovery_file` uniformly via `require_recovery_file`/`require_recovery_file_mut`, returning
//!   `Err` rather than distinguishing checked-vs-unchecked Java exceptions that have no clean
//!   analog in a `Result`-based API. Methods that never touch `recovery_file` in Java
//!   (`removeBuffer`, `setIndexCount`, `setFreeIndexList`) correspondingly have no such guard
//!   here either, matching Java's actual per-method behavior.
//! - **Missing parameter on the initial validity check**: Java's `getParameter(IS_VALID_PARM) ==
//!   VALID` check in the `create == false` constructor branch would throw an unchecked
//!   `NoSuchElementException` if the parameter is entirely absent (propagating out of the
//!   constructor uncaught, since it isn't wrapped in a `try`). This port's `get_parameter`
//!   returns `Option`, so a missing parameter here is simply treated as "not valid" (`!=
//!   Some(VALID)`), which produces the same practical outcome (the constructor fails) via the
//!   ordinary `Err` path instead of an unchecked panic.
//!
//! # Quirks ported faithfully (verified against the real Java source)
//!
//! - **Copy-pasted parameter-key text** (`RecoveryFile.java` lines 39, 42): `MAGIC_NUMBER_PARM`'s
//!   string body is literally `"~RF.VersionFile"` (not `"~RF.RecoveryFile"`), and
//!   `IS_VALID_PARM`'s string body is literally `"~RF.OrigBufCnt"` (a name that describes
//!   `VersionFile`'s original-buffer-count parameter, not a validity flag). Both are cosmetic --
//!   the keys are still unique within this class's own `"~RF."`-prefixed namespace -- but are
//!   ported verbatim as evidence of a copy/paste from `VersionFile.java`.
//! - **Copy-pasted error text** (lines 466, 469, 512, 549): `putBuffer`, `getBuffer`, and
//!   `getUserParameterNames`/`getParameter` all throw `IOException("Version file is closed")`
//!   (and `putBuffer` also throws `"Version file is read-only"`) even though this is
//!   `RecoveryFile`, not `VersionFile`. Ported verbatim in [`closed_err`]/[`read_only_err`].
//! - **`setIndexCount`'s cleanup loop only fires on growth** (lines 422-428): `for (int index =
//!   indexCnt; index < newIndexCount; index++) removeBuffer(index)` only ever iterates when
//!   `newIndexCount > indexCnt` (growth) -- and in that case every index in the range is
//!   necessarily *not yet* present in `bufferIndexMap` (it didn't exist before the growth), so
//!   each `removeBuffer` call is a guaranteed no-op. When `newIndexCount < indexCnt` (shrinkage,
//!   presumably the intended case for pruning stale entries beyond the new count), the loop
//!   condition is false from the start and never executes at all, so buffer-index-map/free-index
//!   entries for indices that no longer exist in the source file are silently left behind. This
//!   is reproduced faithfully in [`RecoveryFile::set_index_count`] and pinned down by
//!   [`tests::set_index_count_shrink_does_not_prune_stale_entries`].
//! - **`vfIndexProvider` is never initialized by the read-only constructor** (the whole body of
//!   `RecoveryFile(LocalBufferFile, File)`, lines 133-139): unlike the 3-arg constructor, this
//!   one never assigns `vfIndexProvider`, leaving it Java-`null`. `removeBuffer` (and
//!   `setIndexCount`/`setFreeIndexList`, which call it) don't check `readOnly` before touching
//!   `vfIndexProvider`, so calling any of them on an instance built via the 2-arg constructor
//!   throws an unchecked `NullPointerException` in Java. This port models the same shape with
//!   `vf_index_provider: Option<IndexProvider>`, left `None` by [`RecoveryFile::open_read_only`],
//!   and [`RecoveryFile::remove_buffer`] reproduces the crash with `.expect(..)`. Tracing every
//!   real call site (`RecoveryMgr.getRecoveryFile`/`BufferMgr.recover` only ever call read
//!   accessors on 2-arg-constructed instances; the 3-arg constructor is used exclusively
//!   wherever mutators are called) confirms this bug is unreachable from any real caller in the
//!   upstream codebase, matching the "dead code ported faithfully" pattern already documented in
//!   `version_file.rs`. Pinned down by
//!   [`tests::remove_buffer_on_read_only_constructed_instance_panics`].

use std::io;
use std::path::{Path, PathBuf};

use super::{BufferFile, IndexProvider, LocalBufferFile};
use crate::framework::db::buffer::{Buffer, DataBuffer};
use crate::util::datastruct::IntIntHashtable;
use crate::util::exception::AssertException;

const MAGIC_NUMBER: i32 = 0x38DE7654;

const VALID: i32 = 1;
const INVALID: i32 = 0;

// Recovery file parameter keys. See the module-level "Quirks ported faithfully" note for the two
// parameter keys whose literal text was evidently copy-pasted from `VersionFile.java`.
const RECOVERY_PARM_PREFIX: &str = "~RF.";
const MAGIC_NUMBER_PARM: &str = "~RF.VersionFile";
const SRC_FILE_ID_HI_PARM: &str = "~RF.SrcIdHi";
const SRC_FILE_ID_LOW_PARM: &str = "~RF.SrcIdLow";
const IS_VALID_PARM: &str = "~RF.OrigBufCnt";
const TIMESTAMP_HI_PARM: &str = "~RF.TimestampHi";
const TIMESTAMP_LOW_PARM: &str = "~RF.TimestampLow";
const MAP_BUFFER_INDEX_PARM: &str = "~RF.MapIndex";
const FREE_LIST_BUFFER_INDEX_PARM: &str = "~RF.FreeListIndex";
const FREE_LIST_SIZE_PARM: &str = "~RF.FreeListSize";
const INDEX_COUNT_PARM: &str = "~RF.BufferCount";

// Exception messages.
const BAD_FREE_LIST: &str = "Recovery file is corrupt - bad free list";
const BAD_BUFFER_MAP: &str = "Recovery file is corrupt - bad buffer map";

// Used by both the Buffer Map and Free Index List.
const NEXT_BUFFER_INDEX_OFFSET: usize = 0;
const FIRST_ENTRY_OFFSET: usize = 4;

const VF_INDEX_PROVIDER_NPE_MSG: &str =
    "NullPointerException: vf_index_provider is None -- this RecoveryFile was constructed via \
     RecoveryFile::open_read_only (the read-only 2-arg constructor), which mirrors \
     db.buffers.RecoveryFile(LocalBufferFile, File) in never initializing vfIndexProvider. \
     Calling a mutator on such an instance throws an unchecked NullPointerException in the \
     original Java too -- see recovery_file.rs's module-level quirks doc.";

/// Records buffer changes and parameters necessary to recover a `LocalBufferFile` after a crash
/// without an explicit save. Mirrors `db.buffers.RecoveryFile`.
pub struct RecoveryFile {
    read_only: bool,
    valid: bool,
    timestamp: i64,
    modified: bool,

    // NOTE: `Debug` is implemented manually below rather than derived, since `LocalBufferFile`
    // does not implement `Debug`. The manual impl reports whether the file is open without
    // trying to print its contents -- same rationale as `VersionFile`'s manual `Debug` impl.
    recovery_file: Option<LocalBufferFile>,

    src_file_id: u64,
    index_cnt: i32,
    vf_index_provider: Option<IndexProvider>,
    free_list_index: i32,
    map_index: i32,

    /// Sorted to facilitate binary search, matching the Java field comment.
    free_indexes: Vec<i32>,

    /// Maps buffer IDs to recovery-file buffer indexes.
    buffer_index_map: IntIntHashtable,
}

impl std::fmt::Debug for RecoveryFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryFile")
            .field("read_only", &self.read_only)
            .field("valid", &self.valid)
            .field("timestamp", &self.timestamp)
            .field("modified", &self.modified)
            .field("recovery_file_open", &self.recovery_file.is_some())
            .field("src_file_id", &self.src_file_id)
            .field("index_cnt", &self.index_cnt)
            .field("vf_index_provider", &self.vf_index_provider)
            .field("free_list_index", &self.free_list_index)
            .field("map_index", &self.map_index)
            .field("free_indexes", &self.free_indexes)
            .finish_non_exhaustive()
    }
}

fn closed_err() -> io::Error {
    // Verbatim copy of the Java text -- see the module-level "Quirks ported faithfully" note.
    io::Error::new(io::ErrorKind::Other, "Version file is closed")
}

fn read_only_err() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Version file is read-only")
}

fn corrupt_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn assert_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, AssertException::with_message(msg).to_string())
}

fn require_recovery_file(recovery_file: &Option<LocalBufferFile>) -> io::Result<&LocalBufferFile> {
    recovery_file.as_ref().ok_or_else(closed_err)
}

fn require_recovery_file_mut(
    recovery_file: &mut Option<LocalBufferFile>,
) -> io::Result<&mut LocalBufferFile> {
    recovery_file.as_mut().ok_or_else(closed_err)
}

/// Splits a 64-bit file ID into the `(hi, lo)` 32-bit halves used to store it as a pair of
/// integer parameters. Mirrors `(int) (srcFileId >>> 32)` / `(int) (srcFileId & 0xffffffffL)`.
fn split_file_id(file_id: u64) -> (i32, i32) {
    let hi = (file_id >> 32) as i32;
    let lo = (file_id & 0xFFFF_FFFF) as u32 as i32;
    (hi, lo)
}

/// Rejoins the `(hi, lo)` halves produced by [`split_file_id`]. Mirrors `((long) hi << 32) | (lo
/// & 0xffffffffL)`.
fn join_file_id(hi: i32, lo: i32) -> u64 {
    ((hi as i64 as u64) << 32) | (lo as u32 as u64)
}

/// Splits a millisecond timestamp into the `(hi, lo)` 32-bit halves. Mirrors `(int) (t >>> 32)` /
/// `(int) (t & 0xffffffffL)`.
fn split_millis(t: i64) -> (i32, i32) {
    let hi = ((t as u64) >> 32) as i32;
    let lo = (t & 0xFFFF_FFFF) as i32;
    (hi, lo)
}

/// Rejoins the `(hi, lo)` halves produced by [`split_millis`]. Mirrors `((long) hi << 32) | (lo &
/// 0xffffffffL)`.
fn join_millis(hi: i32, lo: i32) -> i64 {
    ((hi as i64) << 32) | ((lo as u32) as i64)
}

impl RecoveryFile {
    /// Construct a new recovery file for update/output. Mirrors `RecoveryFile(LocalBufferFile,
    /// File, boolean)`.
    ///
    /// # Parameters
    /// - `src_bf`: the original source buffer file to which this file applies.
    /// - `rfile_path`: recovery buffer file to be updated/created.
    /// - `create`: `true` to create the file, `false` to open and update an existing one.
    pub fn new(src_bf: &LocalBufferFile, rfile_path: PathBuf, create: bool) -> io::Result<Self> {
        if create {
            let index_cnt = src_bf.get_index_count() as i32;
            let mut recovery_file = LocalBufferFile::create(rfile_path, src_bf.get_buffer_size())?;

            // Save magic number for recovery file.
            recovery_file.set_parameter(MAGIC_NUMBER_PARM, MAGIC_NUMBER);

            // Mark as invalid.
            recovery_file.set_parameter(IS_VALID_PARM, INVALID);

            // Save original and source file ID as user parameter values.
            let src_file_id = src_bf.get_file_id();
            let (hi, lo) = split_file_id(src_file_id);
            recovery_file.set_parameter(SRC_FILE_ID_HI_PARM, hi);
            recovery_file.set_parameter(SRC_FILE_ID_LOW_PARM, lo);

            Ok(Self {
                read_only: false,
                valid: false,
                timestamp: 0,
                modified: true,
                recovery_file: Some(recovery_file),
                src_file_id,
                index_cnt,
                vf_index_provider: Some(IndexProvider::new()),
                free_list_index: -1,
                map_index: -1,
                free_indexes: Vec::new(),
                buffer_index_map: IntIntHashtable::new(),
            })
        } else {
            let recovery_file = LocalBufferFile::open(rfile_path, false)?;

            // See the module-level "Adaptations" note: a missing parameter here (`None`) is
            // treated as "not valid" rather than reproducing Java's unchecked
            // NoSuchElementException.
            let valid = recovery_file.get_parameter(IS_VALID_PARM) == Some(VALID);
            if !valid {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Can not update invalid recovery file",
                ));
            }

            let mut this_ = Self {
                read_only: false,
                valid,
                timestamp: 0,
                modified: false,
                recovery_file: Some(recovery_file),
                src_file_id: 0,
                index_cnt: 0,
                vf_index_provider: None,
                free_list_index: -1,
                map_index: -1,
                free_indexes: Vec::new(),
                buffer_index_map: IntIntHashtable::new(),
            };

            this_.parse_file()?;

            if this_.src_file_id != src_bf.get_file_id() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Recovery file not associated with source file",
                ));
            }

            let idx_cnt = require_recovery_file(&this_.recovery_file)?.get_index_count() as i32;
            let free_idx = require_recovery_file(&this_.recovery_file)?.get_free_indexes();
            this_.vf_index_provider = Some(IndexProvider::with_initial_state(idx_cnt, &free_idx));

            Ok(this_)
        }
    }

    /// Construct a read-only recovery file. Mirrors `RecoveryFile(LocalBufferFile, File)`.
    ///
    /// See the module-level quirks note: unlike [`Self::new`], this constructor never
    /// initializes `vf_index_provider` -- mutators called on the resulting instance will panic.
    pub fn open_read_only(src_bf: &LocalBufferFile, rfile_path: PathBuf) -> io::Result<Self> {
        let recovery_file = LocalBufferFile::open(rfile_path, true)?;
        let mut this_ = Self {
            read_only: true,
            valid: false,
            timestamp: 0,
            modified: false,
            recovery_file: Some(recovery_file),
            src_file_id: 0,
            index_cnt: 0,
            vf_index_provider: None,
            free_list_index: -1,
            map_index: -1,
            free_indexes: Vec::new(),
            buffer_index_map: IntIntHashtable::new(),
        };
        this_.parse_file()?;
        let is_valid_param = require_recovery_file(&this_.recovery_file)?.get_parameter(IS_VALID_PARM);
        this_.valid = is_valid_param == Some(VALID) && this_.src_file_id == src_bf.get_file_id();
        Ok(this_)
    }

    fn set_modified(&mut self) {
        if self.valid {
            // Java derefs `recoveryFile` unconditionally here with no null check; this port
            // no-ops instead of reproducing that (very narrow, practically unreachable) NPE --
            // see the module-level "Adaptations" note.
            if let Some(rf) = self.recovery_file.as_mut() {
                rf.set_parameter(IS_VALID_PARM, INVALID);
            }
            self.valid = false;
            self.modified = true;
        }
    }

    /// Returns the physical file path for this recovery file. Mirrors `getFile()`.
    pub fn get_file(&self) -> io::Result<&Path> {
        Ok(require_recovery_file(&self.recovery_file)?.get_file())
    }

    /// Returns whether this recovery file currently holds a complete, uncorrupted snapshot.
    /// Mirrors `isValid()`.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Returns the timestamp (milliseconds since the epoch) of the last completed snapshot.
    /// Mirrors `getTimestamp()`.
    pub fn get_timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Close the recovery file, flushing the buffer map and free-index list if modified. Mirrors
    /// `close()`.
    pub fn close(&mut self) -> io::Result<()> {
        if self.recovery_file.is_none() {
            return Ok(());
        }

        let is_rf_read_only = require_recovery_file(&self.recovery_file)?.is_read_only();
        if !self.read_only && self.modified && !is_rf_read_only {
            self.save_buffer_map()?;
            self.save_free_index_list()?;

            let index_cnt = self.index_cnt;
            require_recovery_file_mut(&mut self.recovery_file)?
                .set_parameter(INDEX_COUNT_PARM, index_cnt);

            let free = self
                .vf_index_provider
                .as_ref()
                .expect(VF_INDEX_PROVIDER_NPE_MSG)
                .get_free_indexes();
            require_recovery_file_mut(&mut self.recovery_file)?.set_free_indexes(&free)?;

            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let (hi, lo) = split_millis(t);
            let rf = require_recovery_file_mut(&mut self.recovery_file)?;
            rf.set_parameter(TIMESTAMP_HI_PARM, hi);
            rf.set_parameter(TIMESTAMP_LOW_PARM, lo);
            rf.set_parameter(IS_VALID_PARM, VALID); // mark as valid
        }
        require_recovery_file_mut(&mut self.recovery_file)?.close()?;
        self.recovery_file = None;
        Ok(())
    }

    fn parse_file(&mut self) -> io::Result<()> {
        match require_recovery_file(&self.recovery_file)?.get_parameter(MAGIC_NUMBER_PARM) {
            None => return Err(corrupt_err("Corrupt recovery file")),
            Some(v) if v != MAGIC_NUMBER => return Err(corrupt_err("Invalid recovery file")),
            _ => {}
        }

        let hi = require_recovery_file(&self.recovery_file)?.get_parameter(TIMESTAMP_HI_PARM);
        let lo = require_recovery_file(&self.recovery_file)?.get_parameter(TIMESTAMP_LOW_PARM);
        self.timestamp = match (hi, lo) {
            (Some(h), Some(l)) => join_millis(h, l),
            _ => {
                // Not as good -- better than nothing. Mirrors `recoveryFile.getFile()
                // .lastModified()`, which returns 0 on error.
                let path = require_recovery_file(&self.recovery_file)?.get_file().to_path_buf();
                std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0)
            }
        };

        let src_hi = require_recovery_file(&self.recovery_file)?
            .get_parameter(SRC_FILE_ID_HI_PARM)
            .ok_or_else(|| corrupt_err("Corrupt recovery file"))?;
        let src_lo = require_recovery_file(&self.recovery_file)?
            .get_parameter(SRC_FILE_ID_LOW_PARM)
            .ok_or_else(|| corrupt_err("Corrupt recovery file"))?;
        self.src_file_id = join_file_id(src_hi, src_lo);

        self.index_cnt = require_recovery_file(&self.recovery_file)?
            .get_parameter(INDEX_COUNT_PARM)
            .ok_or_else(|| corrupt_err("Corrupt recovery file"))?;

        self.read_buffer_map()?;
        self.read_free_index_list()?;

        Ok(())
    }

    fn save_buffer_map(&mut self) -> io::Result<()> {
        let buffer_size = require_recovery_file(&self.recovery_file)?.get_buffer_size();
        let mut buf = DataBuffer::new(0, buffer_size);

        if self.map_index < 0 {
            let map_index =
                self.vf_index_provider.as_mut().expect(VF_INDEX_PROVIDER_NPE_MSG).allocate_index();
            self.map_index = map_index;
            buf.set_id(map_index);
            buf.put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
            require_recovery_file_mut(&mut self.recovery_file)?
                .set_parameter(MAP_BUFFER_INDEX_PARM, map_index);
        } else {
            buf = require_recovery_file(&self.recovery_file)?.get(self.map_index)?;
        }

        let max_offset = (buffer_size - 8) & !0x07;
        let mut offset = FIRST_ENTRY_OFFSET;
        let mut this_index = self.map_index;
        let real_indexes = self.buffer_index_map.get_keys();

        for i in 0..=real_indexes.len() {
            if offset > max_offset {
                let mut new_buf = false;
                let mut next_index = buf.get_int(NEXT_BUFFER_INDEX_OFFSET);
                if next_index < 0 {
                    next_index = self
                        .vf_index_provider
                        .as_mut()
                        .expect(VF_INDEX_PROVIDER_NPE_MSG)
                        .allocate_index();
                    new_buf = true;
                }

                buf.put_int(NEXT_BUFFER_INDEX_OFFSET, next_index);
                require_recovery_file_mut(&mut self.recovery_file)?.put(&buf, this_index)?;

                this_index = next_index;
                if new_buf {
                    buf.set_id(this_index);
                    buf.put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
                } else {
                    buf = require_recovery_file(&self.recovery_file)?.get(this_index)?;
                }

                offset = FIRST_ENTRY_OFFSET;
            }

            if i == real_indexes.len() {
                buf.put_int(offset, -1);
            } else {
                let real_index = real_indexes[i];
                offset = buf.put_int(offset, real_index) as usize;
                let recovery_index = self
                    .buffer_index_map
                    .get(real_index)
                    .map_err(|_| assert_err("bufferIndexMap entry missing for its own key"))?;
                offset = buf.put_int(offset, recovery_index) as usize;
            }
        }

        // Make sure last buffer is saved.
        require_recovery_file_mut(&mut self.recovery_file)?.put(&buf, this_index)?;
        Ok(())
    }

    fn read_buffer_map(&mut self) -> io::Result<()> {
        let map_index = require_recovery_file(&self.recovery_file)?
            .get_parameter(MAP_BUFFER_INDEX_PARM)
            .ok_or_else(|| corrupt_err("Corrupt recovery file"))?;
        self.map_index = map_index;

        let buffer_size = require_recovery_file(&self.recovery_file)?.get_buffer_size();
        let max_offset = (buffer_size - 8) & !0x07;

        let mut this_index = map_index;
        let mut map_buffer = require_recovery_file(&self.recovery_file)?
            .get(this_index)
            .map_err(|_| corrupt_err(BAD_BUFFER_MAP))?;

        let mut offset = FIRST_ENTRY_OFFSET;
        self.buffer_index_map = IntIntHashtable::new();

        loop {
            if offset > max_offset {
                this_index = map_buffer.get_int(NEXT_BUFFER_INDEX_OFFSET);
                map_buffer = require_recovery_file(&self.recovery_file)?
                    .get(this_index)
                    .map_err(|_| corrupt_err(BAD_BUFFER_MAP))?;
                offset = FIRST_ENTRY_OFFSET;
            }

            // Read map entry -- end of list signified by -1.
            let real_index = map_buffer.get_int(offset);
            if real_index < 0 {
                return Ok(());
            }
            offset += 4;
            let recovery_index = map_buffer.get_int(offset);
            offset += 4;
            self.buffer_index_map.put(real_index, recovery_index);
        }
    }

    fn save_free_index_list(&mut self) -> io::Result<()> {
        let buffer_size = require_recovery_file(&self.recovery_file)?.get_buffer_size();
        let mut buf = DataBuffer::new(0, buffer_size);

        if self.free_list_index < 0 {
            let idx = self
                .vf_index_provider
                .as_mut()
                .expect(VF_INDEX_PROVIDER_NPE_MSG)
                .allocate_index();
            self.free_list_index = idx;
            buf.set_id(idx);
            buf.put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
            require_recovery_file_mut(&mut self.recovery_file)?
                .set_parameter(FREE_LIST_BUFFER_INDEX_PARM, idx);
        } else {
            buf = require_recovery_file(&self.recovery_file)?.get(self.free_list_index)?;
        }
        let free_len = self.free_indexes.len() as i32;
        require_recovery_file_mut(&mut self.recovery_file)?
            .set_parameter(FREE_LIST_SIZE_PARM, free_len);

        let max_offset = (buffer_size - 4) & !0x03;
        let mut offset = FIRST_ENTRY_OFFSET;
        let mut this_index = self.free_list_index;

        for i in 0..=self.free_indexes.len() {
            if offset > max_offset {
                let mut new_buf = false;
                let mut next_index = buf.get_int(NEXT_BUFFER_INDEX_OFFSET);
                if next_index < 0 {
                    next_index = self
                        .vf_index_provider
                        .as_mut()
                        .expect(VF_INDEX_PROVIDER_NPE_MSG)
                        .allocate_index();
                    new_buf = true;
                }

                buf.put_int(NEXT_BUFFER_INDEX_OFFSET, next_index);
                require_recovery_file_mut(&mut self.recovery_file)?.put(&buf, this_index)?;

                this_index = next_index;
                if new_buf {
                    buf.set_id(this_index);
                    buf.put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
                } else {
                    buf = require_recovery_file(&self.recovery_file)?.get(this_index)?;
                }

                offset = FIRST_ENTRY_OFFSET;
            }

            let val = if i == self.free_indexes.len() { -1 } else { self.free_indexes[i] };
            offset = buf.put_int(offset, val) as usize;
        }

        // Make sure last buffer is saved.
        require_recovery_file_mut(&mut self.recovery_file)?.put(&buf, this_index)?;
        Ok(())
    }

    fn read_free_index_list(&mut self) -> io::Result<()> {
        let free_list_index = require_recovery_file(&self.recovery_file)?
            .get_parameter(FREE_LIST_BUFFER_INDEX_PARM)
            .ok_or_else(|| corrupt_err("Corrupt recovery file"))?;
        self.free_list_index = free_list_index;

        let size = require_recovery_file(&self.recovery_file)?
            .get_parameter(FREE_LIST_SIZE_PARM)
            .ok_or_else(|| corrupt_err("Corrupt recovery file"))?;
        let size = size as usize;
        let mut free_indexes = vec![0i32; size];

        let buffer_size = require_recovery_file(&self.recovery_file)?.get_buffer_size();
        let max_offset = (buffer_size - 4) & !0x03;

        let mut this_index = free_list_index;
        let mut list_buffer = require_recovery_file(&self.recovery_file)?
            .get(this_index)
            .map_err(|_| corrupt_err(BAD_FREE_LIST))?;
        let mut offset = FIRST_ENTRY_OFFSET;
        let mut entry_ix: usize = 0;

        loop {
            if offset > max_offset {
                this_index = list_buffer.get_int(NEXT_BUFFER_INDEX_OFFSET);
                list_buffer = require_recovery_file(&self.recovery_file)?
                    .get(this_index)
                    .map_err(|_| corrupt_err(BAD_FREE_LIST))?;
                offset = FIRST_ENTRY_OFFSET;
            }

            // Read entry -- end of list signified by -1.
            let orig_index = list_buffer.get_int(offset);
            if orig_index < 0 {
                break;
            }
            if entry_ix == size {
                return Err(corrupt_err(BAD_FREE_LIST));
            }
            offset += 4;
            free_indexes[entry_ix] = orig_index;
            entry_ix += 1;
        }
        if entry_ix != size {
            return Err(corrupt_err(BAD_FREE_LIST));
        }
        free_indexes.sort();
        self.free_indexes = free_indexes;
        Ok(())
    }

    /// Set the current index count for the file. Mirrors `setIndexCount(int)`.
    ///
    /// See the module-level quirks note: this cleanup loop only ever fires when
    /// `new_index_count` is larger than the current count (growth), in which case every removal
    /// is a guaranteed no-op; a shrinking count leaves stale entries behind.
    pub fn set_index_count(&mut self, new_index_count: i32) {
        self.set_modified();
        for index in self.index_cnt..new_index_count {
            self.remove_buffer(index);
        }
        self.index_cnt = new_index_count;
    }

    /// Returns the index count for the file. Mirrors `getIndexCount()`.
    pub fn get_index_count(&self) -> i32 {
        self.index_cnt
    }

    /// Set the free index list. Mirrors `setFreeIndexList(int[])`.
    pub fn set_free_index_list(&mut self, free_indexes: &[i32]) {
        self.set_modified();
        let mut sorted = free_indexes.to_vec();
        sorted.sort();
        self.free_indexes = sorted;
        for &index in free_indexes {
            self.remove_buffer(index);
        }
    }

    /// Returns the list of free indexes associated with the original buffer file. Mirrors
    /// `getFreeIndexList()`.
    pub fn get_free_index_list(&self) -> &[i32] {
        &self.free_indexes
    }

    /// Store a buffer which has been modified in the target. Mirrors `putBuffer(DataBuffer)`.
    pub fn put_buffer(&mut self, buf: &DataBuffer) -> io::Result<()> {
        if self.recovery_file.is_none() {
            return Err(closed_err());
        }
        if self.read_only {
            return Err(read_only_err());
        }
        self.set_modified();
        let id = buf.get_id();
        let vf_index = match self.buffer_index_map.get(id) {
            Ok(v) => v,
            Err(_) => {
                let v = self
                    .vf_index_provider
                    .as_mut()
                    .expect(VF_INDEX_PROVIDER_NPE_MSG)
                    .allocate_index();
                self.buffer_index_map.put(id, v);
                v
            }
        };
        require_recovery_file_mut(&mut self.recovery_file)?.put(buf, vf_index)
    }

    /// Remove a buffer previously stored to the snapshot by removing it from the map. It is OK
    /// to invoke this method for an index whose buffer was never put into this file. Mirrors
    /// `removeBuffer(int)`.
    ///
    /// # Panics
    ///
    /// Panics if this instance was constructed via [`Self::open_read_only`] and `id` is actually
    /// present in the buffer map -- see the module-level quirks note.
    pub fn remove_buffer(&mut self, id: i32) {
        self.set_modified();
        if let Ok(vf_index) = self.buffer_index_map.remove(id) {
            self.vf_index_provider.as_mut().expect(VF_INDEX_PROVIDER_NPE_MSG).free_index(vf_index);
        }
    }

    /// Get the modified buffer associated with the specified storage index in the original file.
    /// Returns `None` if the buffer has not been modified. Mirrors `getBuffer(DataBuffer, int)`.
    ///
    /// Diverges from Java's out-parameter shape by returning an owned `DataBuffer`, matching the
    /// same adaptation already made by `VersionFile::get_old_buffer`.
    pub fn get_buffer(&self, id: i32) -> io::Result<Option<DataBuffer>> {
        if self.recovery_file.is_none() {
            return Err(closed_err());
        }
        let vf_index = match self.buffer_index_map.get(id) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let buf = require_recovery_file(&self.recovery_file)?.get(vf_index)?;
        Ok(Some(buf))
    }

    /// Returns the list of buffer indexes stored within this file. Mirrors
    /// `getBufferIndexes()`.
    pub fn get_buffer_indexes(&self) -> Vec<i32> {
        self.buffer_index_map.get_keys()
    }

    /// Returns the file ID for the original source buffer file. Mirrors `getSourceFileID()`.
    pub fn get_source_file_id(&self) -> u64 {
        self.src_file_id
    }

    /// Returns a list of parameters defined within the original buffer file. Mirrors
    /// `getUserParameterNames()`.
    pub fn get_user_parameter_names(&self) -> io::Result<Vec<String>> {
        let rf = require_recovery_file(&self.recovery_file)?;
        Ok(rf
            .get_parameter_names()
            .into_iter()
            .filter(|name| !name.starts_with(RECOVERY_PARM_PREFIX))
            .collect())
    }

    /// Get a parameter value associated with the original buffer file. Mirrors
    /// `getParameter(String)`.
    ///
    /// Java's underlying `getParameter` throws the unchecked `NoSuchElementException` for a
    /// missing parameter; this port's `LocalBufferFile::get_parameter` returns `Option<i32>`
    /// instead, so a missing parameter is surfaced here as `Err` with `io::ErrorKind::NotFound`
    /// -- the same adaptation already made by `VersionFile::get_old_parameter`.
    pub fn get_parameter(&self, name: &str) -> io::Result<i32> {
        let rf = require_recovery_file(&self.recovery_file)?;
        rf.get_parameter(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("No such parameter: {name}")))
    }

    /// Clear all user parameters (except this class's own internal recovery parameters, which
    /// are preserved). Mirrors `clearParameters()`.
    pub fn clear_parameters(&mut self) -> io::Result<()> {
        self.set_modified();
        let rf = require_recovery_file_mut(&mut self.recovery_file)?;
        let all_names = rf.get_parameter_names();
        let mut recovery_props: Vec<(String, i32)> = Vec::new();
        for name in &all_names {
            if name.starts_with(RECOVERY_PARM_PREFIX) {
                if let Some(v) = rf.get_parameter(name) {
                    recovery_props.push((name.clone(), v));
                }
            }
        }
        rf.clear_parameters();
        for (name, value) in recovery_props {
            rf.set_parameter(&name, value);
        }
        Ok(())
    }

    /// Set a user parameter. Mirrors `setParameter(String, int)`.
    pub fn set_parameter(&mut self, name: &str, value: i32) -> io::Result<()> {
        self.set_modified();
        require_recovery_file_mut(&mut self.recovery_file)?.set_parameter(name, value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smallest buffer size that safely holds `RecoveryFile`'s own header parameters. See
    /// `version_file.rs`'s `SAFE_TEST_BUFFER_SIZE` doc comment: `LocalBufferFile::write_header()`
    /// fails with "Buffer size too small" when the header parameters do not fit in one buffer.
    /// `RecoveryFile` unconditionally sets up to 10 header parameters (`MAGIC_NUMBER_PARM`,
    /// `SRC_FILE_ID_HI/LOW_PARM`, `IS_VALID_PARM`, `TIMESTAMP_HI/LOW_PARM`,
    /// `MAP_BUFFER_INDEX_PARM`, `FREE_LIST_BUFFER_INDEX_PARM`, `FREE_LIST_SIZE_PARM`,
    /// `INDEX_COUNT_PARM`) by the time it's closed, so any test that closes a `RecoveryFile`
    /// needs a buffer size comfortably above the resulting header.
    const SAFE_TEST_BUFFER_SIZE: usize = 256;

    /// As [`SAFE_TEST_BUFFER_SIZE`], with extra headroom for tests that also set a couple of
    /// named user parameters via [`RecoveryFile::set_parameter`].
    const LARGER_SAFE_TEST_BUFFER_SIZE: usize = 320;

    #[test]
    fn split_and_join_file_id_round_trip() {
        for id in [0u64, 1, u64::MAX, 0xDEAD_BEEF_CAFE_BABE, 0x8000_0000_0000_0000, 0x7FFF_FFFF_FFFF_FFFF]
        {
            let (hi, lo) = split_file_id(id);
            assert_eq!(join_file_id(hi, lo), id, "round trip failed for {id:#x}");
        }
    }

    #[test]
    fn split_and_join_millis_round_trip() {
        for t in [0i64, 1, i64::MAX / 2, 1_723_000_000_000] {
            let (hi, lo) = split_millis(t);
            assert_eq!(join_millis(hi, lo), t, "round trip failed for {t}");
        }
    }

    #[test]
    fn create_records_source_file_id_and_marks_modified() {
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), 64).unwrap();

        let rf = RecoveryFile::new(&src, dir.path().join("r.rf"), true).unwrap();
        assert_eq!(rf.get_source_file_id(), src.get_file_id());
        assert!(!rf.is_valid(), "freshly created recovery file is marked invalid until close()");
        assert_eq!(rf.get_index_count(), 0);
    }

    #[test]
    fn put_buffer_then_get_buffer_round_trips_without_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), 64).unwrap();
        let mut rf = RecoveryFile::new(&src, dir.path().join("r.rf"), true).unwrap();

        let mut buf = DataBuffer::new(3, 64);
        buf.get_data_mut()[0] = 0x42;
        rf.put_buffer(&buf).unwrap();

        let fetched = rf.get_buffer(3).unwrap().expect("buffer 3 was stored");
        assert_eq!(fetched.get_data()[0], 0x42);

        // An id that was never put returns None, not an error.
        assert!(rf.get_buffer(4).unwrap().is_none());
        assert_eq!(rf.get_buffer_indexes(), vec![3]);
    }

    #[test]
    fn remove_buffer_forgets_stored_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), 64).unwrap();
        let mut rf = RecoveryFile::new(&src, dir.path().join("r.rf"), true).unwrap();

        let buf = DataBuffer::new(7, 64);
        rf.put_buffer(&buf).unwrap();
        assert!(rf.get_buffer(7).unwrap().is_some());

        rf.remove_buffer(7);
        assert!(rf.get_buffer(7).unwrap().is_none());
        assert!(rf.get_buffer_indexes().is_empty());

        // Removing an id that was never stored is a silent no-op, mirroring Java's
        // `catch (NoValueException e) { /* ignore? */ }`.
        rf.remove_buffer(999);
    }

    #[test]
    fn put_buffer_rejected_once_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), SAFE_TEST_BUFFER_SIZE).unwrap();
        let rfile_path = dir.path().join("r.rf");
        let mut rf = RecoveryFile::new(&src, rfile_path.clone(), true).unwrap();
        rf.set_index_count(0);
        rf.set_free_index_list(&[]);
        rf.close().unwrap();

        let mut rf = RecoveryFile::open_read_only(&src, rfile_path).unwrap();
        let buf = DataBuffer::new(1, SAFE_TEST_BUFFER_SIZE);
        let err = rf.put_buffer(&buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(err.to_string(), "Version file is read-only");
    }

    #[test]
    fn operations_on_closed_recovery_file_return_closed_error() {
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), SAFE_TEST_BUFFER_SIZE).unwrap();
        let mut rf = RecoveryFile::new(&src, dir.path().join("r.rf"), true).unwrap();
        rf.close().unwrap();

        let buf = DataBuffer::new(0, 64);
        let err = rf.put_buffer(&buf).unwrap_err();
        assert_eq!(err.to_string(), "Version file is closed");
        assert!(rf.get_buffer(0).is_err());
        assert!(rf.get_user_parameter_names().is_err());
        assert!(rf.get_parameter("x").is_err());
        assert!(rf.get_file().is_err());
        assert!(rf.set_parameter("x", 1).is_err());
        assert!(rf.clear_parameters().is_err());

        // A second close() is a no-op, mirroring Java's `if (recoveryFile == null) return;`.
        rf.close().unwrap();
    }

    #[test]
    fn open_rejects_file_missing_magic_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-recovery-file.bf");
        let mut plain = LocalBufferFile::create(path.clone(), 64).unwrap();
        plain.close().unwrap();

        let src = LocalBufferFile::create(dir.path().join("src.bf"), 64).unwrap();
        let err = RecoveryFile::open_read_only(&src, path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn update_mode_rejects_a_file_never_marked_valid() {
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), SAFE_TEST_BUFFER_SIZE).unwrap();
        let rfile_path = dir.path().join("r.rf");

        // Create it but never close() it, so IS_VALID_PARM is never flipped to VALID.
        {
            let _rf = RecoveryFile::new(&src, rfile_path.clone(), true).unwrap();
        }

        let err = RecoveryFile::new(&src, rfile_path, false).unwrap_err();
        assert_eq!(err.to_string(), "Can not update invalid recovery file");
    }

    #[test]
    fn set_index_count_shrink_does_not_prune_stale_entries() {
        // See the module-level quirks note citing RecoveryFile.java's setIndexCount(): the
        // cleanup loop `for (index = indexCnt; index < newIndexCount; index++)
        // removeBuffer(index)` only ever fires on growth (where it's a guaranteed no-op, since
        // those indices can't already be mapped); shrinking the count never prunes now-
        // out-of-range entries.
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), 64).unwrap();
        let mut rf = RecoveryFile::new(&src, dir.path().join("r.rf"), true).unwrap();

        rf.set_index_count(10);
        let buf = DataBuffer::new(8, 64);
        rf.put_buffer(&buf).unwrap();
        assert_eq!(rf.get_buffer_indexes(), vec![8]);

        // Shrink from 10 down to 3 -- index 8 is now out of range but is never removed.
        rf.set_index_count(3);
        assert_eq!(rf.get_index_count(), 3);
        assert_eq!(
            rf.get_buffer_indexes(),
            vec![8],
            "faithfully reproduced Java quirk: shrinking the index count leaves stale \
             buffer-map entries for indices beyond the new count"
        );
    }

    #[test]
    fn remove_buffer_on_read_only_constructed_instance_panics() {
        // See the module-level quirks note: RecoveryFile::open_read_only never initializes
        // vf_index_provider, mirroring Java's un-set `vfIndexProvider` field for the 2-arg
        // constructor. removeBuffer() doesn't check readOnly before touching vfIndexProvider,
        // so calling it on an instance actually holding a mapped buffer throws an unchecked
        // NullPointerException in the original Java; this port reproduces that as a panic.
        let dir = tempfile::tempdir().unwrap();
        let src = LocalBufferFile::create(dir.path().join("src.bf"), SAFE_TEST_BUFFER_SIZE).unwrap();
        let rfile_path = dir.path().join("r.rf");

        let mut rf = RecoveryFile::new(&src, rfile_path.clone(), true).unwrap();
        let buf = DataBuffer::new(2, SAFE_TEST_BUFFER_SIZE);
        rf.put_buffer(&buf).unwrap();
        rf.close().unwrap();

        let mut rf = RecoveryFile::open_read_only(&src, rfile_path).unwrap();
        assert_eq!(rf.get_buffer_indexes(), vec![2], "the mapped buffer survived the round trip");

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rf.remove_buffer(2);
        }));
        assert!(result.is_err(), "expected remove_buffer to panic on a read-only-constructed instance");
    }

    #[test]
    fn full_round_trip_through_close_and_reopen() {
        // Mirrors the shape of the sibling VersionFile test: a buffer size small enough to
        // stress the multi-block buffer-map/free-list chaining logic while still large enough
        // for RecoveryFile's own header parameters to fit in one block.
        let dir = tempfile::tempdir().unwrap();
        let buffer_size = LARGER_SAFE_TEST_BUFFER_SIZE;
        let src_index_count = 60;

        let mut src = LocalBufferFile::create(dir.path().join("src.bf"), buffer_size).unwrap();
        for i in 0..src_index_count {
            let mut buf = DataBuffer::new(i as i32, buffer_size);
            buf.get_data_mut()[0] = i as u8;
            src.put(&buf, i as i32).unwrap();
        }
        let src_file_id = src.get_file_id();

        let rfile_path = dir.path().join("r.rf");
        let mut rf = RecoveryFile::new(&src, rfile_path.clone(), true).unwrap();
        assert_eq!(rf.get_source_file_id(), src_file_id);

        rf.set_index_count(src_index_count as i32);
        let free: Vec<i32> = (1..src_index_count as i32).step_by(2).collect();
        rf.set_free_index_list(&free);
        rf.set_parameter("PARM1", 111).unwrap();
        rf.set_parameter("PARM2", 222).unwrap();

        // Record modified content for every even (non-free) index.
        for i in (0..src_index_count as i32).step_by(2) {
            let mut buf = DataBuffer::new(i, buffer_size);
            buf.get_data_mut()[0] = (i + 1) as u8; // distinguishable from the source's own data
            rf.put_buffer(&buf).unwrap();
        }
        rf.close().unwrap();

        // Reopen read-only and verify everything survives the round trip.
        let mut rf = RecoveryFile::open_read_only(&src, rfile_path.clone()).unwrap();
        assert!(rf.is_valid());
        assert_eq!(rf.get_source_file_id(), src_file_id);
        assert_eq!(rf.get_index_count(), src_index_count as i32);

        let mut free_indexes = rf.get_free_index_list().to_vec();
        free_indexes.sort();
        let mut expected_free = free.clone();
        expected_free.sort();
        assert_eq!(free_indexes, expected_free);

        let mut buffer_indexes = rf.get_buffer_indexes();
        buffer_indexes.sort();
        let expected_buffers: Vec<i32> = (0..src_index_count as i32).step_by(2).collect();
        assert_eq!(buffer_indexes, expected_buffers);

        for &i in &buffer_indexes {
            let buf = rf.get_buffer(i).unwrap().expect("buffer was stored");
            assert_eq!(buf.get_data()[0], (i + 1) as u8);
        }

        let mut names = rf.get_user_parameter_names().unwrap();
        names.sort();
        assert_eq!(names, vec!["PARM1".to_string(), "PARM2".to_string()]);
        assert_eq!(rf.get_parameter("PARM1").unwrap(), 111);
        assert_eq!(rf.get_parameter("PARM2").unwrap(), 222);
        assert_eq!(rf.get_parameter("PARM3").unwrap_err().kind(), io::ErrorKind::NotFound);

        assert!(rf.get_timestamp() > 0, "close() should have recorded a real timestamp");

        rf.close().unwrap();

        // --- Update mode: reopen for further mutation, exercising the "reuse existing on-disk
        // chain" branches of save_buffer_map/save_free_index_list (map_index/free_list_index
        // already >= 0 on entry), which the create=true path above never touches. ---
        let mut rf = RecoveryFile::new(&src, rfile_path.clone(), false).unwrap();
        assert_eq!(rf.get_source_file_id(), src_file_id);
        assert_eq!(rf.get_index_count(), src_index_count as i32);
        // Existing content from the first session is visible immediately (no need to reopen).
        assert_eq!(rf.get_buffer(0).unwrap().unwrap().get_data()[0], 1u8);

        // Overwrite one existing entry and add a brand new one.
        let mut buf0 = DataBuffer::new(0, buffer_size);
        buf0.get_data_mut()[0] = 0xAA;
        rf.put_buffer(&buf0).unwrap();

        let mut buf_new = DataBuffer::new(1, buffer_size); // index 1 was free, now gets content
        buf_new.get_data_mut()[0] = 0xBB;
        rf.put_buffer(&buf_new).unwrap();

        rf.close().unwrap();

        let mut rf = RecoveryFile::open_read_only(&src, rfile_path).unwrap();
        assert!(rf.is_valid());
        assert_eq!(rf.get_buffer(0).unwrap().unwrap().get_data()[0], 0xAA);
        assert_eq!(rf.get_buffer(1).unwrap().unwrap().get_data()[0], 0xBB);
        // Untouched entries from the first session survive the update.
        assert_eq!(rf.get_buffer(2).unwrap().unwrap().get_data()[0], 3u8);
        rf.close().unwrap();
    }
}
