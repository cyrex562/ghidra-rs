//! Port of `db.buffers.VersionFile`.
//!
//! Records buffer changes and parameters necessary to reconstruct an older version of a
//! `LocalBufferFile` -- the on-disk format backing undo/redo and check-in/check-out version
//! history. A version file stores: the original and target buffer files' file IDs, the original
//! file's buffer count and free-index list, a copy of the original file's user parameters, and a
//! map from original-file buffer index to a buffer (stored within this file) holding that
//! buffer's *old* contents -- i.e. only buffers that changed between the original and target
//! versions are actually stored.
//!
//! The Java class is package-private, concrete, and has no `extends` clause -- like
//! [`super::change_map::ChangeMap`] and [`super::index_provider::IndexProvider`] in this same
//! package, it is a plain data holder with no inheritance to decouple via composition.
//!
//! # Adaptation: `BufferFile::get`'s "empty buffer" signalling
//!
//! Java's `BufferFile.get(DataBuffer buf, int index)` fills the caller-supplied `buf` in place
//! and never throws merely because the buffer is empty; it instead sets `buf.isEmpty()`, and
//! `VersionFile.readBufferMap`/`readFreeIndexList` check that flag explicitly afterward to detect
//! a corrupt buffer-map/free-list chain. This port's [`super::BufferFile`] trait (established
//! before this file, see `local_buffer_file.rs`) instead returns `io::Result<DataBuffer>`, with
//! an empty block surfacing as `Err`. Since the only way `readBufferMap`/`readFreeIndexList` ever
//! observe an empty buffer is exactly this corruption case (every index they read was written by
//! `VersionFile` itself before being read back), collapsing "empty" and "read error" into a
//! single `Err` here is behaviorally equivalent for this class -- both cases are translated to
//! this port's `BAD_BUFFER_MAP`/`BAD_FREE_LIST` corrupt-file errors, matching the outcome (if not
//! the precise mechanism) of the Java code.
//!
//! # Dead code ported faithfully (not exercised by any real caller)
//!
//! Two pieces of this class are unreachable given its own field invariants, verified by tracing
//! every assignment site in the Java source:
//!
//! - **`VersionFile(BufferFile)` (this port's [`VersionFile::from_buffer_file`])**: every call
//!   site in the upstream codebase (`VersionFileHandler`, `VersionedLocalBufferFileTest`) passes
//!   a `java.io.File`, not a `BufferFile`, which resolves to the `VersionFile(File)` overload
//!   instead. This constructor is otherwise unused in-tree. It is still ported faithfully below
//!   since it is part of the class's real method surface (package-private is not the same as
//!   private -- other `db.buffers` classes could construct one), but note that unlike the other
//!   two constructors, it does **not** call `open()`/`parseFile()`, so `original_buf_count`,
//!   `free_indexes`, and `buffer_index_map` are left at their empty/default values until some
//!   other path populates them.
//! - **The `initialBufCount > 0` branch of `abort()`**: `read_only` is `false` only immediately
//!   after [`VersionFile::create`], which unconditionally sets `initial_buf_count = 0`.
//!   `initial_buf_count` is only ever set positive by [`VersionFile::open`] or
//!   [`VersionFile::from_buffer_file`], both of which set `read_only = true` first. No path can
//!   therefore reach `abort()` with `read_only == false && initial_buf_count > 0`. This port
//!   preserves the branch's shape (see [`VersionFile::abort`]) but leaves its body a documented
//!   gap rather than adding a `LocalBufferFile` on-disk truncate operation (`truncate(int)` in
//!   Java) solely to service code that cannot run.

use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

use super::{BufferFile, IndexProvider, LocalBufferFile};
use crate::framework::db::buffer::{Buffer, DataBuffer};
use crate::util::datastruct::{IntArrayList, IntIntHashtable};
use crate::util::exception::AssertException;

const MAGIC_NUMBER: i32 = 0x382D3435;

// Version file parameter keys. Mirrors `VERSION_PARM_PREFIX` + each suffix constant; written out
// as the already-concatenated literal since Rust `const` declarations can't concatenate other
// `const &str`s at compile time the way Java string-literal `+` folding can.
const VERSION_PARM_PREFIX: &str = "~VF.";
const MAGIC_NUMBER_PARM: &str = "~VF.VersionFile";
const ORIGINAL_FILE_ID_HI_PARM: &str = "~VF.OriginalIdHi";
const ORIGINAL_FILE_ID_LOW_PARM: &str = "~VF.OriginalIdLow";
const TARGET_FILE_ID_HI_PARM: &str = "~VF.TargetIdHi";
const TARGET_FILE_ID_LOW_PARM: &str = "~VF.TargetIdLow";
const ORIGINAL_BUFFER_COUNT_PARM: &str = "~VF.OrigBufCnt";
const MAP_BUFFER_INDEX_PARM: &str = "~VF.MapIndex";
const FREE_LIST_BUFFER_INDEX_PARM: &str = "~VF.FreeListIndex";
const FREE_LIST_SIZE_PARM: &str = "~VF.FreeListSize";

// Exception messages.
const BAD_FREE_LIST: &str = "Version file is corrupt - bad free list";
const BAD_BUFFER_MAP: &str = "Version file is corrupt - bad buffer map";

// Used by both the Buffer Map and Free Index List.
const NEXT_BUFFER_INDEX_OFFSET: usize = 0;
const FIRST_ENTRY_OFFSET: usize = 4;
const BUFFER_MAP_ENTRY_SIZE: usize = 8;
const FREE_LIST_ENTRY_SIZE: usize = 4;

/// Records buffer changes and parameters necessary to reconstruct an older version of a
/// `LocalBufferFile`. Mirrors `db.buffers.VersionFile`.
pub struct VersionFile {
    // NOTE: `Debug` is implemented manually below rather than derived, since `version_file`'s
    // `Box<dyn BufferFile>` doesn't implement `Debug` (the trait doesn't require it, and adding
    // it would ripple across every `BufferFile` implementor in this crate for a diagnostic-only
    // need). The manual impl reports whether the underlying file is open without trying to print
    // its contents.
    file: Option<PathBuf>,
    last_modified: Option<SystemTime>,
    read_only: bool,

    buffer_size: usize,
    original_buf_count: i32,
    initial_buf_count: i32,

    version_file: Option<Box<dyn BufferFile>>,
    target_file_id: u64,
    original_file_id: u64,
    vf_index_provider: IndexProvider,
    /// Sorted to facilitate binary search, matching the Java field comment.
    free_indexes: Vec<i32>,

    /// Maps buffer IDs to version file buffer indexes.
    buffer_index_map: IntIntHashtable,
    new_map_ids: IntArrayList,
    last_map_buffer: Option<DataBuffer>,
    last_map_index: i32,
    next_map_entry_offset: usize,
}

impl std::fmt::Debug for VersionFile {
    // Manual impl (not `#[derive]`) since `version_file: Option<Box<dyn BufferFile>>` holds a
    // trait object and `BufferFile` has no `Debug` supertrait; the trait object's presence/type
    // is summarized instead of formatted field-by-field.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionFile")
            .field("file", &self.file)
            .field("last_modified", &self.last_modified)
            .field("read_only", &self.read_only)
            .field("buffer_size", &self.buffer_size)
            .field("original_buf_count", &self.original_buf_count)
            .field("initial_buf_count", &self.initial_buf_count)
            .field("version_file_open", &self.version_file.is_some())
            .field("target_file_id", &self.target_file_id)
            .field("original_file_id", &self.original_file_id)
            .field("free_indexes", &self.free_indexes)
            .field("last_map_index", &self.last_map_index)
            .field("next_map_entry_offset", &self.next_map_entry_offset)
            .finish_non_exhaustive()
    }
}


fn closed_err() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "Version file is closed")
}

fn read_only_err() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "Version file is read-only")
}

fn corrupt_err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

fn require_version_file(version_file: &Option<Box<dyn BufferFile>>) -> io::Result<&dyn BufferFile> {
    version_file.as_deref().ok_or_else(closed_err)
}

fn require_version_file_mut<'a>(
    version_file: &'a mut Option<Box<dyn BufferFile>>,
) -> io::Result<&'a mut dyn BufferFile> {
    match version_file.as_mut() {
        Some(boxed) => Ok(boxed.as_mut()),
        None => Err(closed_err()),
    }
}

/// Splits a 64-bit file ID into the `(hi, lo)` 32-bit halves used to store it as a pair of
/// integer parameters. Mirrors the bit manipulation inlined in `VersionFile`'s write constructor:
/// `(int)(originalFileId >> 32)` / `(int)(originalFileId & 0xffffffffL)`.
fn split_file_id(file_id: u64) -> (i32, i32) {
    let hi = (file_id >> 32) as i32;
    let lo = (file_id & 0xFFFF_FFFF) as u32 as i32;
    (hi, lo)
}

/// Rejoins the `(hi, lo)` halves produced by [`split_file_id`] back into the original 64-bit file
/// ID. Mirrors `VersionFile.parseFile()`'s `((long) hi << 32) | (lo & 0xffffffffL)`.
fn join_file_id(hi: i32, lo: i32) -> u64 {
    ((hi as i64 as u64) << 32) | (lo as u32 as u64)
}

impl VersionFile {
    /// Construct a new version file for output. Mirrors `VersionFile(LocalBufferFile,
    /// LocalBufferFile, File)`.
    ///
    /// # Parameters
    /// - `original_bf`: the original buffer file which is to be reconstructed from this version
    ///   file.
    /// - `target_bf`: the buffer file to which this version file will be applied.
    /// - `vfile_path`: version buffer file to be created.
    pub fn create(
        original_bf: &LocalBufferFile,
        target_bf: &LocalBufferFile,
        vfile_path: PathBuf,
    ) -> io::Result<Self> {
        let buffer_size = original_bf.get_buffer_size();
        let original_buf_count = original_bf.get_index_count() as i32;

        let mut version_file = LocalBufferFile::create(vfile_path.clone(), buffer_size)?;
        let mut vf_index_provider = IndexProvider::new();

        // Save magic number for version file.
        version_file.set_parameter(MAGIC_NUMBER_PARM, MAGIC_NUMBER);

        // Save original and target file IDs as user parameter values.
        let original_file_id = original_bf.get_file_id();
        let (orig_hi, orig_lo) = split_file_id(original_file_id);
        version_file.set_parameter(ORIGINAL_FILE_ID_HI_PARM, orig_hi);
        version_file.set_parameter(ORIGINAL_FILE_ID_LOW_PARM, orig_lo);
        let target_file_id = target_bf.get_file_id();

        // Save original buffer count.
        version_file.set_parameter(ORIGINAL_BUFFER_COUNT_PARM, original_buf_count);

        // Create first map buffer (buffer ID is same as index).
        let new_map_ids = IntArrayList::new();
        let buffer_index_map = IntIntHashtable::new();
        let mut last_map_buffer = DataBuffer::new(0, buffer_size);
        let last_map_index = vf_index_provider.allocate_index();
        last_map_buffer.set_id(last_map_index);
        last_map_buffer.put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
        last_map_buffer.put_int(FIRST_ENTRY_OFFSET, -1);
        let next_map_entry_offset = FIRST_ENTRY_OFFSET;
        version_file.put(&last_map_buffer, last_map_index)?;
        version_file.set_parameter(MAP_BUFFER_INDEX_PARM, last_map_index);

        // Save original free list.
        let mut free_indexes = original_bf.get_free_indexes();
        free_indexes.sort();

        let mut this_ = Self {
            file: Some(vfile_path),
            last_modified: None,
            read_only: false,
            buffer_size,
            original_buf_count,
            initial_buf_count: 0, // new file
            version_file: Some(Box::new(version_file)),
            target_file_id,
            original_file_id,
            vf_index_provider,
            free_indexes,
            buffer_index_map,
            new_map_ids,
            last_map_buffer: Some(last_map_buffer),
            last_map_index,
            next_map_entry_offset,
        };

        let free_list_index = this_.save_free_index_list()?;
        {
            let vf = require_version_file_mut(&mut this_.version_file)?;
            vf.set_parameter(FREE_LIST_BUFFER_INDEX_PARM, free_list_index);
            vf.set_parameter(FREE_LIST_SIZE_PARM, this_.free_indexes.len() as i32);
        }

        // Copy original parameter values.
        for name in original_bf.get_parameter_names() {
            if let Some(value) = original_bf.get_parameter(&name) {
                require_version_file_mut(&mut this_.version_file)?.set_parameter(&name, value);
            }
        }

        Ok(this_)
    }

    /// Construct a read-only version file from an existing version file path. Mirrors
    /// `VersionFile(File)`.
    pub fn open_read_only(vfile_path: PathBuf) -> io::Result<Self> {
        let mut vf = Self {
            file: Some(vfile_path),
            last_modified: None,
            read_only: true,
            buffer_size: 0,
            original_buf_count: 0,
            initial_buf_count: 0,
            version_file: None,
            target_file_id: 0,
            original_file_id: 0,
            vf_index_provider: IndexProvider::new(),
            free_indexes: Vec::new(),
            buffer_index_map: IntIntHashtable::new(),
            new_map_ids: IntArrayList::new(),
            last_map_buffer: None,
            last_map_index: 0,
            next_map_entry_offset: 0,
        };
        vf.open()?;
        Ok(vf)
    }

    /// Construct a read-only version file from an already-open, read-only `BufferFile`. Mirrors
    /// `VersionFile(BufferFile)`.
    ///
    /// See the module-level "Dead code ported faithfully" note: no real caller in the upstream
    /// codebase actually reaches this constructor, and unlike [`Self::open_read_only`] it does
    /// not parse the buffer map / free list -- those stay empty until populated some other way.
    ///
    /// # Panics
    ///
    /// Panics (mirroring Java's unchecked `AssertException("Read-only buffer file expected")`)
    /// if `version_file` is not read-only.
    pub fn from_buffer_file(version_file: Box<dyn BufferFile>) -> io::Result<Self> {
        if !version_file.is_read_only() {
            panic!("{}", AssertException::with_message("Read-only buffer file expected"));
        }
        let buffer_size = version_file.get_buffer_size();
        let initial_buf_count = version_file.get_index_count() as i32;
        Ok(Self {
            file: None,
            last_modified: None,
            read_only: true,
            buffer_size,
            original_buf_count: 0,
            initial_buf_count,
            version_file: Some(version_file),
            target_file_id: 0,
            original_file_id: 0,
            vf_index_provider: IndexProvider::new(),
            free_indexes: Vec::new(),
            buffer_index_map: IntIntHashtable::new(),
            new_map_ids: IntArrayList::new(),
            last_map_buffer: None,
            last_map_index: 0,
            next_map_entry_offset: 0,
        })
    }

    /// Abort the creation/update of this version file. This method should be invoked in place of
    /// [`Self::close`] on a failure condition. An attempt is made to restore the version file to
    /// its initial state or remove it if it was new. Mirrors `abort()`.
    pub fn abort(&mut self) -> io::Result<()> {
        if self.version_file.is_none() {
            return Ok(());
        }

        if self.read_only {
            require_version_file_mut(&mut self.version_file)?.close()?;
        } else if self.initial_buf_count > 0 {
            // Unreachable under this class's invariants -- see the module-level doc comment.
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VersionFile::abort: truncate-on-abort branch is unreachable under this \
                 class's field invariants (read_only is always true whenever \
                 initial_buf_count > 0) and is not implemented; see module docs",
            ));
        } else {
            require_version_file_mut(&mut self.version_file)?.delete()?;
        }
        self.version_file = None;
        self.file = None;
        Ok(())
    }

    /// Close the version file. Mirrors `close()`.
    pub fn close(&mut self) -> io::Result<()> {
        if self.version_file.is_none() {
            return Ok(());
        }

        if !self.read_only {
            let is_vf_read_only = require_version_file(&self.version_file)?.is_read_only();
            if !is_vf_read_only {
                self.update_buffer_map()?;
            }

            // Set target file ID.
            let (hi, lo) = split_file_id(self.target_file_id);
            let vf = require_version_file_mut(&mut self.version_file)?;
            vf.set_parameter(TARGET_FILE_ID_HI_PARM, hi);
            vf.set_parameter(TARGET_FILE_ID_LOW_PARM, lo);
        }
        require_version_file_mut(&mut self.version_file)?.close()?;
        self.version_file = None;

        if !self.read_only {
            if let Some(path) = &self.file {
                self.last_modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
            }
        }
        Ok(())
    }

    /// Reopen version file as read-only. Mirrors `open()`.
    pub fn open(&mut self) -> io::Result<()> {
        if self.version_file.is_some() {
            return Ok(());
        }
        let path = self
            .file
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Version file has been aborted"))?;
        self.read_only = true;
        let lbf = LocalBufferFile::open(path.clone(), true)?;
        self.buffer_size = lbf.get_buffer_size();
        self.initial_buf_count = lbf.get_index_count() as i32;
        self.version_file = Some(Box::new(lbf));

        let good_file = require_version_file(&self.version_file)?.get_parameter(MAGIC_NUMBER_PARM)
            == Some(MAGIC_NUMBER);
        if !good_file {
            return Err(corrupt_err("Corrupt version file"));
        }

        let mod_time = std::fs::metadata(&path)?.modified()?;
        if Some(mod_time) != self.last_modified {
            let result = self.parse_file();
            if result.is_err() {
                let _ = self.close();
            }
            result?;
            self.last_modified = Some(mod_time);
        }
        Ok(())
    }

    fn parse_file(&mut self) -> io::Result<()> {
        fn get_param(vf: &dyn BufferFile, name: &str) -> io::Result<i32> {
            vf.get_parameter(name).ok_or_else(|| corrupt_err("Corrupt version file"))
        }

        self.original_buf_count =
            get_param(require_version_file(&self.version_file)?, ORIGINAL_BUFFER_COUNT_PARM)?;

        let orig_hi = get_param(require_version_file(&self.version_file)?, ORIGINAL_FILE_ID_HI_PARM)?;
        let orig_lo = get_param(require_version_file(&self.version_file)?, ORIGINAL_FILE_ID_LOW_PARM)?;
        self.original_file_id = join_file_id(orig_hi, orig_lo);

        let target_hi = get_param(require_version_file(&self.version_file)?, TARGET_FILE_ID_HI_PARM)?;
        let target_lo = get_param(require_version_file(&self.version_file)?, TARGET_FILE_ID_LOW_PARM)?;
        self.target_file_id = join_file_id(target_hi, target_lo);

        let map_index = get_param(require_version_file(&self.version_file)?, MAP_BUFFER_INDEX_PARM)?;
        self.read_buffer_map(map_index)?;

        let free_list_index =
            get_param(require_version_file(&self.version_file)?, FREE_LIST_BUFFER_INDEX_PARM)?;
        let free_list_size = get_param(require_version_file(&self.version_file)?, FREE_LIST_SIZE_PARM)?;
        self.read_free_index_list(free_list_index, free_list_size)?;

        Ok(())
    }

    fn update_buffer_map(&mut self) -> io::Result<()> {
        let max_offset = self.buffer_size - BUFFER_MAP_ENTRY_SIZE;

        let cnt = self.new_map_ids.size();
        for i in 0..cnt {
            let orig_index = self.new_map_ids.get(i);
            let ver_index = self.buffer_index_map.get(orig_index).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Other,
                    AssertException::with_message(
                        "newMapIds entry missing from bufferIndexMap",
                    )
                    .to_string(),
                )
            })?;

            if self.next_map_entry_offset > max_offset {
                let next_index = self.vf_index_provider.allocate_index();
                self.last_map_buffer
                    .as_mut()
                    .expect("last_map_buffer initialized by the write constructor")
                    .put_int(NEXT_BUFFER_INDEX_OFFSET, next_index);
                {
                    let buf = self.last_map_buffer.as_ref().unwrap();
                    let last_index = self.last_map_index;
                    require_version_file_mut(&mut self.version_file)?.put(buf, last_index)?;
                }
                self.next_map_entry_offset = FIRST_ENTRY_OFFSET;
                self.last_map_index = next_index;
                self.last_map_buffer.as_mut().unwrap().set_id(next_index);
            }

            let buf = self.last_map_buffer.as_mut().unwrap();
            self.next_map_entry_offset = buf.put_int(self.next_map_entry_offset, orig_index) as usize;
            self.next_map_entry_offset = buf.put_int(self.next_map_entry_offset, ver_index) as usize;
        }

        // Mark end of list.
        if self.next_map_entry_offset > max_offset {
            let next_index = self.vf_index_provider.allocate_index();
            self.last_map_buffer.as_mut().unwrap().put_int(NEXT_BUFFER_INDEX_OFFSET, next_index);
            {
                let buf = self.last_map_buffer.as_ref().unwrap();
                let last_index = self.last_map_index;
                require_version_file_mut(&mut self.version_file)?.put(buf, last_index)?;
            }
            self.next_map_entry_offset = FIRST_ENTRY_OFFSET;
            self.last_map_index = next_index;
            self.last_map_buffer.as_mut().unwrap().set_id(next_index);
        }
        self.last_map_buffer.as_mut().unwrap().put_int(self.next_map_entry_offset, -1);

        // Make sure last buffer is saved.
        self.last_map_buffer.as_mut().unwrap().put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
        {
            let buf = self.last_map_buffer.as_ref().unwrap();
            let last_index = self.last_map_index;
            require_version_file_mut(&mut self.version_file)?.put(buf, last_index)?;
        }

        self.new_map_ids.clear();
        Ok(())
    }

    fn read_buffer_map(&mut self, mut map_index: i32) -> io::Result<()> {
        self.buffer_index_map = IntIntHashtable::new();
        let max_offset = self.buffer_size - BUFFER_MAP_ENTRY_SIZE;

        self.last_map_index = map_index;
        let mut last_map_buffer =
            require_version_file(&self.version_file)?.get(map_index).map_err(|_| corrupt_err(BAD_BUFFER_MAP))?;
        self.next_map_entry_offset = FIRST_ENTRY_OFFSET;

        loop {
            if self.next_map_entry_offset > max_offset {
                map_index = last_map_buffer.get_int(NEXT_BUFFER_INDEX_OFFSET);
                last_map_buffer = require_version_file(&self.version_file)?
                    .get(map_index)
                    .map_err(|_| corrupt_err(BAD_BUFFER_MAP))?;
                self.last_map_index = map_index;
                self.next_map_entry_offset = FIRST_ENTRY_OFFSET;
            }

            // Read map entry -- end of list signified by -1.
            let orig_index = last_map_buffer.get_int(self.next_map_entry_offset);
            if orig_index < 0 {
                self.last_map_buffer = Some(last_map_buffer);
                return Ok(());
            }
            self.next_map_entry_offset += 4;
            let ver_index = last_map_buffer.get_int(self.next_map_entry_offset);
            self.next_map_entry_offset += 4;
            self.buffer_index_map.put(orig_index, ver_index);
        }
    }

    fn save_free_index_list(&mut self) -> io::Result<i32> {
        let free_list_index = self.vf_index_provider.allocate_index();
        let mut this_index = free_list_index;

        let max_offset = self.buffer_size - FREE_LIST_ENTRY_SIZE;

        let mut buf = DataBuffer::new(0, self.buffer_size);
        buf.set_id(this_index);
        let mut offset = FIRST_ENTRY_OFFSET;

        // Save freeIndexes entries.
        for i in 0..self.free_indexes.len() {
            if offset > max_offset {
                let next_index = self.vf_index_provider.allocate_index();
                buf.put_int(NEXT_BUFFER_INDEX_OFFSET, next_index);
                require_version_file_mut(&mut self.version_file)?.put(&buf, this_index)?;

                offset = FIRST_ENTRY_OFFSET;
                this_index = next_index;
                buf.set_id(this_index);
            }

            // Save list entry as single integer.
            offset = buf.put_int(offset, self.free_indexes[i]) as usize;
        }

        // Mark end of list.
        if offset > max_offset {
            let next_index = self.vf_index_provider.allocate_index();
            buf.put_int(NEXT_BUFFER_INDEX_OFFSET, next_index);
            require_version_file_mut(&mut self.version_file)?.put(&buf, this_index)?;

            offset = FIRST_ENTRY_OFFSET;
            this_index = next_index;
            buf.set_id(this_index);
        }
        buf.put_int(offset, -1);

        // Make sure last buffer is saved.
        buf.put_int(NEXT_BUFFER_INDEX_OFFSET, -1);
        require_version_file_mut(&mut self.version_file)?.put(&buf, this_index)?;

        Ok(free_list_index)
    }

    fn read_free_index_list(&mut self, mut list_index: i32, size: i32) -> io::Result<()> {
        let size = size as usize;
        let mut free_indexes = vec![0i32; size];

        let max_offset = self.buffer_size - FREE_LIST_ENTRY_SIZE;

        let mut list_buffer = require_version_file(&self.version_file)?
            .get(list_index)
            .map_err(|_| corrupt_err(BAD_FREE_LIST))?;
        let mut offset = FIRST_ENTRY_OFFSET;
        let mut entry_ix: usize = 0;

        loop {
            if offset > max_offset {
                list_index = list_buffer.get_int(NEXT_BUFFER_INDEX_OFFSET);
                list_buffer = require_version_file(&self.version_file)?
                    .get(list_index)
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

    /// Change the file ID associated with the buffer file to which this version file can be
    /// applied. Mirrors `setTargetFileId(long)`.
    pub fn set_target_file_id(&mut self, file_id: u64) -> io::Result<()> {
        if self.version_file.is_none() {
            return Err(closed_err());
        }
        if self.read_only {
            return Err(read_only_err());
        }
        self.target_file_id = file_id;
        Ok(())
    }

    /// Returns true if this version file will accept old buffer data for the specified buffer
    /// index. Mirrors `isPutOK(int)`.
    pub fn is_put_ok(&self, index: i32) -> bool {
        index >= 0
            && index < self.original_buf_count
            && !self.buffer_index_map.contains(index)
            && !self.is_free_index(index)
    }

    /// Returns true if the specified index was free in the original file. Mirrors
    /// `isFreeIndex(int)`.
    fn is_free_index(&self, index: i32) -> bool {
        self.free_indexes.binary_search(&index).is_ok()
    }

    /// Returns the list of free indexes associated with the original buffer file. Mirrors
    /// `getFreeIndexList()`.
    ///
    /// Unlike the Java accessor (which returns a direct reference to the mutable internal
    /// array), this returns a borrowed slice rather than a defensive copy or a leaked mutable
    /// alias -- no caller in this port needs to mutate it.
    pub fn get_free_index_list(&self) -> &[i32] {
        &self.free_indexes
    }

    /// Store original buffer which has been modified in the target. When reverting to the
    /// original file version, these buffers should replace the newer version. Mirrors
    /// `putOldBuffer(DataBuffer, int)`.
    pub fn put_old_buffer(&mut self, buf: &DataBuffer, index: i32) -> io::Result<()> {
        if self.version_file.is_none() {
            return Err(closed_err());
        }
        if self.read_only {
            return Err(read_only_err());
        }
        if self.is_put_ok(index) {
            let vf_index = self.vf_index_provider.allocate_index();
            require_version_file_mut(&mut self.version_file)?.put(buf, vf_index)?;
            self.buffer_index_map.put(index, vf_index);
            self.new_map_ids.add(index);
        }
        Ok(())
    }

    /// Get original buffer associated with the specified storage index in the original file.
    /// Returns `None` if the buffer has not been modified. Mirrors `getOldBuffer(DataBuffer,
    /// int)`.
    ///
    /// Diverges from Java's out-parameter shape (`getOldBuffer(DataBuffer buf, int index)`,
    /// which fills and returns the caller-supplied buffer) by returning an owned `DataBuffer`
    /// instead, matching this port's `BufferFile::get`, which already made the same adaptation.
    pub fn get_old_buffer(&self, index: i32) -> io::Result<Option<DataBuffer>> {
        if self.version_file.is_none() {
            return Err(closed_err());
        }
        let vf_index = match self.buffer_index_map.get(index) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let buf = require_version_file(&self.version_file)?.get(vf_index)?;
        Ok(Some(buf))
    }

    /// Returns list of original buffer indexes stored within this file. These indexes reflect
    /// those buffers which have been modified since the original version. Mirrors
    /// `getOldBufferIndexes()`.
    pub fn get_old_buffer_indexes(&self) -> Vec<i32> {
        self.buffer_index_map.get_keys()
    }

    /// Returns file ID for buffer file to which this version file may be applied. Mirrors
    /// `getTargetFileID()`.
    pub fn get_target_file_id(&self) -> u64 {
        self.target_file_id
    }

    /// Returns file ID for original buffer file which may be produced with this version file.
    /// Mirrors `getOriginalFileID()`.
    pub fn get_original_file_id(&self) -> u64 {
        self.original_file_id
    }

    /// Returns buffer count for original buffer file. Mirrors `getOriginalBufferCount()`.
    pub fn get_original_buffer_count(&self) -> i32 {
        self.original_buf_count
    }

    /// Returns a list of parameters defined within the original buffer file. Mirrors
    /// `getOldParameterNames()`.
    pub fn get_old_parameter_names(&self) -> io::Result<Vec<String>> {
        let vf = require_version_file(&self.version_file)?;
        Ok(vf
            .get_parameter_names()
            .into_iter()
            .filter(|name| !name.starts_with(VERSION_PARM_PREFIX))
            .collect())
    }

    /// Get a parameter value associated with the original buffer file. Mirrors
    /// `getOldParameter(String)`.
    ///
    /// Java's underlying `BufferFile.getParameter(String)` throws the unchecked
    /// `NoSuchElementException` for a missing parameter (exercised directly by
    /// `VersionFileTest.testVersionFile()`, which asserts it for a never-set parameter name).
    /// This port's `BufferFile::get_parameter` returns `Option<i32>` instead of throwing, so a
    /// missing parameter is surfaced here as `Err` with `io::ErrorKind::NotFound`.
    pub fn get_old_parameter(&self, name: &str) -> io::Result<i32> {
        let vf = require_version_file(&self.version_file)?;
        vf.get_parameter(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("No such parameter: {name}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smallest buffer size that safely holds `VersionFile`'s own header parameters.
    ///
    /// `LocalBufferFile::write_header()` requires the fixed 32-byte header plus every
    /// parameter (8 bytes + name each) to fit in one buffer, failing with "Buffer size too small"
    /// otherwise, as Java's `LocalBufferFile.writeHeader()` does. Every `VersionFile`
    /// unconditionally sets 9 header parameters by the time it's closed (7 in the write
    /// constructor, 2 more in `close()`), whose keys alone total 136 bytes, so any test that
    /// closes a `VersionFile` needs a buffer size above the resulting ~240-byte header -- a tiny
    /// `buffer_size` like 32 or 64 makes `close()` fail.
    const SAFE_TEST_BUFFER_SIZE: usize = 256;

    /// Like [`SAFE_TEST_BUFFER_SIZE`], but with extra headroom for tests that also copy a couple
    /// of named parameters (e.g. "PARM1"/"PARM2") from the original file into the version file's
    /// header, which need a bit more room than the 9 built-in parameters alone.
    const LARGER_SAFE_TEST_BUFFER_SIZE: usize = 320;

    fn make_pair(dir: &std::path::Path, buffer_size: usize) -> (LocalBufferFile, LocalBufferFile) {
        let original = LocalBufferFile::create(dir.join("orig.bf"), buffer_size).unwrap();
        let target = LocalBufferFile::create(dir.join("target.bf"), buffer_size).unwrap();
        (original, target)
    }

    #[test]
    fn split_and_join_file_id_round_trip() {
        for id in [0u64, 1, u64::MAX, 0xDEAD_BEEF_CAFE_BABE, 0x8000_0000_0000_0000, 0x7FFF_FFFF_FFFF_FFFF] {
            let (hi, lo) = split_file_id(id);
            assert_eq!(join_file_id(hi, lo), id, "round trip failed for {id:#x}");
        }
    }

    #[test]
    fn create_records_original_and_target_file_ids() {
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);

        let vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();
        assert_eq!(vf.get_original_file_id(), original.get_file_id());
        // Target file ID is captured at construction even though it isn't flushed to the
        // underlying parameter storage until close().
        assert_eq!(vf.get_target_file_id(), target.get_file_id());
        assert_eq!(vf.get_original_buffer_count(), 0);
    }

    #[test]
    fn put_old_buffer_then_get_old_buffer_round_trips_without_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let (mut original, target) = make_pair(dir.path(), 64);

        // Give the original file two allocated buffers so isPutOK() accepts indexes 0 and 1.
        let mut seed = DataBuffer::new(0, 64);
        seed.get_data_mut()[0] = 0xAA;
        original.put(&seed, 0).unwrap();
        original.put(&seed, 1).unwrap();

        let mut vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();

        let mut old_buf = DataBuffer::new(0, 64);
        old_buf.get_data_mut()[0] = 0x11;
        vf.put_old_buffer(&old_buf, 0).unwrap();

        let fetched = vf.get_old_buffer(0).unwrap().expect("buffer 0 was stored");
        assert_eq!(fetched.get_data()[0], 0x11);

        // Index 1 was never put -- no old data recorded for it.
        assert!(vf.get_old_buffer(1).unwrap().is_none());

        assert_eq!(vf.get_old_buffer_indexes(), vec![0]);
    }

    #[test]
    fn is_put_ok_rejects_out_of_range_already_mapped_and_free_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let (mut original, target) = make_pair(dir.path(), 64);
        for i in 0..4 {
            let buf = DataBuffer::new(0, 64);
            original.put(&buf, i).unwrap();
        }
        original.set_free_indexes(&[2]).unwrap();

        let mut vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();

        assert!(!vf.is_put_ok(-1), "negative index must be rejected");
        assert!(!vf.is_put_ok(4), "index >= originalBufCount must be rejected");
        assert!(!vf.is_put_ok(2), "index free in the original file must be rejected");
        assert!(vf.is_put_ok(0));

        let buf = DataBuffer::new(0, 64);
        vf.put_old_buffer(&buf, 0).unwrap();
        assert!(!vf.is_put_ok(0), "an already-mapped index must be rejected on a second put");
    }

    #[test]
    fn put_old_buffer_on_disallowed_index_is_a_silent_no_op() {
        // Mirrors Java's putOldBuffer(): a disallowed index is silently ignored rather than
        // raising an error (only isPutOK() gates the store).
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let mut vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();

        let buf = DataBuffer::new(0, 64);
        // originalBufCount is 0 here, so every index is out of range.
        vf.put_old_buffer(&buf, 0).unwrap();
        assert!(vf.get_old_buffer(0).unwrap().is_none());
        assert!(vf.get_old_buffer_indexes().is_empty());
    }

    #[test]
    fn operations_on_closed_version_file_return_closed_error() {
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let mut vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();
        vf.close().unwrap();

        let buf = DataBuffer::new(0, 64);
        assert!(vf.put_old_buffer(&buf, 0).is_err());
        assert!(vf.get_old_buffer(0).is_err());
        assert!(vf.set_target_file_id(1).is_err());
        assert!(vf.get_old_parameter_names().is_err());
        assert!(vf.get_old_parameter("x").is_err());
    }

    #[test]
    fn set_target_file_id_rejected_once_read_only() {
        let dir = tempfile::tempdir().unwrap();
        // See SAFE_TEST_BUFFER_SIZE's doc comment: must be large enough for VersionFile's own
        // header parameters to fit in one block.
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let mut vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();
        vf.close().unwrap();

        vf.open().unwrap();
        let err = vf.set_target_file_id(42).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn full_round_trip_through_close_and_reopen() {
        // Mirrors the shape of the upstream VersionFileTest.testVersionFile(), using a buffer
        // size small enough to stress the multi-block buffer-map/free-list chaining logic
        // (BUFFER_MAP_ENTRY_SIZE=8, FREE_LIST_ENTRY_SIZE=4) while still being large enough for
        // VersionFile's own header parameters to fit in one block (see
        // `LARGER_SAFE_TEST_BUFFER_SIZE`'s doc comment) -- unlike most of this module's tests,
        // this one also copies two named parameters (PARM1/PARM2) from the original file, which
        // need a bit more headroom than `SAFE_TEST_BUFFER_SIZE` provides.
        let dir = tempfile::tempdir().unwrap();
        let buffer_size = LARGER_SAFE_TEST_BUFFER_SIZE; // max_offset for map entries = 312, i.e. 39 entries/buffer
        let orig_buf_count = 200;

        let mut original = LocalBufferFile::create(dir.path().join("orig.bf"), buffer_size).unwrap();
        let target = LocalBufferFile::create(dir.path().join("target.bf"), buffer_size).unwrap();

        for i in 0..orig_buf_count {
            let mut buf = DataBuffer::new(i as i32, buffer_size);
            buf.get_data_mut()[0] = i as u8;
            original.put(&buf, i as i32).unwrap();
        }
        // Free every other buffer.
        let free: Vec<i32> = (1..orig_buf_count as i32).step_by(2).collect();
        original.set_free_indexes(&free).unwrap();
        original.set_parameter("PARM1", 111);
        original.set_parameter("PARM2", 222);

        let original_file_id = original.get_file_id();
        let target_file_id = target.get_file_id();

        let vfile_path = dir.path().join("v.vf");
        let mut vf = VersionFile::create(&original, &target, vfile_path.clone()).unwrap();
        assert_eq!(vf.get_target_file_id(), target_file_id);
        assert_eq!(vf.get_original_file_id(), original_file_id);

        // Record "modified" buffers for every even index.
        for i in (0..orig_buf_count as i32).step_by(2) {
            let mut buf = DataBuffer::new(i, buffer_size);
            buf.get_data_mut()[0] = i as u8;
            vf.put_old_buffer(&buf, i).unwrap();
        }
        vf.close().unwrap();

        // Reopen read-only and verify everything survives the round trip.
        let mut vf = VersionFile::open_read_only(vfile_path).unwrap();
        assert_eq!(vf.get_original_buffer_count(), orig_buf_count as i32);
        assert_eq!(vf.get_target_file_id(), target_file_id);
        assert_eq!(vf.get_original_file_id(), original_file_id);

        let mut free_indexes = vf.get_free_index_list().to_vec();
        free_indexes.sort();
        let mut expected_free = free.clone();
        expected_free.sort();
        assert_eq!(free_indexes, expected_free);

        let mut buffer_indexes = vf.get_old_buffer_indexes();
        buffer_indexes.sort();
        let expected_buffers: Vec<i32> = (0..orig_buf_count as i32).step_by(2).collect();
        assert_eq!(buffer_indexes, expected_buffers);

        for &i in &buffer_indexes {
            let buf = vf.get_old_buffer(i).unwrap().expect("buffer was stored");
            assert_eq!(buf.get_data()[0], i as u8);
        }

        let mut names = vf.get_old_parameter_names().unwrap();
        names.sort();
        assert_eq!(names, vec!["PARM1".to_string(), "PARM2".to_string()]);
        assert_eq!(vf.get_old_parameter("PARM1").unwrap(), 111);
        assert_eq!(vf.get_old_parameter("PARM2").unwrap(), 222);

        // Mirrors VersionFileTest's explicit NoSuchElementException assertion for a parameter
        // that was never set.
        assert_eq!(vf.get_old_parameter("PARM3").unwrap_err().kind(), io::ErrorKind::NotFound);

        vf.close().unwrap();
    }

    #[test]
    fn open_rejects_file_missing_magic_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-version-file.bf");
        // A plain LocalBufferFile with no VersionFile magic-number parameter set.
        let mut plain = LocalBufferFile::create(path.clone(), 64).unwrap();
        plain.close().unwrap();

        let err = VersionFile::open_read_only(path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn abort_on_new_write_file_deletes_it() {
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let vfile_path = dir.path().join("v.vf");
        let mut vf = VersionFile::create(&original, &target, vfile_path.clone()).unwrap();
        assert!(vfile_path.exists());

        vf.abort().unwrap();
        assert!(!vfile_path.exists(), "abort() on a brand-new version file should delete it");

        // A second abort() call is a no-op, mirroring Java's `if (versionFile == null) return;`.
        vf.abort().unwrap();
    }

    #[test]
    fn abort_on_read_only_file_just_closes_it() {
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let vfile_path = dir.path().join("v.vf");
        let mut vf = VersionFile::create(&original, &target, vfile_path.clone()).unwrap();
        vf.close().unwrap();

        let mut vf = VersionFile::open_read_only(vfile_path.clone()).unwrap();
        vf.abort().unwrap();
        // Unlike the new-file case, aborting a read-only version file only closes it -- the file
        // on disk is left alone.
        assert!(vfile_path.exists());
    }

    #[test]
    fn from_buffer_file_panics_on_non_read_only_input() {
        let dir = tempfile::tempdir().unwrap();
        let lbf = LocalBufferFile::create(dir.path().join("v.vf"), 64).unwrap();
        assert!(!lbf.is_read_only());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            VersionFile::from_buffer_file(Box::new(lbf))
        }));
        assert!(result.is_err(), "expected from_buffer_file to panic on a writable BufferFile");
    }

    #[test]
    fn from_buffer_file_on_read_only_input_leaves_parse_derived_fields_at_defaults() {
        // See the module-level "Dead code ported faithfully" note: this constructor never calls
        // open()/parseFile(), so originalBufCount/freeIndexes/bufferIndexMap stay empty even
        // though the underlying BufferFile is a real, valid version file.
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let vfile_path = dir.path().join("v.vf");
        let mut vf = VersionFile::create(&original, &target, vfile_path.clone()).unwrap();
        vf.close().unwrap();

        let lbf = LocalBufferFile::open(vfile_path, true).unwrap();
        let vf2 = VersionFile::from_buffer_file(Box::new(lbf)).unwrap();
        assert_eq!(vf2.get_original_buffer_count(), 0);
        assert!(vf2.get_free_index_list().is_empty());
        assert!(vf2.get_old_buffer_indexes().is_empty());
    }

    #[test]
    fn abort_truncate_branch_is_a_documented_unimplemented_gap() {
        // This branch is unreachable through the public constructors (see module docs), but its
        // shape is still ported; exercise it directly to pin down the documented-gap error.
        let dir = tempfile::tempdir().unwrap();
        let (original, target) = make_pair(dir.path(), SAFE_TEST_BUFFER_SIZE);
        let mut vf = VersionFile::create(&original, &target, dir.path().join("v.vf")).unwrap();
        vf.read_only = false; // already false, kept explicit for clarity
        vf.initial_buf_count = 5; // force the otherwise-unreachable branch
        let err = vf.abort().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
