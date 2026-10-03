//! Port of `db.buffers.VersionFileHandler`.
//!
//! Allows a set of [`VersionFile`]s to be used in the dynamic reconstruction of an older
//! `BufferFile`. In an attempt to conserve file handles, only one `VersionFile` is held open at
//! any point in time.
//!
//! When constructed, this handler determines the set of `VersionFile`s needed to reconstruct an
//! older version from a specified target version, by walking version files `origVer..targetVer`
//! and chaining each one's original/target file IDs against its neighbors.
//!
//! The Java class is package-private, concrete, and has no `extends` clause -- like
//! [`VersionFile`] itself, it is a plain data holder with no inheritance to decouple via
//! composition.
//!
//! # Adaptation: `getOldBuffer`'s out-parameter and "empty buffer" signalling
//!
//! Java's `getOldBuffer(DataBuffer buf, int index)` fills a caller-supplied `buf` in place and
//! returns it, `null`, or (for a buffer free in the original version) the same `buf` re-tagged
//! with `setId(-1)`/`setEmpty(true)`/`setDirty(false)`. This port's [`DataBuffer`] has no
//! `isEmpty`/`isDirty` flags to set (see `version_file.rs`'s module docs, which made the same
//! observation for `VersionFile.getOldBuffer`), and there is no caller-supplied buffer to mutate
//! in place. [`get_old_buffer`](VersionFileHandler::get_old_buffer) instead returns an
//! [`OldBufferResult`] enum with one variant per real Java outcome: `Modified` (old data was
//! found in a version file), `Free` (the buffer was free in the original version -- stands in for
//! Java's empty-flagged buffer), and `Unmodified` (no override applies -- Java's `null`).

use std::collections::HashMap;
use std::io;

use super::{BufferFile, BufferFileManager, VersionFile};
use crate::framework::db::buffer::{Buffer, DataBuffer};
use crate::util::datastruct::IntIntHashtable;
use crate::util::exception::AssertException;

/// Outcome of [`VersionFileHandler::get_old_buffer`]. See the module docs for how this adapts
/// Java's out-parameter/`null`/empty-flagged-buffer convention.
pub enum OldBufferResult {
    /// Old (pre-modification) data recovered from one of the handler's version files.
    Modified(DataBuffer),
    /// The buffer was free (unallocated) in the original version being reconstructed.
    Free,
    /// The buffer has not been modified since the original version -- callers should keep
    /// whatever buffer they already have loaded from the target/current file.
    Unmodified,
}

impl std::fmt::Debug for OldBufferResult {
    // Manual impl (not `#[derive]`) since `Modified` holds a `DataBuffer`, which does not itself
    // implement `Debug` (see `db/buffers`'s established convention for this exact situation in
    // `version_file.rs`'s manual `Debug` for `VersionFile`); the buffer's id/length are summarized
    // instead of its contents.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OldBufferResult::Modified(buf) => f
                .debug_tuple("Modified")
                .field(&format_args!("DataBuffer(id={}, len={})", buf.get_id(), buf.length()))
                .finish(),
            OldBufferResult::Free => write!(f, "Free"),
            OldBufferResult::Unmodified => write!(f, "Unmodified"),
        }
    }
}

/// Reconstructs an older `BufferFile` version by chaining a set of [`VersionFile`]s. Mirrors
/// `db.buffers.VersionFileHandler`.
#[derive(Debug)]
pub struct VersionFileHandler {
    version_files: Vec<VersionFile>,
    /// Index into `version_files` of the currently-open file, if any. Mirrors the Java `int
    /// openFileIx` field (`-1` sentinel becomes `None`).
    open_file_ix: Option<usize>,

    /// Maps buffer indexes (in the original/target chain) to the `version_files` index holding
    /// that buffer's old data. Mirrors the `IntIntHashtable bufferMap` field.
    buffer_map: IntIntHashtable,

    original_buf_count: i32,
    max_buf_count: i32,
    original_file_id: u64,
    /// Free index list of the oldest (original) version file in the chain. Sorted, mirroring
    /// [`VersionFile::get_free_index_list`]'s own contract.
    free_indexes: Vec<i32>,
    /// Mirrors the `Hashtable<String,Integer> origParms` field.
    orig_parms: HashMap<String, i32>,
}

impl VersionFileHandler {
    /// Construct a version file handler. `VersionFile`s will be used to provide original
    /// `BufferFile` data for the version `orig_ver`.
    ///
    /// Mirrors `VersionFileHandler(BufferFileManager, long, int, int)`.
    ///
    /// # Parameters
    /// - `bf_mgr`: manager for the buffer file which will use this handler to reconstruct an
    ///   older version.
    /// - `target_file_id`: file ID of the buffer file to which the version file buffers will be
    ///   applied.
    /// - `target_ver`: version of the target buffer file.
    /// - `orig_ver`: an older version number.
    ///
    /// # Errors
    /// Returns `Err` if an IO error occurs, data is missing, or the version file chain does not
    /// consistently link `orig_ver` to `target_ver` (a "wrong file ID" `IOException` in Java,
    /// mapped here to `io::ErrorKind::InvalidData`/`NotFound`).
    pub fn new(
        bf_mgr: &dyn BufferFileManager,
        target_file_id: u64,
        target_ver: i32,
        orig_ver: i32,
    ) -> io::Result<Self> {
        let mut version_files: Vec<VersionFile> = Vec::new();
        let mut open_file_ix: Option<usize> = None;
        let mut buffer_map = IntIntHashtable::new();
        let mut original_buf_count: i32 = 0;
        let mut max_buf_count: i32 = 0;
        let mut original_file_id: u64 = 0;
        let mut free_indexes: Vec<i32> = Vec::new();
        let mut orig_parms: HashMap<String, i32> = HashMap::new();
        let mut last_target_file_id: u64 = 0;

        let result: io::Result<()> = 'build: {
            for v in orig_ver..target_ver {
                // Close previous version file.
                if let Some(ix) = open_file_ix {
                    if let Err(e) = version_files[ix].close() {
                        break 'build Err(e);
                    }
                }

                // Open next version file.
                let path = match bf_mgr.get_version_file(v) {
                    Some(p) => p,
                    None => {
                        break 'build Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            format!("No version file for version {v}"),
                        ));
                    }
                };
                let vf = match VersionFile::open_read_only(path) {
                    Ok(vf) => vf,
                    Err(e) => break 'build Err(e),
                };
                version_files.push(vf);
                let ix = version_files.len() - 1;
                open_file_ix = Some(ix);

                // Use free index list and parameters from original version file only.
                if ix == 0 {
                    original_buf_count = version_files[ix].get_original_buffer_count();
                    free_indexes = version_files[ix].get_free_index_list().to_vec();
                    let names = match version_files[ix].get_old_parameter_names() {
                        Ok(n) => n,
                        Err(e) => break 'build Err(e),
                    };
                    for name in &names {
                        let value = match version_files[ix].get_old_parameter(name) {
                            Ok(v) => v,
                            Err(e) => break 'build Err(e),
                        };
                        orig_parms.insert(name.clone(), value);
                    }
                    original_file_id = version_files[ix].get_original_file_id();
                }
                else if last_target_file_id != version_files[ix].get_original_file_id() {
                    break 'build Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Incorrect version file - wrong file ID",
                    ));
                }
                last_target_file_id = version_files[ix].get_target_file_id();
                if max_buf_count < version_files[ix].get_original_buffer_count() {
                    max_buf_count = version_files[ix].get_original_buffer_count();
                }

                // Add buffer indexes to map which are not present in earlier version files.
                for idx in version_files[ix].get_old_buffer_indexes() {
                    if !buffer_map.contains(idx) {
                        buffer_map.put(idx, ix as i32);
                    }
                }
            }
            if last_target_file_id != target_file_id {
                break 'build Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Incorrect version file - wrong file ID",
                ));
            }
            Ok(())
        };

        let mut handler = Self {
            version_files,
            open_file_ix,
            buffer_map,
            original_buf_count,
            max_buf_count,
            original_file_id,
            free_indexes,
            orig_parms,
        };

        match result {
            Ok(()) => Ok(handler),
            Err(e) => {
                handler.close();
                Err(e)
            }
        }
    }

    /// Close all file resources. Mirrors `close()`, which swallows any `IOException` from the
    /// underlying close -- reproduced here by discarding the `Result` rather than propagating it.
    pub fn close(&mut self) {
        if let Some(ix) = self.open_file_ix {
            let _ = self.version_files[ix].close();
        }
    }

    /// Returns file ID associated with the original buffer file. Mirrors `getOriginalFileID()`.
    pub fn get_original_file_id(&self) -> u64 {
        self.original_file_id
    }

    /// Returns the list of free indexes associated with the original buffer file. Mirrors
    /// `getFreeIndexList()`.
    pub fn get_free_index_list(&self) -> &[i32] {
        &self.free_indexes
    }

    /// Ensure the version file at `vf_index` is the open one, closing whichever was previously
    /// open. Mirrors the private `getVersionFile(int)`.
    fn get_version_file(&mut self, vf_index: usize) -> io::Result<&mut VersionFile> {
        if self.open_file_ix != Some(vf_index) {
            if let Some(open_ix) = self.open_file_ix {
                self.version_files[open_ix].close()?;
            }
            self.open_file_ix = Some(vf_index);
            self.version_files[vf_index].open()?;
        }
        Ok(&mut self.version_files[self.open_file_ix.expect("just set above")])
    }

    /// Get original buffer associated with the specified storage index in the original file.
    /// Mirrors `getOldBuffer(DataBuffer, int)`. See the module docs for how the three-way return
    /// adapts Java's out-parameter/`null`/empty-flagged-buffer convention.
    pub fn get_old_buffer(&mut self, index: i32) -> io::Result<OldBufferResult> {
        match self.buffer_map.get(index) {
            Ok(vf_index) => {
                let vf = self.get_version_file(vf_index as usize)?;
                match vf.get_old_buffer(index)? {
                    Some(buf) => Ok(OldBufferResult::Modified(buf)),
                    // Invariant: `buffer_map` is only ever populated (see `new`) from a
                    // constituent version file's own `get_old_buffer_indexes()`, so that same
                    // version file's `get_old_buffer(index)` must always succeed here.
                    None => Err(io::Error::new(
                        io::ErrorKind::Other,
                        AssertException::with_message(
                            "buffer_map entry missing from its own version file's buffer map",
                        )
                        .to_string(),
                    )),
                }
            }
            Err(_) => {
                if self.free_indexes.binary_search(&index).is_ok() {
                    Ok(OldBufferResult::Free)
                }
                else {
                    Ok(OldBufferResult::Unmodified)
                }
            }
        }
    }

    /// Returns a bit map corresponding to all buffers modified since the original version (e.g.
    /// oldest). This identifies all buffers within the target version (e.g. latest) which must be
    /// reverted to rebuild the original version.
    ///
    /// NOTE: The bit mask may identify buffers which have been removed in the current version.
    /// Mirrors `getReverseModMapData()`.
    pub fn get_reverse_mod_map_data(&self) -> Vec<u8> {
        // Allocate map based upon number of buffers corresponding to latest version changes.
        let bit_map_size = ((self.max_buf_count + 7) / 8) as usize;
        let mut data = vec![0u8; bit_map_size];

        // Mark excess bits corresponding to maxBufCount and beyond as changed.
        let excess = self.max_buf_count % 8;
        if excess != 0 {
            data[bit_map_size - 1] |= 0xffu8 << excess;
        }
        for index in self.buffer_map.get_keys() {
            if index >= self.max_buf_count {
                eprintln!("VersionFileHandler: unexpected buffer index");
                continue;
            }
            set_map_data_bit(&mut data, index);
        }
        data
    }

    /// Returns a bit map corresponding to all buffers modified since the original version (e.g.
    /// oldest). This identifies all buffers contained within the original version (e.g. oldest)
    /// which have been modified during any revision up until the original version.
    ///
    /// NOTE: The bit mask may identify buffers which have been removed in the current version.
    /// Mirrors `getForwardModMapData()`.
    pub fn get_forward_mod_map_data(&self) -> Vec<u8> {
        let bit_map_size = ((self.original_buf_count + 7) / 8) as usize;
        let mut data = vec![0u8; bit_map_size];

        let excess = self.original_buf_count % 8;
        if excess != 0 {
            data[bit_map_size - 1] |= 0xffu8 << excess;
        }
        for index in self.buffer_map.get_keys() {
            if index < self.original_buf_count {
                set_map_data_bit(&mut data, index);
            }
        }
        data
    }

    /// Returns buffer count for original buffer file. Mirrors `getOriginalBufferCount()`.
    pub fn get_original_buffer_count(&self) -> i32 {
        self.original_buf_count
    }

    /// Returns a list of parameters defined within the original buffer file. Mirrors
    /// `getOldParameterNames()`.
    pub fn get_old_parameter_names(&self) -> Vec<String> {
        self.orig_parms.keys().cloned().collect()
    }

    /// Get a parameter value associated with the original buffer file. Mirrors
    /// `getOldParameter(String)`.
    ///
    /// Java's version throws the unchecked `NoSuchElementException` for a missing parameter; this
    /// port does no IO for a simple in-memory lookup, so it returns `Option<i32>` instead
    /// (`None` standing in for that exception) rather than an `io::Result`, unlike
    /// [`VersionFile::get_old_parameter`] (which does need `io::Result` since it consults a
    /// possibly-closed underlying file).
    pub fn get_old_parameter(&self, name: &str) -> Option<i32> {
        self.orig_parms.get(name).copied()
    }
}

fn set_map_data_bit(data: &mut [u8], index: i32) {
    let byte_offset = (index / 8) as usize;
    let bit_mask = 1u8 << (index % 8);
    data[byte_offset] |= bit_mask;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::Buffer;
    use crate::framework::db::buffers::LocalBufferFile;
    use std::cell::RefCell;
    use std::path::PathBuf;

    /// A `BufferFileManager` backed by a fixed map of version -> version-file path, enough to
    /// drive [`VersionFileHandler::new`] in tests without a real database directory structure.
    struct MockBufferFileManager {
        version_files: RefCell<HashMap<i32, PathBuf>>,
    }

    impl MockBufferFileManager {
        fn new() -> Self {
            Self { version_files: RefCell::new(HashMap::new()) }
        }

        fn register(&self, version: i32, path: PathBuf) {
            self.version_files.borrow_mut().insert(version, path);
        }
    }

    impl BufferFileManager for MockBufferFileManager {
        fn get_current_version(&self) -> i32 {
            0
        }
        fn get_buffer_file(&self, version: i32) -> PathBuf {
            PathBuf::from(format!("/db/buffer.{version}"))
        }
        fn get_version_file(&self, version: i32) -> Option<PathBuf> {
            self.version_files.borrow().get(&version).cloned()
        }
        fn get_change_data_file(&self, _version: i32) -> Option<PathBuf> {
            None
        }
        fn get_change_map_file(&self) -> Option<PathBuf> {
            None
        }
        fn version_created(&mut self, _version: i32, _comment: &str, _checkin_id: i64) -> io::Result<()> {
            Ok(())
        }
        fn update_ended(&mut self, _checkin_id: i64) {}
    }

    const BUF_SIZE: usize = 256;

    fn buf_with_byte(id: i32, byte: u8) -> DataBuffer {
        let mut b = DataBuffer::new(id, BUF_SIZE);
        b.get_data_mut()[0] = byte;
        b
    }

    /// Builds a three-version chain (v0 -> v1 -> v2) of `LocalBufferFile`s plus the two
    /// `VersionFile`s bridging them, registered with a `MockBufferFileManager`, mirroring how
    /// real check-in/check-out history is laid out on disk. Buffer 0 changes between v0 and v1;
    /// buffer 1 changes between v1 and v2; buffer 2 is marked free in v0 and never touched again.
    /// Returns `(manager, bf0_file_id, bf2_file_id)`.
    fn build_three_version_chain(dir: &std::path::Path) -> (MockBufferFileManager, u64, u64) {
        let mut bf0 = LocalBufferFile::create(dir.join("v0.bf"), BUF_SIZE).unwrap();
        for i in 0..4 {
            bf0.put(&buf_with_byte(i, 0xA0 + i as u8), i).unwrap();
        }
        bf0.set_free_indexes(&[2]).unwrap();
        bf0.set_parameter("ORIGPARM", 777);

        let mut bf1 = LocalBufferFile::create(dir.join("v1.bf"), BUF_SIZE).unwrap();
        for i in 0..4 {
            bf1.put(&buf_with_byte(i, 0xB0 + i as u8), i).unwrap();
        }
        bf1.set_free_indexes(&[2]).unwrap();

        let mut bf2 = LocalBufferFile::create(dir.join("v2.bf"), BUF_SIZE).unwrap();
        for i in 0..4 {
            bf2.put(&buf_with_byte(i, 0xC0 + i as u8), i).unwrap();
        }
        bf2.set_free_indexes(&[2]).unwrap();

        let bf0_id = bf0.get_file_id();
        let bf2_id = bf2.get_file_id();

        // VF(0): bridges v0 -> v1. Buffer 0 is the only one that changed.
        let mut vf0 = VersionFile::create(&bf0, &bf1, dir.join("vf0.vf")).unwrap();
        vf0.put_old_buffer(&buf_with_byte(0, 0xA0), 0).unwrap();
        vf0.close().unwrap();

        // VF(1): bridges v1 -> v2. Buffer 1 is the only one that changed.
        let mut vf1 = VersionFile::create(&bf1, &bf2, dir.join("vf1.vf")).unwrap();
        vf1.put_old_buffer(&buf_with_byte(1, 0xB1), 1).unwrap();
        vf1.close().unwrap();

        let mgr = MockBufferFileManager::new();
        mgr.register(0, dir.join("vf0.vf"));
        mgr.register(1, dir.join("vf1.vf"));

        (mgr, bf0_id, bf2_id)
    }

    #[test]
    fn new_builds_handler_and_collects_original_version_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, bf0_id, bf2_id) = build_three_version_chain(dir.path());

        let handler = VersionFileHandler::new(&mgr, bf2_id, 2, 0).unwrap();

        assert_eq!(handler.get_original_file_id(), bf0_id);
        assert_eq!(handler.get_original_buffer_count(), 4);
        assert_eq!(handler.get_free_index_list(), &[2]);
        assert_eq!(handler.get_old_parameter("ORIGPARM"), Some(777));
        assert_eq!(handler.get_old_parameter("NOPE"), None);
        assert_eq!(handler.get_old_parameter_names(), vec!["ORIGPARM".to_string()]);
    }

    #[test]
    fn get_old_buffer_resolves_across_the_version_file_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _bf0_id, bf2_id) = build_three_version_chain(dir.path());
        let mut handler = VersionFileHandler::new(&mgr, bf2_id, 2, 0).unwrap();

        // Buffer 0's old data lives in VF(0) (the first, closed-after-open file).
        match handler.get_old_buffer(0).unwrap() {
            OldBufferResult::Modified(buf) => assert_eq!(buf.get_data()[0], 0xA0),
            other => panic!("expected Modified, got {other:?}"),
        }

        // Buffer 1's old data lives in VF(1) -- fetching it forces the handler to close VF(0)
        // and reopen VF(1), exercising the "only one file open at a time" behavior.
        match handler.get_old_buffer(1).unwrap() {
            OldBufferResult::Modified(buf) => assert_eq!(buf.get_data()[0], 0xB1),
            other => panic!("expected Modified, got {other:?}"),
        }

        // Re-fetching buffer 0 must still work after the handler swapped which file is open.
        match handler.get_old_buffer(0).unwrap() {
            OldBufferResult::Modified(buf) => assert_eq!(buf.get_data()[0], 0xA0),
            other => panic!("expected Modified, got {other:?}"),
        }
    }

    #[test]
    fn get_old_buffer_reports_free_index_from_original_version() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _bf0_id, bf2_id) = build_three_version_chain(dir.path());
        let mut handler = VersionFileHandler::new(&mgr, bf2_id, 2, 0).unwrap();

        assert!(matches!(handler.get_old_buffer(2).unwrap(), OldBufferResult::Free));
    }

    #[test]
    fn get_old_buffer_reports_unmodified_for_untouched_index() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _bf0_id, bf2_id) = build_three_version_chain(dir.path());
        let mut handler = VersionFileHandler::new(&mgr, bf2_id, 2, 0).unwrap();

        // Buffer 3 was never freed nor recorded as changed in any version file in the chain.
        assert!(matches!(handler.get_old_buffer(3).unwrap(), OldBufferResult::Unmodified));
    }

    #[test]
    fn new_rejects_chain_with_wrong_target_file_id() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _bf0_id, _bf2_id) = build_three_version_chain(dir.path());

        // A target file ID that doesn't match the chain's actual final target.
        let bogus_target_id: u64 = 0xDEAD_BEEF;
        let err = VersionFileHandler::new(&mgr, bogus_target_id, 2, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn new_reports_missing_version_file() {
        let mgr = MockBufferFileManager::new();
        // No version files registered at all.
        let err = VersionFileHandler::new(&mgr, 42, 1, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn get_reverse_and_forward_mod_map_data_mark_changed_buffers() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _bf0_id, bf2_id) = build_three_version_chain(dir.path());
        let handler = VersionFileHandler::new(&mgr, bf2_id, 2, 0).unwrap();

        // bufferMap has entries for indexes 0 and 1 (both < originalBufCount == 4 == maxBufCount
        // here), so both bit maps should have bits 0 and 1 set from that loop. Separately, per
        // Java's own comment ("Mark excess bits corresponding to maxBufCount and beyond as
        // changed"), getReverseModMapData/getForwardModMapData *also* unconditionally set every
        // bit at position `count % 8` and above in the map's last byte -- here `4 % 8 == 4`, so
        // bits 4-7 are deliberately set to 1 too (0xF0), not left at 0. This is real,
        // Java-verified behavior (VersionFileHandler.java:191-194/219-222), not a bug in the
        // port -- an earlier version of this test wrongly asserted those bits should be clear.
        let reverse = handler.get_reverse_mod_map_data();
        let forward = handler.get_forward_mod_map_data();

        assert_eq!(reverse[0] & 0b0000_0011, 0b0000_0011);
        assert_eq!(reverse[0] & 0b1111_0000, 0b1111_0000, "excess bits (>= maxBufCount) are marked changed, matching Java");
        assert_eq!(forward[0] & 0b0000_0011, 0b0000_0011);
        assert_eq!(forward[0] & 0b1111_0000, 0b1111_0000, "excess bits (>= originalBufCount) are marked changed, matching Java");
    }

    #[test]
    fn close_is_idempotent_and_swallows_errors() {
        let dir = tempfile::tempdir().unwrap();
        let (mgr, _bf0_id, bf2_id) = build_three_version_chain(dir.path());
        let mut handler = VersionFileHandler::new(&mgr, bf2_id, 2, 0).unwrap();

        handler.close();
        // A second close() is a no-op / does not panic, mirroring Java's tolerant close().
        handler.close();
    }
}
