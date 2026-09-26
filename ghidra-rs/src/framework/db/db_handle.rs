use super::buffer::Buffer;
use super::buffer_mgr::BufferMgr;
use super::buffers::{BufferFile, LocalBufferFile};
use super::chained_buffer::ChainedBuffer;
use super::db_buffer::DBBuffer;
use super::db_buffer_impl::DBBufferImpl;
use super::db_parms::DBParms;
use super::master_table::MasterTable;
use super::schema::Schema;
use super::table::Table;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};
use thiserror::Error;

/// Error type returned by [`DBHandle::save_as`], combining the checked exceptions declared on
/// `DBHandle.saveAs(File, boolean, TaskMonitor)` (`IOException`, `CancelledException`).
#[derive(Error, Debug)]
pub enum SaveAsError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Cancelled(#[from] CancelledException),
}

pub struct DBHandle {
    pub buffer_mgr: Arc<RwLock<BufferMgr>>,
    db_parms: DBParms,
    master_table: MasterTable,
}

impl DBHandle {
    pub fn new() -> io::Result<Self> {
        let mut buffer_mgr = BufferMgr::new(BufferMgr::DEFAULT_BUFFER_SIZE);
        let mut db_parms = DBParms::new(&mut buffer_mgr, true)?;
        db_parms.set(
            &mut buffer_mgr,
            DBParms::MASTER_TABLE_ROOT_BUFFER_ID_PARM,
            -1,
        )?;

        let buffer_mgr = Arc::new(RwLock::new(buffer_mgr));
        Ok(Self {
            master_table: MasterTable::new(buffer_mgr.clone()),
            buffer_mgr,
            db_parms,
        })
    }

    pub fn get_buffer_mgr(&self) -> Arc<RwLock<BufferMgr>> {
        self.buffer_mgr.clone()
    }

    pub fn get_db_parms(&self) -> &DBParms {
        &self.db_parms
    }

    pub fn create_table(
        &mut self,
        name: String,
        schema: Arc<Schema>,
    ) -> io::Result<Arc<RwLock<Table>>> {
        let bm = self.buffer_mgr.clone();
        self.master_table
            .create_table(name, schema, bm)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AlreadyExists, "Table already exists"))
    }

    pub fn get_table(&self, name: &str) -> Option<Arc<RwLock<Table>>> {
        self.master_table.get_table(name)
    }

    pub fn delete_table(&mut self, name: &str) -> bool {
        self.master_table.delete_table(name)
    }

    /// Creates a new [`DBBuffer`] of the given length (zero-initialized), backed by a real
    /// [`ChainedBuffer`] over this handle's [`BufferMgr`]. Mirrors `DBHandle.createBuffer(int)`.
    pub fn create_buffer(&mut self, length: usize) -> io::Result<Box<dyn DBBuffer>> {
        let chained = ChainedBuffer::new(length, false, None, 0, self.buffer_mgr.clone())?;
        Ok(Box::new(DBBufferImpl::new(chained)))
    }

    /// Returns the [`DBBuffer`] previously created with the given first-buffer id. Mirrors
    /// `DBHandle.getBuffer(int)`.
    pub fn get_buffer(&self, buffer_id: i32) -> io::Result<Box<dyn DBBuffer>> {
        let chained = ChainedBuffer::from_existing(self.buffer_mgr.clone(), buffer_id, None, 0)?;
        Ok(Box::new(DBBufferImpl::new(chained)))
    }

    /// Write the current contents of this handle's buffers out to a new [`LocalBufferFile`] at
    /// `path`.
    ///
    /// This is a minimal, `RecoveryMgr`-driven port of `DBHandle.saveAs(File, boolean,
    /// TaskMonitor)`: `crate::framework::db::buffer_mgr::BufferMgr` is an in-memory-only,
    /// reduced stand-in for Java's real (disk-backed, checkpointed) `db.buffers.BufferMgr` --
    /// see `super::buffers::recovery_mgr`'s module doc for the full context -- so this method
    /// only implements the one thing `RecoveryMgr::start_snapshot`'s change-set-persistence path
    /// actually needs: copying every currently-allocated buffer verbatim into a freshly created
    /// buffer file. It deliberately does not implement the full `saveAs` contract (buffer
    /// compaction, checkpoint/version history, re-pointing this handle's own storage at the new
    /// file when `associate_with_new_file` is set, etc.); `associate_with_new_file` is accepted
    /// for signature fidelity but otherwise unused.
    pub fn save_as(
        &self,
        path: &Path,
        _associate_with_new_file: bool,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), SaveAsError> {
        monitor.check_cancelled()?;
        let bm = self.buffer_mgr.read().unwrap();
        let mut out = LocalBufferFile::create(path.to_path_buf(), bm.get_buffer_size())?;
        for id in 0..bm.buffer_count() as i32 {
            monitor.check_cancelled()?;
            if let Ok(buf_arc) = bm.get_buffer(id) {
                let buf = buf_arc.read().unwrap();
                out.put(&buf, id)?;
            }
        }
        out.close()?;
        Ok(())
    }
}

#[cfg(test)]
mod save_as_tests {
    use super::*;

    #[test]
    fn save_as_copies_all_allocated_buffers_to_a_fresh_file() {
        let dbh = DBHandle::new().unwrap();
        // DBHandle::new() already allocates buffer 0 for DBParms.
        {
            let bm = dbh.buffer_mgr.write().unwrap();
            assert_eq!(bm.buffer_count(), 1);
        }

        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("saved.db");
        let monitor = crate::util::task::DummyMonitor;
        dbh.save_as(&out_path, true, &monitor).unwrap();

        assert!(out_path.exists());
        let mut reopened = LocalBufferFile::open(out_path, true).unwrap();
        assert_eq!(reopened.get_index_count(), 1);
        // Buffer 0 (DBParms) starts with its CHAINED_BUFFER_DATA_NODE marker byte.
        let buf0 = reopened.get(0).unwrap();
        assert_eq!(buf0.get_byte(0), 9);
        reopened.close().unwrap();
    }

    #[test]
    fn save_as_reports_cancellation() {
        struct AlwaysCancelled;
        impl TaskMonitor for AlwaysCancelled {
            fn is_cancelled(&self) -> bool {
                true
            }
            fn set_show_progress_value(&self, _show: bool) {}
            fn set_message(&self, _message: &str) {}
            fn get_message(&self) -> String {
                String::new()
            }
            fn set_progress(&self, _value: i64) {}
            fn initialize(&self, _max: i64) {}
            fn set_maximum(&self, _max: i64) {}
            fn get_maximum(&self) -> i64 {
                0
            }
            fn set_indeterminate(&self, _indeterminate: bool) {}
            fn is_indeterminate(&self) -> bool {
                false
            }
            fn check_cancelled(&self) -> Result<(), CancelledException> {
                Err(CancelledException::default())
            }
            fn increment_progress(&self, _amount: i64) {}
            fn get_progress(&self) -> i64 {
                0
            }
            fn cancel(&self) {}
            fn add_cancelled_listener(&self, _listener: Box<dyn crate::util::task::CancelledListener>) {}
            fn remove_cancelled_listener(&self, _listener: &dyn crate::util::task::CancelledListener) {}
            fn set_cancel_enabled(&self, _enabled: bool) {}
            fn is_cancel_enabled(&self) -> bool {
                true
            }
            fn clear_cancelled(&self) {}
        }

        let dbh = DBHandle::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("saved.db");
        let err = dbh.save_as(&out_path, true, &AlwaysCancelled).unwrap_err();
        assert!(matches!(err, SaveAsError::Cancelled(_)));
    }
}
