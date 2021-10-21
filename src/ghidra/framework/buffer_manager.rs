use std::collections::HashSet;
use std::default::default;
use std::sync::RwLock;
use std::thread::Thread;
use crate::ghidra::framework::buffer_file::BufferFile;
use crate::ghidra::framework::data_buffer::DataBuffer;

pub const BUFFER_MANAGER_ALWAYS_PRECACHE_PROPERTY: String = "db.always.precache".to_string();
pub const BUFFER_MANAGER_ALWAYS_PRECACHE: bool = false;
pub const BUFFER_MANAGER_DEFAULT_BUFFER_SIZE: isize = 16 * 1024;
pub const BUFFER_MANAGER_DEFAULT_CHECKPOINT_CACHE: isize = 10;
pub const BUFFER_MANAGER_CACHE_SIZE: isize = 4 * 1024 * 1024;
pub const BUFFER_MANAGER_MINIMUM_CACHE_SIZE: isize = 64 * 1024;
pub const BUFFER_MANAGER_CACHE_FILE_PREFIX: String = "ghidra".to_string();
pub const BUFFER_MANAGER_CACHE_FILE_EXT: String = ".cache".to_string();
pub const BUFFER_MANAGER_HEAD: isize = -1;
pub const BUFFER_MANAGER_TAIL: isize = -2;
pub const BUFFER_MANAGER_INITIAL_BUFFER_SIZE: isize = 1024;

pub enum PreCacheStatus {
    Init,
    Running,
    Interrupted,
    Stopped,
}

#[derive(Clone,Debug,Default)]
pub struct BufferManager {
    pub open_instances: HashSet<BufferManager>,
    pub max_checkpoints: isize,
    pub max_cache_size: isize,
    pub current_checkpoint: i32,
    pub corrupted_state: bool,
    pub source_file: dyn BufferFile,
    pub cache_file: LocalBufferFile,
    pub recovery_manager: RecoveryManager,
    pub snapshot_lock: bool,
    pub modified_since_snapshot: bool,
    pub has_non_undoable_changes: bool,
    pub buffer_size: isize,
    pub cache_head: BufferNode,
    pub cache_tail: BufferNode,
    pub cache_size: isize,
    pub buffers_on_hande: isize,
    pub lock_count: i32,
    pub free_buffers: Vec<DataBuffer>,
    pub cache_hists: i64,
    pub cache_misses: i64,
    pub low_water_mark: i64,
    pub check_point_heads: Vec<BufferNode>,
    pub redo_checkpoint_heads: Option<Vec<BufferNode>>,
    pub current_checkpoint_head: BufferNode,
    pub baseline_checkpoint_head: BufferNode,
    pub index_provider: IndexProvider,
    pub cache_index_privder: IndexProvider,
    pub buffer_table: Vec<DataBuffer>,
    pub pre_cache_status: PreCacheStatus,
    pub pre_cache_thread: Thread,
    pub pre_cache_lock: bool,
}

impl BufferManager {
    fn new() -> BufferManager {
        BufferManager::default()
    }

    fn new2(requested_buffer_size: isize, approx_cache_size: isize, max_undos: isize) -> BufferManager {
        let mut mgr: BufferManager = BufferManager::default();
        mgr.buffer_size = requested_buffer_size;
        mgr.cache_size = approx_cache_size;
        mgr.max_checkpoints = max_undos;
        mgr
    }

    fn from_source_file(source_file: &dyn BufferFile) -> BufferManager {
        BufferManager {
            source_file: source_file.clone(),
            buffer_size: BUFFER_MANAGER_DEFAULT_BUFFER_SIZE,
            cache_size: BUFFER_MANAGER_CACHE_SIZE,
            max_checkpoints: BUFFER_MANAGER_DEFAULT_CHECKPOINT_CACHE,
            ..default()
        }
    }

    fn from_source_file_2(source_file: &BufferFile, approx_cache_size: isize, max_undos: isize) -> BufferManager {
        BufferManager {
            source_file: source_file.clone(),
            cache_size: approx_cache_size,
            max_checkpoints: max_undos,
            buffer_size: BUFFER_MANAGER_DEFAULT_CHECKPOINT_CACHE,
            ..default()
        }
    }

    fn from_source_file_3(source_file: &dyn BufferFile, requested_buffer_size: isize, approx_cache_size: isize, max_undos: isize) -> BufferManager {
        let buf_size = requested_buffer_size;
        let count = source_file.get_index_count();
        let index_provider = IndexProvider::new(count, source_file.get_free_indexes());
        let mut max_check_points = max_undos + 1;
        if max_undos < 1 {
            max_check_points = DEFAULT_CHECKPOINT_COUNT;
        }
        let mut approx_cache_size2 = approx_cache_size;
        if approx_cache_size < MINIMUM_CACHE_SIZE {
            approx_cache_size2 = MINIMUM_CACHE_SIZE;
        }

        let mut cache_head = BufferNode::new(HEAD, -1);
        let mut cache_tail = BufferNode::new(TAIL, -1);
        cache_head.next_cached = cache_tail;
        cache_tail.prev_cached = cache_head;
        let mut cache_file = LocalBufferFile::new(buf_size, CACHE_FILE_PREFIX, CACHE_FILE_EXT);
        let mut cache_index_provider = IndexProvider::new();
        start_checkpoint();
        let mut baseline_checkpoint_head = current_checkpoint_head;
        current_checkpoint_head = None;

        let parm_names: Vec<String> = source_file.get_parameter_names();
        for i in 0 .. parm_names.len() {
            let name: String = parm_names[i].clone();
            cache_file.set_parameter(name, source_file.get_parameter(&name));
        }

        let mut buf_mgr = BufferManager {
            source_file: source_file.clone(),
            buffer_size: requested_buffer_size,
            cache_size: approx_cache_size,
            max_checkpoints: max_undos,
            ..default()
        };

        add_instance(&buf_mgr);

        if always_pre_cache {
            start_pre_cache_if_needed()
        }

        buf_mgr
    }

    pub fn enable_pre_cache(&self) {
        // TODO: add synch block
        if self.pre_cache_status == PreCacheStatus.INIT {
            start_pre_cache_if_needed();
        }
    }

    pub fn add_instance(&mut self, buf_mgr: &BufferManager) {
        if self.open_instances.is_empty() {
            self.open_instances.clear();
            // TODO: launch as a runnable
            for inst in self.open_instances.iter() {
                inst.dispose();
            }
            shutdown_hook_registry.add_shutdown_hook(cleanup_task, ShutdownPriority.DISPOSE_FILE_HANDLES);
        }
        self.open_instances.insert(buf_mgr.clone());
    }

    pub fn set_corrupted_state(&mut self) {
        self.corrupted_state = true;
    }

    pub fn is_corrupted(&self) -> bool {
        self.corrupted_state
    }

    pub fn remove_instance(&mut self, buf_mgr: &BufferManager) {
        self.open_instances.remove(buf_mgr);
    }

    pub fn get_lock_count(&self) -> {
        self.lock_count
    }

    pub fn get_buffer_size(&self) -> {
        self.buffer_size
    }

    pub fn get_source_file(&self) -> BufferManager {
        self.source_file.clone()
    }

    pub fn get_parameter(&self, name: &String) -> isize {
        self.cache_file.get_parameter(name)
    }

    pub fn set_parameter(&mut self, name: &String, value: &isize) {
        self.cache_file.set_parameter(name, value);
    }

    pub fn dispose(&mut self) {
        self.dispose2(false);
    }

    pub fn dispose2(&mut self, keep_recovery_data: bool) {
        // todo: sync block
        // synchronized (snapshotLock) {
        //
        // 			stopPreCache();
        self.stop_pre_cache();
        //
        // 			synchronized (this) {
        //
        // 				if (recoveryMgr != null) {
        if self.recovery_manager != None {
            // 					if (!keepRecoveryData) {
            // 						recoveryMgr.dispose();
            // 					}
            if !keep_recovery_data {
                self.recovery_manager.dispose();
            }
            // 					recoveryMgr = null;
            self.recovery_manager = None;
            // 				}
        }
            // 				if (sourceFile != null) {
            // 					sourceFile.dispose();
            // 					sourceFile = null;
            // 				}
        if self.source_file.is_some() {
            self.source_file.dispose();
            self.source_file = None;
        }
            // 				if (cacheFile != null) {
            // 					cacheFile.delete();
            // 					cacheFile = null;
            // 				}
        if self.cache_file.is_some() {
            self.cache_file.delete();
            self.cache_file = None;
        }
            //
            // 				// Dispose all buffer nodes - speeds up garbage collection
            // 				if (checkpointHeads != null) {
            // 					Iterator<BufferNode> iter = checkpointHeads.iterator();
            // 					while (iter.hasNext()) {
            // 						BufferNode node = iter.next();
            // 						while (node != null) {
            // 							BufferNode next = node.nextInCheckpoint;
            // 							node.buffer = null;
            // 							node.nextCached = null;
            // 							node.prevCached = null;
            // 							node.nextInCheckpoint = null;
            // 							node.prevInCheckpoint = null;
            // 							node.nextVersion = null;
            // 							node.prevVersion = null;
            // 							node = next;
            // 						}
            // 					}
            // 					checkpointHeads = null;
            // 				}
        if !self.check_point_heads.is_empty() {
            for cph in self.check_point_heads {

            }
        }
            // 				if (redoCheckpointHeads != null) {
            // 					Iterator<BufferNode> iter = redoCheckpointHeads.iterator();
            // 					while (iter.hasNext()) {
            // 						BufferNode node = iter.next();
            // 						while (node != null) {
            // 							BufferNode next = node.nextInCheckpoint;
            // 							node.buffer = null;
            // 							node.nextCached = null;
            // 							node.prevCached = null;
            // 							node.nextInCheckpoint = null;
            // 							node.prevInCheckpoint = null;
            // 							node.nextVersion = null;
            // 							node.prevVersion = null;
            // 							node = next;
            // 						}
            // 					}
            // 					redoCheckpointHeads = null;
            // 				}
            // 				bufferTable = null;
            // 				currentCheckpointHead = null;
            // 				baselineCheckpointHead = null;
            // 				hasNonUndoableChanges = false;
            //
            // 				removeInstance(this);
            // 			}
            // 		}
    } // end of dispose2
} // end of impl BufferManager
