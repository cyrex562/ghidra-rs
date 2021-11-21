/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// package db.buffers;
//
// import ghidra.util.exception.AssertException;
// import ghidra.util.exception.CancelledException;
//
// import java.io.File;
// import java.io.IOException;
// import java.util.NoSuchElementException;
//
// import db.ChainedBuffer;

use std::fs::File;
use crate::ghidra::framework::buffer::buffer_manager::BufferManager;
use crate::ghidra_error::GhidraError;

pub const MAGIC_NUMBER: i32 = 0x73D9A3BC;
pub const CACHE_SIZE: isize = 64*1024;

pub const MODMAP_PARM_PREFIX: String = "~MF.".to_string();
pub const MAGIC_NUMBER_PARM: String = MODMAP_PARM_PREFIX.as_str() + "ModMapFile".to_string();
pub const BUFFER_ID_PARM: String = MODMAP_PARM_PREFIX.as_str() + "BufferId".to_string();
pub const TARGET_FILE_ID_HI_PARM: String = MODMAP_PARM_PREFIX.as_str() + "TargetIdHi".to_string();
pub const TARGET_FILE_ID_LOW_PARM: String = MODMAP_PARM_PREFIX.as_str() + "TargetIdLow".to_string();
pub const INDEX_CNT_PARM: String = MODMAP_PARM_PREFIX.as_str() + "IndexCnt".to_string();
pub const INITIAL_VERSION_PARM: String = MODMAP_PARM_PREFIX.as_str() + "InitialVersion".to_string();

/**
 * <code>ChangeMapFile</code> tracks which buffers within a LocalBufferFile 
 * have been modified between an older and newer version.  The older
 * file is also referred to as the target file.
 */
#[derive(Clone,Debug)]
pub struct ChangeMapFile {
    pub file: File,
    pub buf_mgr: Option<BufferManager>,
    pub buffer: ChainedBuffer,
    pub index_count: isize,
    pub read_only: bool,
}

impl ChangeMapFile {
	/**
	 * Construct a map file for output.  If the file exists it will be updated,
	 * otherwise a new file will be created.
	 * @param file map file
	 * @param targetFile associated target buffer file
	 * @param create if true a new map file will be created
	 * @throws IOException if file already exists or an IO error occurs
	 */
	pub fn new(&mut self, file: &mut File, old_file: &LocalManagedBufferFile, new_file: &LocalManagedBufferFile) -> Result<ChangeMapFile, GhidraError> {

		self.file = file.try_clone()?;
		self.readOnly = false;
		let mut map_file: LocalBufferFile;
		let mut success: bool = false;
		// try {
			if !file.exists() {
				self.index_count = old_file.get_index_count();
				self.buf_mgr = Some(BufferManager::new2(
                    DEFAULT_BUFFER_SIZE,
                    CACHE_SIZE,
                    1));

                self.buf_mgr.map(|mut s| {s.set_parameter(&MAGIC_NUMBER_PARM, (&MAGIC_NUMBER) as &isize); s});
				let ver = old_file.get_version();
				self.buf_mgr.map(|mut s| {s.set_parameter(&INITIAL_VERSION_PARM, ver); s});
                self.buf_mgr.map(|mut s| {s.set_parameter(&INDEX_CNT_PARM, &self.index_count); s});
				// Create chained buffer
				let mut size: isize = ((self.index_count - 1) / 8) + 1;
				let mut buffer = ChainedBuffer::new(size, &self.buf_mgr);
				self.buf_mgr.set_parameter(&BUFFER_ID_PARM, buffer.get_id());
				
				// Mark all spare bits as changed
				let mut last_byte_offset: isize = (indexCnt-1) / 8;
				let mut last_byte: isize = 0;
				let mut index: isize = self.index_count;
				let mut bit: i32;
                let mut bit = index % 8;
				while (bit) != 0 {
					let mut bit_mask = 1 << bit;
					last_byte = (last_byte | bit_mask);
					index += 1;
                    bit = index % 8;
				}
				buffer.put_byte(last_byte_offset, last_byte);
								
			}
			else {

				map_file = LocalBufferFile::new(file, true);
				if map_file.getParameter(MAGIC_NUMBER_PARM) != MAGIC_NUMBER {
					// TODO: throw new IOException("Bad modification map file: " + file);
				}
				
				let mut old_target_file_id: i64 = map_file.get_parameter(TARGET_FILE_ID_HI_PARM) << 32 | (map_file.get_parameter(TARGET_FILE_ID_LOW_PARM) & 0xffffffff);
				if old_target_file_id != old_file.getFileId() {
					// TODO: throw new IOException("Modification map file does not correspond to target: " + file);
				}
				
				self.buf_mgr = BufferManager::new2(map_file, CACHE_SIZE, 1);
				
				self.index_count = self.buf_mgr.get_parameter(&INDEX_CNT_PARM);
				if new_file.get_index_count() < self.index_count {
					// TODO: throw new AssertException();
				}

				let mut id: isize = self.buf_mgr.get_parameter(&BUFFER_ID_PARM);
				let mut buffer = ChainedBuffer::new(&self.buf_mgr, id);
			}
			
			let target_file_id: i64 = new_file.getFileId();
			self.buf_mgr.set_parameter(&TARGET_FILE_ID_HI_PARM, (int)(target_file_id >> 32));
			self.buf_mgr.set_parameter(&TARGET_FILE_ID_LOW_PARM, (int)(target_file_id & 0xffffffff));

        success = true;
		// }
		// catch (NoSuchElementException e) {
		// 	throw new IOException("Required modification map paramater (" + e.getMessage() + ") not found: " + file);
		// }
		// finally {
			if !success {
                self.buf_mgr.dispose();
                self.map_file.dispose();
                return Err(GhidraError{code: 0, message: "general failure".to_string() });
			}
        Ok(self.clone())
		// }

	}
	
	/**
	 * Construct map file for reading.  
	 * @param file existing map file
	 * @throws IOException if an IO error occurs
	 */
	pub fn new2(file: &File, target_file: &LocalBufferFile ) -> Result<ChangeMapFile, GhidraError> {
        let mut map_file = LocalBufferFile::new(file, true);
        let mut x = ChangeMapFile {
            file: file.try_clone()?,
            buf_mgr: BufferManager::new(),
            buffer: ChainedBuffer::new(),
            index_count: 0,
            read_only: true
        };

        if map_file.get_parameter(&MAGIC_NUMBER_PARM) != MAGIC_NUMBER {
            return Err(GhidraError{code: 0, message: "invlaid parmeter value for map file".to_string()});
        }

        let mut old_target_file_id = (map_file.get_parameter(&TARGET_FILE_ID_HI_PARM) << 32) | (map_file.get_parameter(&TARGET_FILE_ID_LOW_PARM) & 0xffffffff);
        if old_target_file_id != target_file.get_file_id() {
            return Err(GhidraError{code: 0, message: fmt!("modification map file does not correspond to target: {:?}", file)});
        }

        x.buf_mgr = BufferManager::new2(map_file, CACHE_SIZE, 1);
        x.index_count = x.buf_mgr.get_parameter(&INDEX_CNT_PARM);
        if target_file.get_index_count() < x.index_count {
            return Err(GhidraError::new(0, "invalid index count"));
        }

        let id = x.buf_mgr.get_parameter(&BUFFER_ID_PARM);
        x.buffer = ChainedBuffer::new(&x.buf_mgr, id);


        if !success {
            x.buf_mgr.dispose();
            map_file.dispose();
        }

        Ok(x)
	}

	/**
	 * Returns true if this change map corresponds to the specified target file.
	 * @param targetFile
	 */
	pub fn is_valid_for(&self, target_file: &LocalBufferFile) -> bool {
		let target_file_id = (self.buf_mgr.get_parameter(&TARGET_FILE_ID_HI_PARM) << 32) |
			(self.buf_mgr.get_parameter(&TARGET_FILE_ID_LOW_PARM) & 0xffffffff);
		return target_file_id == target_file.get_file_id();
	}

	/**
	 * Abort the creation/update of this file.
	 * This method should be invoked in place of close on a failure condition.
	 * An attempt is made to restore the version file to its initial state
	 * or remove it if it was new.
	 */
	pub fn abort(&mut self) {
        self.buf_mgr.dispose();
	}
	
	/**
	 * Close the file.
	 */
	pub fn close(&mut self) -> Result<(), GhidraError> {
		let mut map_file: LocalBufferFile;
		let mut success = false;
		// try {
			if !self.read_only {
				// let tmp_file: File = new File(file.getParentFile(), file.getName() + LocalBufferFile.TEMP_FILE_EXT);
				let tmp_file: File = File::create(&self.file + TEMP_FILE_EXT)?;
                map_file = LocalBufferFile::new(&tmp_file, self.buf_mgr.get_buffer_size());
				self.buf_mgr.save_as(map_file, true, None);
				self.buf_mgr.dispose();
				self.buf_mgr = None;
				file.delete();
				if (!tmpFile.renameTo(file)) {
					// throw new IOException("Failed to update file: " + file);

				}
			}
			else {
				self.buf_mgr.dispose();
				// self.buf_mgr = null;
			}
			success = true;
		// } catch (CancelledException e) {
		// }
		// finally {
			if !success {
                map_file.delete();
                self.buf_mgr.dispose();
			}
		// }
	}

	/**
	 * Mark buffer as changed
	 * @param id
	 * @throws IOException
	 */
	void bufferChanged(int index, boolean empty) throws IOException {
		if (index >= indexCnt) {
			return; // no need to track new buffers
		}
		int byte_offset = index / 8;
		byte b;
		if (empty) {
			// Clear bit if buffer is removed
			int bit_mask = ~(1 << (index % 8));
			b = (byte)(buffer.getByte(byte_offset) & bit_mask);
		}
		else {
			// Set bit if buffer is set
			int bit_mask = 1 << (index % 8);
			b = (byte)(buffer.getByte(byte_offset) | bit_mask);
		}
		buffer.putByte(byte_offset, b);
	}

	/**
	 * Returns data suitable for use by the ChangeMap class.
	 * @throws IOException
	 * @see ChangeMap
	 */
	byte[] getModData() throws IOException {
		return buffer.get(0, buffer.length());
	}
	
}
