use super::BufferFile;
use crate::framework::db::buffer::{Buffer, DataBuffer};
use rand::Rng;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

pub struct LocalBufferFile {
    file: File,
    path: PathBuf,
    read_only: bool,
    block_size: usize,
    buffer_size: usize,
    file_id: u64,
    free_index: i32,
    parameters: HashMap<String, i32>,
    index_count: usize,
}

impl LocalBufferFile {
    const MAGIC_NUMBER: u64 = 0x2f30312c34292c2a;
    const HEADER_FORMAT_VERSION: i32 = 1;
    const BUFFER_PREFIX_SIZE: usize = 5;
    const EMPTY_BUFFER: u8 = 0x01;

    pub fn create(path: PathBuf, buffer_size: usize) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;

        let mut rng = rand::thread_rng();
        let mut lbf = Self {
            file,
            path,
            read_only: false,
            block_size: buffer_size + Self::BUFFER_PREFIX_SIZE,
            buffer_size,
            file_id: rng.gen(),
            free_index: -1,
            parameters: HashMap::new(),
            index_count: 0,
        };

        lbf.write_header()?;
        Ok(lbf)
    }

    pub fn open(path: PathBuf, read_only: bool) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&path)?;

        let mut header = vec![0u8; 32]; // Fixed part of header
        file.read_exact(&mut header)?;

        let magic = u64::from_be_bytes(header[0..8].try_into().unwrap());
        if magic != Self::MAGIC_NUMBER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid magic number",
            ));
        }

        let file_id = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let version = i32::from_be_bytes(header[16..20].try_into().unwrap());
        if version != Self::HEADER_FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported header version",
            ));
        }

        let block_size = i32::from_be_bytes(header[20..24].try_into().unwrap()) as usize;
        let free_index = i32::from_be_bytes(header[24..28].try_into().unwrap());
        let param_count = i32::from_be_bytes(header[28..32].try_into().unwrap());

        let mut parameters = HashMap::new();
        for _ in 0..param_count {
            let mut name_len_buf = [0u8; 4];
            file.read_exact(&mut name_len_buf)?;
            let name_len = i32::from_be_bytes(name_len_buf) as usize;
            let mut name_buf = vec![0u8; name_len];
            file.read_exact(&mut name_buf)?;
            let name = String::from_utf8_lossy(&name_buf).to_string();
            let mut val_buf = [0u8; 4];
            file.read_exact(&mut val_buf)?;
            let val = i32::from_be_bytes(val_buf);
            parameters.insert(name, val);
        }

        let file_len = file.metadata()?.len();
        let index_count = if file_len <= block_size as u64 {
            0
        } else {
            ((file_len - block_size as u64) / block_size as u64) as usize
        };

        Ok(Self {
            file,
            path,
            read_only,
            block_size,
            buffer_size: block_size - Self::BUFFER_PREFIX_SIZE,
            file_id,
            free_index,
            parameters,
            index_count,
        })
    }

    fn write_header(&mut self) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&Self::MAGIC_NUMBER.to_be_bytes())?;
        self.file.write_all(&self.file_id.to_be_bytes())?;
        self.file
            .write_all(&Self::HEADER_FORMAT_VERSION.to_be_bytes())?;
        self.file
            .write_all(&(self.block_size as i32).to_be_bytes())?;
        self.file.write_all(&self.free_index.to_be_bytes())?;
        self.file
            .write_all(&(self.parameters.len() as i32).to_be_bytes())?;

        for (name, val) in &self.parameters {
            self.file.write_all(&(name.len() as i32).to_be_bytes())?;
            self.file.write_all(name.as_bytes())?;
            self.file.write_all(&val.to_be_bytes())?;
        }

        // Pad header block to block_size
        let current_pos = self.file.stream_position()?;
        if current_pos < self.block_size as u64 {
            let padding = vec![0u8; (self.block_size as u64 - current_pos) as usize];
            self.file.write_all(&padding)?;
        }
        Ok(())
    }

    fn read_block_prefix(&self, index: i32) -> io::Result<(u8, i32)> {
        let mut file = &self.file;
        let offset = (index as u64 + 1) * self.block_size as u64;
        file.seek(SeekFrom::Start(offset))?;

        let mut prefix = [0u8; 5];
        file.read_exact(&mut prefix)?;
        let flags = prefix[0];
        let id_or_next = i32::from_be_bytes(prefix[1..5].try_into().unwrap());
        Ok((flags, id_or_next))
    }
}

impl BufferFile for LocalBufferFile {
    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn set_read_only(&mut self) -> io::Result<bool> {
        if self.read_only {
            return Ok(true);
        }
        self.write_header()?;
        self.file.sync_all()?;
        self.read_only = true;
        // Re-open file read-only
        self.file = OpenOptions::new().read(true).open(&self.path)?;
        Ok(true)
    }

    fn get_buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn get_index_count(&self) -> usize {
        self.index_count
    }

    fn get_free_indexes(&self) -> Vec<i32> {
        let mut free = Vec::new();
        let mut next = self.free_index;
        while next != -1 {
            free.push(next);
            if let Ok((flags, next_id)) = self.read_block_prefix(next) {
                if (flags & Self::EMPTY_BUFFER) != 0 {
                    next = next_id;
                } else {
                    break; // Corrupt?
                }
            } else {
                break;
            }
        }
        free.sort();
        free
    }

    fn set_free_indexes(&mut self, indexes: &[i32]) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Read-only"));
        }

        let mut sorted_indexes = indexes.to_vec();
        sorted_indexes.sort();

        if sorted_indexes.is_empty() {
            self.free_index = -1;
        } else {
            self.free_index = sorted_indexes[0];
            for i in 0..sorted_indexes.len() {
                let current = sorted_indexes[i];
                let next = if i + 1 < sorted_indexes.len() {
                    sorted_indexes[i + 1]
                } else {
                    -1
                };

                let offset = (current as u64 + 1) * self.block_size as u64;
                self.file.seek(SeekFrom::Start(offset))?;
                let mut prefix = [0u8; 5];
                prefix[0] = Self::EMPTY_BUFFER;
                prefix[1..5].copy_from_slice(&next.to_be_bytes());
                self.file.write_all(&prefix)?;
            }
        }
        Ok(())
    }

    fn get_parameter(&self, name: &str) -> Option<i32> {
        self.parameters.get(name).cloned()
    }

    fn set_parameter(&mut self, name: &str, value: i32) {
        self.parameters.insert(name.to_string(), value);
    }

    fn get_parameter_names(&self) -> Vec<String> {
        self.parameters.keys().cloned().collect()
    }

    fn get(&self, index: i32) -> io::Result<DataBuffer> {
        let mut file = &self.file;
        let offset = (index as u64 + 1) * self.block_size as u64;
        file.seek(SeekFrom::Start(offset))?;

        let mut prefix = [0u8; 5];
        file.read_exact(&mut prefix)?;
        let flags = prefix[0];
        let id_or_next = i32::from_be_bytes(prefix[1..5].try_into().unwrap());

        if (flags & Self::EMPTY_BUFFER) != 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Buffer is empty"));
        }

        let mut data = vec![0u8; self.buffer_size];
        file.read_exact(&mut data)?;

        Ok(DataBuffer::from_data(id_or_next, data))
    }

    fn put(&mut self, buf: &DataBuffer, index: i32) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Read-only"));
        }
        let offset = (index as u64 + 1) * self.block_size as u64;
        self.file.seek(SeekFrom::Start(offset))?;

        let mut prefix = [0u8; 5];
        prefix[0] = 0; // Not empty
        prefix[1..5].copy_from_slice(&buf.get_id().to_be_bytes());
        self.file.write_all(&prefix)?;

        self.file.write_all(buf.get_data())?;

        if (index as usize) >= self.index_count {
            self.index_count = index as usize + 1;
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        if !self.read_only {
            self.write_header()?;
            self.file.sync_all()?;
        }
        Ok(())
    }

    fn delete(&mut self) -> io::Result<bool> {
        if self.read_only {
            return Ok(false);
        }
        let path = self.path.clone();
        // Close file before deleting (Windows requirement)
        // We can't really call close() here easily if we want to delete,
        // because we don't want to write header if we are deleting.
        std::fs::remove_file(path)?;
        Ok(true)
    }
}
