use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::g_binary_reader::ByteProvider;

/// File-backed [`ByteProvider`] that supports random-access reads and writes.
///
/// Mirrors `mobiledevices.dmg.ghidra.GByteProvider` from the original Ghidra source.
/// The underlying [`std::fs::File`] plays the role of `GRandomAccessFile` —
/// providing seekable, random-access I/O without an additional buffering layer.
pub struct GByteProvider {
    path: PathBuf,
    file: File,
}

impl GByteProvider {
    /// Opens the file at `path` in read-only mode.
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        Ok(GByteProvider { path, file })
    }

    /// Opens the file using the given permissions string.
    ///
    /// Accepted values: `"r"` (read-only), `"rw"` / `"rws"` / `"rwd"` (read + write).
    pub fn new_with_permissions<P: AsRef<Path>>(path: P, permissions: &str) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = match permissions {
            "r" => File::open(&path)?,
            "rw" | "rws" | "rwd" => OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&path)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown permissions string: {permissions}"),
                ));
            }
        };
        Ok(GByteProvider { path, file })
    }

    /// Returns a reference to the underlying path.
    pub fn get_path(&self) -> &Path {
        &self.path
    }

    /// Returns the file-name component of the path, or `""` if unavailable.
    pub fn get_name(&self) -> &str {
        self.path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
    }

    /// Returns the absolute path as a `String`.
    ///
    /// If the stored path is already absolute it is returned as-is; otherwise
    /// it is resolved against the current working directory, mirroring
    /// `java.io.File.getAbsolutePath()`.
    pub fn get_absolute_path(&self) -> String {
        if self.path.is_absolute() {
            self.path.to_string_lossy().into_owned()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(&self.path))
                .unwrap_or_else(|_| self.path.clone())
                .to_string_lossy()
                .into_owned()
        }
    }

    /// Opens a fresh read handle positioned at `index`.
    ///
    /// Mirrors `getInputStream(long index)` in the Java source.
    pub fn get_input_stream(&self, index: u64) -> io::Result<impl Read> {
        let mut f = File::open(&self.path)?;
        f.seek(SeekFrom::Start(index))?;
        Ok(f)
    }
}

impl ByteProvider for GByteProvider {
    fn length(&mut self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn is_valid_index(&mut self, index: u64) -> bool {
        self.file
            .metadata()
            .map(|m| index < m.len())
            .unwrap_or(false)
    }

    fn read_byte(&mut self, index: u64) -> io::Result<u8> {
        self.file.seek(SeekFrom::Start(index))?;
        let mut buf = [0u8; 1];
        self.file.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_bytes(&mut self, index: u64, length: usize) -> io::Result<Vec<u8>> {
        self.file.seek(SeekFrom::Start(index))?;
        let mut buf = vec![0u8; length];
        self.file.read_exact(&mut buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(e.kind(), format!("Unable to read {length} bytes"))
            } else {
                e
            }
        })?;
        Ok(buf)
    }

    fn write_byte(&mut self, index: u64, value: u8) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(index))?;
        self.file.write_all(&[value])
    }

    fn write_bytes(&mut self, index: u64, values: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(index))?;
        self.file.write_all(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn make_temp_file(content: &[u8]) -> PathBuf {
        let n = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("gbp_test_{}_{}.bin", pid, n));
        std::fs::write(&path, content).unwrap();
        path
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn length_matches_file_size() {
        let path = make_temp_file(&[1, 2, 3, 4, 5]);
        let mut p = GByteProvider::new(&path).unwrap();
        assert_eq!(p.length().unwrap(), 5);
        cleanup(&path);
    }

    #[test]
    fn is_valid_index_bounds() {
        let path = make_temp_file(&[0u8; 4]);
        let mut p = GByteProvider::new(&path).unwrap();
        assert!(p.is_valid_index(0));
        assert!(p.is_valid_index(3));
        assert!(!p.is_valid_index(4));
        cleanup(&path);
    }

    #[test]
    fn read_byte_at_various_offsets() {
        let path = make_temp_file(&[0xAB, 0xCD, 0xEF]);
        let mut p = GByteProvider::new(&path).unwrap();
        assert_eq!(p.read_byte(0).unwrap(), 0xAB);
        assert_eq!(p.read_byte(1).unwrap(), 0xCD);
        assert_eq!(p.read_byte(2).unwrap(), 0xEF);
        cleanup(&path);
    }

    #[test]
    fn read_byte_out_of_bounds_errors() {
        let path = make_temp_file(&[0u8]);
        let mut p = GByteProvider::new(&path).unwrap();
        assert!(p.read_byte(10).is_err());
        cleanup(&path);
    }

    #[test]
    fn read_bytes_subrange() {
        let path = make_temp_file(&[1, 2, 3, 4, 5]);
        let mut p = GByteProvider::new(&path).unwrap();
        assert_eq!(p.read_bytes(1, 3).unwrap(), vec![2u8, 3, 4]);
        cleanup(&path);
    }

    #[test]
    fn read_bytes_partial_read_errors() {
        let path = make_temp_file(&[1, 2]);
        let mut p = GByteProvider::new(&path).unwrap();
        let err = p.read_bytes(0, 5).unwrap_err();
        assert!(err.to_string().contains("5") || err.kind() == io::ErrorKind::UnexpectedEof);
        cleanup(&path);
    }

    #[test]
    fn write_byte_round_trip() {
        let path = make_temp_file(&[0u8; 4]);
        let mut p = GByteProvider::new_with_permissions(&path, "rw").unwrap();
        p.write_byte(2, 0xAB).unwrap();
        assert_eq!(p.read_byte(2).unwrap(), 0xAB);
        cleanup(&path);
    }

    #[test]
    fn write_bytes_round_trip() {
        let path = make_temp_file(&[0u8; 4]);
        let mut p = GByteProvider::new_with_permissions(&path, "rw").unwrap();
        p.write_bytes(0, &[1, 2, 3, 4]).unwrap();
        assert_eq!(p.read_bytes(0, 4).unwrap(), vec![1u8, 2, 3, 4]);
        cleanup(&path);
    }

    #[test]
    fn write_byte_read_only_errors() {
        let path = make_temp_file(&[0u8; 4]);
        let mut p = GByteProvider::new(&path).unwrap();
        assert!(p.write_byte(0, 0xFF).is_err());
        cleanup(&path);
    }

    #[test]
    fn get_name_returns_filename() {
        let path = make_temp_file(&[]);
        let p = GByteProvider::new(&path).unwrap();
        assert_eq!(p.get_name(), path.file_name().unwrap().to_str().unwrap());
        cleanup(&path);
    }

    #[test]
    fn get_absolute_path_is_absolute() {
        let path = make_temp_file(&[]);
        let p = GByteProvider::new(&path).unwrap();
        assert!(Path::new(&p.get_absolute_path()).is_absolute());
        cleanup(&path);
    }

    #[test]
    fn get_path_matches_constructor_path() {
        let path = make_temp_file(&[]);
        let p = GByteProvider::new(&path).unwrap();
        assert_eq!(p.get_path(), path.as_path());
        cleanup(&path);
    }

    #[test]
    fn get_input_stream_reads_from_offset() {
        let path = make_temp_file(&[10, 20, 30, 40]);
        let p = GByteProvider::new(&path).unwrap();
        let mut stream = p.get_input_stream(2).unwrap();
        let mut buf = vec![0u8; 2];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(buf, vec![30u8, 40]);
        cleanup(&path);
    }

    #[test]
    fn unknown_permissions_returns_error() {
        let path = make_temp_file(&[]);
        let result = GByteProvider::new_with_permissions(&path, "invalid");
        assert!(result.is_err());
        cleanup(&path);
    }

    #[test]
    fn new_nonexistent_file_returns_error() {
        assert!(GByteProvider::new("/nonexistent/path/that/does/not/exist.bin").is_err());
    }

    #[test]
    fn rw_permissions_read_write() {
        let path = make_temp_file(&[0u8; 8]);
        let mut p = GByteProvider::new_with_permissions(&path, "rw").unwrap();
        p.write_bytes(0, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        assert_eq!(p.read_bytes(0, 4).unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        cleanup(&path);
    }
}
