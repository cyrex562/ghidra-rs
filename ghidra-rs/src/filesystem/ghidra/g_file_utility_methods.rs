use std::io::{self, Read, Write};
use std::path::PathBuf;

const GHIDRA_FILE_SYSTEM_PREFIX: &str = "ghidra_file_system_";
const GHIDRA_FILE_SYSTEM_SUFFIX: &str = ".tmp";

/// Writes all bytes from `input` to a new temporary file and returns its path.
///
/// Mirrors `GFileUtilityMethods.writeTemporaryFile(InputStream)`.
pub fn write_temporary_file<R: Read>(input: R) -> io::Result<PathBuf> {
    write_temporary_file_limited(input, usize::MAX)
}

/// Writes up to `max_bytes` bytes from `input` to a new temporary file and returns its path.
///
/// Mirrors `GFileUtilityMethods.writeTemporaryFile(InputStream, int)`.
pub fn write_temporary_file_limited<R: Read>(mut input: R, max_bytes: usize) -> io::Result<PathBuf> {
    let path = make_temp_path(GHIDRA_FILE_SYSTEM_PREFIX);
    let mut file = std::fs::File::create(&path)?;
    let mut buffer = [0u8; 8192];
    let mut n_written = 0usize;
    loop {
        let limit = max_bytes.saturating_sub(n_written).min(buffer.len());
        if limit == 0 {
            break;
        }
        let n_read = input.read(&mut buffer[..limit])?;
        if n_read == 0 {
            break;
        }
        file.write_all(&buffer[..n_read])?;
        n_written += n_read;
    }
    Ok(path)
}

/// Writes `bytes` to a new temporary file and returns its path.
///
/// `prefix` defaults to `"ghidra_file_system_"` when `None`.  If the prefix is
/// shorter than 3 characters it is padded with `'_'` to satisfy OS requirements
/// for `tmpfile`-style names (mirrors Java `File.createTempFile` precondition).
///
/// Mirrors `GFileUtilityMethods.writeTemporaryFile(byte[], String)`.
pub fn write_temporary_file_from_bytes(bytes: &[u8], prefix: Option<&str>) -> io::Result<PathBuf> {
    let prefix = build_prefix(prefix);
    let path = make_temp_path(&prefix);
    std::fs::write(&path, bytes)?;
    Ok(path)
}

fn build_prefix(prefix: Option<&str>) -> String {
    match prefix {
        None => GHIDRA_FILE_SYSTEM_PREFIX.to_string(),
        Some(p) => {
            let mut s = p.to_string();
            while s.len() < 3 {
                s.push('_');
            }
            s
        }
    }
}

fn make_temp_path(prefix: &str) -> PathBuf {
    use rand::Rng;
    let rand_suffix: u64 = rand::thread_rng().gen();
    std::env::temp_dir().join(format!("{}{:016x}{}", prefix, rand_suffix, GHIDRA_FILE_SYSTEM_SUFFIX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_all_bytes_from_reader() {
        let data = b"hello world";
        let path = write_temporary_file(Cursor::new(data)).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_limited_bytes_truncates_at_max() {
        let data = b"abcdefghij";
        let path = write_temporary_file_limited(Cursor::new(data), 5).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"abcde");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_limited_bytes_larger_than_input() {
        let data = b"xyz";
        let path = write_temporary_file_limited(Cursor::new(data), 100).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"xyz");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_limited_zero_writes_nothing() {
        let data = b"should not appear";
        let path = write_temporary_file_limited(Cursor::new(data), 0).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_bytes_from_slice_roundtrip() {
        let data = b"test bytes";
        let path = write_temporary_file_from_bytes(data, None).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_bytes_none_prefix_uses_default() {
        let path = write_temporary_file_from_bytes(b"x", None).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with(GHIDRA_FILE_SYSTEM_PREFIX));
        assert!(name.ends_with(GHIDRA_FILE_SYSTEM_SUFFIX));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_bytes_short_prefix_padded_to_three_chars() {
        let path = write_temporary_file_from_bytes(b"x", Some("ab")).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("ab_"), "expected 'ab_' prefix, got '{}'", name);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_bytes_empty_prefix_padded() {
        let path = write_temporary_file_from_bytes(b"x", Some("")).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("___"), "expected '___' prefix, got '{}'", name);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_bytes_long_prefix_unchanged() {
        let path = write_temporary_file_from_bytes(b"x", Some("myprefix")).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("myprefix"), "expected 'myprefix' prefix, got '{}'", name);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn temp_files_have_tmp_suffix() {
        let path = write_temporary_file(Cursor::new(b"")).unwrap();
        assert!(path.to_str().unwrap().ends_with(GHIDRA_FILE_SYSTEM_SUFFIX));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_across_buffer_boundary() {
        // Write more than 8192 bytes to exercise the buffer loop
        let data: Vec<u8> = (0u8..=255).cycle().take(10_000).collect();
        let path = write_temporary_file(Cursor::new(&data)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
        let _ = std::fs::remove_file(&path);
    }
}
