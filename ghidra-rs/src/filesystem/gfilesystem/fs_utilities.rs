pub const SEPARATOR_CHARS: &str = "/\\:";
pub const SEPARATOR: char = '/';

/// Characters that are escaped even though they fall in the printable ASCII range, because
/// they are used as FSRL portion separators (`%` for the escape marker itself, `?` for the
/// parameter separator, `|` for the FSRL-part separator).
const ESCAPE_CHARS: &str = "%?|";

/// Returns a copy of `s` with FSRL-problematic characters escaped as `%nn` sequences, where
/// `nn` are hexdigits specifying the byte value (UTF-8 encoded for non-ASCII characters).
///
/// Mirrors `FSUtilities.escapeEncode(String)`; the inverse is [`escape_decode`].
pub fn escape_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cv = c as u32;
        if !(32..=126).contains(&cv) || ESCAPE_CHARS.contains(c) {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).as_bytes() {
                out.push('%');
                out.push_str(&format!("{:02x}", b));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A malformed FSRL / URL-ish string, mirroring the `java.net.MalformedURLException` thrown by
/// `FSUtilities.escapeDecode` and `FSRL.fromString`.
///
/// Java's `MalformedURLException` is an `IOException`, so this converts into [`std::io::Error`]
/// (kind [`std::io::ErrorKind::InvalidInput`]) for callers that propagate I/O errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct MalformedUrlError(pub String);

impl From<MalformedUrlError> for std::io::Error {
    fn from(e: MalformedUrlError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
    }
}

/// Decodes a string previously encoded with [`escape_encode`], replacing each run of `%nn`
/// sequences with the UTF-8 string those byte values encode.
///
/// Mirrors `FSUtilities.escapeDecode(String)`. Where Java lets a non-hex escape surface as an
/// unchecked `NumberFormatException`, this reports it as a [`MalformedUrlError`] like the other
/// bad-escape cases.
pub fn escape_decode(s: &str) -> Result<String, MalformedUrlError> {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut sb = String::with_capacity(s.len());
    let mut i = 0;
    while i < len {
        let mut c = chars[i];
        if c == '%' {
            let mut bytes: Vec<u8> = Vec::new();
            while i + 2 < len && c == '%' {
                let hex: String = chars[i + 1..i + 3].iter().collect();
                let v = i64::from_str_radix(&hex, 16).map_err(|_| {
                    MalformedUrlError(format!("Bad hex characters in escape (%) pattern: {s}"))
                })?;
                if v < 0 {
                    return Err(MalformedUrlError(format!(
                        "Bad hex characters in escape (%) pattern: {s}"
                    )));
                }
                bytes.push(v as u8);
                i += 3;
                if i < len {
                    c = chars[i];
                }
            }
            if i < len && c == '%' {
                return Err(MalformedUrlError(format!("Bad escape pattern in {s}")));
            }
            sb.push_str(&String::from_utf8_lossy(&bytes));
        } else {
            sb.push(c);
            i += 1;
        }
    }
    Ok(sb)
}

/// Concatenates path strings, ensuring correct separators between parts.
///
/// Handles both forward and back slashes in input but only inserts a forward slash
/// when a separator is needed.
///
/// Returns `None` if all provided paths are `None` or the slice is empty.
pub fn append_path(paths: &[Option<&str>]) -> Option<String> {
    if paths.iter().all(|p| p.is_none()) {
        return None;
    }

    let mut buffer = String::new();
    for path_opt in paths {
        let path = match path_opt {
            None => continue,
            Some(p) if p.is_empty() => continue,
            Some(p) => *p,
        };

        let empty_buffer = buffer.is_empty();
        let buffer_ends_with_slash =
            !empty_buffer && matches!(buffer.as_bytes().last(), Some(b'/') | Some(b'\\'));
        let path_starts_with_slash =
            matches!(path.as_bytes().first(), Some(b'/') | Some(b'\\'));

        if !buffer_ends_with_slash && !path_starts_with_slash && !empty_buffer {
            buffer.push('/');
            buffer.push_str(path);
        } else if path_starts_with_slash && buffer_ends_with_slash {
            buffer.push_str(&path[1..]);
        } else {
            buffer.push_str(path);
        }
    }

    Some(buffer)
}

/// Splits `path` into its individual directory and filename components. For example,
/// `"/dir/dir/dir/file"` becomes `["", "dir", "dir", "dir", "file"]`.
///
/// Mirrors `FSUtilities.splitPath(String)`: `None` is treated as `""`, back slashes are
/// normalized to forward slashes, and -- like Java's `String.split` -- trailing empty
/// components are dropped (so `"/"` yields no components, while `""` yields one empty one).
pub fn split_path(path: Option<&str>) -> Vec<String> {
    let normalized = path.unwrap_or("").replace('\\', "/");
    if normalized.is_empty() {
        return vec![String::new()];
    }
    let mut parts: Vec<String> = normalized.split('/').map(str::to_owned).collect();
    while parts.last().is_some_and(String::is_empty) {
        parts.pop();
    }
    parts
}

/// Converts a native OS path (which may use `\` separators) into an absolute unix-style path.
///
/// Mirrors `FSUtilities.normalizeNativePath(String)`, which is
/// `appendPath("/", FilenameUtils.separatorsToUnix(path))`.
pub fn normalize_native_path(path: &str) -> String {
    let unix_path = path.replace('\\', "/");
    append_path(&[Some("/"), Some(&unix_path)]).unwrap_or_else(|| "/".to_string())
}

/// Returns the file extension of `path` at the given extension depth.
///
/// - `ext_level = 1` returns the last `.ext` suffix.
/// - `ext_level = 2` returns the last two `.ext1.ext2` suffix.
/// - Returns `None` if the path contains fewer than `ext_level` dot-separated
///   extensions in the filename portion (i.e., before any separator character).
///
/// # Panics
/// Panics if `ext_level` is 0.
pub fn get_extension(path: &str, ext_level: usize) -> Option<&str> {
    assert!(ext_level >= 1, "Bad extension level: {}", ext_level);

    let mut level = ext_level;
    let bytes = path.as_bytes();

    for i in (0..path.len()).rev() {
        let c = bytes[i] as char;
        if SEPARATOR_CHARS.contains(c) {
            return None;
        }
        if c == '.' {
            level -= 1;
            if level == 0 {
                return Some(&path[i..]);
            }
        }
    }
    None
}

/// Best-effort sanitizing of an untrusted string that will be used to create a file on the
/// user's local filesystem. Mirrors `FSUtilities.getSafeFilename(String)`.
pub fn get_safe_filename(untrusted_filename: &str) -> String {
    let replaced: String = untrusted_filename
        .chars()
        .map(|c| if matches!(c, '/' | '\\' | ':' | '|') { '_' } else { c })
        .collect();
    let trimmed = replaced.trim_matches(|c: char| c <= ' ');
    match trimmed {
        "" => "empty_filename".to_string(),
        "." => "dot".to_string(),
        ".." => "dotdot".to_string(),
        other => escape_encode(other),
    }
}

/// Copies `is` to `os` while updating `monitor`, returning the number of bytes copied.
///
/// Mirrors `FSUtilities.streamCopy(InputStream, OutputStream, TaskMonitor)`: progress is set
/// to the running total and cancellation is checked after every buffer.
pub fn stream_copy(
    is: &mut dyn std::io::Read,
    os: &mut dyn std::io::Write,
    monitor: &dyn crate::util::task::TaskMonitor,
) -> Result<u64, super::g_file_system::GFileSystemError> {
    let mut buffer = vec![0u8; IO_BUFFER_SIZE];
    let mut total: u64 = 0;
    loop {
        let n = is.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        os.write_all(&buffer[..n])?;
        total += n as u64;
        monitor.set_progress(total as i64);
        monitor.check_cancelled()?;
    }
    os.flush()?;
    Ok(total)
}

/// `FileUtilities.IO_BUFFER_SIZE`.
const IO_BUFFER_SIZE: usize = 32 * 1024;

/// Copies the contents of `provider` to `dest_file`, returning the number of bytes copied.
/// Mirrors `FSUtilities.copyByteProviderToFile(ByteProvider, File, TaskMonitor)`.
pub fn copy_byte_provider_to_file(
    provider: &dyn crate::app::util::bin::byte_provider::ByteProvider,
    dest_file: &std::path::Path,
    monitor: &dyn crate::util::task::TaskMonitor,
) -> Result<u64, super::g_file_system::GFileSystemError> {
    let mut is = provider.get_input_stream(0)?;
    let mut fos = std::fs::File::create(dest_file)?;
    stream_copy(&mut is, &mut fos, monitor)
}

/// The lowercase hex MD5 of everything `is` produces. Mirrors
/// `FSUtilities.getMD5(InputStream, String, long, TaskMonitor)`.
pub fn get_md5_of_stream(
    is: &mut dyn std::io::Read,
    name: &str,
    expected_length: i64,
    monitor: &dyn crate::util::task::TaskMonitor,
) -> Result<String, super::g_file_system::GFileSystemError> {
    use md5::{Digest, Md5};
    monitor.initialize(expected_length);
    monitor.set_message(&format!("Hashing {name}"));
    let buf_size = expected_length.clamp(1024, 1024 * 1024) as usize;
    let mut buf = vec![0u8; buf_size];
    let mut digest = Md5::new();
    loop {
        let n = is.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
        monitor.increment_progress(n as i64);
        monitor.check_cancelled()?;
    }
    Ok(hex_lower(&digest.finalize()))
}

/// The MD5 of a provider's contents. Mirrors `FSUtilities.getMD5(ByteProvider, TaskMonitor)`.
pub fn get_md5(
    provider: &dyn crate::app::util::bin::byte_provider::ByteProvider,
    monitor: &dyn crate::util::task::TaskMonitor,
) -> Result<String, super::g_file_system::GFileSystemError> {
    let mut is = provider.get_input_stream(0)?;
    let name = provider.get_name().unwrap_or_default();
    get_md5_of_stream(&mut is, &name, provider.length() as i64, monitor)
}

/// The MD5 of a local file. Mirrors `FSUtilities.getFileMD5(File, TaskMonitor)`.
pub fn get_file_md5(
    f: &std::path::Path,
    monitor: &dyn crate::util::task::TaskMonitor,
) -> Result<String, super::g_file_system::GFileSystemError> {
    let mut fis = std::fs::File::open(f)?;
    let len = fis.metadata()?.len() as i64;
    let name = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    get_md5_of_stream(&mut fis, &name, len, monitor)
}

/// Lowercase hex of `bytes` (Java's `NumericUtilities.convertBytesToString`).
pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Returns `true` if `f` is a symbolic link. Mirrors `FSUtilities.isSymlink(File)`.
pub fn is_symlink(f: &std::path::Path) -> bool {
    std::fs::symlink_metadata(f).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// The destination of a symlink, or `None` if not a symlink or on error. Mirrors
/// `FSUtilities.readSymlink(File)`.
pub fn read_symlink(f: &std::path::Path) -> Option<String> {
    std::fs::read_link(f).ok().map(|p| p.to_string_lossy().into_owned())
}

/// The [`FileType`](super::fileinfo::file_type::FileType) of a local file. Mirrors
/// `FSUtilities.getFileType(File)`.
pub fn get_file_type(f: &std::path::Path) -> super::fileinfo::file_type::FileType {
    use super::fileinfo::file_type::FileType;
    if is_symlink(f) {
        return FileType::SymbolicLink;
    }
    match std::fs::metadata(f) {
        Ok(m) if m.is_dir() => FileType::Directory,
        Ok(m) if m.is_file() => FileType::File,
        _ => FileType::Unknown,
    }
}

#[cfg(test)]
mod service_support_tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    #[test]
    fn safe_filename_matches_java() {
        assert_eq!(get_safe_filename("a/b\\c:d|e"), "a_b_c_d_e");
        assert_eq!(get_safe_filename("  "), "empty_filename");
        assert_eq!(get_safe_filename("."), "dot");
        assert_eq!(get_safe_filename(".."), "dotdot");
        assert_eq!(get_safe_filename("x%y"), "x%25y");
    }

    #[test]
    fn md5_of_stream_matches_known_digest() {
        let mut data: &[u8] = b"hello";
        let md5 = get_md5_of_stream(&mut data, "h", 5, &DummyMonitor).unwrap();
        assert_eq!(md5, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn stream_copy_copies_all_bytes() {
        let src = vec![7u8; 100_000];
        let mut out = Vec::new();
        let n = stream_copy(&mut src.as_slice(), &mut out, &DummyMonitor).unwrap();
        assert_eq!(n, 100_000);
        assert_eq!(out, src);
    }

    #[test]
    fn file_type_and_md5_of_local_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.txt");
        std::fs::write(&f, b"hello").unwrap();
        assert_eq!(get_file_type(&f), super::super::fileinfo::file_type::FileType::File);
        assert_eq!(get_file_type(dir.path()), super::super::fileinfo::file_type::FileType::Directory);
        assert!(!is_symlink(&f));
        assert_eq!(get_file_md5(&f, &DummyMonitor).unwrap(), "5d41402abc4b2a76b9719d911017c592");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- split_path -----------------------------------------------------------

    #[test]
    fn split_path_matches_java_string_split() {
        assert_eq!(split_path(Some("/dir/dir/dir/file")), ["", "dir", "dir", "dir", "file"]);
        assert_eq!(split_path(Some("a\\b/c")), ["a", "b", "c"]);
        assert_eq!(split_path(Some("a//b/")), ["a", "", "b"]);
        assert!(split_path(Some("/")).is_empty());
        assert!(split_path(Some("///")).is_empty());
        assert_eq!(split_path(Some("")), [""]);
        assert_eq!(split_path(None), [""]);
    }

    // -- append_path ----------------------------------------------------------

    #[test]
    fn append_path_no_args_returns_none() {
        assert_eq!(append_path(&[]).as_deref(), None);
    }

    #[test]
    fn append_path_all_null_returns_none() {
        assert_eq!(append_path(&[None, None]).as_deref(), None);
        assert_eq!(append_path(&[None, None, None]).as_deref(), None);
    }

    #[test]
    fn append_path_empty_strings() {
        assert_eq!(append_path(&[Some(""), Some("")]).as_deref(), Some(""));
        assert_eq!(append_path(&[Some("")]).as_deref(), Some(""));
        assert_eq!(append_path(&[Some(""), Some(""), Some("")]).as_deref(), Some(""));
    }

    #[test]
    fn append_path_whitespace() {
        assert_eq!(append_path(&[Some("    ")]).as_deref(), Some("    "));
        assert_eq!(append_path(&[Some("    "), Some("\t")]).as_deref(), Some("    /\t"));
    }

    #[test]
    fn append_path_leading_slash_with_empty_or_null() {
        assert_eq!(append_path(&[Some("/"), Some("")]).as_deref(), Some("/"));
        assert_eq!(append_path(&[Some("/"), None]).as_deref(), Some("/"));
        assert_eq!(append_path(&[Some("/"), None, Some("")]).as_deref(), Some("/"));
        assert_eq!(append_path(&[Some("/"), None, None]).as_deref(), Some("/"));
    }

    #[test]
    fn append_path_slash_from_empties() {
        assert_eq!(append_path(&[Some(""), None, Some("/")]).as_deref(), Some("/"));
    }

    #[test]
    fn append_path_simple_segments() {
        assert_eq!(append_path(&[Some(""), Some("blah")]).as_deref(), Some("blah"));
        assert_eq!(append_path(&[Some(""), None, Some("/blah")]).as_deref(), Some("/blah"));
        assert_eq!(append_path(&[Some(""), None, Some("blah")]).as_deref(), Some("blah"));
    }

    #[test]
    fn append_path_strips_duplicate_leading_slash() {
        assert_eq!(
            append_path(&[Some("/blah/"), Some("/leading")]).as_deref(),
            Some("/blah/leading")
        );
        assert_eq!(
            append_path(&[Some("/blah/"), Some("/leading"), Some("dir")]).as_deref(),
            Some("/blah/leading/dir")
        );
    }

    #[test]
    fn append_path_basic_join() {
        assert_eq!(append_path(&[Some("blah")]).as_deref(), Some("blah"));
        assert_eq!(append_path(&[Some("blah"), Some("sub")]).as_deref(), Some("blah/sub"));
        assert_eq!(append_path(&[Some("blah/"), Some("sub")]).as_deref(), Some("blah/sub"));
    }

    #[test]
    fn append_path_backslash_separator() {
        assert_eq!(
            append_path(&[Some("blah\\"), Some("sub")]).as_deref(),
            Some("blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("blah"), Some("/sub")]).as_deref(),
            Some("blah/sub")
        );
        assert_eq!(
            append_path(&[Some("blah"), Some("\\sub")]).as_deref(),
            Some("blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("/blah/blah"), Some("\\sub")]).as_deref(),
            Some("/blah/blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("\\blah\\blah"), Some("\\sub")]).as_deref(),
            Some("\\blah\\blah\\sub")
        );
        assert_eq!(
            append_path(&[Some("\\blah\\blah\\"), Some("\\sub")]).as_deref(),
            Some("\\blah\\blah\\sub")
        );
    }

    // -- append_path multiple separators --------------------------------------

    #[test]
    fn append_path_multiple_separators() {
        assert_eq!(
            append_path(&[Some("/blah"), Some("////")]).as_deref(),
            Some("/blah////")
        );
        assert_eq!(
            append_path(&[Some("/blah/"), Some("////leading")]).as_deref(),
            Some("/blah////leading")
        );
        assert_eq!(
            append_path(&[Some("//"), Some("//")]).as_deref(),
            Some("///")
        );
        assert_eq!(
            append_path(&[Some("\\\\"), Some("\\\\")]).as_deref(),
            Some("\\\\\\")
        );
    }

    // -- escape_encode ----------------------------------------------------------

    #[test]
    fn escape_encode_leaves_normal_ascii_untouched() {
        assert_eq!(escape_encode("dir/example.zip"), "dir/example.zip");
    }

    #[test]
    fn escape_encode_escapes_separator_characters() {
        assert_eq!(escape_encode("a%b?c|d"), "a%25b%3fc%7cd");
    }

    #[test]
    fn escape_encode_escapes_control_characters() {
        assert_eq!(escape_encode("a\tb"), "a%09b");
    }

    #[test]
    fn escape_encode_escapes_non_ascii_as_utf8_bytes() {
        // '\u{e9}' (LATIN SMALL LETTER E WITH ACUTE) encodes to 2 UTF-8 bytes: 0xC3 0xA9.
        assert_eq!(escape_encode("caf\u{e9}"), "caf%c3%a9");
    }

    // -- get_extension --------------------------------------------------------

    #[test]
    fn get_extension_level_1() {
        assert_eq!(get_extension("blah.ext", 1), Some(".ext"));
        assert_eq!(get_extension("blah.xyz.ext", 1), Some(".ext"));
        assert_eq!(get_extension("blah.", 1), Some("."));
        assert_eq!(get_extension("blah", 1), None);
        assert_eq!(get_extension("blah.ext/filename", 1), None);
    }

    #[test]
    fn get_extension_level_2() {
        assert_eq!(get_extension("blah.xyz.ext", 2), Some(".xyz.ext"));
        assert_eq!(get_extension("blah.ext", 2), None);
    }

    #[test]
    #[should_panic(expected = "Bad extension level")]
    fn get_extension_zero_level_panics() {
        get_extension("hi", 0);
    }
}
