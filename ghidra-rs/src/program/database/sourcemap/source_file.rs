//! Port of `ghidra.program.database.sourcemap.SourceFile`.

use std::cmp::Ordering;
use std::fmt;

use crate::util::big_endian_data_converter::INSTANCE as BIG_ENDIAN;
use crate::util::conv::Conv;
use crate::util::data_converter::DataConverter;

use super::SourceFileIdType;

/// An immutable object representing a source file.
///
/// It contains an absolute path along with an optional [`SourceFileIdType`] and identifier. For
/// example, if the id type is [`SourceFileIdType::Md5`], the identifier is the md5 sum of the
/// source file (stored as a byte array).
///
/// Note: path parameters are assumed to be absolute file paths with forward slashes as the
/// separator.
///
/// Note: the Java class's `getUri()` returns a `java.net.URI`; this crate has no URI type (URIs
/// are represented as plain `String`s elsewhere, e.g. `ExtLogicalLocation::uri`), so
/// [`SourceFile::uri`] returns the equivalent `file:` URI string instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceFile {
    path: String,
    id_type: SourceFileIdType,
    identifier: Vec<u8>,
}

impl SourceFile {
    /// Creates a `SourceFile` with only a path. The path is normalized (dot segments are
    /// resolved, see [`SourceFile::with_identifier`]). The id type is [`SourceFileIdType::None`]
    /// and the identifier is empty.
    pub fn new(path: &str) -> Result<Self, String> {
        Self::with_identifier(path, SourceFileIdType::None, None)
    }

    /// Creates a `SourceFile` with a path, id type, and identifier.
    ///
    /// `path_to_validate` must be an absolute path (start with `/`); it is normalized the way
    /// `java.net.URI::normalize` normalizes a path: single-dot segments are dropped, and a
    /// double-dot segment cancels the nearest preceding real segment. A double-dot segment with
    /// no real segment to cancel (i.e. one that would climb above the root) is left in place,
    /// which is then rejected below, mirroring the Java constructor's explicit
    /// `path.startsWith("/../")` check.
    ///
    /// Note: if `id_type` is [`SourceFileIdType::None`], `identifier` is ignored.
    pub fn with_identifier(
        path_to_validate: &str,
        id_type: SourceFileIdType,
        identifier: Option<&[u8]>,
    ) -> Result<Self, String> {
        if path_to_validate.trim().is_empty() {
            return Err("pathToValidate cannot be null or blank".to_string());
        }
        let path = normalize_file_path(path_to_validate)?;
        if path.ends_with('/') {
            return Err("SourceFile URI must represent a file (not a directory)".to_string());
        }
        if path.starts_with("/../") {
            return Err("path must be absolute after normalization".to_string());
        }
        Self::build(path, id_type, identifier)
    }

    /// Creates a `SourceFile` from a path that has already been validated and normalized, e.g.
    /// one read out of the database. `identifier` is still range/length checked.
    ///
    /// IMPORTANT: only use this if `path` is certain to already be a validated, normalized
    /// absolute path; it skips the checks performed by [`SourceFile::with_identifier`].
    pub(crate) fn new_unvalidated(
        path: String,
        id_type: SourceFileIdType,
        identifier: Option<&[u8]>,
    ) -> Result<Self, String> {
        Self::build(path, id_type, identifier)
    }

    fn build(
        path: String,
        id_type: SourceFileIdType,
        identifier: Option<&[u8]>,
    ) -> Result<Self, String> {
        let identifier = validate_and_copy_identifier(id_type, identifier)?;
        Ok(Self { path, id_type, identifier })
    }

    /// Returns a `file:` URI string for this `SourceFile`.
    pub fn uri(&self) -> String {
        format!("file:{}", self.path)
    }

    /// Returns the path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the filename.
    pub fn filename(&self) -> &str {
        match self.path.rfind('/') {
            Some(idx) => &self.path[idx + 1..],
            None => &self.path,
        }
    }

    /// Returns the source file identifier type.
    pub fn id_type(&self) -> SourceFileIdType {
        self.id_type
    }

    /// Returns a copy of the identifier.
    pub fn identifier(&self) -> Vec<u8> {
        self.identifier.clone()
    }

    /// Returns a String representation of the identifier.
    pub fn id_as_string(&self) -> String {
        match self.id_type {
            SourceFileIdType::None => String::new(),
            SourceFileIdType::Timestamp64 => {
                format_instant_utc(BIG_ENDIAN.get_long(&self.identifier))
            }
            _ => self.identifier.iter().map(|&b| Conv::to_hex_string_byte(b)).collect(),
        }
    }
}

fn normalize_file_path(path: &str) -> Result<String, String> {
    if !path.starts_with('/') {
        return Err(format!(
            "path not valid: Relative path in absolute URI: file:{path}"
        ));
    }
    let trailing_slash = path.ends_with('/');
    let mut stack: Vec<&str> = Vec::new();
    let mut last_was_dot_segment = false;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        match segment {
            "." => {
                last_was_dot_segment = true;
            }
            ".." => {
                last_was_dot_segment = true;
                if matches!(stack.last(), Some(&top) if top != "..") {
                    stack.pop();
                }
                else {
                    stack.push("..");
                }
            }
            _ => {
                last_was_dot_segment = false;
                stack.push(segment);
            }
        }
    }
    let mut normalized = format!("/{}", stack.join("/"));
    if !stack.is_empty() && (trailing_slash || last_was_dot_segment) {
        normalized.push('/');
    }
    Ok(normalized)
}

fn validate_and_copy_identifier(
    id_type: SourceFileIdType,
    identifier: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let array: Vec<u8> = if id_type == SourceFileIdType::None {
        Vec::new()
    }
    else {
        identifier.map(|bytes| bytes.to_vec()).unwrap_or_default()
    };
    if array.len() > SourceFileIdType::MAX_LENGTH {
        return Err(format!(
            "identifier array too long; max is {}",
            SourceFileIdType::MAX_LENGTH
        ));
    }
    let expected = id_type.byte_length();
    if expected != 0 && expected != array.len() {
        return Err(format!(
            "identifier array has wrong length for {}",
            java_enum_name(id_type)
        ));
    }
    Ok(array)
}

fn java_enum_name(id_type: SourceFileIdType) -> &'static str {
    match id_type {
        SourceFileIdType::None => "NONE",
        SourceFileIdType::Unknown => "UNKNOWN",
        SourceFileIdType::Timestamp64 => "TIMESTAMP_64",
        SourceFileIdType::Md5 => "MD5",
        SourceFileIdType::Sha1 => "SHA1",
        SourceFileIdType::Sha256 => "SHA256",
        SourceFileIdType::Sha512 => "SHA512",
    }
}

/// Formats a Unix epoch-millisecond timestamp the way `java.time.Instant::toString` does
/// (`DateTimeFormatter.ISO_INSTANT`), e.g. `1970-01-01T00:00:00Z`. Since this is only ever fed a
/// value derived from `Instant.ofEpochMilli`, the fractional part (if any) is always a whole
/// number of milliseconds, so only millisecond-precision fractions need to be produced.
fn format_instant_utc(epoch_millis: i64) -> String {
    const MS_PER_DAY: i64 = 86_400_000;
    let days = epoch_millis.div_euclid(MS_PER_DAY);
    let ms_of_day = epoch_millis.rem_euclid(MS_PER_DAY);
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day / 60_000) % 60;
    let second = (ms_of_day / 1000) % 60;
    let milli = ms_of_day % 1000;
    let (year, month, day) = civil_from_days(days);
    let mut s = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if milli != 0 {
        s.push_str(&format!(".{milli:03}"));
    }
    s.push('Z');
    s
}

/// Converts a day count since the Unix epoch into a proleptic-Gregorian civil date
/// `(year, month, day)`, with a 1-based month and day. Based on Howard Hinnant's
/// `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn compare_identifiers(a: &[u8], b: &[u8]) -> Ordering {
    for (&x, &y) in a.iter().zip(b.iter()) {
        let cmp = (x as i8).cmp(&(y as i8));
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    a.len().cmp(&b.len())
}

impl PartialOrd for SourceFile {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SourceFile {
    /// Mirrors the Java `compareTo`: compares path, then id type, then identifier bytes.
    ///
    /// The identifier comparison mirrors `Arrays.compare(byte[], byte[])`, which compares
    /// Java's signed `byte`s, so bytes are compared as `i8` here rather than `u8`.
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .cmp(&other.path)
            .then_with(|| self.id_type.cmp(&other.id_type))
            .then_with(|| compare_identifiers(&self.identifier, &other.identifier))
    }
}

impl fmt::Display for SourceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path)?;
        if self.id_type == SourceFileIdType::None {
            return Ok(());
        }
        write!(f, " [{}={}]", java_enum_name(self.id_type), self.id_as_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── construction / validation ────────────────────────────────────────────

    #[test]
    fn non_file_path_trailing_slash_fails() {
        assert!(SourceFile::new("/test/dir/").is_err());
    }

    #[test]
    fn relative_path_create_fails() {
        assert!(SourceFile::new("test1/test2.c").is_err());
    }

    #[test]
    fn empty_path_create_fails() {
        assert!(SourceFile::new("").is_err());
        assert!(SourceFile::new("   ").is_err());
    }

    #[test]
    fn path_normalization_linux() {
        let sf = SourceFile::new("/src/test/../dir1/test/../dir2/file.c").unwrap();
        assert_eq!(sf.path(), "/src/dir1/dir2/file.c");
    }

    #[test]
    fn interior_path_normalization_linux_fails() {
        assert!(SourceFile::new("/src/../../../file.c").is_err());
    }

    #[test]
    fn interior_path_normalization_windows_fails() {
        assert!(SourceFile::new("/c:/src/../../../file.c").is_err());
    }

    #[test]
    fn utility_style_normalization() {
        let sf = SourceFile::new("/src/test/../file1.c").unwrap();
        assert_eq!(sf.path(), "/src/file1.c");
        assert_eq!(sf.filename(), "file1.c");

        let sf = SourceFile::new("/C:/Users//guest/./temp/../file.exe").unwrap();
        assert_eq!(sf.path(), "/C:/Users/guest/file.exe");
        assert_eq!(sf.filename(), "file.exe");
    }

    #[test]
    fn new_unvalidated_skips_path_checks_but_still_validates_identifier() {
        // A pre-normalized path (e.g. one already validated by the database) is accepted as-is,
        // even one that a fresh call to `new`/`with_identifier` would reject.
        let sf = SourceFile::new_unvalidated("/already/normalized.c".to_string(), SourceFileIdType::None, None)
            .unwrap();
        assert_eq!(sf.path(), "/already/normalized.c");

        assert!(SourceFile::new_unvalidated(
            "/already/normalized.c".to_string(),
            SourceFileIdType::Md5,
            Some(&[0x01]),
        )
        .is_err());
    }

    #[test]
    fn get_filename() {
        let sf = SourceFile::new("/src/test/file.c").unwrap();
        assert_eq!(sf.filename(), "file.c");
    }

    #[test]
    fn get_uri_matches_java_file_uri_string() {
        let sf = SourceFile::new("/src/test.c").unwrap();
        assert_eq!(sf.uri(), "file:/src/test.c");
    }

    // ── identifier / display string ──────────────────────────────────────────

    #[test]
    fn identifier_display_string() {
        let md5 = hex_bytes("0123456789abcdef0123456789abcdef");
        let sf = SourceFile::with_identifier("/src/test/file.c", SourceFileIdType::Md5, Some(&md5))
            .unwrap();
        assert_eq!(sf.id_type(), SourceFileIdType::Md5);
        assert_eq!(sf.id_as_string(), "0123456789abcdef0123456789abcdef");

        let sf = SourceFile::new("/src/test/file.c").unwrap();
        assert_eq!(sf.id_type(), SourceFileIdType::None);
        assert_eq!(sf.id_as_string(), "");

        let sha1 = hex_bytes("0123456789abcdef0123456789abcdef01234567");
        let sf =
            SourceFile::with_identifier("/src/test/file.c", SourceFileIdType::Sha1, Some(&sha1))
                .unwrap();
        assert_eq!(sf.id_as_string(), "0123456789abcdef0123456789abcdef01234567");

        let sf = SourceFile::with_identifier(
            "/src/test/file.c",
            SourceFileIdType::Timestamp64,
            Some(&0i64.to_be_bytes()),
        )
        .unwrap();
        assert_eq!(sf.id_as_string(), "1970-01-01T00:00:00Z");

        let sf = SourceFile::with_identifier(
            "/src/test/file.c",
            SourceFileIdType::Unknown,
            Some(&[0x12, 0x13]),
        )
        .unwrap();
        assert_eq!(sf.id_as_string(), "1213");
    }

    #[test]
    fn timestamp_display_string_with_millis() {
        let sf = SourceFile::with_identifier(
            "/src/test/file.c",
            SourceFileIdType::Timestamp64,
            Some(&1500i64.to_be_bytes()),
        )
        .unwrap();
        assert_eq!(sf.id_as_string(), "1970-01-01T00:00:01.500Z");
    }

    #[test]
    fn no_identifier_non_null_array_is_ignored() {
        let sf = SourceFile::with_identifier(
            "/src/file.c",
            SourceFileIdType::None,
            Some(&[0x11, 0x22]),
        )
        .unwrap();
        assert_eq!(sf.path(), "/src/file.c");
        assert_eq!(sf.id_type(), SourceFileIdType::None);
        assert_eq!(sf.identifier(), Vec::<u8>::new());
    }

    #[test]
    fn bad_md5_length_fails() {
        assert!(SourceFile::with_identifier(
            "/file.c",
            SourceFileIdType::Md5,
            Some(&[0x11, 0x22])
        )
        .is_err());
    }

    #[test]
    fn md5_null_array_fails() {
        assert!(SourceFile::with_identifier("/file.c", SourceFileIdType::Md5, None).is_err());
    }

    // ── equals / hash / compare ───────────────────────────────────────────────

    #[test]
    fn same_path_different_identifiers_not_equal() {
        let path = "/src/test/file.c";
        let test1 = SourceFile::new(path).unwrap();
        let md5 = hex_bytes("0123456789abcdef0123456789abcdef");
        let test2 =
            SourceFile::with_identifier(path, SourceFileIdType::Md5, Some(&md5)).unwrap();
        assert_ne!(test1, test2);
    }

    #[test]
    fn same_identifier_different_paths_not_equal() {
        let md5 = hex_bytes("0123456789abcdef0123456789abcdef");
        let test1 =
            SourceFile::with_identifier("/src/file1.c", SourceFileIdType::Md5, Some(&md5))
                .unwrap();
        let test2 =
            SourceFile::with_identifier("/src/file2.c", SourceFileIdType::Md5, Some(&md5))
                .unwrap();
        assert_ne!(test1, test2);
    }

    #[test]
    fn compare_orders_by_path_then_id_type_then_identifier() {
        let a = SourceFile::new("/a/file.c").unwrap();
        let b = SourceFile::new("/b/file.c").unwrap();
        assert!(a < b);

        let none = SourceFile::new("/file.c").unwrap();
        let with_id = SourceFile::with_identifier(
            "/file.c",
            SourceFileIdType::Unknown,
            Some(&[0x01]),
        )
        .unwrap();
        assert!(none < with_id);
    }

    #[test]
    fn compare_identifier_bytes_signed() {
        // 0xFF as a Java (signed) byte is -1, which sorts before 0x01.
        let low = SourceFile::with_identifier(
            "/file.c",
            SourceFileIdType::Unknown,
            Some(&[0xFF]),
        )
        .unwrap();
        let high = SourceFile::with_identifier(
            "/file.c",
            SourceFileIdType::Unknown,
            Some(&[0x01]),
        )
        .unwrap();
        assert!(low < high);
    }

    #[test]
    fn to_string_includes_id_type_and_identifier_when_present() {
        let sf = SourceFile::new("/src/file.c").unwrap();
        assert_eq!(sf.to_string(), "/src/file.c");

        let sf = SourceFile::with_identifier(
            "/src/file.c",
            SourceFileIdType::Md5,
            Some(&hex_bytes("0123456789abcdef0123456789abcdef")),
        )
        .unwrap();
        assert_eq!(
            sf.to_string(),
            "/src/file.c [MD5=0123456789abcdef0123456789abcdef]"
        );
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
