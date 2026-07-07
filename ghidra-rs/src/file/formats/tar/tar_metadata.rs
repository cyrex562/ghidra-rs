/// Kind of entry within a tar archive.
///
/// Mirrors the subset of `TarArchiveEntry` entry-type predicates used by Ghidra
/// (`isFile`, `isDirectory`, `isSymbolicLink`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryType {
    File,
    Directory,
    SymbolicLink,
    Unknown,
}

/// Snapshot of the metadata for a single tar archive entry.
///
/// This is the Rust counterpart to
/// `org.apache.commons.compress.archivers.tar.TarArchiveEntry`, carrying only
/// the fields that Ghidra's tar file-system accesses.
#[derive(Debug, Clone)]
pub struct TarArchiveEntry {
    /// Path/name of the entry as stored in the archive.
    pub name: String,
    /// Uncompressed data size in bytes.
    pub size: u64,
    /// Unix permission bits.
    pub mode: u32,
    /// Numeric user ID.
    pub uid: u64,
    /// Numeric group ID.
    pub gid: u64,
    /// User name string.
    pub user_name: String,
    /// Group name string.
    pub group_name: String,
    /// Last-modification time as seconds since the Unix epoch.
    pub mtime: u64,
    /// Entry type (file, directory, symbolic link, or unknown).
    pub entry_type: TarEntryType,
    /// Symlink target; empty string when `entry_type != SymbolicLink`.
    pub link_name: String,
}

impl TarArchiveEntry {
    /// Creates a new entry with all metadata fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: String,
        size: u64,
        mode: u32,
        uid: u64,
        gid: u64,
        user_name: String,
        group_name: String,
        mtime: u64,
        entry_type: TarEntryType,
        link_name: String,
    ) -> Self {
        Self { name, size, mode, uid, gid, user_name, group_name, mtime, entry_type, link_name }
    }

    /// Returns the entry's path as stored in the archive.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the uncompressed data size in bytes.
    pub fn get_size(&self) -> u64 {
        self.size
    }

    /// Returns the Unix permission bits.
    pub fn get_mode(&self) -> u32 {
        self.mode
    }

    /// Returns the numeric user ID.
    pub fn get_long_user_id(&self) -> u64 {
        self.uid
    }

    /// Returns the numeric group ID.
    pub fn get_long_group_id(&self) -> u64 {
        self.gid
    }

    /// Returns the user name string.
    pub fn get_user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns the group name string.
    pub fn get_group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns the last-modification time as seconds since the Unix epoch.
    pub fn get_mtime(&self) -> u64 {
        self.mtime
    }

    /// Returns `true` when this entry is a regular file.
    pub fn is_file(&self) -> bool {
        self.entry_type == TarEntryType::File
    }

    /// Returns `true` when this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.entry_type == TarEntryType::Directory
    }

    /// Returns `true` when this entry is a symbolic link.
    pub fn is_symbolic_link(&self) -> bool {
        self.entry_type == TarEntryType::SymbolicLink
    }

    /// Returns the symlink target, or an empty string for non-symlink entries.
    pub fn get_link_name(&self) -> &str {
        &self.link_name
    }
}

/// Internal metadata pairing a tar archive entry with its sequential position.
///
/// Mirrors `ghidra.file.formats.tar.TarMetadata`.
/// Package-private in Java; used by `TarFileSystem` to associate a parsed
/// [`TarArchiveEntry`] with its zero-based ordinal position in the archive so
/// that the file can be re-located during random access.
#[derive(Debug, Clone)]
pub struct TarMetadata {
    /// The archive entry header and metadata.
    pub tar_archive_entry: TarArchiveEntry,
    /// Zero-based ordinal position of the entry in the archive stream.
    pub file_num: i32,
}

impl TarMetadata {
    /// Creates a new [`TarMetadata`] pairing `tae` with its ordinal `file_num`.
    ///
    /// Mirrors `TarMetadata(TarArchiveEntry tae, int fileNum)`.
    pub fn new(tae: TarArchiveEntry, file_num: i32) -> Self {
        Self { tar_archive_entry: tae, file_num }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, size: u64, entry_type: TarEntryType) -> TarArchiveEntry {
        TarArchiveEntry::new(
            name.to_string(),
            size,
            0o644,
            1000,
            1000,
            "user".to_string(),
            "group".to_string(),
            1_700_000_000,
            entry_type,
            String::new(),
        )
    }

    #[test]
    fn new_stores_entry_and_file_num() {
        let entry = make_entry("etc/passwd", 1024, TarEntryType::File);
        let md = TarMetadata::new(entry, 3);
        assert_eq!(md.file_num, 3);
        assert_eq!(md.tar_archive_entry.get_name(), "etc/passwd");
        assert_eq!(md.tar_archive_entry.get_size(), 1024);
    }

    #[test]
    fn file_num_zero_is_valid() {
        let entry = make_entry("boot/", 0, TarEntryType::Directory);
        let md = TarMetadata::new(entry, 0);
        assert_eq!(md.file_num, 0);
        assert!(md.tar_archive_entry.is_directory());
    }

    #[test]
    fn symlink_entry_preserves_link_name() {
        let mut entry = make_entry("lib/libc.so", 0, TarEntryType::SymbolicLink);
        entry.link_name = "/lib/x86_64-linux-gnu/libc.so.6".to_string();
        let md = TarMetadata::new(entry, 7);
        assert!(md.tar_archive_entry.is_symbolic_link());
        assert_eq!(md.tar_archive_entry.get_link_name(), "/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(md.file_num, 7);
    }

    #[test]
    fn entry_type_predicates_are_exclusive() {
        let file = make_entry("a.txt", 100, TarEntryType::File);
        assert!(file.is_file());
        assert!(!file.is_directory());
        assert!(!file.is_symbolic_link());

        let dir = make_entry("dir/", 0, TarEntryType::Directory);
        assert!(!dir.is_file());
        assert!(dir.is_directory());
        assert!(!dir.is_symbolic_link());

        let sym = make_entry("link", 0, TarEntryType::SymbolicLink);
        assert!(!sym.is_file());
        assert!(!sym.is_directory());
        assert!(sym.is_symbolic_link());
    }

    #[test]
    fn entry_metadata_accessors() {
        let entry = TarArchiveEntry::new(
            "home/user/.bashrc".to_string(),
            512,
            0o600,
            1001,
            1001,
            "alice".to_string(),
            "alice".to_string(),
            1_234_567_890,
            TarEntryType::File,
            String::new(),
        );
        assert_eq!(entry.get_name(), "home/user/.bashrc");
        assert_eq!(entry.get_size(), 512);
        assert_eq!(entry.get_mode(), 0o600);
        assert_eq!(entry.get_long_user_id(), 1001);
        assert_eq!(entry.get_long_group_id(), 1001);
        assert_eq!(entry.get_user_name(), "alice");
        assert_eq!(entry.get_group_name(), "alice");
        assert_eq!(entry.get_mtime(), 1_234_567_890);
        assert_eq!(entry.get_link_name(), "");
    }

    #[test]
    fn large_file_num_is_stored() {
        let entry = make_entry("data/big.bin", u64::MAX, TarEntryType::File);
        let md = TarMetadata::new(entry, i32::MAX);
        assert_eq!(md.file_num, i32::MAX);
        assert_eq!(md.tar_archive_entry.get_size(), u64::MAX);
    }
}
