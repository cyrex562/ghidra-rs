use super::resource::{FileResource, Resource};
use super::resource_file_filter::ResourceFileFilter;
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub struct ResourceFile {
    resource: Box<dyn Resource>,
}

impl ResourceFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            resource: Box::new(FileResource::new(path)),
        }
    }

    pub fn from_resource(resource: Box<dyn Resource>) -> Self {
        Self { resource }
    }

    pub fn join(&self, path: &str) -> Self {
        Self::from_resource(self.resource.get_resource(path))
    }

    pub fn absolute_path(&self) -> String {
        self.resource.absolute_path()
    }

    pub fn name(&self) -> String {
        self.resource.name()
    }

    pub fn is_directory(&self) -> bool {
        self.resource.is_directory()
    }

    pub fn is_file(&self) -> bool {
        self.resource.is_file()
    }

    pub fn exists(&self) -> bool {
        self.resource.exists()
    }

    pub fn last_modified(&self) -> u64 {
        self.resource.last_modified()
    }

    pub fn length(&self) -> u64 {
        self.resource.length()
    }

    pub fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
        self.resource.get_input_stream()
    }

    pub fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
        self.resource.get_output_stream()
    }

    /// Port of `ResourceFile.getFile(boolean)`. When `copy_if_needed` is true, this delegates to
    /// [`Resource::resource_as_file`] (Java: `resource.getResourceAsFile(this)`); otherwise to
    /// [`Resource::get_file`] (Java: `resource.getFile()`, `null` for a compressed-filesystem
    /// entry). For the currently sole implementor, [`FileResource`], both branches return the
    /// same path (see [`FileResource::resource_as_file`]'s docs on the Java quirk it preserves).
    pub fn get_file(&self, copy_if_needed: bool) -> Option<PathBuf> {
        if copy_if_needed {
            Some(self.resource.resource_as_file(self))
        } else {
            self.resource.get_file()
        }
    }

    /// Port of `ResourceFile.listFiles()`.
    pub fn list_files(&self) -> Option<Vec<ResourceFile>> {
        self.resource.list_files()
    }

    /// Port of `ResourceFile.listFiles(ResourceFileFilter)`.
    pub fn list_files_filtered(&self, filter: &dyn ResourceFileFilter) -> Option<Vec<ResourceFile>> {
        self.resource.list_files_filtered(filter)
    }

    /// Port of `ResourceFile.getParentFile()`.
    pub fn get_parent_file(&self) -> Option<ResourceFile> {
        self.resource.parent().map(ResourceFile::from_resource)
    }

    /// Port of `ResourceFile.toURL()`.
    pub fn to_url(&self) -> io::Result<String> {
        self.resource.to_url()
    }

    /// Port of `ResourceFile.toURI()`.
    pub fn to_uri(&self) -> String {
        self.resource.to_uri()
    }

    /// Port of `ResourceFile.delete()`.
    pub fn delete(&self) -> bool {
        self.resource.delete()
    }

    /// Port of `ResourceFile.getCanonicalPath()`.
    pub fn canonical_path(&self) -> io::Result<String> {
        self.resource.canonical_path()
    }

    /// Port of `ResourceFile.getCanonicalFile()`.
    pub fn get_canonical_file(&self) -> ResourceFile {
        ResourceFile::from_resource(self.resource.canonical_resource())
    }

    /// Port of `ResourceFile.canWrite()`.
    pub fn can_write(&self) -> bool {
        self.resource.can_write()
    }

    /// Port of `ResourceFile.mkdir()`.
    pub fn mkdir(&self) -> bool {
        self.resource.mkdir()
    }

    /// Port of `ResourceFile.getFileSystemRoot()`.
    pub fn get_file_system_root(&self) -> PathBuf {
        self.resource.file_system_root()
    }
}

impl Clone for ResourceFile {
    fn clone(&self) -> Self {
        // This is tricky because Resource is a trait object.
        // For now, let's assume standard files and just use the path if it's a FileResource.
        // Or we can add a clone_box to the Resource trait.
        if let Some(path) = self.resource.get_file() {
            return Self::new(path);
        }
        panic!("Cloning non-file ResourceFile not yet supported");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_resource_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let rf = ResourceFile::new(file_path);
        assert!(rf.exists());
        assert!(rf.is_file());
        assert_eq!(rf.name(), "test.txt");
        assert_eq!(rf.length(), 5);

        let mut content = String::new();
        rf.get_input_stream()
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "hello");
    }

    #[test]
    fn get_file_true_and_false_agree_for_a_plain_file_resource() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "hello").unwrap();

        let rf = ResourceFile::new(file_path.clone());
        assert_eq!(rf.get_file(false), Some(file_path.clone()));
        assert_eq!(rf.get_file(true), Some(file_path));
    }

    #[test]
    fn list_files_and_get_parent_file_round_trip() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("child.txt"), "x").unwrap();

        let rf = ResourceFile::new(dir.path().to_path_buf());
        let children = rf.list_files().expect("directory should list");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name(), "child.txt");

        let parent = children[0].get_parent_file().expect("child should have a parent");
        assert_eq!(parent.absolute_path(), rf.absolute_path());
    }

    #[test]
    fn list_files_filtered_applies_the_filter() {
        struct TxtOnly;
        impl crate::generic::jar::resource_file_filter::ResourceFileFilter for TxtOnly {
            fn accept(&self, file: &ResourceFile) -> bool {
                file.name().ends_with(".txt")
            }
        }

        let dir = tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("b.bin"), "b").unwrap();

        let rf = ResourceFile::new(dir.path().to_path_buf());
        let filtered = rf.list_files_filtered(&TxtOnly).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name(), "a.txt");
    }

    #[test]
    fn delete_mkdir_and_can_write_round_trip() {
        let dir = tempdir().unwrap();
        let new_dir = dir.path().join("child");
        let rf = ResourceFile::new(new_dir.clone());
        assert!(rf.mkdir());
        assert!(new_dir.is_dir());

        let file_path = dir.path().join("f.txt");
        fs::write(&file_path, "x").unwrap();
        let file_rf = ResourceFile::new(file_path.clone());
        assert!(file_rf.can_write());
        assert!(file_rf.delete());
        assert!(!file_path.exists());
    }

    #[test]
    fn canonical_path_and_canonical_file_resolve_an_existing_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("real.txt");
        fs::write(&file_path, "x").unwrap();

        let rf = ResourceFile::new(file_path.clone());
        assert!(rf.canonical_path().is_ok());
        let canonical = rf.get_canonical_file();
        assert_eq!(canonical.get_file(false), Some(file_path.canonicalize().unwrap()));
    }

    #[test]
    fn to_uri_and_to_url_are_file_prefixed() {
        let rf = ResourceFile::new(PathBuf::from("/tmp/thing.txt"));
        assert_eq!(rf.to_uri(), "file:///tmp/thing.txt");
        assert_eq!(rf.to_url().unwrap(), "file:///tmp/thing.txt");
    }

    #[test]
    fn get_file_system_root_of_an_absolute_path_is_root() {
        let rf = ResourceFile::new(PathBuf::from("/tmp/a/b"));
        assert_eq!(rf.get_file_system_root(), PathBuf::from("/"));
    }
}
