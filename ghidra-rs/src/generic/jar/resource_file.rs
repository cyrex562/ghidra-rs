use super::resource::{FileResource, Resource};
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

    pub fn get_file(&self, _copy_if_needed: bool) -> Option<PathBuf> {
        self.resource.get_file()
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
}
