use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

pub trait Resource: Send + Sync {
    fn get_resource(&self, path: &str) -> Box<dyn Resource>;
    fn absolute_path(&self) -> String;
    fn name(&self) -> String;
    fn is_directory(&self) -> bool;
    fn is_file(&self) -> bool;
    fn exists(&self) -> bool;
    fn last_modified(&self) -> u64;
    fn length(&self) -> u64;
    fn get_input_stream(&self) -> io::Result<Box<dyn Read>>;
    fn get_output_stream(&self) -> io::Result<Box<dyn Write>>;
    fn get_file(&self) -> Option<PathBuf>;
}

pub struct FileResource {
    path: PathBuf,
}

impl FileResource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Resource for FileResource {
    fn get_resource(&self, path: &str) -> Box<dyn Resource> {
        Box::new(FileResource::new(self.path.join(path)))
    }

    fn absolute_path(&self) -> String {
        self.path.to_string_lossy().to_string()
    }

    fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    fn is_directory(&self) -> bool {
        self.path.is_dir()
    }

    fn is_file(&self) -> bool {
        self.path.is_file()
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn last_modified(&self) -> u64 {
        fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or(0)
    }

    fn length(&self) -> u64 {
        fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    fn get_input_stream(&self) -> io::Result<Box<dyn Read>> {
        Ok(Box::new(fs::File::open(&self.path)?))
    }

    fn get_output_stream(&self) -> io::Result<Box<dyn Write>> {
        Ok(Box::new(fs::File::create(&self.path)?))
    }

    fn get_file(&self) -> Option<PathBuf> {
        Some(self.path.clone())
    }
}
