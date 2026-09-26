use super::resource_file::ResourceFile;

pub trait ResourceFileFilter: Send + Sync {
    fn accept(&self, file: &ResourceFile) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TxtFilter;

    impl ResourceFileFilter for TxtFilter {
        fn accept(&self, file: &ResourceFile) -> bool {
            file.name().ends_with(".txt")
        }
    }

    #[test]
    fn test_accepts_txt_file() {
        let filter = TxtFilter;
        let file = ResourceFile::new(PathBuf::from("data.txt"));
        assert!(filter.accept(&file));
    }

    #[test]
    fn test_rejects_non_txt_file() {
        let filter = TxtFilter;
        let file = ResourceFile::new(PathBuf::from("data.bin"));
        assert!(!filter.accept(&file));
    }
}
