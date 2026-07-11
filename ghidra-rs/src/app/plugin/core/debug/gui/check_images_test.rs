//! Port of CheckImagesTest — verifies no PNG help images are zero-length.

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn find_empty_pngs(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
        let mut empty = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            for entry in std::fs::read_dir(&current)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().map_or(false, |ext| ext == "png") {
                    if path.metadata()?.len() == 0 {
                        empty.push(path);
                    }
                }
            }
        }
        Ok(empty)
    }

    #[test]
    fn test_check_for_empty_images() {
        let help_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../orig_src/Ghidra/Debug/Debugger/src/main/help");
        let empty = find_empty_pngs(&help_dir).expect("failed to walk help directory");
        assert!(
            empty.is_empty(),
            "found empty PNG images: {:?}",
            empty
        );
    }
}
