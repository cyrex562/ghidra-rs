//! Port of `ghidra.program.model.sourcemap.SourcePathTransformer`.

use crate::program::database::sourcemap::SourceFile;
use crate::program::model::sourcemap::SourcePathTransformRecord;

/// `SourcePathTransformer`s are used to transform [`SourceFile`] paths. The intended use is
/// to transform the path of a `SourceFile` in a program's source file manager before sending
/// the path to an IDE.
///
/// There are two types of transformations: file and directory. File transforms map a
/// particular `SourceFile` to an absolute file path. Directory transforms transform an
/// initial segment of a path. For example, the directory transform `"/c:/users/"` ->
/// `"/src/test/"` sends `"/c:/users/dir/file1.c"` to `"/src/test/dir/file1.c"`.
pub trait SourcePathTransformer {
    /// Adds a new file transform. Any existing file transform for `source_file` is
    /// overwritten. `path` must be a valid, normalized file path (with forward slashes).
    fn add_file_transform(&mut self, source_file: &SourceFile, path: &str);

    /// Removes any file transform for `source_file`.
    fn remove_file_transform(&mut self, source_file: &SourceFile);

    /// Adds a new directory transform. Any existing directory transform for `source_dir` is
    /// overwritten. `source_dir` and `target_dir` must be valid, normalized directory paths
    /// (with forward slashes).
    fn add_directory_transform(&mut self, source_dir: &str, target_dir: &str);

    /// Removes any directory transform associated with `source_dir`.
    fn remove_directory_transform(&mut self, source_dir: &str);

    /// Returns the transformed path for `source_file`. The transformed path is determined as
    /// follows:
    /// - If there is a file transform for `source_file`, the file transform is applied.
    /// - Otherwise, the most specific directory transform (i.e., longest source directory
    ///   string) is applied.
    /// - If no directory transform applies, `use_existing_as_default` determines whether
    ///   `source_file`'s path or `None` is returned.
    fn get_transformed_path(
        &self,
        source_file: &SourceFile,
        use_existing_as_default: bool,
    ) -> Option<String>;

    /// Returns a list of all [`SourcePathTransformRecord`]s.
    fn get_transform_records(&self) -> Vec<SourcePathTransformRecord>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockSourcePathTransformer {
        file_transforms: HashMap<SourceFile, String>,
        directory_transforms: HashMap<String, String>,
    }

    impl SourcePathTransformer for MockSourcePathTransformer {
        fn add_file_transform(&mut self, source_file: &SourceFile, path: &str) {
            self.file_transforms.insert(source_file.clone(), path.to_string());
        }

        fn remove_file_transform(&mut self, source_file: &SourceFile) {
            self.file_transforms.remove(source_file);
        }

        fn add_directory_transform(&mut self, source_dir: &str, target_dir: &str) {
            self.directory_transforms.insert(source_dir.to_string(), target_dir.to_string());
        }

        fn remove_directory_transform(&mut self, source_dir: &str) {
            self.directory_transforms.remove(source_dir);
        }

        fn get_transformed_path(
            &self,
            source_file: &SourceFile,
            use_existing_as_default: bool,
        ) -> Option<String> {
            if let Some(path) = self.file_transforms.get(source_file) {
                return Some(path.clone());
            }

            let mut best: Option<(&str, &str)> = None;
            for (src_dir, target_dir) in &self.directory_transforms {
                if source_file.path().starts_with(src_dir.as_str())
                    && best.map_or(true, |(b, _)| src_dir.len() > b.len())
                {
                    best = Some((src_dir.as_str(), target_dir.as_str()));
                }
            }

            if let Some((src_dir, target_dir)) = best {
                let suffix = &source_file.path()[src_dir.len()..];
                return Some(format!("{target_dir}{suffix}"));
            }

            if use_existing_as_default {
                Some(source_file.path().to_string())
            }
            else {
                None
            }
        }

        fn get_transform_records(&self) -> Vec<SourcePathTransformRecord> {
            let mut records: Vec<SourcePathTransformRecord> = self
                .file_transforms
                .iter()
                .map(|(sf, target)| {
                    SourcePathTransformRecord::new(
                        sf.path().to_string(),
                        Some(sf.clone()),
                        target.clone(),
                    )
                })
                .collect();
            records.extend(
                self.directory_transforms
                    .iter()
                    .map(|(src, target)| SourcePathTransformRecord::new(src.clone(), None, target.clone())),
            );
            records
        }
    }

    #[test]
    fn file_transform_overrides_directory_transform() {
        let mut transformer = MockSourcePathTransformer::default();
        let source_file = SourceFile::new("/src/main/file.c").unwrap();

        transformer.add_directory_transform("/src/", "/target/");
        assert_eq!(
            transformer.get_transformed_path(&source_file, false),
            Some("/target/main/file.c".to_string())
        );

        transformer.add_file_transform(&source_file, "/exact/file.c");
        assert_eq!(
            transformer.get_transformed_path(&source_file, false),
            Some("/exact/file.c".to_string())
        );

        transformer.remove_file_transform(&source_file);
        assert_eq!(
            transformer.get_transformed_path(&source_file, false),
            Some("/target/main/file.c".to_string())
        );
    }

    #[test]
    fn most_specific_directory_transform_wins() {
        let mut transformer = MockSourcePathTransformer::default();
        let source_file = SourceFile::new("/src/main/dir/file.c").unwrap();

        transformer.add_directory_transform("/src/", "/generic/");
        transformer.add_directory_transform("/src/main/dir/", "/specific/");

        assert_eq!(
            transformer.get_transformed_path(&source_file, false),
            Some("/specific/file.c".to_string())
        );
    }

    #[test]
    fn no_transform_uses_default_flag() {
        let transformer = MockSourcePathTransformer::default();
        let source_file = SourceFile::new("/no/transform/file.c").unwrap();

        assert_eq!(transformer.get_transformed_path(&source_file, false), None);
        assert_eq!(
            transformer.get_transformed_path(&source_file, true),
            Some("/no/transform/file.c".to_string())
        );
    }

    #[test]
    fn transform_records_reflect_added_transforms() {
        let mut transformer = MockSourcePathTransformer::default();
        transformer.add_directory_transform("/src/", "/target/");

        let records = transformer.get_transform_records();
        assert_eq!(records.len(), 1);
        assert!(records[0].is_directory_transform());
        assert_eq!(records[0].source(), "/src/");
        assert_eq!(records[0].target(), "/target/");
    }

    #[test]
    fn is_object_safe_as_trait_object() {
        let mut transformer: Box<dyn SourcePathTransformer> =
            Box::new(MockSourcePathTransformer::default());
        let source_file = SourceFile::new("/a/b/file.c").unwrap();
        transformer.add_file_transform(&source_file, "/z/file.c");
        assert_eq!(
            transformer.get_transformed_path(&source_file, false),
            Some("/z/file.c".to_string())
        );
    }
}
