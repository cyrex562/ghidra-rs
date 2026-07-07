use std::collections::VecDeque;
use std::path::{Path, PathBuf};

/// Breadth-first recursive directory iterator that yields paths matching a file filter.
///
/// Models `ghidra.pcodeCPort.slgh_compile.DirectoryVisitor`: visits one or more starting
/// directories in BFS order, optionally restricting which subdirectories are descended into
/// via a separate directory filter, and yielding every entry accepted by the file filter.
/// Sorted output (case-sensitive or case-insensitive) matches Java's deterministic ordering.
pub struct DirectoryVisitor {
    starting_directories: Vec<PathBuf>,
    directory_filter: Option<Box<dyn Fn(&Path) -> bool>>,
    filter: Box<dyn Fn(&Path) -> bool>,
    compare_case: bool,
}

impl DirectoryVisitor {
    /// Creates a visitor that descends all subdirectories under `dir`, yielding entries
    /// accepted by `filter` in case-sensitive sorted order.
    pub fn new(dir: PathBuf, filter: impl Fn(&Path) -> bool + 'static) -> Self {
        Self {
            starting_directories: vec![dir],
            directory_filter: None,
            filter: Box::new(filter),
            compare_case: true,
        }
    }

    /// Creates a visitor over multiple starting directories, yielding entries accepted by
    /// `filter` in case-sensitive sorted order.
    pub fn from_dirs(dirs: Vec<PathBuf>, filter: impl Fn(&Path) -> bool + 'static) -> Self {
        Self {
            starting_directories: dirs,
            directory_filter: None,
            filter: Box::new(filter),
            compare_case: true,
        }
    }

    /// Sets whether directory-entry name comparisons for sort order are case-sensitive.
    pub fn with_compare_case(mut self, compare_case: bool) -> Self {
        self.compare_case = compare_case;
        self
    }

    /// Adds a filter controlling which subdirectories are descended into.
    /// Only directories accepted by `df` (in addition to being a directory) are queued.
    pub fn with_directory_filter(mut self, df: impl Fn(&Path) -> bool + 'static) -> Self {
        self.directory_filter = Some(Box::new(df));
        self
    }
}

impl IntoIterator for DirectoryVisitor {
    type Item = PathBuf;
    type IntoIter = BreadthFirstDirectoryVisitor;

    fn into_iter(self) -> Self::IntoIter {
        BreadthFirstDirectoryVisitor::new(
            self.starting_directories,
            self.directory_filter,
            self.filter,
            self.compare_case,
        )
    }
}

/// Iterator produced by [`DirectoryVisitor`]; performs breadth-first traversal.
pub struct BreadthFirstDirectoryVisitor {
    directory_queue: VecDeque<PathBuf>,
    file_queue: VecDeque<PathBuf>,
    directory_filter: Box<dyn Fn(&Path) -> bool>,
    filter: Box<dyn Fn(&Path) -> bool>,
    compare_case: bool,
}

impl BreadthFirstDirectoryVisitor {
    fn new(
        starting_directories: Vec<PathBuf>,
        directory_filter: Option<Box<dyn Fn(&Path) -> bool>>,
        filter: Box<dyn Fn(&Path) -> bool>,
        compare_case: bool,
    ) -> Self {
        let directory_filter: Box<dyn Fn(&Path) -> bool> = match directory_filter {
            None => Box::new(|p: &Path| p.is_dir()),
            Some(df) => Box::new(move |p: &Path| p.is_dir() && df(p)),
        };

        let mut directory_queue = VecDeque::new();
        for dir in starting_directories {
            assert!(dir.is_dir(), "{} is not a directory", dir.display());
            directory_queue.push_back(dir);
        }

        Self {
            directory_queue,
            file_queue: VecDeque::new(),
            directory_filter,
            filter,
            compare_case,
        }
    }

    fn populate_directory_queue(&mut self, directory: &Path) {
        let mut subdirs = Vec::new();
        if let Ok(entries) = std::fs::read_dir(directory) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if (self.directory_filter)(&path) {
                    subdirs.push(path);
                }
            }
        }
        sort_by_name(&mut subdirs, self.compare_case);
        self.directory_queue.extend(subdirs);
    }

    fn populate_file_queue(&mut self, directory: &Path) {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(directory) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if (self.filter)(&path) {
                    files.push(path);
                }
            }
        }
        sort_by_name(&mut files, self.compare_case);
        self.file_queue.extend(files);
    }

    fn ensure_next(&mut self) {
        while self.file_queue.is_empty() && !self.directory_queue.is_empty() {
            let dir = self.directory_queue.pop_front().unwrap();
            self.populate_directory_queue(&dir);
            self.populate_file_queue(&dir);
        }
    }
}

impl Iterator for BreadthFirstDirectoryVisitor {
    type Item = PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        self.ensure_next();
        self.file_queue.pop_front()
    }
}

fn sort_by_name(paths: &mut Vec<PathBuf>, compare_case: bool) {
    if compare_case {
        paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    } else {
        paths.sort_by(|a, b| {
            let a = a
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_lowercase)
                .unwrap_or_default();
            let b = b
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_lowercase)
                .unwrap_or_default();
            a.cmp(&b)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_tree(tmp: &TempDir, structure: &[(&str, bool)]) {
        for (rel, is_dir) in structure {
            let path = tmp.path().join(rel);
            if *is_dir {
                fs::create_dir_all(&path).unwrap();
            } else {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).unwrap();
                }
                fs::write(&path, b"").unwrap();
            }
        }
    }

    fn names(paths: Vec<PathBuf>) -> Vec<String> {
        paths
            .into_iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn yields_matching_files_in_root() {
        let tmp = TempDir::new().unwrap();
        make_tree(&tmp, &[("a.sla", false), ("b.sla", false), ("skip.txt", false)]);

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            });

        let result = names(visitor.into_iter().collect());
        assert_eq!(result, vec!["a.sla", "b.sla"]);
    }

    #[test]
    fn bfs_order_across_subdirectories() {
        let tmp = TempDir::new().unwrap();
        // root/a.sla, root/sub/b.sla — BFS means root files first, then sub files
        make_tree(
            &tmp,
            &[("a.sla", false), ("sub", true), ("sub/b.sla", false)],
        );

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            });

        let result = names(visitor.into_iter().collect());
        assert_eq!(result, vec!["a.sla", "b.sla"]);
    }

    #[test]
    fn bfs_visits_nested_levels() {
        let tmp = TempDir::new().unwrap();
        make_tree(
            &tmp,
            &[
                ("root.sla", false),
                ("sub1", true),
                ("sub1/child.sla", false),
                ("sub2", true),
                ("sub2/other.sla", false),
            ],
        );

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            });

        let result = names(visitor.into_iter().collect());
        // root first, then sub1 and sub2 (BFS), then their children
        assert_eq!(result[0], "root.sla");
        // sub1 and sub2 files follow in sorted order
        let rest: std::collections::HashSet<_> = result[1..].iter().cloned().collect();
        assert!(rest.contains("child.sla"));
        assert!(rest.contains("other.sla"));
    }

    #[test]
    fn sorted_case_sensitive() {
        let tmp = TempDir::new().unwrap();
        make_tree(
            &tmp,
            &[("b.sla", false), ("A.sla", false), ("c.sla", false)],
        );

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            });

        let result = names(visitor.into_iter().collect());
        // Case-sensitive: uppercase 'A' < lowercase 'b' in ASCII order
        assert_eq!(result, vec!["A.sla", "b.sla", "c.sla"]);
    }

    #[test]
    fn sorted_case_insensitive() {
        let tmp = TempDir::new().unwrap();
        make_tree(
            &tmp,
            &[("b.sla", false), ("A.sla", false), ("c.sla", false)],
        );

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            })
            .with_compare_case(false);

        let result = names(visitor.into_iter().collect());
        // Case-insensitive: A, b, c
        assert_eq!(result, vec!["A.sla", "b.sla", "c.sla"]);
    }

    #[test]
    fn directory_filter_restricts_descent() {
        let tmp = TempDir::new().unwrap();
        make_tree(
            &tmp,
            &[
                ("included", true),
                ("included/yes.sla", false),
                ("excluded", true),
                ("excluded/no.sla", false),
            ],
        );

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            })
            .with_directory_filter(|p| {
                p.file_name().and_then(|n| n.to_str()) == Some("included")
            });

        let result = names(visitor.into_iter().collect());
        assert_eq!(result, vec!["yes.sla"]);
    }

    #[test]
    fn multiple_starting_directories() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();
        make_tree(&tmp1, &[("a.sla", false)]);
        make_tree(&tmp2, &[("b.sla", false)]);

        let visitor = DirectoryVisitor::from_dirs(
            vec![tmp1.path().to_path_buf(), tmp2.path().to_path_buf()],
            |p| p.extension().and_then(|e| e.to_str()) == Some("sla"),
        );

        let mut result = names(visitor.into_iter().collect());
        result.sort();
        assert_eq!(result, vec!["a.sla", "b.sla"]);
    }

    #[test]
    fn empty_directory_yields_nothing() {
        let tmp = TempDir::new().unwrap();

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            });

        let result: Vec<_> = visitor.into_iter().collect();
        assert!(result.is_empty());
    }

    #[test]
    fn no_matching_files_yields_nothing() {
        let tmp = TempDir::new().unwrap();
        make_tree(&tmp, &[("readme.txt", false)]);

        let visitor =
            DirectoryVisitor::new(tmp.path().to_path_buf(), |p| {
                p.extension().and_then(|e| e.to_str()) == Some("sla")
            });

        let result: Vec<_> = visitor.into_iter().collect();
        assert!(result.is_empty());
    }

    #[test]
    #[should_panic]
    fn panics_on_non_directory_start() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("not_a_dir.txt");
        fs::write(&file_path, b"").unwrap();

        let visitor = DirectoryVisitor::new(file_path, |_| true);
        let _: Vec<_> = visitor.into_iter().collect();
    }
}
