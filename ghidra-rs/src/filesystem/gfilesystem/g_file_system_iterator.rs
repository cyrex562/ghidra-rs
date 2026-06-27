use std::collections::VecDeque;
use std::io;

use super::g_file::GFile;

/// Iterates over the [`GFile`]s in a filesystem depth-first, yielding only
/// non-directory files.
///
/// An optional filter predicate can exclude files from the results.  Directory
/// traversal is always exhaustive — the filter applies only to leaf files, not
/// to which directories are entered.
///
/// Each call to [`Iterator::next`] may perform I/O to expand a directory listing.
/// I/O failures are surfaced as `Some(Err(…))`; exhaustion is signalled by `None`.
///
/// Files within each directory are yielded in alphabetical (ascending) order;
/// subdirectories are also processed in alphabetical order before sibling
/// subdirectories that come later in the alphabet.
pub struct GFileSystemIterator<FS, Fsrl> {
    file_deque: VecDeque<Box<dyn GFile<FS, Fsrl>>>,
    dir_deque: VecDeque<Box<dyn GFile<FS, Fsrl>>>,
    filter: Box<dyn Fn(&dyn GFile<FS, Fsrl>) -> bool>,
}

impl<FS: 'static, Fsrl: 'static> GFileSystemIterator<FS, Fsrl> {
    /// Creates an iterator over all files in `dir` in depth-first order.
    ///
    /// # Errors
    /// Returns an error if `dir` is not a directory.
    pub fn new(dir: Box<dyn GFile<FS, Fsrl>>) -> io::Result<Self> {
        Self::with_filter(dir, |_| true)
    }

    /// Creates an iterator that applies `filter` to each non-directory file before
    /// yielding it.  Directories are always recursed regardless of `filter`.
    ///
    /// # Errors
    /// Returns an error if `dir` is not a directory.
    pub fn with_filter<F>(dir: Box<dyn GFile<FS, Fsrl>>, filter: F) -> io::Result<Self>
    where
        F: Fn(&dyn GFile<FS, Fsrl>) -> bool + 'static,
    {
        if !dir.is_directory() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid starting directory!",
            ));
        }
        let mut dir_deque = VecDeque::new();
        dir_deque.push_front(dir);
        Ok(Self {
            file_deque: VecDeque::new(),
            dir_deque,
            filter: Box::new(filter),
        })
    }

    /// Populate `file_deque` by expanding directories until either a non-empty batch
    /// of files is found or all directories are exhausted.
    ///
    /// Mirrors `GFileSystemIterator.queueNextFiles()` from the Java source:
    /// subdirectories and files are sorted in reverse alphabetical order and pushed
    /// to the front of their respective deques, yielding alphabetical pop-order.
    fn queue_next_files(&mut self) -> io::Result<()> {
        while self.file_deque.is_empty() && !self.dir_deque.is_empty() {
            let dir = self.dir_deque.pop_front().unwrap();
            let listing = dir.get_listing()?;

            let (mut dirs, files): (Vec<_>, Vec<_>) =
                listing.into_iter().partition(|f| f.is_directory());

            // Reverse-sort then push_front → alphabetical ascending pop order.
            dirs.sort_by(|a, b| b.get_name().cmp(a.get_name()));
            for d in dirs {
                self.dir_deque.push_front(d);
            }

            let mut filtered: Vec<_> = files
                .into_iter()
                .filter(|f| (self.filter)(f.as_ref()))
                .collect();
            filtered.sort_by(|a, b| b.get_name().cmp(a.get_name()));
            for f in filtered {
                self.file_deque.push_front(f);
            }
        }
        Ok(())
    }
}

impl<FS: 'static, Fsrl: 'static> Iterator for GFileSystemIterator<FS, Fsrl> {
    type Item = io::Result<Box<dyn GFile<FS, Fsrl>>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.queue_next_files() {
            Err(e) => Some(Err(e)),
            Ok(()) if self.file_deque.is_empty() => None,
            Ok(()) => Some(Ok(self.file_deque.pop_front().unwrap())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ── Mock types ────────────────────────────────────────────────────────────

    struct MockFs;
    struct MockFsrl;

    struct MockFileData {
        name: String,
        is_dir: bool,
        children: Vec<Arc<MockFileData>>,
        fail_listing: bool,
    }

    struct MockFile {
        data: Arc<MockFileData>,
        fs: MockFs,
        fsrl: MockFsrl,
    }

    impl MockFile {
        fn new(data: Arc<MockFileData>) -> Self {
            MockFile {
                data,
                fs: MockFs,
                fsrl: MockFsrl,
            }
        }

        fn file(name: &str) -> Arc<MockFileData> {
            Arc::new(MockFileData {
                name: name.to_owned(),
                is_dir: false,
                children: vec![],
                fail_listing: false,
            })
        }

        fn dir(name: &str, children: Vec<Arc<MockFileData>>) -> Arc<MockFileData> {
            Arc::new(MockFileData {
                name: name.to_owned(),
                is_dir: true,
                children,
                fail_listing: false,
            })
        }

        fn failing_dir(name: &str) -> Arc<MockFileData> {
            Arc::new(MockFileData {
                name: name.to_owned(),
                is_dir: true,
                children: vec![],
                fail_listing: true,
            })
        }

        fn boxed(data: Arc<MockFileData>) -> Box<dyn GFile<MockFs, MockFsrl>> {
            Box::new(MockFile::new(data))
        }
    }

    impl GFile<MockFs, MockFsrl> for MockFile {
        fn get_filesystem(&self) -> &MockFs {
            &self.fs
        }

        fn get_fsrl(&self) -> &MockFsrl {
            &self.fsrl
        }

        fn get_parent_file(&self) -> Option<&dyn GFile<MockFs, MockFsrl>> {
            None
        }

        fn get_path(&self) -> &str {
            &self.data.name
        }

        fn get_name(&self) -> &str {
            &self.data.name
        }

        fn is_directory(&self) -> bool {
            self.data.is_dir
        }

        fn get_length(&self) -> i64 {
            -1
        }

        fn get_listing(&self) -> io::Result<Vec<Box<dyn GFile<MockFs, MockFsrl>>>> {
            if self.data.fail_listing {
                return Err(io::Error::new(io::ErrorKind::Other, "listing failed"));
            }
            Ok(self
                .data
                .children
                .iter()
                .map(|c| MockFile::boxed(Arc::clone(c)))
                .collect())
        }
    }

    fn collect_names(
        iter: GFileSystemIterator<MockFs, MockFsrl>,
    ) -> io::Result<Vec<String>> {
        iter.map(|r| r.map(|f| f.get_name().to_owned())).collect()
    }

    // ── Construction ──────────────────────────────────────────────────────────

    #[test]
    fn new_with_non_directory_returns_error() {
        let file = MockFile::boxed(MockFile::file("not_a_dir.txt"));
        let result = GFileSystemIterator::new(file);
        let err = result.err().expect("expected error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn with_filter_with_non_directory_returns_error() {
        let file = MockFile::boxed(MockFile::file("not_a_dir.txt"));
        let result = GFileSystemIterator::with_filter(file, |_| true);
        assert!(result.is_err());
    }

    #[test]
    fn new_with_directory_succeeds() {
        let root = MockFile::boxed(MockFile::dir("root", vec![]));
        assert!(GFileSystemIterator::new(root).is_ok());
    }

    // ── Empty / trivial cases ─────────────────────────────────────────────────

    #[test]
    fn empty_directory_yields_nothing() {
        let root = MockFile::boxed(MockFile::dir("root", vec![]));
        let iter = GFileSystemIterator::new(root).unwrap();
        assert_eq!(collect_names(iter).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn directory_with_only_subdirectories_and_no_files_yields_nothing() {
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![MockFile::dir("a", vec![]), MockFile::dir("b", vec![])],
        ));
        let iter = GFileSystemIterator::new(root).unwrap();
        assert_eq!(collect_names(iter).unwrap(), Vec::<String>::new());
    }

    // ── Ordering ──────────────────────────────────────────────────────────────

    #[test]
    fn files_in_single_directory_are_alphabetically_ordered() {
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![
                MockFile::file("c.txt"),
                MockFile::file("a.txt"),
                MockFile::file("b.txt"),
            ],
        ));
        let iter = GFileSystemIterator::new(root).unwrap();
        assert_eq!(collect_names(iter).unwrap(), vec!["a.txt", "b.txt", "c.txt"]);
    }

    // ── Depth-first traversal ─────────────────────────────────────────────────

    #[test]
    fn depth_first_processes_subdirectory_before_sibling_subdir() {
        // root/
        //   b/
        //     file_b.txt
        //   a/
        //     file_a.txt
        // Expected depth-first alphabetical: file_a.txt, file_b.txt
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![
                MockFile::dir("b", vec![MockFile::file("file_b.txt")]),
                MockFile::dir("a", vec![MockFile::file("file_a.txt")]),
            ],
        ));
        let iter = GFileSystemIterator::new(root).unwrap();
        assert_eq!(
            collect_names(iter).unwrap(),
            vec!["file_a.txt", "file_b.txt"]
        );
    }

    #[test]
    fn nested_directories_are_fully_expanded_before_siblings() {
        // root/
        //   b/
        //     file_b.txt
        //   a/
        //     inner/
        //       file_inner.txt
        //     file_a.txt
        // Depth-first alphabetical: file_inner.txt, file_a.txt, file_b.txt
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![
                MockFile::dir("b", vec![MockFile::file("file_b.txt")]),
                MockFile::dir(
                    "a",
                    vec![
                        MockFile::dir("inner", vec![MockFile::file("file_inner.txt")]),
                        MockFile::file("file_a.txt"),
                    ],
                ),
            ],
        ));
        let iter = GFileSystemIterator::new(root).unwrap();
        assert_eq!(
            collect_names(iter).unwrap(),
            vec!["file_inner.txt", "file_a.txt", "file_b.txt"]
        );
    }

    // ── Filter ────────────────────────────────────────────────────────────────

    #[test]
    fn filter_excludes_non_matching_files() {
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![
                MockFile::file("keep.txt"),
                MockFile::file("discard.bin"),
                MockFile::file("also_keep.txt"),
            ],
        ));
        let iter =
            GFileSystemIterator::with_filter(root, |f| f.get_name().ends_with(".txt")).unwrap();
        assert_eq!(
            collect_names(iter).unwrap(),
            vec!["also_keep.txt", "keep.txt"]
        );
    }

    #[test]
    fn filter_applies_only_to_files_not_directories() {
        // filter rejects everything — but directories should still be entered
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![MockFile::dir("subdir", vec![MockFile::file("hidden.txt")])],
        ));
        let iter = GFileSystemIterator::with_filter(root, |_| false).unwrap();
        assert_eq!(collect_names(iter).unwrap(), Vec::<String>::new());
    }

    // ── I/O error handling ────────────────────────────────────────────────────

    #[test]
    fn io_error_from_get_listing_is_yielded_as_err() {
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![MockFile::failing_dir("bad")],
        ));
        let mut iter = GFileSystemIterator::new(root).unwrap();
        let first = iter.next().expect("should yield something");
        let err = first.err().expect("expected IO error");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn iteration_continues_after_io_error_from_sibling_directory() {
        // root/
        //   bad/    ← listing fails
        //   good/
        //     file.txt
        // After the error from "bad", the iterator should still yield file.txt
        // from the "good" sibling (alphabetical: bad < good, so bad goes first).
        let root = MockFile::boxed(MockFile::dir(
            "root",
            vec![
                MockFile::failing_dir("bad"),
                MockFile::dir("good", vec![MockFile::file("file.txt")]),
            ],
        ));
        let mut iter = GFileSystemIterator::new(root).unwrap();

        let first = iter.next().unwrap();
        assert!(first.is_err(), "expected error from bad/");

        let second = iter.next().unwrap();
        assert_eq!(second.unwrap().get_name(), "file.txt");

        assert!(iter.next().is_none());
    }
}
