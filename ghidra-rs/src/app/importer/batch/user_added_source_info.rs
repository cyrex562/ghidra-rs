//! Port of `ghidra.plugins.importer.batch.UserAddedSourceInfo`.

use crate::filesystem::gfilesystem::fsrl::Fsrl;

/// Index of a [`UserAddedSourceInfo`] in the list of user-added sources owned by the batch
/// import session.
///
/// Java shares one mutable `UserAddedSourceInfo` object between the session's source list and
/// every `BatchLoadConfig` discovered under that source, and bumps its counters while recursing.
/// Here the session owns the `UserAddedSourceInfo` values and everything else refers to one by
/// this `Copy` ID (arena + typed ID, per `OWNERSHIP_MIGRATION.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserAddedSourceInfoId(pub usize);

/// Statistics about a file (or container) the user added to a batch import, accumulated while
/// the batch import recursively probes it.
///
/// Port of `ghidra.plugins.importer.batch.UserAddedSourceInfo`. Java's plain get/set bean pairs
/// are public fields here; the FSRL is fixed at construction and read with [`Self::get_fsrl`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAddedSourceInfo {
    fsrl: Fsrl,
    /// Number of importable files found under this source.
    pub file_count: i32,
    /// Number of raw files examined under this source.
    pub raw_file_count: i32,
    /// Number of containers (nested file systems) opened under this source.
    pub container_count: i32,
    /// Deepest container nesting level reached under this source.
    pub max_nest_level: i32,
    /// Whether recursion into this source stopped before reaching the bottom.
    pub recurse_terminated_early: bool,
}

impl UserAddedSourceInfo {
    /// Creates statistics for the user-added source `fsrl`, with every counter at zero.
    pub fn new(fsrl: Fsrl) -> Self {
        Self {
            fsrl,
            file_count: 0,
            raw_file_count: 0,
            container_count: 0,
            max_nest_level: 0,
            recurse_terminated_early: false,
        }
    }

    /// Increments [`Self::raw_file_count`].
    pub fn inc_raw_file_count(&mut self) {
        self.raw_file_count += 1;
    }

    /// Increments [`Self::container_count`].
    pub fn inc_container_count(&mut self) {
        self.container_count += 1;
    }

    /// Java `wasRecurseTerminatedEarly()`.
    pub fn was_recurse_terminated_early(&self) -> bool {
        self.recurse_terminated_early
    }

    /// The FSRL of the file the user added.
    pub fn get_fsrl(&self) -> &Fsrl {
        &self.fsrl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_zero_and_counts() {
        let fsrl = Fsrl::from_string("file:///tmp/a.zip").unwrap();
        let mut u = UserAddedSourceInfo::new(fsrl.clone());
        assert_eq!(u.get_fsrl(), &fsrl);
        assert_eq!((u.file_count, u.raw_file_count, u.container_count, u.max_nest_level), (0, 0, 0, 0));
        assert!(!u.was_recurse_terminated_early());

        u.inc_raw_file_count();
        u.inc_raw_file_count();
        u.inc_container_count();
        u.file_count = 5;
        u.max_nest_level = 3;
        u.recurse_terminated_early = true;
        assert_eq!(u.raw_file_count, 2);
        assert_eq!(u.container_count, 1);
        assert_eq!(u.file_count, 5);
        assert_eq!(u.max_nest_level, 3);
        assert!(u.was_recurse_terminated_early());
    }

    #[test]
    fn ids_index_the_owning_list() {
        let mut sources = vec![
            UserAddedSourceInfo::new(Fsrl::from_string("file:///a").unwrap()),
            UserAddedSourceInfo::new(Fsrl::from_string("file:///b").unwrap()),
        ];
        let id = UserAddedSourceInfoId(1);
        sources[id.0].inc_container_count();
        assert_eq!(sources[1].container_count, 1);
        assert_eq!(sources[0].container_count, 0);
    }
}
