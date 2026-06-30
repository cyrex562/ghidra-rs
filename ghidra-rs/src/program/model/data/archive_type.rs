/// Identifies the type of an archive that holds data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArchiveType {
    /// Built-in archive supplied by Ghidra itself.
    BuiltIn,
    /// Archive backed by a file on disk.
    File,
    /// Archive associated with a Ghidra project.
    Project,
    /// Archive embedded in an open program.
    Program,
    /// Temporary in-memory archive.
    Temporary,
}

impl ArchiveType {
    /// Returns `true` if this is the built-in archive.
    pub fn is_built_in(self) -> bool {
        self == ArchiveType::BuiltIn
    }

    /// Returns `true` if this archive type is a valid source from which data
    /// types may be added to a program (i.e. [`File`](ArchiveType::File) or
    /// [`Project`](ArchiveType::Project)).
    pub fn is_valid_source_archive(self) -> bool {
        self == ArchiveType::File || self == ArchiveType::Project
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_are_distinct() {
        let all = [
            ArchiveType::BuiltIn,
            ArchiveType::File,
            ArchiveType::Project,
            ArchiveType::Program,
            ArchiveType::Temporary,
        ];
        for i in 0..all.len() {
            for j in 0..all.len() {
                if i == j {
                    assert_eq!(all[i], all[j]);
                } else {
                    assert_ne!(all[i], all[j]);
                }
            }
        }
    }

    #[test]
    fn is_built_in_only_for_built_in() {
        assert!(ArchiveType::BuiltIn.is_built_in());
        assert!(!ArchiveType::File.is_built_in());
        assert!(!ArchiveType::Project.is_built_in());
        assert!(!ArchiveType::Program.is_built_in());
        assert!(!ArchiveType::Temporary.is_built_in());
    }

    #[test]
    fn is_valid_source_archive_for_file_and_project() {
        assert!(ArchiveType::File.is_valid_source_archive());
        assert!(ArchiveType::Project.is_valid_source_archive());
        assert!(!ArchiveType::BuiltIn.is_valid_source_archive());
        assert!(!ArchiveType::Program.is_valid_source_archive());
        assert!(!ArchiveType::Temporary.is_valid_source_archive());
    }

    #[test]
    fn clone_preserves_variant() {
        for variant in [
            ArchiveType::BuiltIn,
            ArchiveType::File,
            ArchiveType::Project,
            ArchiveType::Program,
            ArchiveType::Temporary,
        ] {
            assert_eq!(variant.clone(), variant);
        }
    }

    #[test]
    fn debug_contains_variant_name() {
        assert!(format!("{:?}", ArchiveType::BuiltIn).contains("BuiltIn"));
        assert!(format!("{:?}", ArchiveType::File).contains("File"));
        assert!(format!("{:?}", ArchiveType::Project).contains("Project"));
        assert!(format!("{:?}", ArchiveType::Program).contains("Program"));
        assert!(format!("{:?}", ArchiveType::Temporary).contains("Temporary"));
    }

    #[test]
    fn hash_consistent_with_equality() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ArchiveType::BuiltIn);
        assert!(set.contains(&ArchiveType::BuiltIn));
        assert!(!set.contains(&ArchiveType::File));
    }
}
