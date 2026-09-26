//! Port of `ghidra.app.plugin.processors.sleigh.SleighCompilerSpecDescription`.
//!
//! In Java this `extends BasicCompilerSpecDescription`, adding only the `.cspec`
//! [`ResourceFile`] the description was loaded from, and overriding `getSource()` to report that
//! file (rather than the base class's `id name` string). Per this codebase's composition-over-
//! inheritance convention, the Java base class is held as a field rather than "inherited".

use crate::generic::jar::resource_file::ResourceFile;
use crate::program::model::lang::basic_compiler_spec_description::BasicCompilerSpecDescription;
use crate::program::model::lang::compiler_spec_description::CompilerSpecDescription;
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;

/// See the module docs. Port of
/// `ghidra.app.plugin.processors.sleigh.SleighCompilerSpecDescription`.
pub struct SleighCompilerSpecDescription {
    /// Composed in place of Java's `extends BasicCompilerSpecDescription`.
    base: BasicCompilerSpecDescription,
    file: ResourceFile,
}

impl SleighCompilerSpecDescription {
    /// Port of the constructor
    /// `SleighCompilerSpecDescription(CompilerSpecID, String, ResourceFile)`.
    pub fn new(id: CompilerSpecID, name: impl Into<String>, file: ResourceFile) -> Self {
        Self {
            base: BasicCompilerSpecDescription::new(id, name),
            file,
        }
    }

    /// Port of `getFile()`.
    pub fn get_file(&self) -> &ResourceFile {
        &self.file
    }
}

impl CompilerSpecDescription for SleighCompilerSpecDescription {
    fn get_compiler_spec_id(&self) -> CompilerSpecID {
        self.base.get_compiler_spec_id()
    }

    fn get_compiler_spec_name(&self) -> String {
        self.base.get_compiler_spec_name()
    }

    /// Port of the `@Override`n `getSource()`: `return this.file.toString();`. `ResourceFile`
    /// has no Java-style `toString()` in this port, but [`ResourceFile::absolute_path`] is the
    /// Rust stand-in used elsewhere for that purpose (see
    /// `SleighLanguageDescription::is_same_sleigh_language_file`'s doc comment).
    fn get_source(&self) -> String {
        self.file.absolute_path()
    }

    fn as_sleigh_compiler_spec_description(&self) -> Option<&SleighCompilerSpecDescription> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn new_stores_id_name_and_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("x86-64-gcc.cspec");
        fs::write(&path, "<compiler_spec/>").unwrap();
        let file = ResourceFile::new(path.clone());

        let id = CompilerSpecID::new(Some("gcc"));
        let desc = SleighCompilerSpecDescription::new(id.clone(), "GCC", file);

        assert_eq!(desc.get_compiler_spec_id(), id);
        assert_eq!(desc.get_compiler_spec_name(), "GCC");
        assert_eq!(desc.get_file().absolute_path(), path.to_string_lossy());
    }

    #[test]
    fn get_source_returns_file_path_not_base_source() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("subdir").join("arm-be.cspec");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "<compiler_spec/>").unwrap();
        let file = ResourceFile::new(path.clone());

        let id = CompilerSpecID::new(Some("armbe"));
        let desc = SleighCompilerSpecDescription::new(id, "ARM Big Endian", file);

        // SleighCompilerSpecDescription overrides getSource() to report the backing file's
        // path, unlike BasicCompilerSpecDescription's `"{id} {name}"`.
        assert_eq!(desc.get_source(), path.to_string_lossy());
        assert_ne!(desc.get_source(), format!("{} {}", "armbe", "ARM Big Endian"));
    }

    #[test]
    fn implements_compiler_spec_description_trait() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("t.cspec");
        fs::write(&path, "").unwrap();
        let file = ResourceFile::new(path);

        let desc = SleighCompilerSpecDescription::new(
            CompilerSpecID::new(Some("t")),
            "T",
            file,
        );
        let _: &dyn CompilerSpecDescription = &desc;
    }

    #[test]
    fn get_file_returns_same_resource_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("y.cspec");
        fs::write(&path, "data").unwrap();
        let file = ResourceFile::new(path.clone());

        let desc = SleighCompilerSpecDescription::new(
            CompilerSpecID::new(None),
            "default",
            file,
        );
        assert!(desc.get_file().exists());
        assert_eq!(desc.get_file().length(), 4);
    }
}
