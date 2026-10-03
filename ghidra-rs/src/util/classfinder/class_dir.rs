use std::fmt;
use std::path::Path;

use super::ClassFileInfo;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// A root directory of compiled classes, used by the class-search subsystem to enumerate
/// extension-point implementations found under it.
///
/// Port of `ghidra.util.classfinder.ClassDir`. The concrete Java class scans its directory
/// tree at construction time (building a `ClassPackage` tree rooted at `""`) and delegates
/// `getClasses` to it; here that role is represented as a trait so the class-search subsystem
/// can depend on the abstraction rather than a concrete directory-scanning implementation.
pub trait ClassDir: fmt::Display {
    /// Populates `list` with class information found under this directory tree.
    ///
    /// # Errors
    /// Returns `CancelledException` if the operation is cancelled via `monitor`.
    fn get_classes(
        &self,
        list: &mut Vec<ClassFileInfo>,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException>;

    /// Returns the root directory this `ClassDir` was constructed from.
    fn get_dir(&self) -> &Path;

    /// Returns the absolute path of the module containing [`Self::get_dir`], or the empty
    /// string if the directory isn't inside a known module.
    fn get_module_path(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;
    use std::path::PathBuf;

    struct MockClassDir {
        dir: PathBuf,
        module_path: String,
        classes: Vec<ClassFileInfo>,
    }

    impl fmt::Display for MockClassDir {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.dir.display())
        }
    }

    impl ClassDir for MockClassDir {
        fn get_classes(
            &self,
            list: &mut Vec<ClassFileInfo>,
            _monitor: &dyn TaskMonitor,
        ) -> Result<(), CancelledException> {
            list.extend(self.classes.iter().cloned());
            Ok(())
        }

        fn get_dir(&self) -> &Path {
            &self.dir
        }

        fn get_module_path(&self) -> &str {
            &self.module_path
        }
    }

    fn make_class_info(name: &str) -> ClassFileInfo {
        ClassFileInfo::new(
            "/some/module/classes".to_string(),
            name.to_string(),
            "Suffix".to_string(),
            "/some/module".to_string(),
        )
    }

    #[test]
    fn get_classes_populates_list_and_exposes_dir_and_module_path() {
        let class_dir = MockClassDir {
            dir: PathBuf::from("/some/module/classes"),
            module_path: "/some/module".to_string(),
            classes: vec![make_class_info("com.example.ClassA"), make_class_info("com.example.ClassB")],
        };

        let mut list = Vec::new();
        let monitor = DummyMonitor;
        // Use as a trait object to prove object-safety.
        let dyn_dir: &dyn ClassDir = &class_dir;
        dyn_dir.get_classes(&mut list, &monitor).unwrap();

        assert_eq!(list.len(), 2);
        assert_eq!(dyn_dir.get_dir(), Path::new("/some/module/classes"));
        assert_eq!(dyn_dir.get_module_path(), "/some/module");
        assert_eq!(dyn_dir.to_string(), "/some/module/classes");
    }

    #[test]
    fn get_module_path_empty_when_not_in_a_module() {
        let class_dir = MockClassDir {
            dir: PathBuf::from("/standalone/classes"),
            module_path: String::new(),
            classes: vec![],
        };

        assert_eq!(class_dir.get_module_path(), "");
    }
}
