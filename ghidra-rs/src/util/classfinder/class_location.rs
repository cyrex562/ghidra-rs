use super::ClassFileInfo;
use crate::util::exception::CancelledException;
use crate::util::task::TaskMonitor;

/// Represents a place from which classes can be obtained.
///
/// Port of `ghidra.util.classfinder.ClassLocation`.
pub trait ClassLocation {
    /// File extension for compiled class files.
    const CLASS_EXT: &'static str = ".class";

    /// Populates the provided list with class information from this location.
    ///
    /// # Arguments
    /// * `list` - A vector to be populated with class information
    /// * `monitor` - A task monitor for progress tracking and cancellation
    ///
    /// # Errors
    /// Returns `CancelledException` if the operation is cancelled via the monitor.
    fn get_classes(&self, list: &mut Vec<ClassFileInfo>, monitor: &dyn TaskMonitor) -> Result<(), CancelledException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::task::DummyMonitor;

    struct MockClassLocation {
        classes: Vec<ClassFileInfo>,
    }

    impl ClassLocation for MockClassLocation {
        fn get_classes(&self, list: &mut Vec<ClassFileInfo>, _monitor: &dyn TaskMonitor) -> Result<(), CancelledException> {
            list.extend(self.classes.iter().cloned());
            Ok(())
        }
    }

    fn make_class_info(name: &str) -> ClassFileInfo {
        ClassFileInfo::new(
            "/path/to/class".to_string(),
            name.to_string(),
            "Suffix".to_string(),
            "module".to_string(),
        )
    }

    #[test]
    fn class_ext_constant() {
        assert_eq!(MockClassLocation::CLASS_EXT, ".class");
    }

    #[test]
    fn get_classes_populates_list() {
        let location = MockClassLocation {
            classes: vec![
                make_class_info("com.example.ClassA"),
                make_class_info("com.example.ClassB"),
            ],
        };
        let mut list = Vec::new();
        let monitor = DummyMonitor;
        location.get_classes(&mut list, &monitor).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "com.example.ClassA");
        assert_eq!(list[1].name, "com.example.ClassB");
    }

    #[test]
    fn get_classes_appends_to_existing_list() {
        let location = MockClassLocation {
            classes: vec![make_class_info("com.example.ClassC")],
        };
        let mut list = vec![make_class_info("com.example.ClassA")];
        let monitor = DummyMonitor;
        location.get_classes(&mut list, &monitor).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "com.example.ClassA");
        assert_eq!(list[1].name, "com.example.ClassC");
    }

    #[test]
    fn get_classes_with_empty_location() {
        let location = MockClassLocation { classes: vec![] };
        let mut list = vec![make_class_info("com.example.ClassA")];
        let monitor = DummyMonitor;
        location.get_classes(&mut list, &monitor).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "com.example.ClassA");
    }
}
