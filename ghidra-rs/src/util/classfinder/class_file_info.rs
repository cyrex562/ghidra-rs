/// Information about a class file on disk.
///
/// Port of `ghidra.util.classfinder.ClassFileInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClassFileInfo {
    /// Path to the class file (or jar containing the class).
    pub path: String,
    /// Name of the class (including package).
    pub name: String,
    /// Class suffix (i.e., extension point type name).
    pub suffix: String,
    /// Module path for this class.
    pub module: String,
}

impl ClassFileInfo {
    pub fn new(path: String, name: String, suffix: String, module: String) -> Self {
        Self { path, name, suffix, module }
    }

    /// Returns the simple class name (no package name) for the class represented by this info.
    pub fn simple_name(&self) -> &str {
        match self.name.rfind('.') {
            Some(index) => &self.name[index + 1..],
            None => &self.name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(name: &str) -> ClassFileInfo {
        ClassFileInfo::new(
            "/some/path".to_string(),
            name.to_string(),
            "Suffix".to_string(),
            "module".to_string(),
        )
    }

    #[test]
    fn simple_name_with_package() {
        let info = make("ghidra.util.classfinder.ClassFileInfo");
        assert_eq!(info.simple_name(), "ClassFileInfo");
    }

    #[test]
    fn simple_name_no_package() {
        let info = make("MyClass");
        assert_eq!(info.simple_name(), "MyClass");
    }

    #[test]
    fn simple_name_single_level_package() {
        let info = make("ghidra.Foo");
        assert_eq!(info.simple_name(), "Foo");
    }

    #[test]
    fn simple_name_deeply_nested() {
        let info = make("a.b.c.d.e.Deep");
        assert_eq!(info.simple_name(), "Deep");
    }

    #[test]
    fn fields_accessible() {
        let info = ClassFileInfo::new(
            "/a/b.jar".to_string(),
            "com.example.Foo".to_string(),
            "ExtPoint".to_string(),
            "mod1".to_string(),
        );
        assert_eq!(info.path, "/a/b.jar");
        assert_eq!(info.name, "com.example.Foo");
        assert_eq!(info.suffix, "ExtPoint");
        assert_eq!(info.module, "mod1");
    }

    #[test]
    fn clone_equality() {
        let a = make("p.q.R");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
