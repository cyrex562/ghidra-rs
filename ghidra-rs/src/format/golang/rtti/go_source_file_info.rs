use std::fmt;

/// Represents a Go source file and line number tuple.
///
/// Mirrors Ghidra's `GoSourceFileInfo` Java record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GoSourceFileInfo {
    file_name: String,
    line_num: i32,
}

impl GoSourceFileInfo {
    /// Creates a new source-file info pair.
    pub fn new(file_name: impl Into<String>, line_num: i32) -> Self {
        Self {
            file_name: file_name.into(),
            line_num,
        }
    }

    /// Returns the source filename.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Returns the source line number.
    pub fn line_num(&self) -> i32 {
        self.line_num
    }

    /// Returns source location formatted as `"filename:linenum"`.
    pub fn description(&self) -> String {
        format!("{}:{}", self.file_name, self.line_num)
    }

    /// Returns source location formatted as `"File: filename Line: linenum"`.
    pub fn verbose_description(&self) -> String {
        format!("File: {} Line: {}", self.file_name, self.line_num)
    }
}

impl fmt::Display for GoSourceFileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file_name, self.line_num)
    }
}

#[cfg(test)]
mod tests {
    use super::GoSourceFileInfo;

    #[test]
    fn accessors_round_trip() {
        let info = GoSourceFileInfo::new("main.go", 42);
        assert_eq!(info.file_name(), "main.go");
        assert_eq!(info.line_num(), 42);
    }

    #[test]
    fn description_format() {
        let info = GoSourceFileInfo::new("pkg/foo.go", 7);
        assert_eq!(info.description(), "pkg/foo.go:7");
    }

    #[test]
    fn verbose_description_format() {
        let info = GoSourceFileInfo::new("pkg/foo.go", 7);
        assert_eq!(info.verbose_description(), "File: pkg/foo.go Line: 7");
    }

    #[test]
    fn display_matches_description() {
        let info = GoSourceFileInfo::new("src/bar.go", 100);
        assert_eq!(info.to_string(), info.description());
    }

    #[test]
    fn zero_line_number() {
        let info = GoSourceFileInfo::new("init.go", 0);
        assert_eq!(info.description(), "init.go:0");
        assert_eq!(info.verbose_description(), "File: init.go Line: 0");
    }

    #[test]
    fn equality_and_clone() {
        let a = GoSourceFileInfo::new("a.go", 1);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_filename() {
        let info = GoSourceFileInfo::new("", 5);
        assert_eq!(info.description(), ":5");
        assert_eq!(info.verbose_description(), "File:  Line: 5");
    }
}
