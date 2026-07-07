/// Holds information extracted from a PE import data directory entry.
///
/// The DLL name is normalized to uppercase on construction, matching the
/// Java source behaviour (`dll.toUpperCase()`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    address: u32,
    comment: String,
    dll: String,
    name: String,
    is_bound: bool,
}

impl ImportInfo {
    /// Creates a new `ImportInfo`.
    ///
    /// `dll` is converted to uppercase before storage.
    pub fn new(address: u32, comment: String, dll: String, name: String, is_bound: bool) -> Self {
        Self {
            address,
            comment,
            dll: dll.to_uppercase(),
            name,
            is_bound,
        }
    }

    /// Returns the adjusted address where the import occurs.
    pub fn address(&self) -> u32 {
        self.address
    }

    /// Returns a comment string containing extra information about the import.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Returns the name of the imported DLL (always uppercase).
    pub fn dll(&self) -> &str {
        &self.dll
    }

    /// Returns the name of the imported symbol.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns `true` if this is a bound import.
    pub fn is_bound(&self) -> bool {
        self.is_bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(address: u32, comment: &str, dll: &str, name: &str, is_bound: bool) -> ImportInfo {
        ImportInfo::new(
            address,
            comment.to_string(),
            dll.to_string(),
            name.to_string(),
            is_bound,
        )
    }

    #[test]
    fn getters_round_trip() {
        let info = make(0x1000, "some comment", "kernel32.dll", "GetProcAddress", false);
        assert_eq!(info.address(), 0x1000);
        assert_eq!(info.comment(), "some comment");
        assert_eq!(info.dll(), "KERNEL32.DLL");
        assert_eq!(info.name(), "GetProcAddress");
        assert!(!info.is_bound());
    }

    #[test]
    fn dll_normalized_to_uppercase() {
        let info = make(0, "", "ntdll.dll", "NtCreateFile", false);
        assert_eq!(info.dll(), "NTDLL.DLL");
    }

    #[test]
    fn dll_already_uppercase_unchanged() {
        let info = make(0, "", "KERNEL32.DLL", "ExitProcess", false);
        assert_eq!(info.dll(), "KERNEL32.DLL");
    }

    #[test]
    fn dll_mixed_case_normalized() {
        let info = make(0, "", "mSvCrT.dLl", "malloc", false);
        assert_eq!(info.dll(), "MSVCRT.DLL");
    }

    #[test]
    fn is_bound_true() {
        let info = make(0x4000, "", "user32.dll", "MessageBoxA", true);
        assert!(info.is_bound());
    }

    #[test]
    fn is_bound_false() {
        let info = make(0x4000, "", "user32.dll", "MessageBoxA", false);
        assert!(!info.is_bound());
    }

    #[test]
    fn equality() {
        let a = make(0x2000, "cmt", "advapi32.dll", "RegOpenKey", false);
        let b = make(0x2000, "cmt", "ADVAPI32.DLL", "RegOpenKey", false);
        assert_eq!(a, b);
    }

    #[test]
    fn clone_is_independent() {
        let a = make(0x3000, "", "shell32.dll", "ShellExecute", true);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_fields() {
        let info = make(0, "", "", "", false);
        assert_eq!(info.address(), 0);
        assert_eq!(info.comment(), "");
        assert_eq!(info.dll(), "");
        assert_eq!(info.name(), "");
        assert!(!info.is_bound());
    }
}
