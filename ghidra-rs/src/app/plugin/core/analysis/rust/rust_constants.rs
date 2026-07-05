use once_cell::sync::Lazy;

use crate::program::model::data::category_path::CategoryPath;

/// Rust extension to the category path tree (`"/rust"`).
///
/// Mirrors `RustConstants.RUST_CATEGORYPATH` from
/// `ghidra.app.plugin.core.analysis.rust.RustConstants`.
pub static RUST_CATEGORYPATH: Lazy<CategoryPath> = Lazy::new(|| {
    CategoryPath::parse("/rust")
        .expect("RUST_CATEGORYPATH: \"/rust\" is a valid category path")
});

/// Base path for Rust-related extensions.
///
/// Mirrors `RustConstants.RUST_EXTENSIONS_PATH`.
pub const RUST_EXTENSIONS_PATH: &str = "extensions/rust/";

/// Extensions path component for Unix systems.
///
/// Mirrors `RustConstants.RUST_EXTENSIONS_UNIX`.
pub const RUST_EXTENSIONS_UNIX: &str = "unix";

/// Extensions path component for Windows systems.
///
/// Mirrors `RustConstants.RUST_EXTENSIONS_WINDOWS`.
pub const RUST_EXTENSIONS_WINDOWS: &str = "windows";

/// The Rust compiler command name.
///
/// Mirrors `RustConstants.RUST_COMPILER`.
pub const RUST_COMPILER: &str = "rustc";

/// Rust-related environment variable and binary signatures.
///
/// Mirrors `RustConstants.RUST_SIGNATURES`.
pub static RUST_SIGNATURES: &[&[u8]] = &[
    b"RUST_BACKTRACE",
    b"RUST_MIN_STACK",
    b"/rustc/",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_categorypath_initialization() {
        let path = &RUST_CATEGORYPATH;
        assert_eq!(path.get_path(), "/rust");
    }

    #[test]
    fn test_rust_extensions_path() {
        assert_eq!(RUST_EXTENSIONS_PATH, "extensions/rust/");
        assert!(RUST_EXTENSIONS_PATH.starts_with("extensions"));
        assert!(RUST_EXTENSIONS_PATH.ends_with("/"));
    }

    #[test]
    fn test_rust_extensions_platform_names() {
        assert_eq!(RUST_EXTENSIONS_UNIX, "unix");
        assert_eq!(RUST_EXTENSIONS_WINDOWS, "windows");
    }

    #[test]
    fn test_rust_compiler_name() {
        assert_eq!(RUST_COMPILER, "rustc");
    }

    #[test]
    fn test_rust_signatures() {
        assert_eq!(RUST_SIGNATURES.len(), 3);
        assert_eq!(RUST_SIGNATURES[0], b"RUST_BACKTRACE");
        assert_eq!(RUST_SIGNATURES[1], b"RUST_MIN_STACK");
        assert_eq!(RUST_SIGNATURES[2], b"/rustc/");
    }

    #[test]
    fn test_rust_signatures_are_byte_arrays() {
        for sig in RUST_SIGNATURES {
            assert!(!sig.is_empty());
        }
    }
}
