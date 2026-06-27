/// Text (code) section name.
pub const TEXT: &str = ".text";
/// Initialized data section name.
pub const DATA: &str = ".data";
/// Uninitialized data (BSS) section name.
pub const BSS: &str = ".bss";
/// Pad section name.
pub const PAD: &str = ".pad";
/// Loader section name.
pub const LOADER: &str = ".loader";
/// Debug section name.
pub const DEBUG: &str = ".debug";
/// Type-check section name.
pub const TYPCHK: &str = ".typchk";
/// Exception section name.
pub const EXCEPT: &str = ".except";
/// Overflow section name.
pub const OVRFLO: &str = ".ovrflo";
/// Comment/info section name.
pub const INFO: &str = ".info";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(TEXT, ".text");
        assert_eq!(DATA, ".data");
        assert_eq!(BSS, ".bss");
        assert_eq!(PAD, ".pad");
        assert_eq!(LOADER, ".loader");
        assert_eq!(DEBUG, ".debug");
        assert_eq!(TYPCHK, ".typchk");
        assert_eq!(EXCEPT, ".except");
        assert_eq!(OVRFLO, ".ovrflo");
        assert_eq!(INFO, ".info");
    }

    #[test]
    fn all_names_start_with_dot() {
        let names = [TEXT, DATA, BSS, PAD, LOADER, DEBUG, TYPCHK, EXCEPT, OVRFLO, INFO];
        for name in names {
            assert!(name.starts_with('.'), "{name:?} must start with '.'");
        }
    }

    #[test]
    fn all_names_are_distinct() {
        let names = [TEXT, DATA, BSS, PAD, LOADER, DEBUG, TYPCHK, EXCEPT, OVRFLO, INFO];
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "names at index {i} and {j} must be distinct");
                }
            }
        }
    }
}
