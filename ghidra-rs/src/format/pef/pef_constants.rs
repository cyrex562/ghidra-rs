/// Constants for the PEF (Preferred Executable Format) binary format.
///
/// Mirrors `ghidra.app.util.bin.format.pef.PefConstants`.
pub const TVECT: &str = ".TVect";
pub const IMPORT: &str = ".import";
pub const TERM: &str = ".term";
pub const INIT: &str = ".init";
pub const MAIN: &str = ".main";
pub const TOC: &str = ".toc";
pub const GLUE: &str = ".glue";

pub const BASE_ADDRESS: u64 = 0x10000000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_constants_match_java_source() {
        assert_eq!(TVECT, ".TVect");
        assert_eq!(IMPORT, ".import");
        assert_eq!(TERM, ".term");
        assert_eq!(INIT, ".init");
        assert_eq!(MAIN, ".main");
        assert_eq!(TOC, ".toc");
        assert_eq!(GLUE, ".glue");
    }

    #[test]
    fn base_address_matches_java_source() {
        assert_eq!(BASE_ADDRESS, 0x10000000u64);
    }
}
