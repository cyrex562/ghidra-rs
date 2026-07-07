/// DEX modifier constants.
///
/// Mirrors `ghidra.file.formats.android.dex.format.Modifiers`.
///
/// Reference: <https://android.googlesource.com/platform/art/+/refs/heads/android10-release/libdexfile/dex/modifiers.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Modifiers;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modifiers_is_copy() {
        let m = Modifiers;
        let _m2 = m;
        let _m3 = m;
    }

    #[test]
    fn modifiers_debug() {
        assert_eq!(format!("{:?}", Modifiers), "Modifiers");
    }

    #[test]
    fn modifiers_eq() {
        assert_eq!(Modifiers, Modifiers);
    }
}
