/// OAT instruction set identifiers.
///
/// Mirrors `ghidra.file.formats.android.oat.OatInstructionSet`.
///
/// Reference: <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/instruction_set.h#29>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OatInstructionSet {
    None = 0,
    Arm = 1,
    Arm64 = 2,
    Thumb2 = 3,
    X86 = 4,
    X86_64 = 5,
    Mips = 6,
    Mips64 = 7,
}

impl OatInstructionSet {
    pub const DISPLAY_NAME: &'static str = "instruction_set_";

    /// Returns the variant at the given ordinal index, or `None` if out of range.
    ///
    /// Mirrors the Java `valueOf(int)` method which returns `null` on `ArrayIndexOutOfBoundsException`.
    pub fn from_int(instruction_set: i32) -> Option<Self> {
        match instruction_set {
            0 => Some(Self::None),
            1 => Some(Self::Arm),
            2 => Some(Self::Arm64),
            3 => Some(Self::Thumb2),
            4 => Some(Self::X86),
            5 => Some(Self::X86_64),
            6 => Some(Self::Mips),
            7 => Some(Self::Mips64),
            _ => Option::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_constant() {
        assert_eq!(OatInstructionSet::DISPLAY_NAME, "instruction_set_");
    }

    #[test]
    fn from_int_valid_indices() {
        assert_eq!(OatInstructionSet::from_int(0), Some(OatInstructionSet::None));
        assert_eq!(OatInstructionSet::from_int(1), Some(OatInstructionSet::Arm));
        assert_eq!(OatInstructionSet::from_int(2), Some(OatInstructionSet::Arm64));
        assert_eq!(OatInstructionSet::from_int(3), Some(OatInstructionSet::Thumb2));
        assert_eq!(OatInstructionSet::from_int(4), Some(OatInstructionSet::X86));
        assert_eq!(OatInstructionSet::from_int(5), Some(OatInstructionSet::X86_64));
        assert_eq!(OatInstructionSet::from_int(6), Some(OatInstructionSet::Mips));
        assert_eq!(OatInstructionSet::from_int(7), Some(OatInstructionSet::Mips64));
    }

    #[test]
    fn from_int_out_of_range() {
        assert_eq!(OatInstructionSet::from_int(8), Option::None);
        assert_eq!(OatInstructionSet::from_int(-1), Option::None);
        assert_eq!(OatInstructionSet::from_int(100), Option::None);
    }

    #[test]
    fn variants_are_copy() {
        let v = OatInstructionSet::Arm;
        let _v2 = v;
        let _v3 = v;
    }

    #[test]
    fn variants_debug() {
        assert_eq!(format!("{:?}", OatInstructionSet::None), "None");
        assert_eq!(format!("{:?}", OatInstructionSet::X86_64), "X86_64");
    }
}
