/// Packed data content opcodes for the PEF (Preferred Executable Format) binary format.
///
/// Mirrors `ghidra.app.util.bin.format.pef.PackedDataOpcodes`.
/// See Apple's `IOPEFInternals.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedDataOpcodes {
    /// Zero fill `count` bytes.
    Zero = 0,
    /// Block copy `count` bytes.
    Block = 1,
    /// Repeat `count` bytes `count2`+1 times.
    Repeat = 2,
    /// Interleaved repeated and unique data.
    RepeatBlock = 3,
    /// Interleaved zero and unique data.
    RepeatZero = 4,
    /// Reserved.
    Reserved5 = 5,
    /// Reserved.
    Reserved6 = 6,
    /// Reserved.
    Reserved7 = 7,
}

impl PackedDataOpcodes {
    /// Returns the integer value of this opcode.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `PackedDataOpcodes` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(value)` if `value` does not correspond to a known opcode,
    /// mirroring the `IllegalArgumentException` thrown by the Java source.
    pub fn get(value: u32) -> Result<Self, u32> {
        match value {
            0 => Ok(Self::Zero),
            1 => Ok(Self::Block),
            2 => Ok(Self::Repeat),
            3 => Ok(Self::RepeatBlock),
            4 => Ok(Self::RepeatZero),
            5 => Ok(Self::Reserved5),
            6 => Ok(Self::Reserved6),
            7 => Ok(Self::Reserved7),
            _ => Err(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_java_source() {
        assert_eq!(PackedDataOpcodes::Zero.value(), 0);
        assert_eq!(PackedDataOpcodes::Block.value(), 1);
        assert_eq!(PackedDataOpcodes::Repeat.value(), 2);
        assert_eq!(PackedDataOpcodes::RepeatBlock.value(), 3);
        assert_eq!(PackedDataOpcodes::RepeatZero.value(), 4);
        assert_eq!(PackedDataOpcodes::Reserved5.value(), 5);
        assert_eq!(PackedDataOpcodes::Reserved6.value(), 6);
        assert_eq!(PackedDataOpcodes::Reserved7.value(), 7);
    }

    #[test]
    fn get_returns_correct_variants() {
        assert_eq!(PackedDataOpcodes::get(0), Ok(PackedDataOpcodes::Zero));
        assert_eq!(PackedDataOpcodes::get(1), Ok(PackedDataOpcodes::Block));
        assert_eq!(PackedDataOpcodes::get(2), Ok(PackedDataOpcodes::Repeat));
        assert_eq!(PackedDataOpcodes::get(3), Ok(PackedDataOpcodes::RepeatBlock));
        assert_eq!(PackedDataOpcodes::get(4), Ok(PackedDataOpcodes::RepeatZero));
        assert_eq!(PackedDataOpcodes::get(5), Ok(PackedDataOpcodes::Reserved5));
        assert_eq!(PackedDataOpcodes::get(6), Ok(PackedDataOpcodes::Reserved6));
        assert_eq!(PackedDataOpcodes::get(7), Ok(PackedDataOpcodes::Reserved7));
    }

    #[test]
    fn get_rejects_unknown_values() {
        assert_eq!(PackedDataOpcodes::get(8), Err(8));
        assert_eq!(PackedDataOpcodes::get(255), Err(255));
        assert_eq!(PackedDataOpcodes::get(u32::MAX), Err(u32::MAX));
    }

    #[test]
    fn roundtrip_value_then_get() {
        let variants = [
            PackedDataOpcodes::Zero,
            PackedDataOpcodes::Block,
            PackedDataOpcodes::Repeat,
            PackedDataOpcodes::RepeatBlock,
            PackedDataOpcodes::RepeatZero,
            PackedDataOpcodes::Reserved5,
            PackedDataOpcodes::Reserved6,
            PackedDataOpcodes::Reserved7,
        ];
        for variant in variants {
            assert_eq!(PackedDataOpcodes::get(variant.value()), Ok(variant));
        }
    }
}
