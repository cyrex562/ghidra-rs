/// Data application mode for encoded exception handling data.
///
/// See the [Linux Standard Base DWARF extensions specification](http://refspecs.freestandards.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html) for details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DwarfEhDataApplicationMode {
    AbsPtr,
    PcRel,
    TexRel,
    DataRel,
    FuncRel,
    Aligned,
    Indirect,
    Omit,
}

impl DwarfEhDataApplicationMode {
    /// Returns the code value for this mode.
    pub fn code(self) -> u8 {
        match self {
            DwarfEhDataApplicationMode::AbsPtr => 0x00,
            DwarfEhDataApplicationMode::PcRel => 0x10,
            DwarfEhDataApplicationMode::TexRel => 0x20,
            DwarfEhDataApplicationMode::DataRel => 0x30,
            DwarfEhDataApplicationMode::FuncRel => 0x40,
            DwarfEhDataApplicationMode::Aligned => 0x50,
            DwarfEhDataApplicationMode::Indirect => 0x80,
            DwarfEhDataApplicationMode::Omit => 0xf0,
        }
    }

    /// Returns the data application mode for the indicated code, or `None` if the code is invalid.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(DwarfEhDataApplicationMode::AbsPtr),
            0x10 => Some(DwarfEhDataApplicationMode::PcRel),
            0x20 => Some(DwarfEhDataApplicationMode::TexRel),
            0x30 => Some(DwarfEhDataApplicationMode::DataRel),
            0x40 => Some(DwarfEhDataApplicationMode::FuncRel),
            0x50 => Some(DwarfEhDataApplicationMode::Aligned),
            0x80 => Some(DwarfEhDataApplicationMode::Indirect),
            0xf0 => Some(DwarfEhDataApplicationMode::Omit),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_codes() {
        assert_eq!(DwarfEhDataApplicationMode::AbsPtr.code(), 0x00);
        assert_eq!(DwarfEhDataApplicationMode::PcRel.code(), 0x10);
        assert_eq!(DwarfEhDataApplicationMode::TexRel.code(), 0x20);
        assert_eq!(DwarfEhDataApplicationMode::DataRel.code(), 0x30);
        assert_eq!(DwarfEhDataApplicationMode::FuncRel.code(), 0x40);
        assert_eq!(DwarfEhDataApplicationMode::Aligned.code(), 0x50);
        assert_eq!(DwarfEhDataApplicationMode::Indirect.code(), 0x80);
        assert_eq!(DwarfEhDataApplicationMode::Omit.code(), 0xf0);
    }

    #[test]
    fn test_from_code_valid() {
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x00),
            Some(DwarfEhDataApplicationMode::AbsPtr)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x10),
            Some(DwarfEhDataApplicationMode::PcRel)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x20),
            Some(DwarfEhDataApplicationMode::TexRel)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x30),
            Some(DwarfEhDataApplicationMode::DataRel)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x40),
            Some(DwarfEhDataApplicationMode::FuncRel)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x50),
            Some(DwarfEhDataApplicationMode::Aligned)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0x80),
            Some(DwarfEhDataApplicationMode::Indirect)
        );
        assert_eq!(
            DwarfEhDataApplicationMode::from_code(0xf0),
            Some(DwarfEhDataApplicationMode::Omit)
        );
    }

    #[test]
    fn test_from_code_invalid() {
        assert_eq!(DwarfEhDataApplicationMode::from_code(0x01), None);
        assert_eq!(DwarfEhDataApplicationMode::from_code(0x11), None);
        assert_eq!(DwarfEhDataApplicationMode::from_code(0xff), None);
        assert_eq!(DwarfEhDataApplicationMode::from_code(0x60), None);
    }

    #[test]
    fn test_roundtrip() {
        let modes = vec![
            DwarfEhDataApplicationMode::AbsPtr,
            DwarfEhDataApplicationMode::PcRel,
            DwarfEhDataApplicationMode::TexRel,
            DwarfEhDataApplicationMode::DataRel,
            DwarfEhDataApplicationMode::FuncRel,
            DwarfEhDataApplicationMode::Aligned,
            DwarfEhDataApplicationMode::Indirect,
            DwarfEhDataApplicationMode::Omit,
        ];
        for mode in modes {
            assert_eq!(
                DwarfEhDataApplicationMode::from_code(mode.code()),
                Some(mode)
            );
        }
    }

    #[test]
    fn test_clone_copy() {
        let mode = DwarfEhDataApplicationMode::PcRel;
        let mode2 = mode;
        assert_eq!(mode, mode2);
    }

    #[test]
    fn test_debug() {
        let mode = DwarfEhDataApplicationMode::PcRel;
        let debug_str = format!("{:?}", mode);
        assert!(debug_str.contains("PcRel"));
    }
}
