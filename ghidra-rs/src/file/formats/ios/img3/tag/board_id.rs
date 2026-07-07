/// Board ID values for Apple iOS img3 firmware images.
///
/// Mirrors `ghidra.file.formats.ios.img3.tag.BoardID`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BoardId {
    IPhone2G,
    IPhone3G,
    IPhone3Gs,
    IPodTouch1stGen,
    IPodTouch2ndGen,
    IPodTouch3rdGen,
}

impl BoardId {
    /// Returns the integer board ID associated with this device.
    pub fn board_id(self) -> i32 {
        match self {
            BoardId::IPhone2G => 0x0,
            BoardId::IPhone3G => 0x04,
            BoardId::IPhone3Gs => 0x00,
            BoardId::IPodTouch1stGen => 0x02,
            BoardId::IPodTouch2ndGen => 0x00,
            BoardId::IPodTouch3rdGen => 0x02,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn board_ids_match_java_source() {
        assert_eq!(BoardId::IPhone2G.board_id(), 0x0);
        assert_eq!(BoardId::IPhone3G.board_id(), 0x04);
        assert_eq!(BoardId::IPhone3Gs.board_id(), 0x00);
        assert_eq!(BoardId::IPodTouch1stGen.board_id(), 0x02);
        assert_eq!(BoardId::IPodTouch2ndGen.board_id(), 0x00);
        assert_eq!(BoardId::IPodTouch3rdGen.board_id(), 0x02);
    }

    #[test]
    fn iphone2g_board_id_differs_from_iphone3g() {
        assert_ne!(BoardId::IPhone2G.board_id(), BoardId::IPhone3G.board_id());
    }

    #[test]
    fn shared_board_id_values_are_correct() {
        assert_eq!(BoardId::IPhone3Gs.board_id(), BoardId::IPodTouch2ndGen.board_id());
        assert_eq!(BoardId::IPodTouch1stGen.board_id(), BoardId::IPodTouch3rdGen.board_id());
    }

    #[test]
    fn all_variants_are_covered() {
        let variants = [
            BoardId::IPhone2G,
            BoardId::IPhone3G,
            BoardId::IPhone3Gs,
            BoardId::IPodTouch1stGen,
            BoardId::IPodTouch2ndGen,
            BoardId::IPodTouch3rdGen,
        ];
        assert_eq!(variants.len(), 6);
    }
}
