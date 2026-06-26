/// DWARF range list entry encodings (DW_RLE_*) from the DWARF standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFRangeListEntry {
    EndOfList = 0x00,
    BaseAddressx = 0x01,
    StartxEndx = 0x02,
    StartxLength = 0x03,
    OffsetPair = 0x04,
    BaseAddress = 0x05,
    StartEnd = 0x06,
    StartLength = 0x07,
}

impl DWARFRangeListEntry {
    /// Returns the integer value of this range list entry kind.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFRangeListEntry` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known entry kind.
    pub fn find(key: u64) -> Result<Self, u64> {
        match key as u32 {
            0x00 => Ok(Self::EndOfList),
            0x01 => Ok(Self::BaseAddressx),
            0x02 => Ok(Self::StartxEndx),
            0x03 => Ok(Self::StartxLength),
            0x04 => Ok(Self::OffsetPair),
            0x05 => Ok(Self::BaseAddress),
            0x06 => Ok(Self::StartEnd),
            0x07 => Ok(Self::StartLength),
            _ => Err(key),
        }
    }
}

impl std::fmt::Display for DWARFRangeListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::EndOfList => "DW_RLE_end_of_list",
            Self::BaseAddressx => "DW_RLE_base_addressx",
            Self::StartxEndx => "DW_RLE_startx_endx",
            Self::StartxLength => "DW_RLE_startx_length",
            Self::OffsetPair => "DW_RLE_offset_pair",
            Self::BaseAddress => "DW_RLE_base_address",
            Self::StartEnd => "DW_RLE_start_end",
            Self::StartLength => "DW_RLE_start_length",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFRangeListEntry::EndOfList.value(), 0x00);
        assert_eq!(DWARFRangeListEntry::BaseAddressx.value(), 0x01);
        assert_eq!(DWARFRangeListEntry::StartxEndx.value(), 0x02);
        assert_eq!(DWARFRangeListEntry::StartxLength.value(), 0x03);
        assert_eq!(DWARFRangeListEntry::OffsetPair.value(), 0x04);
        assert_eq!(DWARFRangeListEntry::BaseAddress.value(), 0x05);
        assert_eq!(DWARFRangeListEntry::StartEnd.value(), 0x06);
        assert_eq!(DWARFRangeListEntry::StartLength.value(), 0x07);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFRangeListEntry::find(0x00), Ok(DWARFRangeListEntry::EndOfList));
        assert_eq!(DWARFRangeListEntry::find(0x01), Ok(DWARFRangeListEntry::BaseAddressx));
        assert_eq!(DWARFRangeListEntry::find(0x02), Ok(DWARFRangeListEntry::StartxEndx));
        assert_eq!(DWARFRangeListEntry::find(0x03), Ok(DWARFRangeListEntry::StartxLength));
        assert_eq!(DWARFRangeListEntry::find(0x04), Ok(DWARFRangeListEntry::OffsetPair));
        assert_eq!(DWARFRangeListEntry::find(0x05), Ok(DWARFRangeListEntry::BaseAddress));
        assert_eq!(DWARFRangeListEntry::find(0x06), Ok(DWARFRangeListEntry::StartEnd));
        assert_eq!(DWARFRangeListEntry::find(0x07), Ok(DWARFRangeListEntry::StartLength));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFRangeListEntry::find(0x08), Err(0x08));
        assert_eq!(DWARFRangeListEntry::find(0xff), Err(0xff));
        assert_eq!(DWARFRangeListEntry::find(0x100), Err(0x100));
    }

    #[test]
    fn roundtrip_value_then_find() {
        let variants = [
            DWARFRangeListEntry::EndOfList,
            DWARFRangeListEntry::BaseAddressx,
            DWARFRangeListEntry::StartxEndx,
            DWARFRangeListEntry::StartxLength,
            DWARFRangeListEntry::OffsetPair,
            DWARFRangeListEntry::BaseAddress,
            DWARFRangeListEntry::StartEnd,
            DWARFRangeListEntry::StartLength,
        ];
        for variant in variants {
            assert_eq!(DWARFRangeListEntry::find(variant.value() as u64), Ok(variant));
        }
    }

    #[test]
    fn display_matches_dwarf_names() {
        assert_eq!(DWARFRangeListEntry::EndOfList.to_string(), "DW_RLE_end_of_list");
        assert_eq!(DWARFRangeListEntry::BaseAddressx.to_string(), "DW_RLE_base_addressx");
        assert_eq!(DWARFRangeListEntry::StartxEndx.to_string(), "DW_RLE_startx_endx");
        assert_eq!(DWARFRangeListEntry::StartxLength.to_string(), "DW_RLE_startx_length");
        assert_eq!(DWARFRangeListEntry::OffsetPair.to_string(), "DW_RLE_offset_pair");
        assert_eq!(DWARFRangeListEntry::BaseAddress.to_string(), "DW_RLE_base_address");
        assert_eq!(DWARFRangeListEntry::StartEnd.to_string(), "DW_RLE_start_end");
        assert_eq!(DWARFRangeListEntry::StartLength.to_string(), "DW_RLE_start_length");
    }
}
