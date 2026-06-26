/// DWARF location list entry encodings (DW_LLE_*) from the DWARF standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFLocationListEntry {
    EndOfList = 0x00,
    BaseAddressx = 0x01,
    StartxEndx = 0x02,
    StartxLength = 0x03,
    OffsetPair = 0x04,
    DefaultLocation = 0x05,
    BaseAddress = 0x06,
    StartEnd = 0x07,
    StartLength = 0x08,
}

impl DWARFLocationListEntry {
    /// Returns the integer value of this location list entry kind.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFLocationListEntry` for the given integer value.
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
            0x05 => Ok(Self::DefaultLocation),
            0x06 => Ok(Self::BaseAddress),
            0x07 => Ok(Self::StartEnd),
            0x08 => Ok(Self::StartLength),
            _ => Err(key),
        }
    }
}

impl std::fmt::Display for DWARFLocationListEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::EndOfList => "DW_LLE_end_of_list",
            Self::BaseAddressx => "DW_LLE_base_addressx",
            Self::StartxEndx => "DW_LLE_startx_endx",
            Self::StartxLength => "DW_LLE_startx_length",
            Self::OffsetPair => "DW_LLE_offset_pair",
            Self::DefaultLocation => "DW_LLE_default_location",
            Self::BaseAddress => "DW_LLE_base_address",
            Self::StartEnd => "DW_LLE_start_end",
            Self::StartLength => "DW_LLE_start_length",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFLocationListEntry::EndOfList.value(), 0x00);
        assert_eq!(DWARFLocationListEntry::BaseAddressx.value(), 0x01);
        assert_eq!(DWARFLocationListEntry::StartxEndx.value(), 0x02);
        assert_eq!(DWARFLocationListEntry::StartxLength.value(), 0x03);
        assert_eq!(DWARFLocationListEntry::OffsetPair.value(), 0x04);
        assert_eq!(DWARFLocationListEntry::DefaultLocation.value(), 0x05);
        assert_eq!(DWARFLocationListEntry::BaseAddress.value(), 0x06);
        assert_eq!(DWARFLocationListEntry::StartEnd.value(), 0x07);
        assert_eq!(DWARFLocationListEntry::StartLength.value(), 0x08);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFLocationListEntry::find(0x00), Ok(DWARFLocationListEntry::EndOfList));
        assert_eq!(DWARFLocationListEntry::find(0x01), Ok(DWARFLocationListEntry::BaseAddressx));
        assert_eq!(DWARFLocationListEntry::find(0x02), Ok(DWARFLocationListEntry::StartxEndx));
        assert_eq!(DWARFLocationListEntry::find(0x03), Ok(DWARFLocationListEntry::StartxLength));
        assert_eq!(DWARFLocationListEntry::find(0x04), Ok(DWARFLocationListEntry::OffsetPair));
        assert_eq!(DWARFLocationListEntry::find(0x05), Ok(DWARFLocationListEntry::DefaultLocation));
        assert_eq!(DWARFLocationListEntry::find(0x06), Ok(DWARFLocationListEntry::BaseAddress));
        assert_eq!(DWARFLocationListEntry::find(0x07), Ok(DWARFLocationListEntry::StartEnd));
        assert_eq!(DWARFLocationListEntry::find(0x08), Ok(DWARFLocationListEntry::StartLength));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFLocationListEntry::find(0x09), Err(0x09));
        assert_eq!(DWARFLocationListEntry::find(0xff), Err(0xff));
        assert_eq!(DWARFLocationListEntry::find(0x100), Err(0x100));
    }

    #[test]
    fn roundtrip_value_then_find() {
        let variants = [
            DWARFLocationListEntry::EndOfList,
            DWARFLocationListEntry::BaseAddressx,
            DWARFLocationListEntry::StartxEndx,
            DWARFLocationListEntry::StartxLength,
            DWARFLocationListEntry::OffsetPair,
            DWARFLocationListEntry::DefaultLocation,
            DWARFLocationListEntry::BaseAddress,
            DWARFLocationListEntry::StartEnd,
            DWARFLocationListEntry::StartLength,
        ];
        for variant in variants {
            assert_eq!(DWARFLocationListEntry::find(variant.value() as u64), Ok(variant));
        }
    }

    #[test]
    fn display_matches_dwarf_names() {
        assert_eq!(DWARFLocationListEntry::EndOfList.to_string(), "DW_LLE_end_of_list");
        assert_eq!(DWARFLocationListEntry::BaseAddressx.to_string(), "DW_LLE_base_addressx");
        assert_eq!(DWARFLocationListEntry::StartxEndx.to_string(), "DW_LLE_startx_endx");
        assert_eq!(DWARFLocationListEntry::StartxLength.to_string(), "DW_LLE_startx_length");
        assert_eq!(DWARFLocationListEntry::OffsetPair.to_string(), "DW_LLE_offset_pair");
        assert_eq!(DWARFLocationListEntry::DefaultLocation.to_string(), "DW_LLE_default_location");
        assert_eq!(DWARFLocationListEntry::BaseAddress.to_string(), "DW_LLE_base_address");
        assert_eq!(DWARFLocationListEntry::StartEnd.to_string(), "DW_LLE_start_end");
        assert_eq!(DWARFLocationListEntry::StartLength.to_string(), "DW_LLE_start_length");
    }
}
