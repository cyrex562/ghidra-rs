/// Represents the `IMAGE_ROM_OPTIONAL_HEADER` data structure from the PE format.
///
/// ```c
/// typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
///     WORD   Magic;
///     BYTE   MajorLinkerVersion;
///     BYTE   MinorLinkerVersion;
///     DWORD  SizeOfCode;
///     DWORD  SizeOfInitializedData;
///     DWORD  SizeOfUninitializedData;
///     DWORD  AddressOfEntryPoint;
///     DWORD  BaseOfCode;
///     DWORD  BaseOfData;
///     DWORD  BaseOfBss;
///     DWORD  GprMask;
///     DWORD  CprMask[4];
///     DWORD  GpValue;
/// } IMAGE_ROM_OPTIONAL_HEADER, *PIMAGE_ROM_OPTIONAL_HEADER;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OptionalHeaderRom {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub base_of_bss: u32,
    pub gpr_mask: u32,
    pub cpr_mask: [u32; 4],
    pub gp_value: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_zeroed() {
        let h = OptionalHeaderRom::default();
        assert_eq!(h.magic, 0);
        assert_eq!(h.major_linker_version, 0);
        assert_eq!(h.minor_linker_version, 0);
        assert_eq!(h.size_of_code, 0);
        assert_eq!(h.size_of_initialized_data, 0);
        assert_eq!(h.size_of_uninitialized_data, 0);
        assert_eq!(h.address_of_entry_point, 0);
        assert_eq!(h.base_of_code, 0);
        assert_eq!(h.base_of_data, 0);
        assert_eq!(h.base_of_bss, 0);
        assert_eq!(h.gpr_mask, 0);
        assert_eq!(h.cpr_mask, [0u32; 4]);
        assert_eq!(h.gp_value, 0);
    }

    #[test]
    fn round_trip_fields() {
        let h = OptionalHeaderRom {
            magic: 0x0107,
            major_linker_version: 2,
            minor_linker_version: 56,
            size_of_code: 0x1000,
            size_of_initialized_data: 0x2000,
            size_of_uninitialized_data: 0x400,
            address_of_entry_point: 0x100,
            base_of_code: 0x1000,
            base_of_data: 0x3000,
            base_of_bss: 0x5000,
            gpr_mask: 0xDEAD,
            cpr_mask: [1, 2, 3, 4],
            gp_value: 0xBEEF,
        };
        assert_eq!(h.magic, 0x0107);
        assert_eq!(h.major_linker_version, 2);
        assert_eq!(h.minor_linker_version, 56);
        assert_eq!(h.size_of_code, 0x1000);
        assert_eq!(h.size_of_initialized_data, 0x2000);
        assert_eq!(h.size_of_uninitialized_data, 0x400);
        assert_eq!(h.address_of_entry_point, 0x100);
        assert_eq!(h.base_of_code, 0x1000);
        assert_eq!(h.base_of_data, 0x3000);
        assert_eq!(h.base_of_bss, 0x5000);
        assert_eq!(h.gpr_mask, 0xDEAD);
        assert_eq!(h.cpr_mask, [1, 2, 3, 4]);
        assert_eq!(h.gp_value, 0xBEEF);
    }

    #[test]
    fn cpr_mask_has_four_elements() {
        let h = OptionalHeaderRom {
            cpr_mask: [0xA, 0xB, 0xC, 0xD],
            ..Default::default()
        };
        assert_eq!(h.cpr_mask.len(), 4);
        assert_eq!(h.cpr_mask[0], 0xA);
        assert_eq!(h.cpr_mask[3], 0xD);
    }

    #[test]
    fn clone_equality() {
        let h = OptionalHeaderRom {
            magic: 0x0107,
            cpr_mask: [10, 20, 30, 40],
            ..Default::default()
        };
        let h2 = h.clone();
        assert_eq!(h, h2);
    }

    #[test]
    fn max_field_values() {
        let h = OptionalHeaderRom {
            magic: u16::MAX,
            major_linker_version: u8::MAX,
            minor_linker_version: u8::MAX,
            size_of_code: u32::MAX,
            size_of_initialized_data: u32::MAX,
            size_of_uninitialized_data: u32::MAX,
            address_of_entry_point: u32::MAX,
            base_of_code: u32::MAX,
            base_of_data: u32::MAX,
            base_of_bss: u32::MAX,
            gpr_mask: u32::MAX,
            cpr_mask: [u32::MAX; 4],
            gp_value: u32::MAX,
        };
        assert_eq!(h.magic, 0xFFFF);
        assert_eq!(h.size_of_code, 0xFFFF_FFFF);
        assert_eq!(h.cpr_mask, [u32::MAX; 4]);
    }
}
