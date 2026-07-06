//! Chained fixup pointer formats and bit-layout helpers.
//!
//! Ported from `ghidra.app.util.bin.format.macho.dyld.DyldChainedPtr`.
//!
//! See <https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h>.

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

/// `DYLD_CHAINED_PTR_START_NONE`: sentinel meaning a page has no chain start.
pub const DYLD_CHAINED_PTR_START_NONE: u32 = 0xFFFF;
/// `DYLD_CHAINED_PTR_START_MULTI`: flag meaning a page has multiple chain starts.
pub const DYLD_CHAINED_PTR_START_MULTI: u32 = 0x8000;
/// `DYLD_CHAINED_PTR_START_LAST`: flag marking the last chain start entry for a page.
pub const DYLD_CHAINED_PTR_START_LAST: u32 = 0x8000;

/// Chained fixup pointer format, mirroring the `DYLD_CHAINED_PTR_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum DyldChainType {
    /// stride 8, unauth target is vmaddr
    Arm64e,
    /// target is vmaddr
    Ptr64,
    Ptr32,
    Ptr32Cache,
    Ptr32Firmware,
    /// target is vm offset
    Ptr64Offset,
    /// stride 4, unauth target is vm offset
    Arm64eKernel,
    Ptr64KernelCache,
    /// stride 8, unauth target is vm offset
    Arm64eUserland,
    /// stride 4, unauth target is vmaddr
    Arm64eFirmware,
    /// stride 1, x86_64 kernel caches
    X86_64KernelCache,
    /// stride 8, unauth target is vm offset, 24-bit bind
    Arm64eUserland24,
    /// stride 8, regular/auth targets both vm offsets. Only A keys supported
    Arm64eSharedCache,
    Unknown,
}

impl DyldChainType {
    /// Resolves the numeric `DYLD_CHAINED_PTR_*` value to its variant.
    ///
    /// Returns [`DyldChainType::Unknown`] for any unrecognized value, mirroring
    /// `DyldChainType.lookupChainPtr(int)`.
    pub fn lookup_chain_ptr(val: i32) -> DyldChainType {
        match val {
            1 => DyldChainType::Arm64e,
            2 => DyldChainType::Ptr64,
            3 => DyldChainType::Ptr32,
            4 => DyldChainType::Ptr32Cache,
            5 => DyldChainType::Ptr32Firmware,
            6 => DyldChainType::Ptr64Offset,
            7 => DyldChainType::Arm64eKernel,
            8 => DyldChainType::Ptr64KernelCache,
            9 => DyldChainType::Arm64eUserland,
            10 => DyldChainType::Arm64eFirmware,
            11 => DyldChainType::X86_64KernelCache,
            12 => DyldChainType::Arm64eUserland24,
            13 => DyldChainType::Arm64eSharedCache,
            _ => DyldChainType::Unknown,
        }
    }

    /// Returns the numeric `DYLD_CHAINED_PTR_*` value for this format.
    pub fn value(self) -> i32 {
        match self {
            DyldChainType::Arm64e => 1,
            DyldChainType::Ptr64 => 2,
            DyldChainType::Ptr32 => 3,
            DyldChainType::Ptr32Cache => 4,
            DyldChainType::Ptr32Firmware => 5,
            DyldChainType::Ptr64Offset => 6,
            DyldChainType::Arm64eKernel => 7,
            DyldChainType::Ptr64KernelCache => 8,
            DyldChainType::Arm64eUserland => 9,
            DyldChainType::Arm64eFirmware => 10,
            DyldChainType::X86_64KernelCache => 11,
            DyldChainType::Arm64eUserland24 => 12,
            DyldChainType::Arm64eSharedCache => 13,
            DyldChainType::Unknown => -1,
        }
    }

    /// Returns the constant name for this format with the `DYLD_CHAINED_` prefix
    /// stripped, mirroring `DyldChainType.getName()`.
    pub fn name(self) -> &'static str {
        match self {
            DyldChainType::Arm64e => "PTR_ARM64E",
            DyldChainType::Ptr64 => "PTR_64",
            DyldChainType::Ptr32 => "PTR_32",
            DyldChainType::Ptr32Cache => "PTR_32_CACHE",
            DyldChainType::Ptr32Firmware => "PTR_32_FIRMWARE",
            DyldChainType::Ptr64Offset => "PTR_64_OFFSET",
            DyldChainType::Arm64eKernel => "PTR_ARM64E_KERNEL",
            DyldChainType::Ptr64KernelCache => "PTR_64_KERNEL_CACHE",
            DyldChainType::Arm64eUserland => "PTR_ARM64E_USERLAND",
            DyldChainType::Arm64eFirmware => "PTR_ARM64E_FIRMWARE",
            DyldChainType::X86_64KernelCache => "PTR_X86_64_KERNEL_CACHE",
            DyldChainType::Arm64eUserland24 => "PTR_ARM64E_USERLAND24",
            DyldChainType::Arm64eSharedCache => "PTR_ARM64E_SHARED_CACHE",
            DyldChainType::Unknown => "PTR_TYPE_UNKNOWN",
        }
    }

    /// Returns the chain entry stride, in bytes, for this pointer format.
    pub fn stride(self) -> i64 {
        match self {
            DyldChainType::Ptr64
            | DyldChainType::Ptr64Offset
            | DyldChainType::Arm64eKernel
            | DyldChainType::Ptr64KernelCache
            | DyldChainType::Arm64eFirmware
            | DyldChainType::Ptr32
            | DyldChainType::Ptr32Cache
            | DyldChainType::Ptr32Firmware => 4,
            DyldChainType::Arm64e
            | DyldChainType::Arm64eUserland
            | DyldChainType::Arm64eUserland24
            | DyldChainType::Arm64eSharedCache => 8,
            DyldChainType::X86_64KernelCache | DyldChainType::Unknown => 1,
        }
    }

    /// Returns the on-disk size, in bytes, of a chain entry for this pointer format.
    pub fn size(self) -> i32 {
        match self {
            DyldChainType::Ptr32 | DyldChainType::Ptr32Cache | DyldChainType::Ptr32Firmware => 4,
            _ => 8,
        }
    }

    /// Reads the raw chain entry value at `chain_loc` for this pointer format.
    pub fn chain_value(
        self,
        reader: &dyn BinaryReader,
        chain_loc: u64,
    ) -> io::Result<i64> {
        match self {
            DyldChainType::Ptr32 | DyldChainType::Ptr32Cache | DyldChainType::Ptr32Firmware => {
                Ok(reader.read_unsigned_int(chain_loc)? as i64)
            }
            DyldChainType::Arm64e
            | DyldChainType::Arm64eUserland
            | DyldChainType::Arm64eUserland24
            | DyldChainType::Ptr64
            | DyldChainType::Ptr64Offset
            | DyldChainType::Arm64eKernel
            | DyldChainType::Ptr64KernelCache
            | DyldChainType::Arm64eFirmware
            | DyldChainType::X86_64KernelCache
            | DyldChainType::Arm64eSharedCache => reader.read_long(chain_loc),
            DyldChainType::Unknown => Ok(0),
        }
    }

    /// Returns true if this pointer format's target is a vm offset rather than a vmaddr.
    pub fn is_relative(self) -> bool {
        matches!(
            self,
            DyldChainType::Ptr64Offset
                | DyldChainType::Arm64eKernel
                | DyldChainType::Arm64eUserland
                | DyldChainType::Arm64eUserland24
                | DyldChainType::Ptr64KernelCache
                | DyldChainType::X86_64KernelCache
                | DyldChainType::Arm64eSharedCache
        )
    }

    /// Returns true if `chain_value` represents a bind (import) rather than a rebase.
    pub fn is_bound(self, chain_value: i64) -> bool {
        let cv = chain_value as u64;
        match self {
            DyldChainType::Arm64e
            | DyldChainType::Arm64eKernel
            | DyldChainType::Arm64eUserland
            | DyldChainType::Arm64eUserland24 => ((cv >> 62) & 1) != 0,
            DyldChainType::Ptr64 | DyldChainType::Ptr64Offset => ((cv >> 63) & 1) != 0,
            DyldChainType::Ptr32 => ((cv >> 31) & 1) != 0,
            _ => false,
        }
    }

    /// Returns true if `chain_value` carries pointer authentication data.
    pub fn is_authenticated(self, chain_value: i64) -> bool {
        match self {
            DyldChainType::Ptr64
            | DyldChainType::Ptr64Offset
            | DyldChainType::Ptr32
            | DyldChainType::Ptr32Cache
            | DyldChainType::Ptr32Firmware => false,
            _ => ((chain_value as u64 >> 63) & 1) != 0,
        }
    }

    /// Returns the rebase target encoded in `chain_value`, or `-1` if `chain_value`
    /// represents a bind rather than a rebase.
    pub fn target(self, chain_value: i64) -> i64 {
        if self.is_bound(chain_value) {
            return -1;
        }

        if self.is_authenticated(chain_value) {
            match self {
                DyldChainType::Arm64e
                | DyldChainType::Arm64eUserland
                | DyldChainType::Arm64eUserland24
                | DyldChainType::Arm64eKernel => return chain_value & 0xFFFF_FFFF,
                DyldChainType::X86_64KernelCache | DyldChainType::Ptr64KernelCache => {
                    return chain_value & 0x3FFF_FFFF; // 30 bits
                }
                DyldChainType::Arm64eSharedCache => return chain_value & 0x3_FFFF_FFFF, // 34 bits
                _ => {}
            }
        }

        match self {
            DyldChainType::Arm64e
            | DyldChainType::Arm64eUserland
            | DyldChainType::Arm64eUserland24
            | DyldChainType::Arm64eKernel => {
                let mut top8_bits = (chain_value >> 43) & 0xFF;
                let bottom43_bits = chain_value & 0x0000_07FF_FFFF_FFFF;
                // Hack! Top bits don't matter and are a pointer tag
                if top8_bits == 0x80 {
                    top8_bits = 0;
                }
                (top8_bits << 56) | bottom43_bits
            }
            DyldChainType::Ptr64 | DyldChainType::Ptr64Offset => {
                let mut top8_bits = (chain_value >> 36) & 0xFF;
                let bottom36_bits = chain_value & 0xF_FFFF_FFFF;
                // Hack! Top bits don't matter and are a pointer tag
                if top8_bits == 0x80 {
                    top8_bits = 0;
                }
                (top8_bits << 56) | bottom36_bits
            }
            DyldChainType::Ptr32 => chain_value & 0x3F_FFFF, // 26 bits
            DyldChainType::Ptr32Cache => chain_value & 0x3FFF_FFFF, // 30 bits
            DyldChainType::Ptr32Firmware => chain_value & 0x3F_FFFF, // 26 bits
            DyldChainType::X86_64KernelCache | DyldChainType::Ptr64KernelCache => {
                chain_value & 0x3FFF_FFFF // 30 bits
            }
            DyldChainType::Arm64eSharedCache => chain_value & 0x3_FFFF_FFFF, // 34 bits
            _ => 0,
        }
    }

    /// Returns the bind addend encoded in `chain_value`, or `0` if `chain_value`
    /// represents a rebase rather than a bind.
    pub fn addend(self, chain_value: i64) -> i64 {
        if !self.is_bound(chain_value) {
            return 0;
        }

        match self {
            DyldChainType::Arm64e | DyldChainType::Arm64eUserland | DyldChainType::Arm64eUserland24 => {
                let addend = (chain_value as u64 >> 32) & 0x7_FFFF;
                if (addend & 0x4_0000) != 0 {
                    (addend | 0xFFFF_FFFF_FFFC_0000) as i64
                } else {
                    addend as i64
                }
            }
            DyldChainType::Ptr64 | DyldChainType::Ptr64Offset => {
                ((chain_value as u64 >> 24) & 0xFF) as i64
            }
            DyldChainType::Ptr32 => ((chain_value as u64 >> 20) & 0x3F) as i64, // 6 bits
            _ => 0,
        }
    }

    /// Returns the bind ordinal encoded in `chain_value`, or `-1` if `chain_value`
    /// represents a rebase rather than a bind.
    pub fn ordinal(self, chain_value: i64) -> i64 {
        if !self.is_bound(chain_value) {
            return -1;
        }

        match self {
            DyldChainType::Arm64e | DyldChainType::Arm64eKernel | DyldChainType::Arm64eUserland => {
                chain_value & 0xFFFF
            }
            DyldChainType::Arm64eUserland24 | DyldChainType::Ptr64 | DyldChainType::Ptr64Offset => {
                chain_value & 0xFF_FFFF
            }
            DyldChainType::Ptr32 => chain_value & 0xF_FFFF,
            _ => -1,
        }
    }

    /// Returns the offset, in strides, to the next chain entry encoded in `chain_value`.
    pub fn next(self, chain_value: i64) -> i64 {
        let cv = chain_value as u64;
        match self {
            DyldChainType::Arm64e
            | DyldChainType::Arm64eUserland
            | DyldChainType::Arm64eUserland24
            | DyldChainType::Arm64eKernel => ((cv >> 51) & 0x7FF) as i64, // 11-bits
            DyldChainType::Ptr64
            | DyldChainType::Ptr64Offset
            | DyldChainType::X86_64KernelCache
            | DyldChainType::Ptr64KernelCache => ((cv >> 51) & 0xFFF) as i64, // 12 bits
            DyldChainType::Ptr32 => ((cv >> 26) & 0x1F) as i64, // 5 bits
            // Never bound
            DyldChainType::Arm64eFirmware => 0,
            DyldChainType::Ptr32Cache => ((cv >> 30) & 0x3) as i64, // 2 bits
            DyldChainType::Ptr32Firmware => ((cv >> 26) & 0x3F) as i64, // 6 bits
            DyldChainType::Arm64eSharedCache => ((cv >> 52) & 0x7FF) as i64, // 11 bits
            DyldChainType::Unknown => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_chain_ptr_roundtrip() {
        let all = [
            DyldChainType::Arm64e,
            DyldChainType::Ptr64,
            DyldChainType::Ptr32,
            DyldChainType::Ptr32Cache,
            DyldChainType::Ptr32Firmware,
            DyldChainType::Ptr64Offset,
            DyldChainType::Arm64eKernel,
            DyldChainType::Ptr64KernelCache,
            DyldChainType::Arm64eUserland,
            DyldChainType::Arm64eFirmware,
            DyldChainType::X86_64KernelCache,
            DyldChainType::Arm64eUserland24,
            DyldChainType::Arm64eSharedCache,
        ];
        for t in all {
            assert_eq!(DyldChainType::lookup_chain_ptr(t.value()), t);
        }
    }

    #[test]
    fn lookup_chain_ptr_unknown_for_bad_value() {
        assert_eq!(DyldChainType::lookup_chain_ptr(0), DyldChainType::Unknown);
        assert_eq!(DyldChainType::lookup_chain_ptr(99), DyldChainType::Unknown);
        assert_eq!(DyldChainType::Unknown.value(), -1);
    }

    #[test]
    fn name_strips_prefix() {
        assert_eq!(DyldChainType::Arm64e.name(), "PTR_ARM64E");
        assert_eq!(DyldChainType::X86_64KernelCache.name(), "PTR_X86_64_KERNEL_CACHE");
        assert_eq!(DyldChainType::Unknown.name(), "PTR_TYPE_UNKNOWN");
    }

    #[test]
    fn stride_values() {
        assert_eq!(DyldChainType::Ptr64.stride(), 4);
        assert_eq!(DyldChainType::Arm64e.stride(), 8);
        assert_eq!(DyldChainType::X86_64KernelCache.stride(), 1);
        assert_eq!(DyldChainType::Unknown.stride(), 1);
    }

    #[test]
    fn size_values() {
        assert_eq!(DyldChainType::Ptr32.size(), 4);
        assert_eq!(DyldChainType::Ptr64.size(), 8);
        assert_eq!(DyldChainType::Arm64eSharedCache.size(), 8);
    }

    #[test]
    fn is_relative_values() {
        assert!(DyldChainType::Ptr64Offset.is_relative());
        assert!(DyldChainType::Arm64eSharedCache.is_relative());
        assert!(!DyldChainType::Ptr64.is_relative());
        assert!(!DyldChainType::Arm64e.is_relative());
    }

    #[test]
    fn is_bound_arm64e() {
        let bound = 1i64 << 62;
        let unbound = 0i64;
        assert!(DyldChainType::Arm64e.is_bound(bound));
        assert!(!DyldChainType::Arm64e.is_bound(unbound));
    }

    #[test]
    fn is_bound_ptr64() {
        let bound = 1i64 << 63;
        assert!(DyldChainType::Ptr64.is_bound(bound));
        assert!(!DyldChainType::Ptr64.is_bound(0));
    }

    #[test]
    fn is_bound_ptr32() {
        let bound = 1i64 << 31;
        assert!(DyldChainType::Ptr32.is_bound(bound));
        assert!(!DyldChainType::Ptr32.is_bound(0));
    }

    #[test]
    fn is_bound_never_bound_formats() {
        assert!(!DyldChainType::Ptr32Cache.is_bound(-1));
        assert!(!DyldChainType::Arm64eFirmware.is_bound(-1));
    }

    #[test]
    fn is_authenticated_values() {
        let top_bit = 1i64 << 63;
        assert!(!DyldChainType::Ptr64.is_authenticated(top_bit));
        assert!(!DyldChainType::Ptr32.is_authenticated(top_bit));
        assert!(DyldChainType::Arm64e.is_authenticated(top_bit));
        assert!(!DyldChainType::Arm64e.is_authenticated(0));
    }

    #[test]
    fn target_returns_minus_one_when_bound() {
        let bound = 1i64 << 63;
        assert_eq!(DyldChainType::Ptr64.target(bound), -1);
    }

    #[test]
    fn target_ptr32_masks_26_bits() {
        let chain_value = 0x0FFF_FFFFi64;
        assert_eq!(DyldChainType::Ptr32.target(chain_value), chain_value & 0x3F_FFFF);
    }

    #[test]
    fn target_ptr64_strips_pointer_tag() {
        // top8Bits == 0x80 is treated as a plain pointer tag and zeroed out.
        let chain_value = 0x80i64 << 36;
        assert_eq!(DyldChainType::Ptr64.target(chain_value), 0);
    }

    #[test]
    fn target_ptr64_preserves_nonzero_tag() {
        let bottom36 = 0x1234i64;
        let chain_value = (0x12i64 << 36) | bottom36;
        assert_eq!(DyldChainType::Ptr64.target(chain_value), (0x12i64 << 56) | bottom36);
    }

    #[test]
    fn target_arm64e_authenticated_masks_low_32_bits() {
        let auth_bit = 1i64 << 63;
        let chain_value = auth_bit | 0xDEAD_BEEFi64;
        assert_eq!(DyldChainType::Arm64e.target(chain_value), 0xDEAD_BEEF);
    }

    #[test]
    fn addend_zero_when_not_bound() {
        assert_eq!(DyldChainType::Ptr64.addend(0), 0);
    }

    #[test]
    fn addend_ptr64_extracts_byte() {
        let bound_bit = 1i64 << 63;
        let chain_value = bound_bit | (0x7Fi64 << 24);
        assert_eq!(DyldChainType::Ptr64.addend(chain_value), 0x7F);
    }

    #[test]
    fn addend_arm64e_sign_extends_negative() {
        let bound_bit = 1i64 << 62;
        // Set bit 18 of the 19-bit addend field to force sign extension.
        let addend_field = 0x4_0001i64;
        let chain_value = bound_bit | (addend_field << 32);
        assert_eq!(DyldChainType::Arm64e.addend(chain_value), -0x3_FFFF);
    }

    #[test]
    fn ordinal_minus_one_when_not_bound() {
        assert_eq!(DyldChainType::Ptr64.ordinal(0), -1);
    }

    #[test]
    fn ordinal_ptr64_extracts_24_bits() {
        let bound_bit = 1i64 << 63;
        let chain_value = bound_bit | 0xABCDEF;
        assert_eq!(DyldChainType::Ptr64.ordinal(chain_value), 0xABCDEF);
    }

    #[test]
    fn next_arm64e_firmware_never_bound_yields_zero() {
        assert_eq!(DyldChainType::Arm64eFirmware.next(-1), 0);
    }

    #[test]
    fn next_ptr32_extracts_5_bits() {
        let chain_value = 0x1Fi64 << 26;
        assert_eq!(DyldChainType::Ptr32.next(chain_value), 0x1F);
    }

    #[test]
    fn next_unknown_defaults_to_one() {
        assert_eq!(DyldChainType::Unknown.next(0), 1);
    }
}
