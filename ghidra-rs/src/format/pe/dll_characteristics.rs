use std::collections::HashSet;

/// PE DLL characteristics flags from the optional header.
///
/// Each variant corresponds to one bit in the `DllCharacteristics` field of
/// the PE optional header.  See the Microsoft PE/COFF specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DllCharacteristics {
    HighEntropyVa,
    DynamicBase,
    ForceIntegrity,
    NxCompat,
    NoIsolation,
    NoSeh,
    NoBind,
    AppContainer,
    WdmDriver,
    GuardCf,
    TerminalServerAware,
}

impl DllCharacteristics {
    /// All variants in declaration order, used for iteration.
    pub const ALL: &'static [DllCharacteristics] = &[
        DllCharacteristics::HighEntropyVa,
        DllCharacteristics::DynamicBase,
        DllCharacteristics::ForceIntegrity,
        DllCharacteristics::NxCompat,
        DllCharacteristics::NoIsolation,
        DllCharacteristics::NoSeh,
        DllCharacteristics::NoBind,
        DllCharacteristics::AppContainer,
        DllCharacteristics::WdmDriver,
        DllCharacteristics::GuardCf,
        DllCharacteristics::TerminalServerAware,
    ];

    /// Returns the canonical string alias for this characteristic.
    pub fn alias(self) -> &'static str {
        match self {
            DllCharacteristics::HighEntropyVa => "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
            DllCharacteristics::DynamicBase => "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
            DllCharacteristics::ForceIntegrity => "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY",
            DllCharacteristics::NxCompat => "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
            DllCharacteristics::NoIsolation => "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION",
            DllCharacteristics::NoSeh => "IMAGE_DLLCHARACTERISTICS_NO_SEH",
            DllCharacteristics::NoBind => "IMAGE_DLLCHARACTERISTICS_NO_BIND",
            DllCharacteristics::AppContainer => "IMAGE_DLLCHARACTERISTICS_APPCONTAINER",
            DllCharacteristics::WdmDriver => "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER",
            DllCharacteristics::GuardCf => "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
            DllCharacteristics::TerminalServerAware => {
                "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
            }
        }
    }

    /// Returns the bitmask value for this characteristic.
    pub fn mask(self) -> u16 {
        match self {
            DllCharacteristics::HighEntropyVa => 0x0020,
            DllCharacteristics::DynamicBase => 0x0040,
            DllCharacteristics::ForceIntegrity => 0x0080,
            DllCharacteristics::NxCompat => 0x0100,
            DllCharacteristics::NoIsolation => 0x0200,
            DllCharacteristics::NoSeh => 0x0400,
            DllCharacteristics::NoBind => 0x0800,
            DllCharacteristics::AppContainer => 0x1000,
            DllCharacteristics::WdmDriver => 0x2000,
            DllCharacteristics::GuardCf => 0x4000,
            DllCharacteristics::TerminalServerAware => 0x8000,
        }
    }

    /// Returns the human-readable description for this characteristic.
    pub fn description(self) -> &'static str {
        match self {
            DllCharacteristics::HighEntropyVa => {
                "Image can handle a high entropy 64-bit virtual address space."
            }
            DllCharacteristics::DynamicBase => "DLL can be relocated at load time.",
            DllCharacteristics::ForceIntegrity => "Code Integrity checks are enforced.",
            DllCharacteristics::NxCompat => "Image is NX compatible.",
            DllCharacteristics::NoIsolation => {
                "Isolation aware, but do not isolate the image."
            }
            DllCharacteristics::NoSeh => {
                "Does not use structured exception (SE) handling. No SE handler may be called in this image."
            }
            DllCharacteristics::NoBind => "Do not bind the image.",
            DllCharacteristics::AppContainer => "Image must execute in an AppContainer.",
            DllCharacteristics::WdmDriver => "A WDM driver.",
            DllCharacteristics::GuardCf => "Image supports Control Flow Guard.",
            DllCharacteristics::TerminalServerAware => "Terminal Server aware.",
        }
    }
}

/// Returns the set of [`DllCharacteristics`] whose masks are set in `value`.
pub fn resolve_characteristics(value: u16) -> HashSet<DllCharacteristics> {
    DllCharacteristics::ALL
        .iter()
        .copied()
        .filter(|ch| (value & ch.mask()) == ch.mask())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_values() {
        assert_eq!(DllCharacteristics::HighEntropyVa.mask(), 0x0020);
        assert_eq!(DllCharacteristics::DynamicBase.mask(), 0x0040);
        assert_eq!(DllCharacteristics::ForceIntegrity.mask(), 0x0080);
        assert_eq!(DllCharacteristics::NxCompat.mask(), 0x0100);
        assert_eq!(DllCharacteristics::NoIsolation.mask(), 0x0200);
        assert_eq!(DllCharacteristics::NoSeh.mask(), 0x0400);
        assert_eq!(DllCharacteristics::NoBind.mask(), 0x0800);
        assert_eq!(DllCharacteristics::AppContainer.mask(), 0x1000);
        assert_eq!(DllCharacteristics::WdmDriver.mask(), 0x2000);
        assert_eq!(DllCharacteristics::GuardCf.mask(), 0x4000);
        assert_eq!(DllCharacteristics::TerminalServerAware.mask(), 0x8000);
    }

    #[test]
    fn alias_values() {
        assert_eq!(
            DllCharacteristics::HighEntropyVa.alias(),
            "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"
        );
        assert_eq!(
            DllCharacteristics::DynamicBase.alias(),
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"
        );
        assert_eq!(
            DllCharacteristics::TerminalServerAware.alias(),
            "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"
        );
    }

    #[test]
    fn description_values() {
        assert_eq!(
            DllCharacteristics::DynamicBase.description(),
            "DLL can be relocated at load time."
        );
        assert_eq!(
            DllCharacteristics::WdmDriver.description(),
            "A WDM driver."
        );
        assert_eq!(
            DllCharacteristics::GuardCf.description(),
            "Image supports Control Flow Guard."
        );
    }

    #[test]
    fn resolve_zero_returns_empty() {
        assert!(resolve_characteristics(0).is_empty());
    }

    #[test]
    fn resolve_single_flag() {
        let result = resolve_characteristics(0x0040);
        assert_eq!(result.len(), 1);
        assert!(result.contains(&DllCharacteristics::DynamicBase));
    }

    #[test]
    fn resolve_multiple_flags() {
        let value: u16 = 0x0040 | 0x0100 | 0x8000;
        let result = resolve_characteristics(value);
        assert_eq!(result.len(), 3);
        assert!(result.contains(&DllCharacteristics::DynamicBase));
        assert!(result.contains(&DllCharacteristics::NxCompat));
        assert!(result.contains(&DllCharacteristics::TerminalServerAware));
    }

    #[test]
    fn resolve_all_flags() {
        let all_mask: u16 = DllCharacteristics::ALL.iter().map(|c| c.mask()).fold(0, |a, m| a | m);
        let result = resolve_characteristics(all_mask);
        assert_eq!(result.len(), DllCharacteristics::ALL.len());
    }

    #[test]
    fn all_masks_are_powers_of_two() {
        for ch in DllCharacteristics::ALL {
            let m = ch.mask();
            assert!(m.is_power_of_two(), "{} mask {:#06x} is not a power of two", ch.alias(), m);
        }
    }

    #[test]
    fn all_has_correct_count() {
        assert_eq!(DllCharacteristics::ALL.len(), 11);
    }
}
