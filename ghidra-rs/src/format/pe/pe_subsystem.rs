/// PE subsystem identifiers from the optional header.
///
/// Each variant corresponds to a `IMAGE_SUBSYSTEM_*` constant in the
/// Microsoft PE/COFF specification and maps to a numeric value used in the
/// optional header's `Subsystem` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeSubsystem {
    Unknown,
    Native,
    WindowsGui,
    WindowsCui,
    Os2Cui,
    PosixCui,
    NativeWindows,
    WindowsCeGui,
    EfiApplication,
    EfiBootServiceDriver,
    EfiRuntimeDriver,
    EfiRom,
    Xbox,
    WindowsBootApplication,
}

impl PeSubsystem {
    /// All variants in declaration order, mirroring the Java `values()` array.
    pub const ALL: &'static [PeSubsystem] = &[
        PeSubsystem::Unknown,
        PeSubsystem::Native,
        PeSubsystem::WindowsGui,
        PeSubsystem::WindowsCui,
        PeSubsystem::Os2Cui,
        PeSubsystem::PosixCui,
        PeSubsystem::NativeWindows,
        PeSubsystem::WindowsCeGui,
        PeSubsystem::EfiApplication,
        PeSubsystem::EfiBootServiceDriver,
        PeSubsystem::EfiRuntimeDriver,
        PeSubsystem::EfiRom,
        PeSubsystem::Xbox,
        PeSubsystem::WindowsBootApplication,
    ];

    /// Returns the canonical string alias for this subsystem.
    pub fn alias(self) -> &'static str {
        match self {
            PeSubsystem::Unknown => "IMAGE_SUBSYSTEM_UNKNOWN",
            PeSubsystem::Native => "IMAGE_SUBSYSTEM_NATIVE",
            PeSubsystem::WindowsGui => "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            PeSubsystem::WindowsCui => "IMAGE_SUBSYSTEM_WINDOWS_CUI",
            PeSubsystem::Os2Cui => "IMAGE_SUBSYSTEM_OS2_CUI",
            PeSubsystem::PosixCui => "IMAGE_SUBSYSTEM_POSIX_CUI",
            PeSubsystem::NativeWindows => "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
            PeSubsystem::WindowsCeGui => "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            PeSubsystem::EfiApplication => "IMAGE_SUBSYSTEM_EFI_APPLICATION",
            PeSubsystem::EfiBootServiceDriver => "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
            PeSubsystem::EfiRuntimeDriver => "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
            PeSubsystem::EfiRom => "IMAGE_SUBSYSTEM_EFI_ROM",
            PeSubsystem::Xbox => "IMAGE_SUBSYSTEM_XBOX",
            PeSubsystem::WindowsBootApplication => "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
        }
    }

    /// Returns the numeric subsystem identifier used in the PE optional header.
    pub fn value(self) -> u32 {
        match self {
            PeSubsystem::Unknown => 0,
            PeSubsystem::Native => 1,
            PeSubsystem::WindowsGui => 2,
            PeSubsystem::WindowsCui => 3,
            PeSubsystem::Os2Cui => 5,
            PeSubsystem::PosixCui => 7,
            PeSubsystem::NativeWindows => 8,
            PeSubsystem::WindowsCeGui => 9,
            PeSubsystem::EfiApplication => 10,
            PeSubsystem::EfiBootServiceDriver => 11,
            PeSubsystem::EfiRuntimeDriver => 12,
            PeSubsystem::EfiRom => 13,
            PeSubsystem::Xbox => 14,
            PeSubsystem::WindowsBootApplication => 16,
        }
    }

    /// Returns the human-readable description for this subsystem.
    pub fn description(self) -> &'static str {
        match self {
            PeSubsystem::Unknown => "An unknown subsystem",
            PeSubsystem::Native => "Device drivers and native Windows processes",
            PeSubsystem::WindowsGui => "The Windows graphical user interface (GUI) subsystem",
            PeSubsystem::WindowsCui => "The Windows character subsystem",
            PeSubsystem::Os2Cui => "The OS/2 character subsystem",
            PeSubsystem::PosixCui => "The Posix character subsystem",
            PeSubsystem::NativeWindows => "Native Win9x driver",
            PeSubsystem::WindowsCeGui => "Windows CE",
            PeSubsystem::EfiApplication => {
                "An Extensible Firmware Interface (EFI) application"
            }
            PeSubsystem::EfiBootServiceDriver => {
                "An Extensible Firmware Interface (EFI) driver with boot services"
            }
            PeSubsystem::EfiRuntimeDriver => {
                "An Extensible Firmware Interface (EFI) driver with run-time services"
            }
            PeSubsystem::EfiRom => "An Extensible Firmware Interface (EFI) ROM image",
            PeSubsystem::Xbox => "XBOX Image",
            PeSubsystem::WindowsBootApplication => "Windows boot application.",
        }
    }

    /// Resolves a numeric subsystem id to the matching [`PeSubsystem`] variant.
    ///
    /// Returns `Err` with the Java-compatible message when `id` does not match
    /// any known subsystem, mirroring `PeSubsystem.parse(int)`.
    pub fn parse(id: u32) -> Result<PeSubsystem, String> {
        PeSubsystem::ALL
            .iter()
            .copied()
            .find(|ss| ss.value() == id)
            .ok_or_else(|| format!("Can't resolve '{}' to known PeSubsystem", id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_has_correct_count() {
        assert_eq!(PeSubsystem::ALL.len(), 14);
    }

    #[test]
    fn value_roundtrip() {
        for &ss in PeSubsystem::ALL {
            let id = ss.value();
            assert_eq!(PeSubsystem::parse(id), Ok(ss), "roundtrip failed for {ss:?}");
        }
    }

    #[test]
    fn parse_unknown_returns_err() {
        assert_eq!(
            PeSubsystem::parse(99),
            Err("Can't resolve '99' to known PeSubsystem".to_string())
        );
    }

    #[test]
    fn parse_gap_values_return_err() {
        // Values 4, 6, and 15 are absent from the PE spec enum.
        for gap in [4u32, 6, 15] {
            assert!(PeSubsystem::parse(gap).is_err(), "expected err for gap value {gap}");
        }
    }

    #[test]
    fn alias_values() {
        assert_eq!(PeSubsystem::Unknown.alias(), "IMAGE_SUBSYSTEM_UNKNOWN");
        assert_eq!(PeSubsystem::WindowsGui.alias(), "IMAGE_SUBSYSTEM_WINDOWS_GUI");
        assert_eq!(
            PeSubsystem::WindowsBootApplication.alias(),
            "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
        );
    }

    #[test]
    fn value_spot_checks() {
        assert_eq!(PeSubsystem::Unknown.value(), 0);
        assert_eq!(PeSubsystem::Os2Cui.value(), 5);
        assert_eq!(PeSubsystem::EfiApplication.value(), 10);
        assert_eq!(PeSubsystem::WindowsBootApplication.value(), 16);
    }

    #[test]
    fn description_spot_checks() {
        assert_eq!(PeSubsystem::Unknown.description(), "An unknown subsystem");
        assert_eq!(PeSubsystem::Xbox.description(), "XBOX Image");
        assert_eq!(
            PeSubsystem::EfiRom.description(),
            "An Extensible Firmware Interface (EFI) ROM image"
        );
    }

    #[test]
    fn parse_zero_is_unknown() {
        assert_eq!(PeSubsystem::parse(0), Ok(PeSubsystem::Unknown));
    }

    #[test]
    fn all_values_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for &ss in PeSubsystem::ALL {
            assert!(seen.insert(ss.value()), "duplicate value {} for {ss:?}", ss.value());
        }
    }
}
