use std::fmt;

/// Target Processor (CPU Type).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Processor {
    Unknown = -1,
    I8080 = 0x00,
    I8086 = 0x01,
    I80286 = 0x02,
    I80386 = 0x03,
    I80486 = 0x04,
    Pentium = 0x05,
    PentiumProPentiumII = 0x06,
    PentiumIII = 0x07,
    MipsMipsR4000 = 0x10,
    Mips16 = 0x11,
    Mips32 = 0x12,
    Mips64 = 0x13,
    MipsI = 0x14,
    MipsII = 0x15,
    MipsIII = 0x16,
    MipsIV = 0x17,
    MipsV = 0x18,
    M68000 = 0x20,
    M68010 = 0x21,
    M68020 = 0x22,
    M68030 = 0x23,
    M68040 = 0x24,
    Alpha21064 = 0x30,
    Alpha21164 = 0x31,
    Alpha21164A = 0x32,
    Alpha21264 = 0x33,
    Alpha21364 = 0x34,
    Ppc601 = 0x40,
    Ppc603 = 0x41,
    Ppc604 = 0x42,
    Ppc620 = 0x43,
    PpcFp = 0x44,
    PpcBe = 0x45,
    Sh3 = 0x50,
    Sh3E = 0x51,
    Sh3Dsp = 0x52,
    Sh4 = 0x53,
    ShMedia = 0x54,
    Arm3 = 0x60,
    Arm4 = 0x61,
    Arm4T = 0x62,
    Arm5 = 0x63,
    Arm5T = 0x64,
    Arm6 = 0x65,
    ArmXmac = 0x66,
    ArmWmmx = 0x67,
    Arm7 = 0x68,
    Omni = 0x70,
    Ia64Ia641 = 0x80,
    Ia642 = 0x81,
    Cee = 0x90,
    Am33 = 0xA0,
    M32R = 0xB0,
    TriCore = 0xC0,
    X64Amd64 = 0xD0,
    Ebc = 0xE0,
    Thumb = 0xF0,
    ArmNt = 0xF4,
    Arm64 = 0xF6,
    D3D11Shader = 0x100,
    Unk1AB = 0x1AB,
    Unk304 = 0x304,
}

impl Processor {
    /// Returns the display label for this processor.
    pub fn label(self) -> &'static str {
        match self {
            Processor::Unknown => "???",
            Processor::I8080 => "8080",
            Processor::I8086 => "8086",
            Processor::I80286 => "80286",
            Processor::I80386 => "80386",
            Processor::I80486 => "80486",
            Processor::Pentium => "Pentium",
            Processor::PentiumProPentiumII => "Pentium Pro/Pentium II",
            Processor::PentiumIII => "Pentium III",
            Processor::MipsMipsR4000 => "MIPS (Generic)/R4000",
            Processor::Mips16 => "MIPS16",
            Processor::Mips32 => "MIPS32",
            Processor::Mips64 => "MIPS64",
            Processor::MipsI => "MIPS I",
            Processor::MipsII => "MIPS II",
            Processor::MipsIII => "MIPS III",
            Processor::MipsIV => "MIPS IV",
            Processor::MipsV => "MIPS V",
            Processor::M68000 => "M68000",
            Processor::M68010 => "M68010",
            Processor::M68020 => "M68020",
            Processor::M68030 => "M68030",
            Processor::M68040 => "M68040",
            Processor::Alpha21064 => "Alpha/Alpha 21064",
            Processor::Alpha21164 => "Alpha 21164",
            Processor::Alpha21164A => "Alpha 21164a",
            Processor::Alpha21264 => "Alpha 21264",
            Processor::Alpha21364 => "Alpha 21364",
            Processor::Ppc601 => "PPC 601",
            Processor::Ppc603 => "PPC 603",
            Processor::Ppc604 => "PPC 604",
            Processor::Ppc620 => "PPC 620",
            Processor::PpcFp => "PPC w/FP",
            Processor::PpcBe => "PPC (Big Endian)",
            Processor::Sh3 => "SH3",
            Processor::Sh3E => "SH3E",
            Processor::Sh3Dsp => "SH3DSP",
            Processor::Sh4 => "SH4",
            Processor::ShMedia => "SHmedia",
            Processor::Arm3 => "ARMv3 (CE)",
            Processor::Arm4 => "ARMv4 (CE)",
            Processor::Arm4T => "ARMv4T (CE)",
            Processor::Arm5 => "ARMv5 (CE)",
            Processor::Arm5T => "ARMv5T (CE)",
            Processor::Arm6 => "ARMv6 (CE)",
            Processor::ArmXmac => "ARM (XMAC) (CE)",
            Processor::ArmWmmx => "ARM (XMMX) (CE)",
            Processor::Arm7 => "ARMv7 (CE)",
            Processor::Omni => "Omni",
            Processor::Ia64Ia641 => "Itanium",
            Processor::Ia642 => "Itanium (McKinley)",
            Processor::Cee => "CEE",
            Processor::Am33 => "AM33",
            Processor::M32R => "M32R",
            Processor::TriCore => "TriCore",
            Processor::X64Amd64 => "x64",
            Processor::Ebc => "EBC",
            Processor::Thumb => "Thumb (CE)",
            Processor::ArmNt => "ARM",
            Processor::Arm64 => "ARM64",
            Processor::D3D11Shader => "D3D11_SHADER",
            Processor::Unk1AB => "Unknown1ab",
            Processor::Unk304 => "Unknown304",
        }
    }

    /// Returns the numeric value for this processor.
    pub fn value(self) -> i32 {
        self as i32
    }

    /// Returns the [`Processor`] corresponding to `val`, or [`Processor::Unknown`] if not found.
    pub fn from_value(val: i32) -> Self {
        match val {
            0x00 => Processor::I8080,
            0x01 => Processor::I8086,
            0x02 => Processor::I80286,
            0x03 => Processor::I80386,
            0x04 => Processor::I80486,
            0x05 => Processor::Pentium,
            0x06 => Processor::PentiumProPentiumII,
            0x07 => Processor::PentiumIII,
            0x10 => Processor::MipsMipsR4000,
            0x11 => Processor::Mips16,
            0x12 => Processor::Mips32,
            0x13 => Processor::Mips64,
            0x14 => Processor::MipsI,
            0x15 => Processor::MipsII,
            0x16 => Processor::MipsIII,
            0x17 => Processor::MipsIV,
            0x18 => Processor::MipsV,
            0x20 => Processor::M68000,
            0x21 => Processor::M68010,
            0x22 => Processor::M68020,
            0x23 => Processor::M68030,
            0x24 => Processor::M68040,
            0x30 => Processor::Alpha21064,
            0x31 => Processor::Alpha21164,
            0x32 => Processor::Alpha21164A,
            0x33 => Processor::Alpha21264,
            0x34 => Processor::Alpha21364,
            0x40 => Processor::Ppc601,
            0x41 => Processor::Ppc603,
            0x42 => Processor::Ppc604,
            0x43 => Processor::Ppc620,
            0x44 => Processor::PpcFp,
            0x45 => Processor::PpcBe,
            0x50 => Processor::Sh3,
            0x51 => Processor::Sh3E,
            0x52 => Processor::Sh3Dsp,
            0x53 => Processor::Sh4,
            0x54 => Processor::ShMedia,
            0x60 => Processor::Arm3,
            0x61 => Processor::Arm4,
            0x62 => Processor::Arm4T,
            0x63 => Processor::Arm5,
            0x64 => Processor::Arm5T,
            0x65 => Processor::Arm6,
            0x66 => Processor::ArmXmac,
            0x67 => Processor::ArmWmmx,
            0x68 => Processor::Arm7,
            0x70 => Processor::Omni,
            0x80 => Processor::Ia64Ia641,
            0x81 => Processor::Ia642,
            0x90 => Processor::Cee,
            0xA0 => Processor::Am33,
            0xB0 => Processor::M32R,
            0xC0 => Processor::TriCore,
            0xD0 => Processor::X64Amd64,
            0xE0 => Processor::Ebc,
            0xF0 => Processor::Thumb,
            0xF4 => Processor::ArmNt,
            0xF6 => Processor::Arm64,
            0x100 => Processor::D3D11Shader,
            0x1AB => Processor::Unk1AB,
            0x304 => Processor::Unk304,
            _ => Processor::Unknown,
        }
    }
}

impl fmt::Display for Processor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_value_known() {
        assert_eq!(Processor::from_value(0x00), Processor::I8080);
        assert_eq!(Processor::from_value(0x05), Processor::Pentium);
        assert_eq!(Processor::from_value(0xD0), Processor::X64Amd64);
        assert_eq!(Processor::from_value(0xF6), Processor::Arm64);
        assert_eq!(Processor::from_value(0x100), Processor::D3D11Shader);
        assert_eq!(Processor::from_value(0x1AB), Processor::Unk1AB);
        assert_eq!(Processor::from_value(0x304), Processor::Unk304);
    }

    #[test]
    fn from_value_unknown_returns_unknown() {
        assert_eq!(Processor::from_value(0x999), Processor::Unknown);
        assert_eq!(Processor::from_value(-1), Processor::Unknown);
        assert_eq!(Processor::from_value(i32::MAX), Processor::Unknown);
    }

    #[test]
    fn value_roundtrips() {
        let cases = [
            (Processor::I8080, 0x00),
            (Processor::I8086, 0x01),
            (Processor::Pentium, 0x05),
            (Processor::X64Amd64, 0xD0),
            (Processor::Arm64, 0xF6),
            (Processor::Unknown, -1),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.value(), expected);
        }
    }

    #[test]
    fn label_matches_java_source() {
        assert_eq!(Processor::Unknown.label(), "???");
        assert_eq!(Processor::I8080.label(), "8080");
        assert_eq!(Processor::PentiumProPentiumII.label(), "Pentium Pro/Pentium II");
        assert_eq!(Processor::MipsMipsR4000.label(), "MIPS (Generic)/R4000");
        assert_eq!(Processor::Alpha21064.label(), "Alpha/Alpha 21064");
        assert_eq!(Processor::PpcBe.label(), "PPC (Big Endian)");
        assert_eq!(Processor::X64Amd64.label(), "x64");
        assert_eq!(Processor::ArmNt.label(), "ARM");
        assert_eq!(Processor::D3D11Shader.label(), "D3D11_SHADER");
    }

    #[test]
    fn display_equals_label() {
        let variants = [
            Processor::Unknown,
            Processor::Pentium,
            Processor::X64Amd64,
            Processor::Arm64,
        ];
        for v in variants {
            assert_eq!(v.to_string(), v.label());
        }
    }

    #[test]
    fn from_value_covers_all_non_unknown_variants() {
        let non_unknown = [
            (0x00i32, Processor::I8080),
            (0x01, Processor::I8086),
            (0x02, Processor::I80286),
            (0x03, Processor::I80386),
            (0x04, Processor::I80486),
            (0x05, Processor::Pentium),
            (0x06, Processor::PentiumProPentiumII),
            (0x07, Processor::PentiumIII),
            (0x10, Processor::MipsMipsR4000),
            (0x11, Processor::Mips16),
            (0x12, Processor::Mips32),
            (0x13, Processor::Mips64),
            (0x14, Processor::MipsI),
            (0x15, Processor::MipsII),
            (0x16, Processor::MipsIII),
            (0x17, Processor::MipsIV),
            (0x18, Processor::MipsV),
            (0x20, Processor::M68000),
            (0x21, Processor::M68010),
            (0x22, Processor::M68020),
            (0x23, Processor::M68030),
            (0x24, Processor::M68040),
            (0x30, Processor::Alpha21064),
            (0x31, Processor::Alpha21164),
            (0x32, Processor::Alpha21164A),
            (0x33, Processor::Alpha21264),
            (0x34, Processor::Alpha21364),
            (0x40, Processor::Ppc601),
            (0x41, Processor::Ppc603),
            (0x42, Processor::Ppc604),
            (0x43, Processor::Ppc620),
            (0x44, Processor::PpcFp),
            (0x45, Processor::PpcBe),
            (0x50, Processor::Sh3),
            (0x51, Processor::Sh3E),
            (0x52, Processor::Sh3Dsp),
            (0x53, Processor::Sh4),
            (0x54, Processor::ShMedia),
            (0x60, Processor::Arm3),
            (0x61, Processor::Arm4),
            (0x62, Processor::Arm4T),
            (0x63, Processor::Arm5),
            (0x64, Processor::Arm5T),
            (0x65, Processor::Arm6),
            (0x66, Processor::ArmXmac),
            (0x67, Processor::ArmWmmx),
            (0x68, Processor::Arm7),
            (0x70, Processor::Omni),
            (0x80, Processor::Ia64Ia641),
            (0x81, Processor::Ia642),
            (0x90, Processor::Cee),
            (0xA0, Processor::Am33),
            (0xB0, Processor::M32R),
            (0xC0, Processor::TriCore),
            (0xD0, Processor::X64Amd64),
            (0xE0, Processor::Ebc),
            (0xF0, Processor::Thumb),
            (0xF4, Processor::ArmNt),
            (0xF6, Processor::Arm64),
            (0x100, Processor::D3D11Shader),
            (0x1AB, Processor::Unk1AB),
            (0x304, Processor::Unk304),
        ];
        for (val, expected) in non_unknown {
            assert_eq!(Processor::from_value(val), expected, "failed for value {val:#x}");
        }
    }
}
