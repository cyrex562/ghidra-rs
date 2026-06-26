/// DWARF source language constants from www.dwarfstd.org/doc/DWARF4.pdf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DWARFSourceLanguage {
    C89 = 0x0001,
    C = 0x0002,
    Ada83 = 0x0003,
    CPlusPlus = 0x0004,
    Cobol74 = 0x0005,
    Cobol85 = 0x0006,
    Fortran77 = 0x0007,
    Fortran90 = 0x0008,
    Pascal83 = 0x0009,
    Modula2 = 0x000a,
    Java = 0x000b,
    C99 = 0x000c,
    Ada95 = 0x000d,
    Fortran95 = 0x000e,
    Pl1 = 0x000f,
    ObjC = 0x0010,
    ObjCPlusPlus = 0x0011,
    Upc = 0x0012,
    D = 0x0013,
    Python = 0x0014,
    OpenCl = 0x0015,
    Go = 0x0016,
    Modula3 = 0x0017,
    Haskell = 0x0018,
    CPlusPlus03 = 0x0019,
    CPlusPlus11 = 0x001a,
    OCaml = 0x001b,
    Rust = 0x001c,
    C11 = 0x001d,
    Swift = 0x001e,
    Julia = 0x001f,
    Dylan = 0x0020,
    CPlusPlus14 = 0x0021,
    Fortran03 = 0x0022,
    Fortran08 = 0x0023,
    RenderScript = 0x0024,
    Bliss = 0x0025,
    LoUser = 0x8000,
    MipsAssembler = 0x8001,
    GoogleRenderScript = 0x8e57,
    SunAssembler = 0x9001,
    AltiumAssembler = 0x9101,
    BorlandDelphi = 0xb000,
    HiUser = 0xffff,
}

impl DWARFSourceLanguage {
    /// Returns the integer value of this source language code.
    pub fn value(self) -> u32 {
        self as u32
    }

    /// Returns the `DWARFSourceLanguage` for the given integer value.
    ///
    /// # Errors
    /// Returns `Err(key)` if `key` does not correspond to a known language code.
    pub fn find(key: u32) -> Result<Self, u32> {
        match key {
            0x0001 => Ok(Self::C89),
            0x0002 => Ok(Self::C),
            0x0003 => Ok(Self::Ada83),
            0x0004 => Ok(Self::CPlusPlus),
            0x0005 => Ok(Self::Cobol74),
            0x0006 => Ok(Self::Cobol85),
            0x0007 => Ok(Self::Fortran77),
            0x0008 => Ok(Self::Fortran90),
            0x0009 => Ok(Self::Pascal83),
            0x000a => Ok(Self::Modula2),
            0x000b => Ok(Self::Java),
            0x000c => Ok(Self::C99),
            0x000d => Ok(Self::Ada95),
            0x000e => Ok(Self::Fortran95),
            0x000f => Ok(Self::Pl1),
            0x0010 => Ok(Self::ObjC),
            0x0011 => Ok(Self::ObjCPlusPlus),
            0x0012 => Ok(Self::Upc),
            0x0013 => Ok(Self::D),
            0x0014 => Ok(Self::Python),
            0x0015 => Ok(Self::OpenCl),
            0x0016 => Ok(Self::Go),
            0x0017 => Ok(Self::Modula3),
            0x0018 => Ok(Self::Haskell),
            0x0019 => Ok(Self::CPlusPlus03),
            0x001a => Ok(Self::CPlusPlus11),
            0x001b => Ok(Self::OCaml),
            0x001c => Ok(Self::Rust),
            0x001d => Ok(Self::C11),
            0x001e => Ok(Self::Swift),
            0x001f => Ok(Self::Julia),
            0x0020 => Ok(Self::Dylan),
            0x0021 => Ok(Self::CPlusPlus14),
            0x0022 => Ok(Self::Fortran03),
            0x0023 => Ok(Self::Fortran08),
            0x0024 => Ok(Self::RenderScript),
            0x0025 => Ok(Self::Bliss),
            0x8000 => Ok(Self::LoUser),
            0x8001 => Ok(Self::MipsAssembler),
            0x8e57 => Ok(Self::GoogleRenderScript),
            0x9001 => Ok(Self::SunAssembler),
            0x9101 => Ok(Self::AltiumAssembler),
            0xb000 => Ok(Self::BorlandDelphi),
            0xffff => Ok(Self::HiUser),
            _ => Err(key),
        }
    }

    /// Returns `true` if the value falls in the vendor-defined range
    /// (`DW_LANG_lo_user..=DW_LANG_hi_user`).
    pub fn is_user_defined(value: u32) -> bool {
        value >= 0x8000 && value <= 0xffff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_dwarf_spec() {
        assert_eq!(DWARFSourceLanguage::C89.value(), 0x0001);
        assert_eq!(DWARFSourceLanguage::C.value(), 0x0002);
        assert_eq!(DWARFSourceLanguage::Ada83.value(), 0x0003);
        assert_eq!(DWARFSourceLanguage::CPlusPlus.value(), 0x0004);
        assert_eq!(DWARFSourceLanguage::Cobol74.value(), 0x0005);
        assert_eq!(DWARFSourceLanguage::Cobol85.value(), 0x0006);
        assert_eq!(DWARFSourceLanguage::Fortran77.value(), 0x0007);
        assert_eq!(DWARFSourceLanguage::Fortran90.value(), 0x0008);
        assert_eq!(DWARFSourceLanguage::Pascal83.value(), 0x0009);
        assert_eq!(DWARFSourceLanguage::Modula2.value(), 0x000a);
        assert_eq!(DWARFSourceLanguage::Java.value(), 0x000b);
        assert_eq!(DWARFSourceLanguage::C99.value(), 0x000c);
        assert_eq!(DWARFSourceLanguage::Ada95.value(), 0x000d);
        assert_eq!(DWARFSourceLanguage::Fortran95.value(), 0x000e);
        assert_eq!(DWARFSourceLanguage::Pl1.value(), 0x000f);
        assert_eq!(DWARFSourceLanguage::ObjC.value(), 0x0010);
        assert_eq!(DWARFSourceLanguage::ObjCPlusPlus.value(), 0x0011);
        assert_eq!(DWARFSourceLanguage::Upc.value(), 0x0012);
        assert_eq!(DWARFSourceLanguage::D.value(), 0x0013);
        assert_eq!(DWARFSourceLanguage::Python.value(), 0x0014);
        assert_eq!(DWARFSourceLanguage::OpenCl.value(), 0x0015);
        assert_eq!(DWARFSourceLanguage::Go.value(), 0x0016);
        assert_eq!(DWARFSourceLanguage::Modula3.value(), 0x0017);
        assert_eq!(DWARFSourceLanguage::Haskell.value(), 0x0018);
        assert_eq!(DWARFSourceLanguage::CPlusPlus03.value(), 0x0019);
        assert_eq!(DWARFSourceLanguage::CPlusPlus11.value(), 0x001a);
        assert_eq!(DWARFSourceLanguage::OCaml.value(), 0x001b);
        assert_eq!(DWARFSourceLanguage::Rust.value(), 0x001c);
        assert_eq!(DWARFSourceLanguage::C11.value(), 0x001d);
        assert_eq!(DWARFSourceLanguage::Swift.value(), 0x001e);
        assert_eq!(DWARFSourceLanguage::Julia.value(), 0x001f);
        assert_eq!(DWARFSourceLanguage::Dylan.value(), 0x0020);
        assert_eq!(DWARFSourceLanguage::CPlusPlus14.value(), 0x0021);
        assert_eq!(DWARFSourceLanguage::Fortran03.value(), 0x0022);
        assert_eq!(DWARFSourceLanguage::Fortran08.value(), 0x0023);
        assert_eq!(DWARFSourceLanguage::RenderScript.value(), 0x0024);
        assert_eq!(DWARFSourceLanguage::Bliss.value(), 0x0025);
        assert_eq!(DWARFSourceLanguage::LoUser.value(), 0x8000);
        assert_eq!(DWARFSourceLanguage::MipsAssembler.value(), 0x8001);
        assert_eq!(DWARFSourceLanguage::GoogleRenderScript.value(), 0x8e57);
        assert_eq!(DWARFSourceLanguage::SunAssembler.value(), 0x9001);
        assert_eq!(DWARFSourceLanguage::AltiumAssembler.value(), 0x9101);
        assert_eq!(DWARFSourceLanguage::BorlandDelphi.value(), 0xb000);
        assert_eq!(DWARFSourceLanguage::HiUser.value(), 0xffff);
    }

    #[test]
    fn find_returns_correct_variants() {
        assert_eq!(DWARFSourceLanguage::find(0x0001), Ok(DWARFSourceLanguage::C89));
        assert_eq!(DWARFSourceLanguage::find(0x0004), Ok(DWARFSourceLanguage::CPlusPlus));
        assert_eq!(DWARFSourceLanguage::find(0x001c), Ok(DWARFSourceLanguage::Rust));
        assert_eq!(DWARFSourceLanguage::find(0x8000), Ok(DWARFSourceLanguage::LoUser));
        assert_eq!(DWARFSourceLanguage::find(0x8001), Ok(DWARFSourceLanguage::MipsAssembler));
        assert_eq!(DWARFSourceLanguage::find(0xb000), Ok(DWARFSourceLanguage::BorlandDelphi));
        assert_eq!(DWARFSourceLanguage::find(0xffff), Ok(DWARFSourceLanguage::HiUser));
    }

    #[test]
    fn find_rejects_invalid_keys() {
        assert_eq!(DWARFSourceLanguage::find(0x0000), Err(0x0000));
        assert_eq!(DWARFSourceLanguage::find(0x0026), Err(0x0026));
        assert_eq!(DWARFSourceLanguage::find(0x7fff), Err(0x7fff));
        assert_eq!(DWARFSourceLanguage::find(0x8002), Err(0x8002));
    }

    #[test]
    fn is_user_defined_range() {
        assert!(DWARFSourceLanguage::is_user_defined(0x8000));
        assert!(DWARFSourceLanguage::is_user_defined(0x8001));
        assert!(DWARFSourceLanguage::is_user_defined(0xffff));
        assert!(!DWARFSourceLanguage::is_user_defined(0x7fff));
        assert!(!DWARFSourceLanguage::is_user_defined(0x0001));
    }

    #[test]
    fn roundtrip_value_then_find() {
        let variants = [
            DWARFSourceLanguage::C89,
            DWARFSourceLanguage::C,
            DWARFSourceLanguage::Ada83,
            DWARFSourceLanguage::CPlusPlus,
            DWARFSourceLanguage::Cobol74,
            DWARFSourceLanguage::Cobol85,
            DWARFSourceLanguage::Fortran77,
            DWARFSourceLanguage::Fortran90,
            DWARFSourceLanguage::Pascal83,
            DWARFSourceLanguage::Modula2,
            DWARFSourceLanguage::Java,
            DWARFSourceLanguage::C99,
            DWARFSourceLanguage::Ada95,
            DWARFSourceLanguage::Fortran95,
            DWARFSourceLanguage::Pl1,
            DWARFSourceLanguage::ObjC,
            DWARFSourceLanguage::ObjCPlusPlus,
            DWARFSourceLanguage::Upc,
            DWARFSourceLanguage::D,
            DWARFSourceLanguage::Python,
            DWARFSourceLanguage::OpenCl,
            DWARFSourceLanguage::Go,
            DWARFSourceLanguage::Modula3,
            DWARFSourceLanguage::Haskell,
            DWARFSourceLanguage::CPlusPlus03,
            DWARFSourceLanguage::CPlusPlus11,
            DWARFSourceLanguage::OCaml,
            DWARFSourceLanguage::Rust,
            DWARFSourceLanguage::C11,
            DWARFSourceLanguage::Swift,
            DWARFSourceLanguage::Julia,
            DWARFSourceLanguage::Dylan,
            DWARFSourceLanguage::CPlusPlus14,
            DWARFSourceLanguage::Fortran03,
            DWARFSourceLanguage::Fortran08,
            DWARFSourceLanguage::RenderScript,
            DWARFSourceLanguage::Bliss,
            DWARFSourceLanguage::LoUser,
            DWARFSourceLanguage::MipsAssembler,
            DWARFSourceLanguage::GoogleRenderScript,
            DWARFSourceLanguage::SunAssembler,
            DWARFSourceLanguage::AltiumAssembler,
            DWARFSourceLanguage::BorlandDelphi,
            DWARFSourceLanguage::HiUser,
        ];
        for variant in variants {
            assert_eq!(DWARFSourceLanguage::find(variant.value()), Ok(variant));
        }
    }
}
