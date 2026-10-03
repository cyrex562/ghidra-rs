//! Port of `ghidra.app.util.bin.format.macho.dyld.DyldArchitecture`.
//!
//! A fixed table of the `dyld_v1*` cache signatures Ghidra recognizes, each paired with the
//! Mach-O CPU type/subtype, processor name, endianness and bitness it implies.
//!
//! Java compares the static instances by identity (`this == X86`); every entry here has a unique
//! signature, so the derived field-wise [`PartialEq`] is equivalent.

use std::fmt;
use std::io;

use crate::app::util::bin::byte_provider::ByteProvider;
use crate::format::macho::cpu_sub_types::{
    CPU_SUBTYPE_ARM_V6, CPU_SUBTYPE_ARM_V7, CPU_SUBTYPE_ARM_V7F, CPU_SUBTYPE_ARM_V7K,
    CPU_SUBTYPE_ARM_V7S, CPU_SUBTYPE_MULTIPLE,
};
use crate::format::macho::cpu_types::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64_32, CPU_TYPE_ARM_64, CPU_TYPE_POWERPC, CPU_TYPE_X86,
    CPU_TYPE_X86_64,
};
use crate::program::model::lang::compiler_spec_id::CompilerSpecID;
use crate::program::model::lang::endian::Endian;
use crate::program::model::lang::language_compiler_spec_pair::LanguageCompilerSpecPair;
use crate::program::model::lang::language_id::LanguageID;
use crate::program::model::lang::language_not_found_exception::LanguageNotFoundException;

/// A DYLD shared cache architecture, identified by its 16-byte `dyld_v1*` magic signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DyldArchitecture {
    cpu_type: i32,
    cpu_sub_type: i32,
    signature: &'static str,
    processor: &'static str,
    endianness: Endian,
    is_64bit: bool,
}

impl DyldArchitecture {
    /// Magic value prefix.
    pub const DYLD_V1_SIGNATURE_PREFIX: &'static str = "dyld_v1";

    /// Maximum length of any signature (including the trailing NUL).
    pub const DYLD_V1_SIGNATURE_LEN: usize = 0x10;

    const fn new(
        cpu_type: i32,
        cpu_sub_type: i32,
        signature: &'static str,
        processor: &'static str,
        endianness: Endian,
        is_64bit: bool,
    ) -> Self {
        // Java throws IllegalArgumentException here; every entry is a compile-time constant, so
        // a bad length is a build error instead.
        assert!(signature.len() + 1 == Self::DYLD_V1_SIGNATURE_LEN, "invalid signature string length");
        DyldArchitecture { cpu_type, cpu_sub_type, signature, processor, endianness, is_64bit }
    }

    pub const X86: DyldArchitecture = Self::new(CPU_TYPE_X86, CPU_SUBTYPE_MULTIPLE, "dyld_v1    i386", "i386", Endian::Little, false);
    pub const X86_64: DyldArchitecture = Self::new(CPU_TYPE_X86_64, CPU_SUBTYPE_MULTIPLE, "dyld_v1  x86_64", "x86_64", Endian::Little, true);
    pub const X86_64H: DyldArchitecture = Self::new(CPU_TYPE_X86_64, CPU_SUBTYPE_MULTIPLE, "dyld_v1 x86_64h", "x86_64", Endian::Little, true);
    pub const POWERPC: DyldArchitecture = Self::new(CPU_TYPE_POWERPC, CPU_SUBTYPE_MULTIPLE, "dyld_v1     ppc", "rosetta", Endian::Big, false);
    pub const ARMV6: DyldArchitecture = Self::new(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6, "dyld_v1   armv6", "armv6", Endian::Little, false);
    pub const ARMV7: DyldArchitecture = Self::new(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7, "dyld_v1   armv7", "arm7", Endian::Little, false);
    pub const ARMV7F: DyldArchitecture = Self::new(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7F, "dyld_v1  armv7f", "arm7", Endian::Little, false);
    pub const ARMV7S: DyldArchitecture = Self::new(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S, "dyld_v1  armv7s", "arm7", Endian::Little, false);
    pub const ARMV7K: DyldArchitecture = Self::new(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K, "dyld_v1  armv7k", "arm7", Endian::Little, false);
    pub const ARMV8A: DyldArchitecture = Self::new(CPU_TYPE_ARM_64, CPU_SUBTYPE_MULTIPLE, "dyld_v1   arm64", "AARCH64", Endian::Little, true);
    pub const ARMV8AE: DyldArchitecture = Self::new(CPU_TYPE_ARM_64, CPU_SUBTYPE_MULTIPLE, "dyld_v1  arm64e", "AARCH64", Endian::Little, true);
    pub const ARM64_32: DyldArchitecture = Self::new(CPU_TYPE_ARM64_32, CPU_SUBTYPE_MULTIPLE, "dyld_v1arm64_32", "ARM64_32", Endian::Little, false);

    /// All known architectures, in Java's `ARCHITECTURES` order.
    pub const ARCHITECTURES: [DyldArchitecture; 12] = [
        Self::X86,
        Self::X86_64,
        Self::X86_64H,
        Self::POWERPC,
        Self::ARMV6,
        Self::ARMV7,
        Self::ARMV7F,
        Self::ARMV7S,
        Self::ARMV7K,
        Self::ARMV8A,
        Self::ARMV8AE,
        Self::ARM64_32,
    ];

    /// Returns the architecture with the given signature, or `None` if there is none.
    ///
    /// Port of `getArchitecture(String)`.
    pub fn get_architecture(signature: &str) -> Option<DyldArchitecture> {
        Self::ARCHITECTURES.iter().find(|a| a.signature == signature).copied()
    }

    /// Reads the signature from the first [`DYLD_V1_SIGNATURE_LEN`](Self::DYLD_V1_SIGNATURE_LEN)
    /// bytes of `provider` and looks it up.
    ///
    /// Port of `getArchitecture(ByteProvider)`. Java decodes with `new String(bytes)` and then
    /// `trim()`s, which strips the trailing NUL along with any other ASCII control/space chars.
    pub fn get_architecture_from_provider(
        provider: &dyn ByteProvider,
    ) -> io::Result<Option<DyldArchitecture>> {
        let bytes = provider.read_bytes(0, Self::DYLD_V1_SIGNATURE_LEN as u64)?;
        let signature = String::from_utf8_lossy(&bytes);
        Ok(Self::get_architecture(java_trim(&signature)))
    }

    /// Port of `getCpuType()`.
    pub fn cpu_type(&self) -> i32 {
        self.cpu_type
    }

    /// Port of `getCpuSubType()`.
    pub fn cpu_sub_type(&self) -> i32 {
        self.cpu_sub_type
    }

    /// Port of `getSignature()`.
    pub fn signature(&self) -> &'static str {
        self.signature
    }

    /// Port of `getProcessor()`.
    pub fn get_processor(&self) -> &'static str {
        self.processor
    }

    /// Port of `getEndianness()`.
    pub fn endianness(&self) -> Endian {
        self.endianness
    }

    /// Port of `is64bit()`.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Port of `isX86()`.
    pub fn is_x86(&self) -> bool {
        *self == Self::X86 || *self == Self::X86_64 || *self == Self::X86_64H
    }

    /// Port of `isPowerPC()`.
    pub fn is_power_pc(&self) -> bool {
        *self == Self::POWERPC
    }

    /// Port of `isARM()`.
    pub fn is_arm(&self) -> bool {
        !self.is_x86() && !self.is_power_pc()
    }

    /// Port of `getLanguageCompilerSpecPair(LanguageService)`. The Java `LanguageService`
    /// parameter is never read by the method body, so it is not carried over.
    pub fn get_language_compiler_spec_pair(
        &self,
    ) -> Result<LanguageCompilerSpecPair, LanguageNotFoundException> {
        let (lang, cspec) = if *self == Self::X86 {
            ("x86:LE:32:default", "gcc")
        } else if *self == Self::X86_64 || *self == Self::X86_64H {
            ("x86:LE:64:default", "gcc")
        } else if *self == Self::POWERPC {
            ("PowerPC:BE:32:default", "macosx")
        } else if *self == Self::ARMV6 {
            ("ARM:LE:32:v6", "default")
        } else if *self == Self::ARMV7 || *self == Self::ARMV7S {
            ("ARM:LE:32:v7", "default")
        } else {
            return Err(LanguageNotFoundException::with_message(format!(
                "Unable to locate language for {self}"
            )));
        };
        Ok(LanguageCompilerSpecPair::from_ids(
            LanguageID::new(lang).expect("non-empty language id"),
            CompilerSpecID::new(Some(cspec)),
        ))
    }
}

impl fmt::Display for DyldArchitecture {
    /// Port of `toString()`: the signature.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.signature)
    }
}

/// Java `String.trim()`: strips leading/trailing chars `<= ' '` (including NUL).
fn java_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c <= ' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::util::bin::byte_array_provider::ByteArrayProvider;

    #[test]
    fn lookup_by_signature() {
        let arch = DyldArchitecture::get_architecture("dyld_v1  arm64e").unwrap();
        assert_eq!(arch, DyldArchitecture::ARMV8AE);
        assert_eq!(arch.get_processor(), "AARCH64");
        assert_eq!(arch.cpu_type(), CPU_TYPE_ARM_64);
        assert!(arch.is_64bit());
        assert!(arch.is_arm());
        assert!(DyldArchitecture::get_architecture("dyld_v1 arm64e").is_none());
        assert!(DyldArchitecture::get_architecture("not a dyld cache").is_none());
    }

    #[test]
    fn every_signature_is_fifteen_chars_with_prefix() {
        for a in DyldArchitecture::ARCHITECTURES {
            assert_eq!(a.signature().len() + 1, DyldArchitecture::DYLD_V1_SIGNATURE_LEN);
            assert!(a.signature().starts_with(DyldArchitecture::DYLD_V1_SIGNATURE_PREFIX));
            assert_eq!(a.to_string(), a.signature());
        }
    }

    #[test]
    fn classification() {
        assert!(DyldArchitecture::X86_64H.is_x86());
        assert!(!DyldArchitecture::X86_64H.is_arm());
        assert!(DyldArchitecture::POWERPC.is_power_pc());
        assert_eq!(DyldArchitecture::POWERPC.endianness(), Endian::Big);
        assert!(!DyldArchitecture::POWERPC.is_arm());
        assert!(DyldArchitecture::ARMV7K.is_arm());
        assert_eq!(DyldArchitecture::ARMV7K.cpu_sub_type(), CPU_SUBTYPE_ARM_V7K);
        // X86_64 and X86_64h share cpu type/processor but are distinct entries.
        assert_ne!(DyldArchitecture::X86_64, DyldArchitecture::X86_64H);
    }

    #[test]
    fn lookup_from_provider_trims_nul() {
        let mut bytes = b"dyld_v1  x86_64\0".to_vec();
        bytes.extend_from_slice(&[0xAA; 16]);
        let provider = ByteArrayProvider::new(bytes);
        let arch = DyldArchitecture::get_architecture_from_provider(&provider).unwrap();
        assert_eq!(arch, Some(DyldArchitecture::X86_64));

        let provider = ByteArrayProvider::new(b"dyld_v1  mips32\0".to_vec());
        assert_eq!(DyldArchitecture::get_architecture_from_provider(&provider).unwrap(), None);

        let short = ByteArrayProvider::new(b"dyld".to_vec());
        assert!(DyldArchitecture::get_architecture_from_provider(&short).is_err());
    }

    #[test]
    fn language_pairs() {
        let pair = DyldArchitecture::X86_64H.get_language_compiler_spec_pair().unwrap();
        assert_eq!(pair.get_language_id().to_string(), "x86:LE:64:default");
        assert_eq!(pair.get_compiler_spec_id().to_string(), "gcc");
        let pair = DyldArchitecture::POWERPC.get_language_compiler_spec_pair().unwrap();
        assert_eq!(pair.get_language_id().to_string(), "PowerPC:BE:32:default");
        assert_eq!(pair.get_compiler_spec_id().to_string(), "macosx");
        let pair = DyldArchitecture::ARMV7S.get_language_compiler_spec_pair().unwrap();
        assert_eq!(pair.get_language_id().to_string(), "ARM:LE:32:v7");
        let err = DyldArchitecture::ARMV8A.get_language_compiler_spec_pair().unwrap_err();
        assert_eq!(err.message(), "Unable to locate language for dyld_v1   arm64");
        assert!(DyldArchitecture::ARMV7F.get_language_compiler_spec_pair().is_err());
    }
}
