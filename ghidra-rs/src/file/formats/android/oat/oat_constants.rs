use crate::format::elf::elf_section_header_constants::DOT_RODATA;

/// OAT file format constants.
///
/// Mirrors `ghidra.file.formats.android.oat.OatConstants`.
///
/// Reference: <https://android.googlesource.com/platform/art/+/master/runtime/oat.h>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OatConstants;

impl OatConstants {
    pub const MAGIC: &'static str = "oat\n";

    pub const SYMBOL_OAT_BSS: &'static str = "oatbss";
    pub const SYMBOL_OAT_BSS_LASTWORD: &'static str = "oatbsslastword";
    pub const SYMBOL_OAT_BSS_METHODS: &'static str = "oatbssmethods";
    pub const SYMBOL_OAT_BSS_ROOTS: &'static str = "oatbssroots";
    pub const SYMBOL_OAT_DATA: &'static str = "oatdata";
    pub const SYMBOL_OAT_DATA_BIMGRELRO: &'static str = "oatdatabimgrelro";
    pub const SYMBOL_OAT_DATA_BIMGRELRO_LASTWORD: &'static str = "oatdatabimgrelrolastword";
    pub const SYMBOL_OAT_DEX: &'static str = "oatdex";
    pub const SYMBOL_OAT_DEX_LASTWORD: &'static str = "oatdexlastword";
    pub const SYMBOL_OAT_EXEC: &'static str = "oatexec";
    pub const SYMBOL_OAT_LASTWORD: &'static str = "oatlastword";

    pub const OAT_SECTION_NAME: &'static str = DOT_RODATA;

    pub const DOT_OAT_PATCHES_SECTION_NAME: &'static str = ".oat_patches";

    // Keys from the OAT header "key/value" store.
    pub const K_APEX_VERSIONS_KEY: &'static str = "apex-versions";
    pub const K_BOOT_CLASS_PATH_KEY: &'static str = "bootclasspath";
    pub const K_BOOT_CLASS_PATH_CHECKSUMS_KEY: &'static str = "bootclasspath-checksums";
    pub const K_CLASS_PATH_KEY: &'static str = "classpath";
    pub const K_COMPILATION_REASON_KEY: &'static str = "compilation-reason";
    pub const K_COMPILER_FILTER: &'static str = "compiler-filter";
    pub const K_CONCURRENT_COPYING: &'static str = "concurrent-copying";
    pub const K_DEBUGGABLE_KEY: &'static str = "debuggable";
    pub const K_DEX2OAT_CMD_LINE_KEY: &'static str = "dex2oat-cmdline";
    pub const K_DEX2OAT_HOST_KEY: &'static str = "dex2oat-host";
    pub const K_HAS_PATCH_INFO_KEY: &'static str = "has-patch-info";
    pub const K_IMAGE_LOCATION_KEY: &'static str = "image-location";
    pub const K_NATIVE_DEBUGGABLE_KEY: &'static str = "native-debuggable";
    pub const K_PIC_KEY: &'static str = "pic";
    pub const K_REQUIRES_IMAGE: &'static str = "requires-image";

    /// Boolean value used in the Key/Value store for TRUE.
    pub const K_TRUE_VALUE: &'static str = "true";
    /// Boolean value used in the Key/Value store for FALSE.
    pub const K_FALSE_VALUE: &'static str = "false";

    // NOTE: we plan to only support RELEASE versions...
    // Upper case indicates supported version.

    /// <https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/oat.cc#24>
    pub const OAT_VERSION_007: &'static str = "007";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/kitkat-dev/runtime/oat.cc#24>
    pub const OAT_VERSION_008: &'static str = "008";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/oat.cc#25>
    pub const OAT_VERSION_039: &'static str = "039";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-release/runtime/oat.cc#25>
    pub const OAT_VERSION_045: &'static str = "045";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-wear-release/runtime/oat.cc#27>
    pub const OAT_VERSION_051: &'static str = "051";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/marshmallow-release/runtime/oat.h#34>
    pub const OAT_VERSION_064: &'static str = "064";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/nougat-release/runtime/oat.h#34>
    pub const OAT_VERSION_079: &'static str = "079";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/n-iot-preview-2/runtime/oat.h#34>
    pub const OAT_VERSION_083: &'static str = "083";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/nougat-mr1-release/runtime/oat.h#34>
    pub const OAT_VERSION_088: &'static str = "088";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/o-preview/runtime/oat.h#34>
    pub const OAT_VERSION_114: &'static str = "114";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/oreo-release/runtime/oat.h#34>
    pub const OAT_VERSION_124: &'static str = "124";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/n-iot-preview-4/runtime/oat.h#34>
    pub const OAT_VERSION_125: &'static str = "125";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/oreo-dr3-release/runtime/oat.h#34>
    pub const OAT_VERSION_126: &'static str = "126";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/oreo-m2-release/runtime/oat.h#34>
    pub const OAT_VERSION_131: &'static str = "131";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/o-iot-preview-5/runtime/oat.h#34>
    pub const OAT_VERSION_132: &'static str = "132";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-6/runtime/oat.h#34>
    pub const OAT_VERSION_135: &'static str = "135";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/pie-release/runtime/oat.h#34>
    pub const OAT_VERSION_138: &'static str = "138";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-7/runtime/oat.h#34>
    pub const OAT_VERSION_139: &'static str = "139";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/o-mr1-iot-preview-8/runtime/oat.h#34>
    pub const OAT_VERSION_140: &'static str = "140";
    /// <https://android.googlesource.com/platform/art/+/refs/tags/android-o-mr1-iot-release-1.0.0/runtime/oat.h#34>
    pub const OAT_VERSION_141: &'static str = "141";
    /// <https://android.googlesource.com/platform/art/+/refs/tags/android-o-mr1-iot-release-1.0.1/runtime/oat.h#34>
    pub const OAT_VERSION_146: &'static str = "146";
    /// <https://android.googlesource.com/platform/art/+/refs/tags/android-n-iot-release-polk-at1/runtime/oat.h#34>
    pub const OAT_VERSION_147: &'static str = "147";
    /// <https://android.googlesource.com/platform/art/+/refs/tags/android-q-preview-1/runtime/oat.h#33>
    pub const OAT_VERSION_166: &'static str = "166";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android10-release/runtime/oat.h#34>
    pub const OAT_VERSION_170: &'static str = "170";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android11-release/runtime/oat.h#34>
    pub const OAT_VERSION_183: &'static str = "183";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android12-release/runtime/oat.h#36>
    pub const OAT_VERSION_195: &'static str = "195";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android-s-beta-4/runtime/oat.h#36>
    pub const OAT_VERSION_197: &'static str = "197";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android-s-v2-preview-1/runtime/oat.h#36>
    pub const OAT_VERSION_199: &'static str = "199";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android-t-preview-1/runtime/oat.h#36>
    pub const OAT_VERSION_220: &'static str = "220";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android-s-v2-beta-3/runtime/oat.h#36>
    pub const OAT_VERSION_223: &'static str = "223";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/android13-release/runtime/oat.h#36>
    pub const OAT_VERSION_225: &'static str = "225";
    /// <https://android.googlesource.com/platform/art/+/master/runtime/oat.h#36>
    pub const OAT_VERSION_227: &'static str = "227";

    /// Versions that have been actively tested and verified.
    ///
    /// All other versions will be considered unsupported until tested on exemplar firmware.
    pub const SUPPORTED_VERSIONS: &'static [&'static str] = &[
        Self::OAT_VERSION_007,
        Self::OAT_VERSION_039,
        Self::OAT_VERSION_045,
        Self::OAT_VERSION_051,
        Self::OAT_VERSION_064,
        Self::OAT_VERSION_079,
        Self::OAT_VERSION_088,
        Self::OAT_VERSION_124,
        Self::OAT_VERSION_126,
        Self::OAT_VERSION_131,
        Self::OAT_VERSION_138,
        Self::OAT_VERSION_170,
        Self::OAT_VERSION_183,
        Self::OAT_VERSION_195,
        Self::OAT_VERSION_199,
        Self::OAT_VERSION_220,
        Self::OAT_VERSION_223,
        Self::OAT_VERSION_225,
    ];

    /// Returns true if the given OAT version string is supported by Ghidra.
    pub fn is_supported_version(version: &str) -> bool {
        Self::SUPPORTED_VERSIONS.contains(&version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_value() {
        assert_eq!(OatConstants::MAGIC, "oat\n");
    }

    #[test]
    fn symbol_names() {
        assert_eq!(OatConstants::SYMBOL_OAT_BSS, "oatbss");
        assert_eq!(OatConstants::SYMBOL_OAT_BSS_LASTWORD, "oatbsslastword");
        assert_eq!(OatConstants::SYMBOL_OAT_BSS_METHODS, "oatbssmethods");
        assert_eq!(OatConstants::SYMBOL_OAT_BSS_ROOTS, "oatbssroots");
        assert_eq!(OatConstants::SYMBOL_OAT_DATA, "oatdata");
        assert_eq!(
            OatConstants::SYMBOL_OAT_DATA_BIMGRELRO,
            "oatdatabimgrelro"
        );
        assert_eq!(
            OatConstants::SYMBOL_OAT_DATA_BIMGRELRO_LASTWORD,
            "oatdatabimgrelrolastword"
        );
        assert_eq!(OatConstants::SYMBOL_OAT_DEX, "oatdex");
        assert_eq!(OatConstants::SYMBOL_OAT_DEX_LASTWORD, "oatdexlastword");
        assert_eq!(OatConstants::SYMBOL_OAT_EXEC, "oatexec");
        assert_eq!(OatConstants::SYMBOL_OAT_LASTWORD, "oatlastword");
    }

    #[test]
    fn oat_section_name_is_dot_rodata() {
        assert_eq!(OatConstants::OAT_SECTION_NAME, ".rodata");
    }

    #[test]
    fn dot_oat_patches_section_name() {
        assert_eq!(OatConstants::DOT_OAT_PATCHES_SECTION_NAME, ".oat_patches");
    }

    #[test]
    fn key_value_store_keys() {
        assert_eq!(OatConstants::K_APEX_VERSIONS_KEY, "apex-versions");
        assert_eq!(OatConstants::K_BOOT_CLASS_PATH_KEY, "bootclasspath");
        assert_eq!(
            OatConstants::K_BOOT_CLASS_PATH_CHECKSUMS_KEY,
            "bootclasspath-checksums"
        );
        assert_eq!(OatConstants::K_CLASS_PATH_KEY, "classpath");
        assert_eq!(OatConstants::K_COMPILATION_REASON_KEY, "compilation-reason");
        assert_eq!(OatConstants::K_COMPILER_FILTER, "compiler-filter");
        assert_eq!(OatConstants::K_CONCURRENT_COPYING, "concurrent-copying");
        assert_eq!(OatConstants::K_DEBUGGABLE_KEY, "debuggable");
        assert_eq!(OatConstants::K_DEX2OAT_CMD_LINE_KEY, "dex2oat-cmdline");
        assert_eq!(OatConstants::K_DEX2OAT_HOST_KEY, "dex2oat-host");
        assert_eq!(OatConstants::K_HAS_PATCH_INFO_KEY, "has-patch-info");
        assert_eq!(OatConstants::K_IMAGE_LOCATION_KEY, "image-location");
        assert_eq!(OatConstants::K_NATIVE_DEBUGGABLE_KEY, "native-debuggable");
        assert_eq!(OatConstants::K_PIC_KEY, "pic");
        assert_eq!(OatConstants::K_REQUIRES_IMAGE, "requires-image");
    }

    #[test]
    fn boolean_key_values() {
        assert_eq!(OatConstants::K_TRUE_VALUE, "true");
        assert_eq!(OatConstants::K_FALSE_VALUE, "false");
    }

    #[test]
    fn supported_versions_contains_all_listed_versions() {
        assert_eq!(OatConstants::SUPPORTED_VERSIONS.len(), 18);
        assert!(OatConstants::SUPPORTED_VERSIONS.contains(&OatConstants::OAT_VERSION_007));
        assert!(OatConstants::SUPPORTED_VERSIONS.contains(&OatConstants::OAT_VERSION_225));
    }

    #[test]
    fn is_supported_version_true_for_supported() {
        assert!(OatConstants::is_supported_version(OatConstants::OAT_VERSION_007));
        assert!(OatConstants::is_supported_version(OatConstants::OAT_VERSION_138));
        assert!(OatConstants::is_supported_version(OatConstants::OAT_VERSION_225));
    }

    #[test]
    fn is_supported_version_false_for_unsupported() {
        // OAT_VERSION_008, 083, 114, etc. are defined but not in SUPPORTED_VERSIONS.
        assert!(!OatConstants::is_supported_version(OatConstants::OAT_VERSION_008));
        assert!(!OatConstants::is_supported_version(OatConstants::OAT_VERSION_083));
        assert!(!OatConstants::is_supported_version("999"));
        assert!(!OatConstants::is_supported_version(""));
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(OatConstants::default(), OatConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = OatConstants;
        assert_eq!(a, a.clone());
    }
}
