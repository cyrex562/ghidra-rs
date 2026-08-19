use crate::program::database::program_db::ProgramDB;
use crate::program::model::address::Address;
use crate::program::model::listing::Program;
use crate::program::model::mem::Memory;

/// Android Runtime (ART) image format constants.
///
/// Reference: <https://android.googlesource.com/platform/art/+/master/runtime/image.cc>
///
/// Mirrors `ghidra.file.formats.android.art.ArtConstants`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArtConstants;

impl ArtConstants {
    pub const ART_NAME: &'static str = "Android Runtime (ART)";
    pub const MAGIC: &'static str = "art\n";
    pub const VERSION_LENGTH: i32 = 4;

    /// <https://android.googlesource.com/platform/art/+/refs/heads/kitkat-release/runtime/image.cc#26>
    pub const ART_VERSION_005: &'static str = "005";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-release/runtime/image.cc#26>
    pub const ART_VERSION_009: &'static str = "009";
    /// <https://android.googlesource.com/platform/art/+/refs/heads/lollipop-mr1-wfc-release/runtime/image.cc#26>
    pub const ART_VERSION_012: &'static str = "012";
    /// <https://android.googlesource.com/platform/art/+/marshmallow-release/runtime/image.cc#26>
    pub const ART_VERSION_017: &'static str = "017";
    /// <https://android.googlesource.com/platform/art/+/nougat-release/runtime/image.cc#26>
    pub const ART_VERSION_029: &'static str = "029";
    /// <https://android.googlesource.com/platform/art/+/nougat-mr2-pixel-release/runtime/image.cc#26>
    pub const ART_VERSION_030: &'static str = "030";
    /// <https://android.googlesource.com/platform/art/+/oreo-release/runtime/image.cc#28>
    pub const ART_VERSION_043: &'static str = "043";
    /// <https://android.googlesource.com/platform/art/+/oreo-dr1-release/runtime/image.cc#28>
    pub const ART_VERSION_044: &'static str = "044";
    /// <https://android.googlesource.com/platform/art/+/oreo-mr1-release/runtime/image.cc#28>
    pub const ART_VERSION_046: &'static str = "046";
    /// <https://android.googlesource.com/platform/art/+/pie-release/runtime/image.cc#28>
    pub const ART_VERSION_056: &'static str = "056";
    /// Q. <https://android.googlesource.com/platform/art/+/android10-release/runtime/image.cc#31>
    pub const ART_VERSION_074: &'static str = "074";
    /// R. <https://android.googlesource.com/platform/art/+/android11-release/runtime/image.cc#31>
    pub const ART_VERSION_085: &'static str = "085";
    /// S. <https://android.googlesource.com/platform/art/+/android12-release/runtime/image.cc#31>
    pub const ART_VERSION_099: &'static str = "099";
    /// S v2, 13. <https://android.googlesource.com/platform/art/+/android13-release/runtime/image.cc#31>
    pub const ART_VERSION_106: &'static str = "106";

    /// NOTE: only going to support RELEASE versions.
    pub const SUPPORTED_VERSIONS: &'static [&'static str] = &[
        Self::ART_VERSION_005,
        Self::ART_VERSION_009,
        Self::ART_VERSION_012,
        Self::ART_VERSION_017,
        Self::ART_VERSION_029,
        Self::ART_VERSION_030,
        Self::ART_VERSION_043,
        Self::ART_VERSION_044,
        Self::ART_VERSION_046,
        Self::ART_VERSION_056,
        Self::ART_VERSION_074,
        Self::ART_VERSION_085,
        Self::ART_VERSION_099,
        Self::ART_VERSION_106,
    ];

    pub fn is_supported_version(version: &str) -> bool {
        Self::SUPPORTED_VERSIONS
            .iter()
            .any(|supported| *supported == version)
    }

    /// Returns true if the given ProgramDB contains ART information.
    pub fn is_art(program: &ProgramDB) -> bool {
        Self::find_art(program).is_some()
    }

    /// Returns the start address of the ART image within the given ProgramDB, if found.
    pub fn find_art(program: &ProgramDB) -> Option<Address> {
        let factory = program.get_address_factory()?;
        let default_space = factory.get_default_address_space()?;
        let min_address = default_space.min_address();

        let memory = program.get_memory();
        let memory_guard = memory.read().ok()?;

        let mut bytes = vec![0u8; Self::MAGIC.len()];
        let bytes_read = memory_guard.get_bytes(&min_address, &mut bytes);

        if bytes_read == Self::MAGIC.len() && Self::MAGIC.as_bytes() == &bytes[..] {
            Some(min_address)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn art_name_value() {
        assert_eq!(ArtConstants::ART_NAME, "Android Runtime (ART)");
    }

    #[test]
    fn magic_value() {
        assert_eq!(ArtConstants::MAGIC, "art\n");
    }

    #[test]
    fn version_length_value() {
        assert_eq!(ArtConstants::VERSION_LENGTH, 4);
    }

    #[test]
    fn supported_versions_contains_all() {
        assert_eq!(ArtConstants::SUPPORTED_VERSIONS.len(), 14);
        assert_eq!(ArtConstants::SUPPORTED_VERSIONS[0], "005");
        assert_eq!(ArtConstants::SUPPORTED_VERSIONS[13], "106");
    }

    #[test]
    fn is_supported_version_true_for_known_versions() {
        assert!(ArtConstants::is_supported_version("005"));
        assert!(ArtConstants::is_supported_version("056"));
        assert!(ArtConstants::is_supported_version("106"));
    }

    #[test]
    fn is_supported_version_false_for_unknown_version() {
        assert!(!ArtConstants::is_supported_version("999"));
        assert!(!ArtConstants::is_supported_version(""));
    }

    #[test]
    fn can_construct_and_default() {
        assert_eq!(ArtConstants::default(), ArtConstants);
    }

    #[test]
    fn clone_is_equal() {
        let a = ArtConstants;
        assert_eq!(a, a.clone());
    }
}
