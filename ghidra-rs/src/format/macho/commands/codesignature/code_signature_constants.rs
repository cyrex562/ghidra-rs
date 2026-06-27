/// Code Signature magic constants.
///
/// See <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;
pub const CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT: u32 = 0xfade8181;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_values_match_java_source() {
        assert_eq!(CSMAGIC_REQUIREMENT, 0xfade0c00);
        assert_eq!(CSMAGIC_REQUIREMENTS, 0xfade0c01);
        assert_eq!(CSMAGIC_CODEDIRECTORY, 0xfade0c02);
        assert_eq!(CSMAGIC_EMBEDDED_SIGNATURE, 0xfade0cc0);
        assert_eq!(CSMAGIC_EMBEDDED_SIGNATURE_OLD, 0xfade0b02);
        assert_eq!(CSMAGIC_EMBEDDED_ENTITLEMENTS, 0xfade7171);
        assert_eq!(CSMAGIC_EMBEDDED_DER_ENTITLEMENTS, 0xfade7172);
        assert_eq!(CSMAGIC_DETACHED_SIGNATURE, 0xfade0cc1);
        assert_eq!(CSMAGIC_BLOBWRAPPER, 0xfade0b01);
        assert_eq!(CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT, 0xfade8181);
    }

    #[test]
    fn magic_values_are_distinct() {
        let values = [
            CSMAGIC_REQUIREMENT,
            CSMAGIC_REQUIREMENTS,
            CSMAGIC_CODEDIRECTORY,
            CSMAGIC_EMBEDDED_SIGNATURE,
            CSMAGIC_EMBEDDED_SIGNATURE_OLD,
            CSMAGIC_EMBEDDED_ENTITLEMENTS,
            CSMAGIC_EMBEDDED_DER_ENTITLEMENTS,
            CSMAGIC_DETACHED_SIGNATURE,
            CSMAGIC_BLOBWRAPPER,
            CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT,
        ];
        for i in 0..values.len() {
            for j in (i + 1)..values.len() {
                assert_ne!(values[i], values[j]);
            }
        }
    }

    #[test]
    fn requirements_is_one_more_than_requirement() {
        assert_eq!(CSMAGIC_REQUIREMENTS, CSMAGIC_REQUIREMENT + 1);
    }

    #[test]
    fn codedirectory_is_two_more_than_requirement() {
        assert_eq!(CSMAGIC_CODEDIRECTORY, CSMAGIC_REQUIREMENT + 2);
    }
}
