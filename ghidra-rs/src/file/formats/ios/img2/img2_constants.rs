//! Constants for Apple IMG2 firmware image files.
//!
//! Port of `ghidra.file.formats.ios.img2.Img2Constants`, a statics-only Java class; the
//! constants live directly in this module rather than on a type.
//!
//! The `IMAGE_TYPE_*` names keep Java's mixed case on purpose: `IMAGE_TYPE_batl` and
//! `IMAGE_TYPE_batL` differ only by case, so upper-casing them would collide.
#![allow(non_upper_case_globals)]

/// IMG2 magic value.
pub const IMG2_SIGNATURE: &str = "Img2";

/// IMG2 magic value as bytes (the signature as it appears on disk, byte-reversed).
pub const IMG2_SIGNATURE_BYTES: [u8; 4] = [b'2', b'g', b'm', b'I'];

/// Overall size of the IMG2 header.
pub const IMG2_LENGTH: usize = 0x400;

/// `applelogo.img2`
pub const IMAGE_TYPE_logo: &str = "logo";
/// `batterycharging.img2`
pub const IMAGE_TYPE_batC: &str = "batC";
/// `batterylow0.img2`
pub const IMAGE_TYPE_batl: &str = "batl";
/// `batterylow1.img2`
pub const IMAGE_TYPE_batL: &str = "batL";
/// `DeviceTree.m68ap.img2`
pub const IMAGE_TYPE_dtre: &str = "dtre";
/// `iBoot.m68a9.RELEASE.img2`
pub const IMAGE_TYPE_ibot: &str = "ibot";
/// `LLB.m68ap.RELEASE.img2`
pub const IMAGE_TYPE_llbz: &str = "llbz";
/// `needservice.img2` (the Java constant name and value disagree -- `nsvr` vs `"nsrv"` --
/// and both are preserved as-is).
pub const IMAGE_TYPE_nsvr: &str = "nsrv";
/// `recoverymode.img2`
pub const IMAGE_TYPE_recm: &str = "recm";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_are_reversed_signature() {
        let mut reversed: Vec<u8> = IMG2_SIGNATURE.bytes().collect();
        reversed.reverse();
        assert_eq!(reversed, IMG2_SIGNATURE_BYTES);
        assert_eq!(&IMG2_SIGNATURE_BYTES, b"2gmI");
    }

    #[test]
    fn header_length_matches_java() {
        assert_eq!(IMG2_LENGTH, 1024);
    }

    #[test]
    fn image_types_match_java_values() {
        assert_eq!(IMAGE_TYPE_logo, "logo");
        assert_eq!(IMAGE_TYPE_batC, "batC");
        assert_ne!(IMAGE_TYPE_batl, IMAGE_TYPE_batL);
        assert_eq!(IMAGE_TYPE_batl, "batl");
        assert_eq!(IMAGE_TYPE_batL, "batL");
        assert_eq!(IMAGE_TYPE_dtre, "dtre");
        assert_eq!(IMAGE_TYPE_ibot, "ibot");
        assert_eq!(IMAGE_TYPE_llbz, "llbz");
        assert_eq!(IMAGE_TYPE_nsvr, "nsrv");
        assert_eq!(IMAGE_TYPE_recm, "recm");
    }
}
