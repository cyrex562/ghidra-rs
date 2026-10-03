//! Constants for Apple IMG3 firmware image files.
//!
//! Port of `ghidra.file.formats.ios.img3.Img3Constants`, a statics-only Java class; the
//! constants live directly in this module rather than on a type.

/// IMG3 magic value.
pub const IMG3_SIGNATURE: &str = "Img3";
/// IMG3 magic value as bytes (the signature as it appears on disk, byte-reversed).
pub const IMG3_SIGNATURE_BYTES: [u8; 4] = [b'3', b'g', b'm', b'I'];
/// The length (in bytes) of the signature.
pub const IMG3_SIGNATURE_LENGTH: usize = IMG3_SIGNATURE_BYTES.len();

/// Board ID tag.
pub const IMG3_TAG_BDID_MAGIC: &str = "BDID";
/// Board to be used with.
pub const IMG3_TAG_BORD_MAGIC: &str = "BORD";
/// Chip to be used with; e.g. "8900" => "S5L8900".
pub const IMG3_TAG_CHIP_PROD: &str = "CHIP";
/// Certificate.
pub const IMG3_TAG_CERT_MAGIC: &str = "CERT";
/// The code portion of the firmware, usually encrypted.
pub const IMG3_TAG_DATA_MAGIC: &str = "DATA";
/// Exclusive chip ID unique to every device with iPhone OS running.
pub const IMG3_TAG_ECID_MAGIC: &str = "ECID";
/// Contains the KEY and IV required to decrypt the GID-key.
pub const IMG3_TAG_KBAG_MAGIC: &str = "KBAG";
/// Production Mode.
pub const IMG3_TAG_PROD_MAGIC: &str = "PROD";
/// Security Domain.
pub const IMG3_TAG_SDOM_MAGIC: &str = "SDOM";
/// Security EPOCH.
pub const IMG3_TAG_SEPO_MAGIC: &str = "SEPO";
/// SCEP tag.
pub const IMG3_TAG_SCEP_MAGIC: &str = "SCEP";
/// RSA encrypted SHA1 hash of the file.
pub const IMG3_TAG_SHSH_MAGIC: &str = "SHSH";
/// Type information.
pub const IMG3_TAG_TYPE_MAGIC: &str = "TYPE";
/// iBoot version of image.
pub const IMG3_TAG_VERS_MAGIC: &str = "VERS";

/// Low-level bootloader image type.
pub const IMG3_TYPE_LLB: &str = "illb";
/// iBoot image type.
pub const IMG3_TYPE_IBOOT: &str = "ibot";
/// iBEC image type.
pub const IMG3_TYPE_IBEC: &str = "ibec";
/// iBSS image type.
pub const IMG3_TYPE_IBSS: &str = "ibss";
/// Kernel image type.
pub const IMG3_TYPE_KERNEL: &str = "krnl";
/// Ramdisk image type.
pub const IMG3_TYPE_RAMDISK: &str = "rdsk";
/// Apple logo image type.
pub const IMG3_TYPE_APPLE_LOGO: &str = "logo";
/// Recovery mode image type.
pub const IMG3_TYPE_RECOVERY_MODE: &str = "recm";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_bytes_are_reversed_signature() {
        let mut reversed: Vec<u8> = IMG3_SIGNATURE.bytes().collect();
        reversed.reverse();
        assert_eq!(reversed, IMG3_SIGNATURE_BYTES);
        assert_eq!(IMG3_SIGNATURE_LENGTH, 4);
    }

    #[test]
    fn tags_are_four_ascii_bytes() {
        for tag in [
            IMG3_TAG_BDID_MAGIC,
            IMG3_TAG_BORD_MAGIC,
            IMG3_TAG_CHIP_PROD,
            IMG3_TAG_CERT_MAGIC,
            IMG3_TAG_DATA_MAGIC,
            IMG3_TAG_ECID_MAGIC,
            IMG3_TAG_KBAG_MAGIC,
            IMG3_TAG_PROD_MAGIC,
            IMG3_TAG_SDOM_MAGIC,
            IMG3_TAG_SEPO_MAGIC,
            IMG3_TAG_SCEP_MAGIC,
            IMG3_TAG_SHSH_MAGIC,
            IMG3_TAG_TYPE_MAGIC,
            IMG3_TAG_VERS_MAGIC,
        ] {
            assert_eq!(tag.len(), IMG3_SIGNATURE_LENGTH, "{tag}");
            assert!(tag.is_ascii());
        }
    }

    #[test]
    fn values_match_java() {
        assert_eq!(IMG3_TAG_CHIP_PROD, "CHIP");
        assert_eq!(IMG3_TAG_SHSH_MAGIC, "SHSH");
        assert_eq!(IMG3_TYPE_LLB, "illb");
        assert_eq!(IMG3_TYPE_IBOOT, "ibot");
        assert_eq!(IMG3_TYPE_IBEC, "ibec");
        assert_eq!(IMG3_TYPE_IBSS, "ibss");
        assert_eq!(IMG3_TYPE_KERNEL, "krnl");
        assert_eq!(IMG3_TYPE_RAMDISK, "rdsk");
        assert_eq!(IMG3_TYPE_APPLE_LOGO, "logo");
        assert_eq!(IMG3_TYPE_RECOVERY_MODE, "recm");
    }
}
