/// Beginning of the common block.
pub const C_BCOMM: u8 = 135;
/// Beginning of include file.
pub const C_BINCL: u8 = 108;
/// Beginning or end of inner block.
pub const C_BLOCK: u8 = 100;
/// Beginning of static block.
pub const C_BSTAT: u8 = 143;
/// Declaration of object (type).
pub const C_DECL: u8 = 140;
/// Local member of common block.
pub const C_ECOML: u8 = 136;
/// End of common block.
pub const C_ECOMM: u8 = 127;
/// End of include file.
pub const C_EINCL: u8 = 109;
/// Alternate entry.
pub const C_ENTRY: u8 = 141;
/// End of static block.
pub const C_ESTAT: u8 = 144;
/// External symbol.
pub const C_EXT: u8 = 2;
/// Beginning or end of function.
pub const C_FCN: u8 = 101;
/// Source file name and compiler information.
pub const C_FILE: u8 = 103;
/// Function or procedure.
pub const C_FUN: u8 = 142;
/// Global variable.
pub const C_GSYM: u8 = 128;
/// Unnamed external symbol.
pub const C_HIDEXT: u8 = 107;
/// Comment section reference (same numeric value as C_BLOCK).
pub const C_INFO: u8 = 100;
/// Automatic variable allocated on stack.
pub const C_LSYM: u8 = 129;
/// Symbol table entry marked for deletion.
pub const C_NULL: u8 = 0;
/// Argument to subroutine allocated on stack.
pub const C_PSYM: u8 = 130;
/// Argument to function or procedure stored in register.
pub const C_RPSYM: u8 = 132;
/// Register variable.
pub const C_RSYM: u8 = 131;
/// Static symbol (unknown).
pub const C_STAT: u8 = 3;
/// Statically allocated symbol.
pub const C_STSYM: u8 = 133;
/// Reserved.
pub const C_TCSYM: u8 = 134;
/// Weak external symbol.
pub const C_WEAKEXT: u8 = 111;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_java_values() {
        assert_eq!(C_BCOMM, 135);
        assert_eq!(C_BINCL, 108);
        assert_eq!(C_BLOCK, 100);
        assert_eq!(C_BSTAT, 143);
        assert_eq!(C_DECL, 140);
        assert_eq!(C_ECOML, 136);
        assert_eq!(C_ECOMM, 127);
        assert_eq!(C_EINCL, 109);
        assert_eq!(C_ENTRY, 141);
        assert_eq!(C_ESTAT, 144);
        assert_eq!(C_EXT, 2);
        assert_eq!(C_FCN, 101);
        assert_eq!(C_FILE, 103);
        assert_eq!(C_FUN, 142);
        assert_eq!(C_GSYM, 128);
        assert_eq!(C_HIDEXT, 107);
        assert_eq!(C_INFO, 100);
        assert_eq!(C_LSYM, 129);
        assert_eq!(C_NULL, 0);
        assert_eq!(C_PSYM, 130);
        assert_eq!(C_RPSYM, 132);
        assert_eq!(C_RSYM, 131);
        assert_eq!(C_STAT, 3);
        assert_eq!(C_STSYM, 133);
        assert_eq!(C_TCSYM, 134);
        assert_eq!(C_WEAKEXT, 111);
    }

    #[test]
    fn c_block_and_c_info_share_value() {
        // Both are 100 in the Java source; preserve the Java parity exactly.
        assert_eq!(C_BLOCK, C_INFO);
    }
}
