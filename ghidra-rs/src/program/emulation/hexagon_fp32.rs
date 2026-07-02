/// Hexagon FP32 floating-point constants and utilities.
///
/// Provides bit field definitions and extraction functions for IEEE 754 32-bit
/// floating-point values used in Hexagon processor emulation.
///
/// Mirrors `ghidra.program.emulation.HexagonFp32` from Java.

pub const FP32_FRAC_POS: u32 = 0;
pub const FP32_FRAC_SIZE: u32 = 23;
pub const FP32_FRAC_MASK: u32 = ((1 << FP32_FRAC_SIZE) - 1) << FP32_FRAC_POS;

pub const FP32_EXP_POS: u32 = FP32_FRAC_POS + FP32_FRAC_SIZE;
pub const FP32_EXP_SIZE: u32 = 8;
pub const FP32_EXP_MASK: u32 = ((1 << FP32_EXP_SIZE) - 1) << FP32_EXP_POS;

pub const FP32_SIGN_POS: u32 = FP32_EXP_POS + FP32_EXP_SIZE;
pub const FP32_BIAS: u32 = (1 << (FP32_EXP_SIZE - 1)) - 1;

/// Extracts the exponent field from a 32-bit float representation.
pub fn mask_fp32_exponent(value_bits: u32) -> u32 {
    FP32_EXP_MASK & value_bits
}

/// Extracts the fraction field from a 32-bit float representation.
pub fn mask_fp32_fraction(value_bits: u32) -> u32 {
    FP32_FRAC_MASK & value_bits
}

/// Checks if a 32-bit float is zero (both exponent and fraction are zero).
pub fn is_fp32_zero(exp: u32, frac: u32) -> bool {
    exp == 0 && frac == 0
}

/// Checks if a 32-bit float is normal (exponent is non-zero and not all ones).
pub fn is_fp32_normal(exp: u32, _frac: u32) -> bool {
    exp != 0 && exp != FP32_EXP_MASK
}

/// Checks if a 32-bit float is subnormal (exponent is zero but fraction is non-zero).
pub fn is_fp32_subnormal(exp: u32, frac: u32) -> bool {
    exp == 0 && frac != 0
}

/// Checks if a 32-bit float is infinite (exponent all ones, fraction is zero).
pub fn is_fp32_infinite(exp: u32, frac: u32) -> bool {
    exp == FP32_EXP_MASK && frac == 0
}

/// Checks if a 32-bit float is NaN (exponent all ones, fraction is non-zero).
pub fn is_fp32_nan(exp: u32, frac: u32) -> bool {
    exp == FP32_EXP_MASK && frac != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(FP32_FRAC_POS, 0);
        assert_eq!(FP32_FRAC_SIZE, 23);
        assert_eq!(FP32_EXP_POS, 23);
        assert_eq!(FP32_EXP_SIZE, 8);
        assert_eq!(FP32_SIGN_POS, 31);
        assert_eq!(FP32_BIAS, 127);
    }

    #[test]
    fn test_frac_mask() {
        assert_eq!(FP32_FRAC_MASK, 0x007FFFFF);
    }

    #[test]
    fn test_exp_mask() {
        assert_eq!(FP32_EXP_MASK, 0x7F800000);
    }

    #[test]
    fn test_mask_fp32_fraction() {
        let bits = 0x3F800000u32; // 1.0
        assert_eq!(mask_fp32_fraction(bits), 0);

        let bits = 0x3F800001u32;
        assert_eq!(mask_fp32_fraction(bits), 1);

        let bits = 0x3FFFFFFFu32;
        assert_eq!(mask_fp32_fraction(bits), 0x007FFFFF);
    }

    #[test]
    fn test_mask_fp32_exponent() {
        let bits = 0x3F800000u32; // 1.0
        assert_eq!(mask_fp32_exponent(bits), 0x3F800000);

        let bits = 0x00000000u32; // 0.0
        assert_eq!(mask_fp32_exponent(bits), 0);

        let bits = 0x7F800000u32; // Infinity
        assert_eq!(mask_fp32_exponent(bits), 0x7F800000);
    }

    #[test]
    fn test_is_fp32_zero() {
        assert!(is_fp32_zero(0, 0));
        assert!(!is_fp32_zero(1, 0));
        assert!(!is_fp32_zero(0, 1));
        assert!(!is_fp32_zero(1, 1));
    }

    #[test]
    fn test_is_fp32_normal() {
        assert!(!is_fp32_normal(0, 0));
        assert!(!is_fp32_normal(0, 1));
        assert!(is_fp32_normal(1, 0));
        assert!(is_fp32_normal(1, 1));
        assert!(!is_fp32_normal(FP32_EXP_MASK, 0));
        assert!(!is_fp32_normal(FP32_EXP_MASK, 1));
    }

    #[test]
    fn test_is_fp32_subnormal() {
        assert!(!is_fp32_subnormal(0, 0));
        assert!(is_fp32_subnormal(0, 1));
        assert!(!is_fp32_subnormal(1, 0));
        assert!(!is_fp32_subnormal(1, 1));
    }

    #[test]
    fn test_is_fp32_infinite() {
        assert!(!is_fp32_infinite(0, 0));
        assert!(!is_fp32_infinite(0, 1));
        assert!(!is_fp32_infinite(FP32_EXP_MASK, 1));
        assert!(is_fp32_infinite(FP32_EXP_MASK, 0));
    }

    #[test]
    fn test_is_fp32_nan() {
        assert!(!is_fp32_nan(0, 0));
        assert!(!is_fp32_nan(0, 1));
        assert!(is_fp32_nan(FP32_EXP_MASK, 1));
        assert!(!is_fp32_nan(FP32_EXP_MASK, 0));
    }

    #[test]
    fn test_float_classification_1_0() {
        let bits = 0x3F800000u32; // 1.0
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_normal(exp, frac));
        assert!(!is_fp32_zero(exp, frac));
        assert!(!is_fp32_subnormal(exp, frac));
        assert!(!is_fp32_infinite(exp, frac));
        assert!(!is_fp32_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_zero() {
        let bits = 0x00000000u32; // 0.0
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_zero(exp, frac));
        assert!(!is_fp32_normal(exp, frac));
        assert!(!is_fp32_subnormal(exp, frac));
        assert!(!is_fp32_infinite(exp, frac));
        assert!(!is_fp32_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_subnormal() {
        let bits = 0x00000001u32; // Smallest subnormal
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_subnormal(exp, frac));
        assert!(!is_fp32_zero(exp, frac));
        assert!(!is_fp32_normal(exp, frac));
        assert!(!is_fp32_infinite(exp, frac));
        assert!(!is_fp32_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_positive_infinity() {
        let bits = 0x7F800000u32; // +Infinity
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_infinite(exp, frac));
        assert!(!is_fp32_zero(exp, frac));
        assert!(!is_fp32_normal(exp, frac));
        assert!(!is_fp32_subnormal(exp, frac));
        assert!(!is_fp32_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_nan() {
        let bits = 0x7F800001u32; // NaN
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_nan(exp, frac));
        assert!(!is_fp32_zero(exp, frac));
        assert!(!is_fp32_normal(exp, frac));
        assert!(!is_fp32_subnormal(exp, frac));
        assert!(!is_fp32_infinite(exp, frac));
    }

    #[test]
    fn test_float_classification_negative_infinity() {
        let bits = 0xFF800000u32; // -Infinity
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_infinite(exp, frac));
    }

    #[test]
    fn test_float_classification_negative_zero() {
        let bits = 0x80000000u32; // -0.0
        let exp = mask_fp32_exponent(bits);
        let frac = mask_fp32_fraction(bits);
        assert!(is_fp32_zero(exp, frac));
    }
}
