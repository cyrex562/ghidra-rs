/// Hexagon FP64 floating-point constants and utilities.
///
/// Provides bit field definitions, extraction functions, and the `dfmpyhh`/`dfmpyfix`
/// double-precision fused-multiply helpers used in Hexagon processor emulation.
///
/// Mirrors `ghidra.program.emulation.HexagonFp64` from Java.
pub const FP64_FRAC_POS: u32 = 0;
pub const FP64_FRAC_SIZE: u32 = 52;
pub const FP64_FRAC_MASK: i64 = ((1i64 << FP64_FRAC_SIZE) - 1) << FP64_FRAC_POS;

pub const FP64_EXP_POS: u32 = FP64_FRAC_POS + FP64_FRAC_SIZE;
pub const FP64_EXP_SIZE: u32 = 11;
pub const FP64_EXP_MASK: i64 = ((1i64 << FP64_EXP_SIZE) - 1) << FP64_EXP_POS;

pub const FP64_SIGN_POS: u32 = FP64_EXP_POS + FP64_EXP_SIZE;
pub const FP64_BIAS: i32 = (1i32 << (FP64_EXP_SIZE - 1)) - 1;
pub const FP64_EXP_INF: i32 = ((FP64_EXP_MASK as u64) >> FP64_EXP_POS) as i32;

/// Extracts the exponent field from a 64-bit float representation.
pub fn mask_fp64_exponent(value_bits: i64) -> i64 {
    FP64_EXP_MASK & value_bits
}

/// Extracts the fraction field from a 64-bit float representation.
pub fn mask_fp64_fraction(value_bits: i64) -> i64 {
    FP64_FRAC_MASK & value_bits
}

/// Checks if a 64-bit float is zero (both exponent and fraction are zero).
pub fn is_fp64_zero(exp: i64, frac: i64) -> bool {
    exp == 0 && frac == 0
}

/// Checks if a 64-bit float is normal (exponent is non-zero and not all ones).
pub fn is_fp64_normal(exp: i64, _frac: i64) -> bool {
    exp != 0 && exp != FP64_EXP_MASK
}

/// Checks if a 64-bit float is subnormal (exponent is zero but fraction is non-zero).
pub fn is_fp64_subnormal(exp: i64, frac: i64) -> bool {
    exp == 0 && frac != 0
}

/// Checks if a 64-bit float is infinite (exponent all ones, fraction is zero).
pub fn is_fp64_infinite(exp: i64, frac: i64) -> bool {
    exp == FP64_EXP_MASK && frac == 0
}

/// Checks if a 64-bit float is NaN (exponent all ones, fraction is non-zero).
pub fn is_fp64_nan(exp: i64, frac: i64) -> bool {
    exp == FP64_EXP_MASK && frac != 0
}

/// Checks if a 64-bit float's raw bit pattern has the sign bit set.
pub fn is_fp64_negative(bits: i64) -> bool {
    bits < 0
}

fn get_fp64_fraction(exp: i64, frac: i64) -> i64 {
    // Note: No additional shifting of frac necessary, as FP64_FRAC_POS = 0
    if is_fp64_normal(exp, frac) {
        return frac | (1i64 << FP64_FRAC_SIZE);
    }
    if is_fp64_zero(exp, frac) {
        return 0;
    }
    if !is_fp64_subnormal(exp, frac) {
        return -1;
    }
    frac
}

fn get_fp64_exponent(exp: i64, frac: i64) -> i32 {
    if is_fp64_normal(exp, frac) {
        return ((exp as u64) >> FP64_EXP_POS) as i32;
    }
    if is_fp64_subnormal(exp, frac) {
        return (((exp as u64) >> FP64_EXP_POS) as i32).wrapping_add(1);
    }
    -1
}

fn enc_sign(negative: bool) -> i64 {
    if negative { i64::MIN } else { 0 }
}

fn enc_exp(exp: i32, mant_upper: i64) -> i64 {
    if ((mant_upper as u64) >> (FP64_FRAC_SIZE - 32)) == 0 {
        return 0;
    }
    ((exp as u32) as i64) << FP64_EXP_POS
}

fn enc_frac(mant_upper: i64, mant_lower: i32) -> i64 {
    ((mant_upper << 32) | ((mant_lower as u32) as i64)) & FP64_FRAC_MASK
}

/// Double-precision fused multiply, accumulating the high half of the product into `rdd`.
#[allow(unused_assignments)]
pub fn dfmpyhh(rdd: i64, rss: i64, rtt: i64) -> i64 {
    let exp_rss = mask_fp64_exponent(rss);
    let frac_rss = mask_fp64_fraction(rss);

    let exp_rtt = mask_fp64_exponent(rtt);
    let frac_rtt = mask_fp64_fraction(rtt);

    if is_fp64_zero(exp_rss, frac_rss)
        || is_fp64_nan(exp_rss, frac_rss)
        || is_fp64_infinite(exp_rss, frac_rss)
        || is_fp64_zero(exp_rtt, frac_rtt)
        || is_fp64_nan(exp_rtt, frac_rtt)
        || is_fp64_infinite(exp_rtt, frac_rtt)
    {
        return (f64::from_bits(rss as u64) * f64::from_bits(rtt as u64)).to_bits() as i64;
    }

    // Read Accumulated from rdd
    let mut sticky = (rdd & 1) != 0;
    let mut mant_lower: i32 = (rdd >> 1) as i32;
    let mut mant_upper: i64 = rdd >> 33;

    let prod = ((get_fp64_fraction(exp_rss, frac_rss) as u64) >> 32)
        .wrapping_mul((get_fp64_fraction(exp_rtt, frac_rtt) as u64) >> 32) as i64;
    mant_upper = mant_upper.wrapping_add(prod);

    let mut exp = get_fp64_exponent(exp_rss, frac_rss)
        .wrapping_add(get_fp64_exponent(exp_rtt, frac_rtt))
        .wrapping_sub(FP64_BIAS)
        .wrapping_sub(20);
    if !is_fp64_normal(exp_rss, frac_rss) || !is_fp64_normal(exp_rtt, frac_rtt) {
        // Crush to inexact 0
        sticky = true;
        exp = -4096;
    }

    let negative = is_fp64_negative(rss) ^ is_fp64_negative(rtt);

    // round
    let mut round = false;
    let mut guard = false;
    if sticky && mant_lower == 0 && mant_upper == 0 {
        return 0.0_f64.to_bits() as i64;
    }

    // normalize right for fraction
    // 32 is size of mantLower
    while ((mant_upper as u64) >> (FP64_FRAC_SIZE + 1 - 32)) != 0 {
        sticky |= round;
        round = guard;
        guard = (mant_lower & 1) != 0;
        mant_lower = ((mant_lower as u32) >> 1) as i32;
        mant_lower |= (((mant_upper as u64) << 63) >> 32) as i32;
        mant_upper = ((mant_upper as u64) >> 1) as i64;
        exp = exp.wrapping_add(1);
    }
    // (else) normalize left for fraction
    while (mant_upper & (1i64 << (FP64_FRAC_SIZE - 32))) == 0 {
        mant_upper <<= 1;
        mant_upper |= ((mant_lower as u32) >> 31) as i64;
        mant_lower <<= 1;
        mant_lower |= if guard { 1 } else { 0 };
        guard = round;
        round = sticky;
        exp = exp.wrapping_sub(1);
    }
    // normalize right for exponent
    if (1i32.wrapping_sub(exp)) > 130 {
        // if (exp < -129)
        sticky |= round | guard | (mant_lower == 0 && mant_upper == 0);
        guard = false;
        round = false;
        exp = 1;
    }
    while (1i32.wrapping_sub(exp)) >= 64 {
        // while (exp <= -63)
        // Can this be re-specialized to this 64|32-bit split?
        sticky |= round | guard | (mant_lower == 0 && (mant_upper & 0x0_ffff_ffffi64) == 0);
        guard = ((mant_upper as u64) >> 31) != 0;
        round = ((mant_upper as u64) >> 30) != 0;
        // effective shift right 64 bits
        //
        // | ----- long upper ---- | int lower |
        //
        // |BB:AA:99:88:77:66:55:44|33:22:11:00|
        //
        // |00:00:00:00:00:00:00:00|BB:AA:99:88|
        mant_lower = ((mant_upper as u64) >> 32) as i32;
        mant_upper = 0;
        exp = exp.wrapping_add(64);
    }
    while (1i32.wrapping_sub(exp)) >= 0 {
        sticky |= round;
        round = guard;
        guard = (mant_lower & 1) != 0;
        mant_lower = ((mant_lower as u32) >> 1) as i32;
        mant_lower |= (((mant_upper as u64) << 63) >> 32) as i32;
        mant_upper = ((mant_upper as u64) >> 1) as i64;
        exp = exp.wrapping_add(1);
    }

    // one more normalize right for fraction
    if ((mant_upper as u64) >> (FP64_FRAC_SIZE + 1 - 32)) != 0 {
        sticky |= round;
        round = guard;
        guard = (mant_lower & 1) != 0;
        mant_lower = ((mant_lower as u32) >> 1) as i32;
        mant_lower |= (((mant_upper as u64) << 63) >> 32) as i32;
        mant_upper = ((mant_upper as u64) >> 1) as i64;
        exp = exp.wrapping_add(1);
    }
    if exp >= FP64_EXP_INF {
        let inf = if negative {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
        return inf.to_bits() as i64;
    }
    enc_sign(negative) | enc_exp(exp, mant_upper) | enc_frac(mant_upper, mant_lower)
}

/// Double-precision fused multiply "fix" helper: rescales denormal operands by 2^52
/// so subsequent multiply steps stay in normal range.
pub fn dfmpyfix(rss: i64, rtt: i64) -> i64 {
    let exp_rss = mask_fp64_exponent(rss);
    let frac_rss = mask_fp64_fraction(rss);

    let exp_rtt = mask_fp64_exponent(rtt);
    let frac_rtt = mask_fp64_exponent(rtt);

    if !is_fp64_normal(exp_rss, frac_rss)
        && is_fp64_normal(exp_rtt, frac_rtt)
        && exp_rtt >= (512i64 << FP64_EXP_POS)
    {
        return (f64::from_bits(rss as u64) * 2f64.powi(52)).to_bits() as i64;
    }
    if !is_fp64_normal(exp_rtt, frac_rtt)
        && is_fp64_normal(exp_rss, frac_rss)
        && exp_rss >= (512i64 << FP64_EXP_POS)
    {
        return (f64::from_bits(rss as u64) * 2f64.powi(-52)).to_bits() as i64;
    }
    rss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(FP64_FRAC_POS, 0);
        assert_eq!(FP64_FRAC_SIZE, 52);
        assert_eq!(FP64_EXP_POS, 52);
        assert_eq!(FP64_EXP_SIZE, 11);
        assert_eq!(FP64_SIGN_POS, 63);
        assert_eq!(FP64_BIAS, 1023);
        assert_eq!(FP64_EXP_INF, 2047);
    }

    #[test]
    fn test_frac_mask() {
        assert_eq!(FP64_FRAC_MASK, 0x000F_FFFF_FFFF_FFFFi64);
    }

    #[test]
    fn test_exp_mask() {
        assert_eq!(FP64_EXP_MASK, 0x7FF0_0000_0000_0000u64 as i64);
    }

    #[test]
    fn test_mask_fp64_fraction() {
        let bits = 0x3FF0_0000_0000_0000i64; // 1.0
        assert_eq!(mask_fp64_fraction(bits), 0);

        let bits = 0x3FF0_0000_0000_0001i64;
        assert_eq!(mask_fp64_fraction(bits), 1);
    }

    #[test]
    fn test_mask_fp64_exponent() {
        let bits = 0x3FF0_0000_0000_0000i64; // 1.0
        assert_eq!(mask_fp64_exponent(bits), 0x3FF0_0000_0000_0000i64);

        let bits = 0i64; // 0.0
        assert_eq!(mask_fp64_exponent(bits), 0);

        let bits = 0x7FF0_0000_0000_0000u64 as i64; // Infinity
        assert_eq!(mask_fp64_exponent(bits), FP64_EXP_MASK);
    }

    #[test]
    fn test_float_classification_1_0() {
        let bits = 1.0f64.to_bits() as i64;
        let exp = mask_fp64_exponent(bits);
        let frac = mask_fp64_fraction(bits);
        assert!(is_fp64_normal(exp, frac));
        assert!(!is_fp64_zero(exp, frac));
        assert!(!is_fp64_subnormal(exp, frac));
        assert!(!is_fp64_infinite(exp, frac));
        assert!(!is_fp64_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_zero() {
        let bits = 0.0f64.to_bits() as i64;
        let exp = mask_fp64_exponent(bits);
        let frac = mask_fp64_fraction(bits);
        assert!(is_fp64_zero(exp, frac));
        assert!(!is_fp64_normal(exp, frac));
        assert!(!is_fp64_subnormal(exp, frac));
        assert!(!is_fp64_infinite(exp, frac));
        assert!(!is_fp64_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_subnormal() {
        let bits = 1i64; // smallest subnormal
        let exp = mask_fp64_exponent(bits);
        let frac = mask_fp64_fraction(bits);
        assert!(is_fp64_subnormal(exp, frac));
        assert!(!is_fp64_zero(exp, frac));
        assert!(!is_fp64_normal(exp, frac));
        assert!(!is_fp64_infinite(exp, frac));
        assert!(!is_fp64_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_infinity() {
        let bits = f64::INFINITY.to_bits() as i64;
        let exp = mask_fp64_exponent(bits);
        let frac = mask_fp64_fraction(bits);
        assert!(is_fp64_infinite(exp, frac));
        assert!(!is_fp64_zero(exp, frac));
        assert!(!is_fp64_normal(exp, frac));
        assert!(!is_fp64_subnormal(exp, frac));
        assert!(!is_fp64_nan(exp, frac));
    }

    #[test]
    fn test_float_classification_nan() {
        let bits = f64::NAN.to_bits() as i64;
        let exp = mask_fp64_exponent(bits);
        let frac = mask_fp64_fraction(bits);
        assert!(is_fp64_nan(exp, frac));
        assert!(!is_fp64_zero(exp, frac));
        assert!(!is_fp64_normal(exp, frac));
        assert!(!is_fp64_subnormal(exp, frac));
        assert!(!is_fp64_infinite(exp, frac));
    }

    #[test]
    fn test_is_fp64_negative() {
        assert!(is_fp64_negative((-1.0f64).to_bits() as i64));
        assert!(!is_fp64_negative(1.0f64.to_bits() as i64));
        assert!(!is_fp64_negative(0));
    }

    #[test]
    fn test_dfmpyhh_zero_operand_multiplies_via_double() {
        let rdd = 0i64;
        let rss = 0.0f64.to_bits() as i64;
        let rtt = 5.0f64.to_bits() as i64;
        let result = dfmpyhh(rdd, rss, rtt);
        assert_eq!(f64::from_bits(result as u64), 0.0);
    }

    #[test]
    fn test_dfmpyhh_nan_operand_propagates_nan() {
        let rdd = 0i64;
        let rss = f64::NAN.to_bits() as i64;
        let rtt = 5.0f64.to_bits() as i64;
        let result = dfmpyhh(rdd, rss, rtt);
        assert!(f64::from_bits(result as u64).is_nan());
    }

    #[test]
    fn test_dfmpyhh_infinite_operand_propagates_infinity() {
        let rdd = 0i64;
        let rss = f64::INFINITY.to_bits() as i64;
        let rtt = 5.0f64.to_bits() as i64;
        let result = dfmpyhh(rdd, rss, rtt);
        assert!(f64::from_bits(result as u64).is_infinite());
    }

    #[test]
    fn test_dfmpyhh_normal_operands_produce_finite_result() {
        let rdd = 0i64;
        let rss = 1.5f64.to_bits() as i64;
        let rtt = 2.5f64.to_bits() as i64;
        let result = dfmpyhh(rdd, rss, rtt);
        assert!(f64::from_bits(result as u64).is_finite());
    }

    #[test]
    fn test_dfmpyfix_normal_operands_returns_rss_unchanged() {
        let rss = 1.5f64.to_bits() as i64;
        let rtt = 2.5f64.to_bits() as i64;
        assert_eq!(dfmpyfix(rss, rtt), rss);
    }

    #[test]
    fn test_dfmpyfix_denormal_rss_with_large_rtt_scales_up() {
        // Subnormal rss, rtt with a large exponent (>= 512 in exponent-field units).
        let rss = 1i64; // smallest subnormal double
        let rtt = (600i64 << FP64_EXP_POS) | 1; // large exponent field, but not all-ones
        let result = dfmpyfix(rss, rtt);
        let expected = (f64::from_bits(rss as u64) * 2f64.powi(52)).to_bits() as i64;
        assert_eq!(result, expected);
    }
}
