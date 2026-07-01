pub mod arm_cpu_state;
pub mod hexagon_fp32;
pub mod hexagon_fp64;

pub use arm_cpu_state::ArmCpuState;
pub use hexagon_fp32::{
    is_fp32_infinite, is_fp32_nan, is_fp32_normal, is_fp32_subnormal, is_fp32_zero,
    mask_fp32_exponent, mask_fp32_fraction, FP32_BIAS, FP32_EXP_MASK, FP32_EXP_POS,
    FP32_EXP_SIZE, FP32_FRAC_MASK, FP32_FRAC_POS, FP32_FRAC_SIZE, FP32_SIGN_POS,
};
pub use hexagon_fp64::{
    dfmpyfix, dfmpyhh, is_fp64_infinite, is_fp64_nan, is_fp64_negative, is_fp64_normal,
    is_fp64_subnormal, is_fp64_zero, mask_fp64_exponent, mask_fp64_fraction, FP64_BIAS,
    FP64_EXP_INF, FP64_EXP_MASK, FP64_EXP_POS, FP64_EXP_SIZE, FP64_FRAC_MASK, FP64_FRAC_POS,
    FP64_FRAC_SIZE, FP64_SIGN_POS,
};
