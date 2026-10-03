//! Port of `ghidra.pcode.floatformat.FloatFormatFactory`.
//!
//! Java's class holds only statics (a `HashMap<Integer, FloatFormat>` cache and a `synchronized`
//! lookup), so per the shape rules it is a module with no type of that name. The cache only ever
//! holds the six sizes `FloatFormat` supports, so it is one lazily-built static per size rather
//! than a locked map; unsupported sizes fail every time, as in Java (which does not cache them).

use std::sync::OnceLock;

use super::float_format::FloatFormat;
use super::UnsupportedFloatFormatException;

static FORMAT_2: OnceLock<FloatFormat> = OnceLock::new();
static FORMAT_4: OnceLock<FloatFormat> = OnceLock::new();
static FORMAT_8: OnceLock<FloatFormat> = OnceLock::new();
static FORMAT_10: OnceLock<FloatFormat> = OnceLock::new();
static FORMAT_16: OnceLock<FloatFormat> = OnceLock::new();
static FORMAT_32: OnceLock<FloatFormat> = OnceLock::new();

/// Get the float format for a storage size in bytes (2, 4, 8, 10, 16 or 32).
///
/// Port of `FloatFormatFactory.getFloatFormat(int)`.
///
/// # Errors
/// [`UnsupportedFloatFormatException`] if `size` has no IEEE 754 format.
pub fn get_float_format(size: i32) -> Result<&'static FloatFormat, UnsupportedFloatFormatException> {
    let cell = match size {
        2 => &FORMAT_2,
        4 => &FORMAT_4,
        8 => &FORMAT_8,
        10 => &FORMAT_10,
        16 => &FORMAT_16,
        32 => &FORMAT_32,
        _ => return Err(UnsupportedFloatFormatException::with_format_size(size)),
    };
    Ok(cell.get_or_init(|| FloatFormat::new(size).expect("supported float format size")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_sizes_are_cached() {
        for size in [2, 4, 8, 10, 16, 32] {
            let a = get_float_format(size).unwrap();
            let b = get_float_format(size).unwrap();
            assert!(std::ptr::eq(a, b), "size {}", size);
            assert_eq!(a.get_size(), size);
        }
    }

    #[test]
    fn unsupported_sizes_error() {
        for size in [-1, 0, 1, 3, 12, 64] {
            let err = get_float_format(size).unwrap_err();
            assert!(err.to_string().contains(&size.to_string()), "{}", err);
        }
    }
}
