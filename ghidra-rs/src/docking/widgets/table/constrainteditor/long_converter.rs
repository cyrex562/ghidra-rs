/// Converts an `i64` editor value back to the concrete number type `T`.
///
/// Allows byte, short, int, and long number constraints to share a single editor that
/// operates on `i64` values internally; each constraint supplies a `LongConverter`
/// implementation to translate those values back to its own type.
///
/// Corresponds to `docking.widgets.table.constrainteditor.LongConverter` in the Java source.
pub trait LongConverter<T> {
    /// Converts an `i64` value to `T`.
    fn from_long(&self, value: i64) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct I8Converter;
    struct I16Converter;
    struct I32Converter;
    struct I64Converter;

    impl LongConverter<i8> for I8Converter {
        fn from_long(&self, value: i64) -> i8 {
            value as i8
        }
    }

    impl LongConverter<i16> for I16Converter {
        fn from_long(&self, value: i64) -> i16 {
            value as i16
        }
    }

    impl LongConverter<i32> for I32Converter {
        fn from_long(&self, value: i64) -> i32 {
            value as i32
        }
    }

    impl LongConverter<i64> for I64Converter {
        fn from_long(&self, value: i64) -> i64 {
            value
        }
    }

    #[test]
    fn i8_converter_round_trips_valid_range() {
        let c = I8Converter;
        assert_eq!(c.from_long(42), 42_i8);
        assert_eq!(c.from_long(127), i8::MAX);
        assert_eq!(c.from_long(-128), i8::MIN);
        assert_eq!(c.from_long(-1), -1_i8);
    }

    #[test]
    fn i16_converter_round_trips_valid_range() {
        let c = I16Converter;
        assert_eq!(c.from_long(300), 300_i16);
        assert_eq!(c.from_long(32767), i16::MAX);
        assert_eq!(c.from_long(-32768), i16::MIN);
    }

    #[test]
    fn i32_converter_round_trips_valid_range() {
        let c = I32Converter;
        assert_eq!(c.from_long(100_000), 100_000_i32);
        assert_eq!(c.from_long(i32::MAX as i64), i32::MAX);
        assert_eq!(c.from_long(i32::MIN as i64), i32::MIN);
    }

    #[test]
    fn i64_converter_identity_at_extremes() {
        let c = I64Converter;
        assert_eq!(c.from_long(i64::MAX), i64::MAX);
        assert_eq!(c.from_long(i64::MIN), i64::MIN);
        assert_eq!(c.from_long(0), 0_i64);
    }
}
