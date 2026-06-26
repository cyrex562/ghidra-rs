/// Max length (in bytes) of an in-place section name.
pub const SECTION_NAME_LENGTH: usize = 8;

/// Max length (in bytes) of an in-place symbol name.
pub const SYMBOL_NAME_LENGTH: usize = 8;

/// Length (in bytes) of a symbol data structure.
pub const SYMBOL_SIZEOF: usize = 18;

/// Max length (in bytes) of a file name.
pub const FILE_NAME_LENGTH: usize = 14;

/// Number of dimensions of a symbol's auxiliary array.
pub const AUXILIARY_ARRAY_DIMENSION: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_name_length() {
        assert_eq!(SECTION_NAME_LENGTH, 8);
    }

    #[test]
    fn symbol_name_length() {
        assert_eq!(SYMBOL_NAME_LENGTH, 8);
    }

    #[test]
    fn symbol_sizeof() {
        assert_eq!(SYMBOL_SIZEOF, 18);
    }

    #[test]
    fn file_name_length() {
        assert_eq!(FILE_NAME_LENGTH, 14);
    }

    #[test]
    fn auxiliary_array_dimension() {
        assert_eq!(AUXILIARY_ARRAY_DIMENSION, 4);
    }
}
