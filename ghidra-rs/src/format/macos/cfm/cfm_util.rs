/// Aligns `value` up to the next multiple of four.
///
/// Mirrors Ghidra's `CFM_Util.alignToFour`.
pub fn align_to_four(value: i32) -> i32 {
    (value + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_aligned() {
        assert_eq!(align_to_four(0), 0);
        assert_eq!(align_to_four(4), 4);
        assert_eq!(align_to_four(8), 8);
        assert_eq!(align_to_four(100), 100);
    }

    #[test]
    fn one_past_boundary() {
        assert_eq!(align_to_four(1), 4);
        assert_eq!(align_to_four(5), 8);
        assert_eq!(align_to_four(9), 12);
    }

    #[test]
    fn two_past_boundary() {
        assert_eq!(align_to_four(2), 4);
        assert_eq!(align_to_four(6), 8);
    }

    #[test]
    fn three_past_boundary() {
        assert_eq!(align_to_four(3), 4);
        assert_eq!(align_to_four(7), 8);
    }

    #[test]
    fn large_value() {
        assert_eq!(align_to_four(1000), 1000);
        assert_eq!(align_to_four(1001), 1004);
        assert_eq!(align_to_four(1003), 1004);
    }
}
