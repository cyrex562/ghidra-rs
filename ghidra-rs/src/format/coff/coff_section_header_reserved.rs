/// Assuming the underlying processor is word aligned, indicates that a section is byte aligned.
pub const EXPLICITLY_BYTE_ALIGNED: u32 = 0x08;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicitly_byte_aligned_value() {
        assert_eq!(EXPLICITLY_BYTE_ALIGNED, 0x08);
    }
}
