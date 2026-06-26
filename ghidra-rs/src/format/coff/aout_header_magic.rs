/// Magic values for the COFF a.out optional header.
///
/// Both TI C80 and TI COFF share the same magic value `0x0108`.
pub const TIC80_AOUTHDR_MAGIC: u16 = 0x0108;
pub const TICOFF_AOUTHDR_MAGIC: u16 = 0x0108;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tic80_magic_value() {
        assert_eq!(TIC80_AOUTHDR_MAGIC, 0x0108);
    }

    #[test]
    fn ticoff_magic_value() {
        assert_eq!(TICOFF_AOUTHDR_MAGIC, 0x0108);
    }

    #[test]
    fn both_magics_are_equal() {
        assert_eq!(TIC80_AOUTHDR_MAGIC, TICOFF_AOUTHDR_MAGIC);
    }
}
