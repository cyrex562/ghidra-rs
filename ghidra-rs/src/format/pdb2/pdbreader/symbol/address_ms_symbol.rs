/// Implemented by symbols that carry a real segment:offset address.
///
/// Corresponds to the Java interface
/// `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AddressMsSymbol`.
pub trait AddressMsSymbol {
    /// Returns the offset component of the symbol's address.
    fn offset(&self) -> i64;

    /// Returns the segment component of the symbol's address.
    fn segment(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSymbol {
        offset: i64,
        segment: i32,
    }

    impl AddressMsSymbol for MockSymbol {
        fn offset(&self) -> i64 {
            self.offset
        }

        fn segment(&self) -> i32 {
            self.segment
        }
    }

    #[test]
    fn offset_returned_correctly() {
        let sym = MockSymbol { offset: 0x1000, segment: 1 };
        assert_eq!(sym.offset(), 0x1000);
    }

    #[test]
    fn segment_returned_correctly() {
        let sym = MockSymbol { offset: 0, segment: 3 };
        assert_eq!(sym.segment(), 3);
    }

    #[test]
    fn zero_values() {
        let sym = MockSymbol { offset: 0, segment: 0 };
        assert_eq!(sym.offset(), 0);
        assert_eq!(sym.segment(), 0);
    }

    #[test]
    fn large_offset() {
        let sym = MockSymbol { offset: i64::MAX, segment: i32::MAX };
        assert_eq!(sym.offset(), i64::MAX);
        assert_eq!(sym.segment(), i32::MAX);
    }
}
