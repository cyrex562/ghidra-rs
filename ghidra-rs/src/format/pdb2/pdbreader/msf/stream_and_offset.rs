/// A PDB stream number paired with a byte offset within that stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamAndOffset {
    pub number: i32,
    pub offset: i32,
}

impl StreamAndOffset {
    pub fn new(number: i32, offset: i32) -> Self {
        Self { number, offset }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_accessible() {
        let s = StreamAndOffset::new(3, 128);
        assert_eq!(s.number, 3);
        assert_eq!(s.offset, 128);
    }

    #[test]
    fn equality() {
        let a = StreamAndOffset::new(1, 0);
        let b = StreamAndOffset::new(1, 0);
        let c = StreamAndOffset::new(2, 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn copy_semantics() {
        let a = StreamAndOffset::new(5, 10);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn debug_output() {
        let s = StreamAndOffset::new(0, 0);
        let dbg = format!("{:?}", s);
        assert!(dbg.contains("StreamAndOffset"));
        assert!(dbg.contains("number"));
        assert!(dbg.contains("offset"));
    }

    #[test]
    fn zero_values() {
        let s = StreamAndOffset::new(0, 0);
        assert_eq!(s.number, 0);
        assert_eq!(s.offset, 0);
    }

    #[test]
    fn negative_values() {
        let s = StreamAndOffset::new(-1, -1);
        assert_eq!(s.number, -1);
        assert_eq!(s.offset, -1);
    }
}
