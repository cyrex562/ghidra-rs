/// Update level for a Code Fragment Manager (CFM) fragment.
///
/// Mirrors `CFragUpdateLevel` from the original Ghidra Java source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CFragUpdateLevel {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn is_zero_sized_uninhabited() {
        assert_eq!(mem::size_of::<CFragUpdateLevel>(), 0);
    }
}
