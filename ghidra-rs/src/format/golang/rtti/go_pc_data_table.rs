/// Index into a `GoFuncData`'s variable-size pcdata array.
///
/// The discriminant matches the integer index used at runtime.
/// Mirrors Ghidra's `GoPcDataTable` Java enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum GoPcDataTable {
    UnsafePoint = 0,
    StackMapIndex = 1,
    InlTreeIndex = 2,
    ArgLiveIndex = 3,
}

impl GoPcDataTable {
    /// Returns the integer index for this pcdata entry.
    pub fn index(self) -> u8 {
        self as u8
    }

    /// Constructs a variant from its integer index, or `None` if out of range.
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::UnsafePoint),
            1 => Some(Self::StackMapIndex),
            2 => Some(Self::InlTreeIndex),
            3 => Some(Self::ArgLiveIndex),
            _ => None,
        }
    }
}

impl TryFrom<u8> for GoPcDataTable {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_index(value).ok_or(value)
    }
}

#[cfg(test)]
mod tests {
    use super::GoPcDataTable;

    #[test]
    fn discriminants_match_indices() {
        let cases = [
            (GoPcDataTable::UnsafePoint, 0u8),
            (GoPcDataTable::StackMapIndex, 1),
            (GoPcDataTable::InlTreeIndex, 2),
            (GoPcDataTable::ArgLiveIndex, 3),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.index(), expected);
        }
    }

    #[test]
    fn round_trip_from_index() {
        for i in 0u8..4 {
            let variant = GoPcDataTable::from_index(i).expect("valid index");
            assert_eq!(variant.index(), i);
        }
    }

    #[test]
    fn out_of_range_returns_none() {
        assert!(GoPcDataTable::from_index(4).is_none());
        assert!(GoPcDataTable::from_index(255).is_none());
    }

    #[test]
    fn try_from_valid() {
        assert_eq!(GoPcDataTable::try_from(0u8), Ok(GoPcDataTable::UnsafePoint));
        assert_eq!(GoPcDataTable::try_from(3u8), Ok(GoPcDataTable::ArgLiveIndex));
    }

    #[test]
    fn try_from_invalid_returns_err() {
        assert_eq!(GoPcDataTable::try_from(4u8), Err(4));
    }

    #[test]
    fn total_variant_count() {
        assert_eq!((0u8..4).filter_map(GoPcDataTable::from_index).count(), 4);
    }
}
