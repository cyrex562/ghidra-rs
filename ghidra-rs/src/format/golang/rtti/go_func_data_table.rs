/// Index into a `GoFuncData`'s variable-size funcdata array.
///
/// The discriminant matches the integer index used at runtime.
/// Mirrors Ghidra's `GoFuncDataTable` Java enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum GoFuncDataTable {
    ArgsPointerMaps = 0,
    LocalsPointerMaps = 1,
    StackObjects = 2,
    InlTree = 3,
    OpenCodedDeferInfo = 4,
    ArgInfo = 5,
    ArgLiveInfo = 6,
    WrapInfo = 7,
}

impl GoFuncDataTable {
    /// Returns the integer index for this funcdata entry.
    pub fn index(self) -> u8 {
        self as u8
    }

    /// Constructs a variant from its integer index, or `None` if out of range.
    pub fn from_index(index: u8) -> Option<Self> {
        match index {
            0 => Some(Self::ArgsPointerMaps),
            1 => Some(Self::LocalsPointerMaps),
            2 => Some(Self::StackObjects),
            3 => Some(Self::InlTree),
            4 => Some(Self::OpenCodedDeferInfo),
            5 => Some(Self::ArgInfo),
            6 => Some(Self::ArgLiveInfo),
            7 => Some(Self::WrapInfo),
            _ => None,
        }
    }
}

impl TryFrom<u8> for GoFuncDataTable {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_index(value).ok_or(value)
    }
}

#[cfg(test)]
mod tests {
    use super::GoFuncDataTable;

    #[test]
    fn discriminants_match_indices() {
        let cases = [
            (GoFuncDataTable::ArgsPointerMaps, 0u8),
            (GoFuncDataTable::LocalsPointerMaps, 1),
            (GoFuncDataTable::StackObjects, 2),
            (GoFuncDataTable::InlTree, 3),
            (GoFuncDataTable::OpenCodedDeferInfo, 4),
            (GoFuncDataTable::ArgInfo, 5),
            (GoFuncDataTable::ArgLiveInfo, 6),
            (GoFuncDataTable::WrapInfo, 7),
        ];
        for (variant, expected) in cases {
            assert_eq!(variant.index(), expected);
        }
    }

    #[test]
    fn round_trip_from_index() {
        for i in 0u8..8 {
            let variant = GoFuncDataTable::from_index(i).expect("valid index");
            assert_eq!(variant.index(), i);
        }
    }

    #[test]
    fn out_of_range_returns_none() {
        assert!(GoFuncDataTable::from_index(8).is_none());
        assert!(GoFuncDataTable::from_index(255).is_none());
    }

    #[test]
    fn try_from_valid() {
        assert_eq!(GoFuncDataTable::try_from(0u8), Ok(GoFuncDataTable::ArgsPointerMaps));
        assert_eq!(GoFuncDataTable::try_from(7u8), Ok(GoFuncDataTable::WrapInfo));
    }

    #[test]
    fn try_from_invalid_returns_err() {
        assert_eq!(GoFuncDataTable::try_from(8u8), Err(8));
    }

    #[test]
    fn total_variant_count() {
        // Exactly 8 variants (indices 0–7).
        assert_eq!((0u8..8).filter_map(GoFuncDataTable::from_index).count(), 8);
    }
}
