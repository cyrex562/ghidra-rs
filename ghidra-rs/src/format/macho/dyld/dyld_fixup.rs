/// Stores information needed to perform a dyld pointer fixup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldFixup {
    /// Offset of where to perform the fixup (from some base address/index).
    pub offset: i64,
    /// The fixed-up value, or `None` if this fixup is unsupported.
    pub value: Option<i64>,
    /// Size of the fixup in bytes.
    pub size: i32,
    /// Symbol associated with the fixup, if any.
    pub symbol: Option<String>,
    /// Library ordinal associated with the fixup, if any.
    pub lib_ordinal: Option<i32>,
}

impl DyldFixup {
    /// Creates a new `DyldFixup`.
    pub fn new(
        offset: i64,
        value: Option<i64>,
        size: i32,
        symbol: Option<String>,
        lib_ordinal: Option<i32>,
    ) -> Self {
        Self { offset, value, size, symbol, lib_ordinal }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_construction() {
        let fixup = DyldFixup::new(0x100, Some(0xDEAD_BEEF), 8, None, None);
        assert_eq!(fixup.offset, 0x100);
        assert_eq!(fixup.value, Some(0xDEAD_BEEF));
        assert_eq!(fixup.size, 8);
        assert!(fixup.symbol.is_none());
        assert!(fixup.lib_ordinal.is_none());
    }

    #[test]
    fn test_unsupported_fixup_value_is_none() {
        let fixup = DyldFixup::new(0x200, None, 4, Some("_foo".to_string()), Some(1));
        assert!(fixup.value.is_none());
        assert_eq!(fixup.symbol.as_deref(), Some("_foo"));
        assert_eq!(fixup.lib_ordinal, Some(1));
    }

    #[test]
    fn test_zero_offset() {
        let fixup = DyldFixup::new(0, Some(0), 4, None, None);
        assert_eq!(fixup.offset, 0);
        assert_eq!(fixup.value, Some(0));
    }

    #[test]
    fn test_all_fields() {
        let fixup = DyldFixup::new(
            0x1000,
            Some(0x4000),
            8,
            Some("_dyld_stub_binder".to_string()),
            Some(2),
        );
        assert_eq!(fixup.offset, 0x1000);
        assert_eq!(fixup.value, Some(0x4000));
        assert_eq!(fixup.size, 8);
        assert_eq!(fixup.symbol.as_deref(), Some("_dyld_stub_binder"));
        assert_eq!(fixup.lib_ordinal, Some(2));
    }

    #[test]
    fn test_clone_and_eq() {
        let a = DyldFixup::new(0x10, Some(0x20), 4, Some("sym".to_string()), Some(3));
        let b = a.clone();
        assert_eq!(a, b);
    }
}
