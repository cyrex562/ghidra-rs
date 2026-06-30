/// Controls how bit-fields are packed and aligned within composite data types.
///
/// Implementations describe the ABI rules for bit-field layout — specifically
/// whether MSVC or GNU conventions are in effect and how zero-length bit-fields
/// influence alignment.
pub trait BitFieldPacking {
    /// Returns `true` if MSVC packing conventions are used.
    ///
    /// When enabled this takes precedence over all other bit-field packing controls.
    /// When `false`, GNU conventions apply instead.
    fn use_ms_convention(&self) -> bool;

    /// Returns `true` when the alignment of the bit-field type affects the layout
    /// of the containing structure.
    ///
    /// Corresponds to `PCC_BITFIELD_TYPE_MATTERS` in GCC.  When enabled the
    /// alignment of the field's base type is used to ensure individual bit-fields
    /// do not straddle an alignment boundary.
    fn is_type_alignment_enabled(&self) -> bool;

    /// Returns the fixed alignment size in bytes for a bit-field that follows a
    /// zero-length bit-field, or `0` if no such boundary is imposed.
    ///
    /// A non-zero value overrides the base-type alignment when the field exceeds
    /// that normal alignment.  Corresponds to `EMPTY_FIELD_BOUNDARY` in GCC.
    /// This value is only consulted when [`is_type_alignment_enabled`] returns
    /// `false`.
    ///
    /// [`is_type_alignment_enabled`]: BitFieldPacking::is_type_alignment_enabled
    fn get_zero_length_boundary(&self) -> i32;

    /// Returns `true` if `other` has the same packing settings as `self`.
    fn is_equivalent(&self, other: &dyn BitFieldPacking) -> bool {
        self.is_type_alignment_enabled() == other.is_type_alignment_enabled()
            && self.use_ms_convention() == other.use_ms_convention()
            && self.get_zero_length_boundary() == other.get_zero_length_boundary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Packing {
        ms: bool,
        type_align: bool,
        zero_boundary: i32,
    }

    impl BitFieldPacking for Packing {
        fn use_ms_convention(&self) -> bool {
            self.ms
        }

        fn is_type_alignment_enabled(&self) -> bool {
            self.type_align
        }

        fn get_zero_length_boundary(&self) -> i32 {
            self.zero_boundary
        }
    }

    fn gnu() -> Packing {
        Packing { ms: false, type_align: true, zero_boundary: 0 }
    }

    fn msvc() -> Packing {
        Packing { ms: true, type_align: false, zero_boundary: 4 }
    }

    #[test]
    fn is_equivalent_same_settings() {
        let a = gnu();
        let b = Packing { ms: false, type_align: true, zero_boundary: 0 };
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_reflexive() {
        let a = msvc();
        assert!(a.is_equivalent(&msvc()));
    }

    #[test]
    fn is_equivalent_ms_convention_differs() {
        let a = gnu();
        let b = msvc();
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_type_alignment_differs() {
        let a = Packing { ms: false, type_align: true, zero_boundary: 0 };
        let b = Packing { ms: false, type_align: false, zero_boundary: 0 };
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn is_equivalent_zero_boundary_differs() {
        let a = Packing { ms: false, type_align: false, zero_boundary: 0 };
        let b = Packing { ms: false, type_align: false, zero_boundary: 8 };
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn get_zero_length_boundary_value() {
        assert_eq!(msvc().get_zero_length_boundary(), 4);
        assert_eq!(gnu().get_zero_length_boundary(), 0);
    }

    #[test]
    fn use_ms_convention_value() {
        assert!(msvc().use_ms_convention());
        assert!(!gnu().use_ms_convention());
    }

    #[test]
    fn is_type_alignment_enabled_value() {
        assert!(gnu().is_type_alignment_enabled());
        assert!(!msvc().is_type_alignment_enabled());
    }
}
