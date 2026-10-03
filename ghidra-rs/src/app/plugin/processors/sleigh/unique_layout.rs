//! Port of `ghidra.app.plugin.processors.sleigh.UniqueLayout`.
//!
//! Offsets for various ranges in the p-code "unique" address space. Offsets are either:
//!  1. relative to the last temporary allocated statically by the SLEIGH compiler or a
//!     particular language's `.sla` file, or
//!  2. absolute within the unique address space.
//!
//! So the layout of the unique address space looks like:
//!  1. SLEIGH static temporaries
//!  2. Runtime temporaries used by the SLEIGH p-code generator
//!  3. Temporaries used by the `PcodeInjectLibrary` for p-code snippets
//!  4. Temporaries generated during (decompiler) analysis
//!
//! The "unique" space is set to 32 bits across all architectures; the maximum offset is
//! `0xFFFFFFFF`. The offsets and names should match the parallel decompiler enum in
//! `translate.hh`.
//!
//! `ghidra.app.plugin.processors.sleigh.SleighLanguage` is a large, engine-central class whose
//! Rust port lives at [`crate::program::model::lang::sleigh::SleighLanguage`] rather than under
//! this `app::plugin::processors::sleigh` path (an existing, established relocation -- see e.g.
//! `sleigh_parser_context.rs`, which already reaches into that module for `FixedHandle`); this
//! port of `UniqueLayout::getOffset` refers to that same canonical type.

use crate::program::model::lang::sleigh::SleighLanguage;

/// See the module docs. Port of `ghidra.app.plugin.processors.sleigh.UniqueLayout`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UniqueLayout {
    /// First offset after SLEIGH static temporaries. Port of `SLEIGH_BASE(0, true)`.
    SleighBase,
    /// Port of `RUNTIME_BOOLEAN_INVERT(0, true)`.
    RuntimeBooleanInvert,
    /// Port of `RUNTIME_RETURN_LOCATION(0x80, true)`.
    RuntimeReturnLocation,
    /// Port of `RUNTIME_BITRANGE_EA(0x100, true)`.
    RuntimeBitrangeEa,
    /// Port of `INJECT(0x200, true)`.
    Inject,
    /// Port of `ANALYSIS(0x10000000, false)`.
    Analysis,
}

impl UniqueLayout {
    /// The raw offset baked into the Java enum constant (its first constructor argument).
    fn raw_offset(self) -> u64 {
        match self {
            // SLEIGH_BASE and RUNTIME_BOOLEAN_INVERT are both `0` in the Java source -- this is
            // not a typo on our part, the two constants really do share the same raw offset.
            UniqueLayout::SleighBase => 0,
            UniqueLayout::RuntimeBooleanInvert => 0,
            UniqueLayout::RuntimeReturnLocation => 0x80,
            UniqueLayout::RuntimeBitrangeEa => 0x100,
            UniqueLayout::Inject => 0x200,
            UniqueLayout::Analysis => 0x1000_0000,
        }
    }

    /// Whether [`Self::raw_offset`] is relative to the end of SLEIGH statics (the Java enum
    /// constant's second constructor argument, `isRelative`). Only `ANALYSIS` is absolute.
    fn is_relative(self) -> bool {
        !matches!(self, UniqueLayout::Analysis)
    }

    /// Get the starting offset of a named range in the unique address space. The returned offset
    /// is absolute and specific to the given SLEIGH language. Port of
    /// `UniqueLayout.getOffset(SleighLanguage)`.
    ///
    /// Java's parameter is `@Nullable`; when `language` is `null` (here, `None`) a relative
    /// offset is returned unresolved, i.e. as the raw SLEIGH-static-relative value, exactly as
    /// Java's `(isRelative && language != null) ? ... : offset` does.
    pub fn get_offset(self, language: Option<&SleighLanguage>) -> u64 {
        match language {
            Some(language) if self.is_relative() => {
                language.get_unique_base().wrapping_add(self.raw_offset())
            }
            _ => self.raw_offset(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_offsets_match_java_constants() {
        assert_eq!(UniqueLayout::SleighBase.raw_offset(), 0);
        assert_eq!(UniqueLayout::RuntimeBooleanInvert.raw_offset(), 0);
        assert_eq!(UniqueLayout::RuntimeReturnLocation.raw_offset(), 0x80);
        assert_eq!(UniqueLayout::RuntimeBitrangeEa.raw_offset(), 0x100);
        assert_eq!(UniqueLayout::Inject.raw_offset(), 0x200);
        assert_eq!(UniqueLayout::Analysis.raw_offset(), 0x1000_0000);
    }

    #[test]
    fn only_analysis_is_absolute() {
        assert!(UniqueLayout::SleighBase.is_relative());
        assert!(UniqueLayout::RuntimeBooleanInvert.is_relative());
        assert!(UniqueLayout::RuntimeReturnLocation.is_relative());
        assert!(UniqueLayout::RuntimeBitrangeEa.is_relative());
        assert!(UniqueLayout::Inject.is_relative());
        assert!(!UniqueLayout::Analysis.is_relative());
    }

    #[test]
    fn get_offset_without_language_returns_raw_offset_even_when_relative() {
        // Mirrors Java: `(isRelative && language != null) ? ... : offset` -- a null language
        // short-circuits straight to the raw offset regardless of isRelative.
        assert_eq!(UniqueLayout::RuntimeReturnLocation.get_offset(None), 0x80);
        assert_eq!(UniqueLayout::Inject.get_offset(None), 0x200);
        assert_eq!(UniqueLayout::Analysis.get_offset(None), 0x1000_0000);
    }

    #[test]
    fn sleigh_base_and_runtime_boolean_invert_share_raw_offset_but_are_distinct_variants() {
        assert_eq!(
            UniqueLayout::SleighBase.raw_offset(),
            UniqueLayout::RuntimeBooleanInvert.raw_offset()
        );
        assert_ne!(UniqueLayout::SleighBase, UniqueLayout::RuntimeBooleanInvert);
    }

    /// Builds a minimal, real [`SleighLanguage`] by round-tripping a hand-built `.sla`-style
    /// packed document through the crate's own [`PackedEncode`]/[`PackedDecode`] -- the same
    /// technique `program::model::lang::sleigh::mod`'s own `test_sleigh_decode_basic` uses --
    /// so `get_offset`'s `Some(language)` branch is exercised against a genuine `SleighLanguage`
    /// rather than a hand-rolled mock, with a real, chosen `uniqbase`.
    fn build_test_language(unique_base: u64) -> SleighLanguage {
        use crate::program::model::address::DefaultAddressFactory;
        use crate::program::model::pcode::{
            Encoder, PackedDecode, PackedEncode, ATTRIB_BIGENDIAN, ATTRIB_DEFAULTSPACE,
            ATTRIB_DELAY, ATTRIB_ID, ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_PARENT, ATTRIB_SCOPESIZE,
            ATTRIB_SIZE, ATTRIB_SYMBOLSIZE, ATTRIB_UNIQBASE, ATTRIB_VERSION, ELEM_SCOPE,
            ELEM_SLEIGH, ELEM_SPACE, ELEM_SPACES, ELEM_SPACE_OTHER, ELEM_SYMBOL_TABLE,
        };
        use std::sync::Arc;

        let mut enc = PackedEncode::new(Vec::new());

        enc.open_element(ELEM_SLEIGH).unwrap();
        enc.write_signed_integer(ATTRIB_VERSION, 4).unwrap();
        enc.write_bool(ATTRIB_BIGENDIAN, false).unwrap();
        enc.write_unsigned_integer(ATTRIB_UNIQBASE, unique_base)
            .unwrap();

        enc.open_element(ELEM_SPACES).unwrap();
        enc.write_string(ATTRIB_DEFAULTSPACE, "ram").unwrap();

        enc.open_element(ELEM_SPACE_OTHER).unwrap();
        enc.close_element(ELEM_SPACE_OTHER).unwrap();

        enc.open_element(ELEM_SPACE).unwrap();
        enc.write_string(ATTRIB_NAME, "ram").unwrap();
        enc.write_signed_integer(ATTRIB_SIZE, 4).unwrap();
        enc.write_signed_integer(ATTRIB_INDEX, 1).unwrap();
        enc.write_signed_integer(ATTRIB_DELAY, 1).unwrap();
        enc.close_element(ELEM_SPACE).unwrap();

        enc.close_element(ELEM_SPACES).unwrap();

        enc.open_element(ELEM_SYMBOL_TABLE).unwrap();
        enc.write_signed_integer(ATTRIB_SCOPESIZE, 1).unwrap();
        enc.write_signed_integer(ATTRIB_SYMBOLSIZE, 0).unwrap();

        enc.open_element(ELEM_SCOPE).unwrap();
        enc.write_unsigned_integer(ATTRIB_ID, 0).unwrap();
        enc.write_unsigned_integer(ATTRIB_PARENT, 0).unwrap();
        enc.close_element(ELEM_SCOPE).unwrap();

        enc.close_element(ELEM_SYMBOL_TABLE).unwrap();

        enc.close_element(ELEM_SLEIGH).unwrap();

        let data = enc.into_inner();
        let factory = Arc::new(DefaultAddressFactory::new(vec![]));
        let decoder = PackedDecode::new(factory, data);
        SleighLanguage::decode(&decoder, "test-language".to_string())
            .expect("hand-built minimal .sla document should decode")
    }

    #[test]
    fn get_offset_with_language_adds_unique_base_for_relative_variants() {
        let language = build_test_language(0x4000);
        assert_eq!(language.get_unique_base(), 0x4000);

        assert_eq!(UniqueLayout::SleighBase.get_offset(Some(&language)), 0x4000);
        assert_eq!(
            UniqueLayout::RuntimeReturnLocation.get_offset(Some(&language)),
            0x4000 + 0x80
        );
        assert_eq!(
            UniqueLayout::Inject.get_offset(Some(&language)),
            0x4000 + 0x200
        );
    }

    #[test]
    fn get_offset_with_language_ignores_unique_base_for_analysis() {
        let language = build_test_language(0x4000);
        // ANALYSIS is absolute (isRelative = false), so unique_base must not be added.
        assert_eq!(
            UniqueLayout::Analysis.get_offset(Some(&language)),
            0x1000_0000
        );
    }

    #[test]
    fn get_offset_with_zero_unique_base_matches_no_language_case() {
        let language = build_test_language(0);
        assert_eq!(
            UniqueLayout::RuntimeBitrangeEa.get_offset(Some(&language)),
            UniqueLayout::RuntimeBitrangeEa.get_offset(None)
        );
    }
}
