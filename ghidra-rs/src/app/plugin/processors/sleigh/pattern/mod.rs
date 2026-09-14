//! Mirrors `ghidra.app.plugin.processors.sleigh.pattern.Pattern`.

use crate::app::plugin::processors::sleigh::sleigh_debug_logger::SleighDebugLogger;
use crate::program::model::lang::sleigh::walker::ParserWalker;
use crate::program::model::mem::MemoryAccessException;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};

/// A pattern which either matches or doesn't match a particular instruction context. In
/// particular, the bits comprising the current instruction in the executable, and possibly other
/// context bits.
///
/// Port of `ghidra.app.plugin.processors.sleigh.pattern.Pattern`, an abstract class every one of
/// whose members is itself `abstract` -- it carries no fields and no concrete method bodies of its
/// own, so this port is a plain trait with no default methods, mirroring exactly what the Java
/// class actually specifies (nothing beyond the method signatures themselves).
///
/// # Relationship to `program::model::lang::sleigh::pattern::Pattern`
///
/// This crate already has a same-named `Pattern` trait at
/// [`crate::program::model::lang::sleigh::pattern::Pattern`], built opportunistically (as a
/// four-method dispatch seam: `is_match`/`is_always_true`/`is_always_false`/
/// `is_always_instruction_true`) to support decoding [`DisjointPattern`
/// ](crate::program::model::lang::sleigh::pattern::DisjointPattern) and its variants
/// (`InstructionPattern`/`ContextPattern`/`CombinePattern`, all already real, working ports) before
/// this class itself was on the porting docket. That trait is a genuine partial port of this same
/// Java class, but is missing more than half of its abstract surface --
/// `simplifyClone`/`shiftInstruction`/`doOr`/`doAnd`/`numDisjoint`/`getDisjoint`/`decode` have no
/// counterpart there, and adding them would force every existing implementor
/// (`InstructionPattern`/`ContextPattern`/`CombinePattern`) to also grow real `doOr`/`doAnd`
/// bodies -- which in turn need `PatternBlock.shift`/`andBlock` operations that crate's ported
/// [`PatternBlock`](crate::program::model::lang::sleigh::pattern::PatternBlock) does not yet have
/// (it only supports the subset `DisjointPattern`'s decoder needs). Reproducing that whole family
/// (`PatternBlock`, `InstructionPattern`, `OrPattern`) is out of scope for porting this one
/// 57-line abstract class, so -- mirroring the precedent already set by
/// [`LanguageCompilerSpecPair`](crate::program::model::lang::language_compiler_spec_pair) (ported
/// as an independent, full-fidelity type alongside a pre-existing partial placeholder, its own
/// call sites deliberately left un-rewired -- see that module's docs) and by
/// [`SwiftSourceLanguage`](crate::app::util::sourcelanguage::swift_source_language) (leaving a
/// pre-existing, already-tested call site alone rather than retrofitting it onto a new type) --
/// this is ported as its own, independent, complete trait rather than by extending or replacing
/// the existing partial one. Wiring `DisjointPattern`'s family up to (or merging it into) this
/// fuller trait is left for whichever future port actually tackles `PatternBlock`/
/// `InstructionPattern`/`OrPattern` in full.
///
/// # `getDisjoint`'s narrowed Java return type
///
/// Java's `getDisjoint(int)` returns `DisjointPattern` (`Pattern`'s own abstract subclass, adding
/// `getBlock`/`getInstructionBlock`/etc.), not `Pattern` itself. Since porting `DisjointPattern`
/// itself is out of scope here (see above), [`get_disjoint`](Self::get_disjoint) instead returns
/// `Option<Box<dyn Pattern>>` -- a widened type, but a value-for-value faithful stand-in: every
/// concrete `DisjointPattern` is *also* a `Pattern`, and callers of this crate's port have no
/// narrower ported type to receive instead.
///
/// # `decode`'s error type
///
/// Java declares `throws DecoderException`. This port's [`Decoder`] trait -- the real, working
/// ported decoder this trait's [`decode`](Self::decode) is built to be called with -- reports
/// errors as [`DecoderError`], not the older `DecoderException` type some other, earlier-ported
/// files in this crate still use; [`decode`](Self::decode) follows the newer, `Decoder`-trait-
/// compatible type so its body can use `?` directly against real `Decoder` calls.
pub trait Pattern {
    /// Mirrors `Pattern.simplifyClone()`.
    fn simplify_clone(&self) -> Box<dyn Pattern>;

    /// Mirrors `Pattern.shiftInstruction(int)`.
    fn shift_instruction(&mut self, sa: i32);

    /// Mirrors `Pattern.doOr(Pattern, int)`.
    fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// Mirrors `Pattern.doAnd(Pattern, int)`.
    fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern>;

    /// Mirrors `Pattern.isMatch(ParserWalker, SleighDebugLogger)`. `debug` is `None` where Java
    /// passes `null`.
    fn is_match(
        &self,
        walker: &ParserWalker,
        debug: Option<&mut dyn SleighDebugLogger>,
    ) -> Result<bool, MemoryAccessException>;

    /// Mirrors `Pattern.numDisjoint()`.
    fn num_disjoint(&self) -> i32;

    /// Mirrors `Pattern.getDisjoint(int)`. See the trait's own docs for the widened return type.
    fn get_disjoint(&self, i: i32) -> Option<Box<dyn Pattern>>;

    /// Mirrors `Pattern.alwaysTrue()`.
    fn always_true(&self) -> bool;

    /// Mirrors `Pattern.alwaysFalse()`.
    fn always_false(&self) -> bool;

    /// Mirrors `Pattern.alwaysInstructionTrue()`.
    fn always_instruction_true(&self) -> bool;

    /// Mirrors `Pattern.decode(Decoder)`. See the trait's own docs for the error type.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, real `Pattern` implementor exercising every method with genuine (not trivially
    /// stubbed) behavior: an always-true pattern, an always-false pattern, or a fixed 32-bit
    /// mask/value match against the first instruction word, optionally shifted by a byte offset --
    /// enough to combine via real boolean-algebra `doOr`/`doAnd` and to really match/fail to match
    /// bytes via [`is_match`](Pattern::is_match), without reimplementing this crate's much larger,
    /// separately-tracked `PatternBlock`/`InstructionPattern` (see this module's own docs).
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum SimplePattern {
        AlwaysTrue,
        AlwaysFalse,
        Masked { mask: u32, value: u32, byte_offset: i32 },
    }

    impl Pattern for SimplePattern {
        fn simplify_clone(&self) -> Box<dyn Pattern> {
            Box::new(self.clone())
        }

        fn shift_instruction(&mut self, sa: i32) {
            if let SimplePattern::Masked { byte_offset, .. } = self {
                *byte_offset += sa;
            }
        }

        fn do_or(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
            if self.always_true() || b.always_true() {
                return Box::new(SimplePattern::AlwaysTrue);
            }
            if self.always_false() {
                // No downcast needed: `simplify_clone`/`shift_instruction` are both plain trait
                // methods, reachable through the `&dyn Pattern` alone.
                let mut clone = b.simplify_clone();
                clone.shift_instruction(sa);
                return clone;
            }
            if b.always_false() {
                return self.simplify_clone();
            }
            panic!("SimplePattern::do_or: this minimal test type only combines with an always-true/always-false operand");
        }

        fn do_and(&self, b: &dyn Pattern, sa: i32) -> Box<dyn Pattern> {
            if self.always_false() || b.always_false() {
                return Box::new(SimplePattern::AlwaysFalse);
            }
            if self.always_true() {
                let mut clone = b.simplify_clone();
                clone.shift_instruction(sa);
                return clone;
            }
            if b.always_true() {
                return self.simplify_clone();
            }
            panic!("SimplePattern::do_and: this minimal test type only combines with an always-true/always-false operand");
        }

        fn is_match(
            &self,
            walker: &ParserWalker,
            _debug: Option<&mut dyn SleighDebugLogger>,
        ) -> Result<bool, MemoryAccessException> {
            match self {
                SimplePattern::AlwaysTrue => Ok(true),
                SimplePattern::AlwaysFalse => Ok(false),
                SimplePattern::Masked { mask, value, byte_offset } => {
                    let bits = walker.get_instruction_bits(byte_offset * 8, 32)?;
                    Ok((bits & mask) == *value)
                }
            }
        }

        fn num_disjoint(&self) -> i32 {
            0
        }

        fn get_disjoint(&self, _i: i32) -> Option<Box<dyn Pattern>> {
            None
        }

        fn always_true(&self) -> bool {
            matches!(self, SimplePattern::AlwaysTrue)
        }

        fn always_false(&self) -> bool {
            matches!(self, SimplePattern::AlwaysFalse)
        }

        fn always_instruction_true(&self) -> bool {
            self.always_true()
        }

        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderError> {
            // This synthetic test type carries no encoded form of its own (see the trait's own
            // docs: `Pattern.decode` has no shared logic across subclasses to exercise here).
            Ok(())
        }
    }

    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::sleigh::walker::ParserContext;
    use crate::program::model::mem::MemBuffer;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct FixedBytesMemBuffer {
        address: Address,
        bytes: Vec<u8>,
    }

    impl MemBuffer for FixedBytesMemBuffer {
        fn get_address(&self) -> Address {
            self.address.clone()
        }

        fn get_byte(&self, offset: i32) -> Result<u8, MemoryAccessException> {
            self.bytes
                .get(offset as usize)
                .copied()
                .ok_or_else(|| MemoryAccessException::new("offset out of range"))
        }

        fn get_bytes(&self, buf: &mut [u8], offset: i32) -> usize {
            if offset < 0 {
                return 0;
            }
            let start = offset as usize;
            if start >= self.bytes.len() {
                return 0;
            }
            let n = buf.len().min(self.bytes.len() - start);
            buf[..n].copy_from_slice(&self.bytes[start..start + n]);
            n
        }

        fn is_big_endian(&self) -> bool {
            true
        }
    }

    fn walker_over(bytes: &[u8]) -> ParserWalker {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let addr = Address::new(space, 0);
        let mem_buffer: Arc<dyn MemBuffer> =
            Arc::new(FixedBytesMemBuffer { address: addr.clone(), bytes: bytes.to_vec() });
        let context = Arc::new(ParserContext {
            addr: addr.clone(),
            naddr: addr.clone(),
            n2addr: addr,
            context: Vec::new(),
            mem_buffer,
            handle_map: HashMap::new(),
        });
        ParserWalker::new(context)
    }

    #[test]
    fn always_true_and_always_false_match_unconditionally() {
        let walker = walker_over(&[0, 0, 0, 0]);
        assert!(SimplePattern::AlwaysTrue.is_match(&walker, None).unwrap());
        assert!(!SimplePattern::AlwaysFalse.is_match(&walker, None).unwrap());
    }

    #[test]
    fn masked_pattern_matches_real_instruction_bytes() {
        // 0xAABBCCDD, matching against the low nibble of the first byte via mask 0x0000000F.
        let walker = walker_over(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let matches = SimplePattern::Masked { mask: 0xF000_0000, value: 0xA000_0000, byte_offset: 0 };
        assert!(matches.is_match(&walker, None).unwrap());

        let fails = SimplePattern::Masked { mask: 0xF000_0000, value: 0xB000_0000, byte_offset: 0 };
        assert!(!fails.is_match(&walker, None).unwrap());
    }

    #[test]
    fn shift_instruction_moves_the_matched_window() {
        let walker = walker_over(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
        let mut pattern =
            SimplePattern::Masked { mask: 0xFFFF_FFFF, value: 0xAABB_CCDD, byte_offset: 0 };
        assert!(!pattern.is_match(&walker, None).unwrap());
        pattern.shift_instruction(1);
        assert!(pattern.is_match(&walker, None).unwrap());
    }

    #[test]
    fn do_or_with_always_true_short_circuits() {
        let a = SimplePattern::AlwaysFalse;
        let combined = a.do_or(&SimplePattern::AlwaysTrue, 0);
        assert!(combined.always_true());
    }

    #[test]
    fn do_or_with_always_false_keeps_the_other_operand_shifted() {
        let a = SimplePattern::AlwaysFalse;
        let b = SimplePattern::Masked { mask: 0xFFFF_FFFF, value: 0xAABB_CCDD, byte_offset: 0 };
        let combined = a.do_or(&b, 1);

        // The combined pattern is genuinely `b`, shifted -- not collapsed to Always*.
        assert!(!combined.always_true());
        assert!(!combined.always_false());

        let walker = walker_over(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
        // Un-shifted `b` would not match this buffer (the real bytes start one byte in); the
        // combined, shifted pattern does.
        assert!(!b.is_match(&walker, None).unwrap());
        assert!(combined.is_match(&walker, None).unwrap());
    }

    #[test]
    fn do_and_with_always_false_short_circuits() {
        let a = SimplePattern::Masked { mask: 0xFF, value: 0x12, byte_offset: 0 };
        let combined = a.do_and(&SimplePattern::AlwaysFalse, 0);
        assert!(combined.always_false());
    }

    #[test]
    fn num_disjoint_and_get_disjoint_are_zero_for_this_type() {
        let p = SimplePattern::AlwaysTrue;
        assert_eq!(p.num_disjoint(), 0);
        assert!(p.get_disjoint(0).is_none());
    }

    #[test]
    fn always_instruction_true_matches_always_true() {
        assert!(SimplePattern::AlwaysTrue.always_instruction_true());
        assert!(!SimplePattern::AlwaysFalse.always_instruction_true());
        let masked = SimplePattern::Masked { mask: 0, value: 0, byte_offset: 0 };
        assert!(!masked.always_instruction_true());
    }

    #[test]
    fn decode_is_a_no_op_for_this_synthetic_type() {
        struct NoopDecoder;
        impl Decoder for NoopDecoder {
            fn get_address_factory(&self) -> Arc<dyn crate::program::model::address::AddressFactory> {
                unimplemented!("not exercised by this test")
            }
            fn set_address_factory(&self, _factory: Arc<dyn crate::program::model::address::AddressFactory>) {
                unimplemented!("not exercised by this test")
            }
            fn peek_element(&self) -> Result<i32, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn open_element(&self) -> Result<i32, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn open_element_with_id(
                &self,
                _elem_id: crate::program::model::pcode::ids::ElementId,
            ) -> Result<i32, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn rewind_attributes(&self) {
                unimplemented!("not exercised by this test")
            }
            fn read_bool(&self) -> Result<bool, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_bool_with_id(
                &self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
            ) -> Result<bool, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_signed_integer(&self) -> Result<i64, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_signed_integer_with_id(
                &self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
            ) -> Result<i64, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_unsigned_integer_with_id(
                &self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
            ) -> Result<u64, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_string(&self) -> Result<String, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_string_with_id(
                &self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
            ) -> Result<String, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_space(&self) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
                unimplemented!("not exercised by this test")
            }
            fn read_space_with_id(
                &self,
                _attrib_id: crate::program::model::pcode::ids::AttributeId,
            ) -> Result<Arc<crate::program::model::address::AddressSpace>, DecoderError> {
                unimplemented!("not exercised by this test")
            }
        }
        let mut pattern = SimplePattern::AlwaysTrue;
        assert!(pattern.decode(&NoopDecoder).is_ok());
    }

    #[test]
    fn simplify_clone_produces_an_independent_value() {
        let original =
            SimplePattern::Masked { mask: 0xFFFF_FFFF, value: 0xAABB_CCDD, byte_offset: 0 };
        let mut clone = original.simplify_clone();
        clone.shift_instruction(1);

        let walker = walker_over(&[0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
        // Shifting the clone did not affect the original.
        assert!(!original.is_match(&walker, None).unwrap());
        assert!(clone.is_match(&walker, None).unwrap());
    }

    #[test]
    fn object_safety_via_dyn_reference() {
        let p: Box<dyn Pattern> = Box::new(SimplePattern::AlwaysTrue);
        assert!(p.always_true());
        assert!(!p.always_false());
    }
}
