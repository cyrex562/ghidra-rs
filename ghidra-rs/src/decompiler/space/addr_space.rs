//! Models `ghidra.pcodeCPort.space.AddrSpace`.

use super::spacetype::SpaceType;
use crate::decompiler::translate::Translate;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_BIGENDIAN, ATTRIB_DELAY, ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_PHYSICAL, ATTRIB_SIZE,
    ATTRIB_WORDSIZE, ELEM_SPACE,
};
use std::io;

/// Space is big endian if set, little endian otherwise.
pub const BIG_ENDIAN: i32 = 1;
/// This space is heritaged.
pub const HERITAGED: i32 = 2;
/// Dead-code analysis is done on this space.
pub const DOES_DEADCODE: i32 = 4;
/// Space is specific to a particular loadimage.
pub const PROGRAMSPECIFIC: i32 = 8;
/// Justification within aligned word is opposite of endianness.
pub const REVERSE_JUSTIFICATION: i32 = 16;
/// This space is an overlay of another space.
pub const OVERLAY: i32 = 32;
/// This is the base space for overlay space(s).
pub const OVERLAYBASE: i32 = 64;
/// Space is truncated from its original size, expect pointers larger than this size.
pub const TRUNCATED: i32 = 128;
/// Has physical memory associated with it.
pub const HASPHYSICAL: i32 = 256;
/// Quick check for `OtherSpace`.
pub const IS_OTHERSPACE: i32 = 512;

/// A region where processor data is stored.
///
/// An address space is an arbitrary sequence of bytes where a processor can store data. An
/// integer offset paired with an `AddrSpace` forms the address of a byte. The mask, scale, and
/// shortcut character are computed once from an implementor's word size / address size / backing
/// [`Translate`] at construction time (`calcScaleMask` in Java); that construction-time behavior
/// has no equivalent as a trait method, so those values are exposed here as plain accessors,
/// mirroring how [`super::unique_space::UniqueSpace`] already treats construction as an
/// implementor concern.
///
/// Models `ghidra.pcodeCPort.space.AddrSpace`. Promoted from the placeholder stub that only
/// covered [`AddrSpace::encode_basic_attributes`] (needed by
/// [`super::unique_space::UniqueSpace`]); that method is kept below as a real default
/// implementation so existing implementors keep compiling.
///
/// The `*_SPACE`-property flag constants (`BIG_ENDIAN`, `HERITAGED`, ...) live at module scope
/// rather than as associated trait consts, since associated consts make a trait dyn-incompatible
/// and this trait must support `&dyn AddrSpace` (e.g. [`AddrSpace::get_contain`]).
pub trait AddrSpace: Send + Sync {
    /// The name of this space.
    fn name(&self) -> &str;

    /// The translator that owns this space.
    fn get_trans(&self) -> &dyn Translate;

    /// The type of this space.
    fn get_type(&self) -> SpaceType;

    /// The delay in heritaging this space.
    fn get_delay(&self) -> i32;

    /// The unique index of this space.
    fn get_index(&self) -> i32;

    /// The size, in bytes, of the unit being addressed.
    fn get_word_size(&self) -> i32;

    /// Log base 2 of the word size.
    fn get_scale(&self) -> i32;

    /// The size, in bytes, of an address into this space.
    fn get_addr_size(&self) -> i32;

    /// A mask suitable for masking a byte-scaled address.
    fn get_mask(&self) -> i64;

    /// The shortcut character used when printing addresses in this space.
    fn get_short_cut(&self) -> char;

    /// The raw property flags for this space (see the `*_ space property constants above).
    fn flags(&self) -> i32;

    /// The highest offset representable in this space, used by [`AddrSpace::wrap_offset`].
    ///
    /// The Java `highest` field backing this is never assigned anywhere in `AddrSpace`, so it is
    /// always `0` for every space that only goes through this class; the default here preserves
    /// that (apparently unfinished) behavior faithfully rather than guessing at a "fixed" value.
    fn highest(&self) -> i64 {
        0
    }

    /// Whether this space is heritaged.
    fn is_heritaged(&self) -> bool {
        (self.flags() & HERITAGED) != 0
    }

    /// Whether this space has physical memory associated with it.
    fn has_physical(&self) -> bool {
        (self.flags() & HASPHYSICAL) != 0
    }

    /// Whether this space is big endian.
    fn is_big_endian(&self) -> bool {
        (self.flags() & BIG_ENDIAN) != 0
    }

    /// Whether this is (a quick check for) an "other" space.
    fn is_other_space(&self) -> bool {
        (self.flags() & IS_OTHERSPACE) != 0
    }

    /// The space that contains this one, if any. The base implementation always returns `None`;
    /// overlay-style spaces override this to point at their containing space.
    fn get_contain(&self) -> Option<&dyn AddrSpace> {
        None
    }

    /// Whether this space contains `id2`, walking up the [`AddrSpace::get_contain`] chain.
    ///
    /// Java purposely uses reference identity here rather than value equality, since two
    /// otherwise-identically-configured spaces are still distinct spaces.
    fn contain(&self, mut id2: &dyn AddrSpace) -> bool {
        loop {
            if self.is_same_space_as(id2) {
                return true;
            }
            match id2.get_contain() {
                Some(next) => id2 = next,
                None => return false,
            }
        }
    }

    /// Whether `self` and `other` are the very same space (identity, not value, equality).
    ///
    /// Models `AddrSpace.equals`, which purposely compares object identity.
    fn is_same_space_as(&self, other: &dyn AddrSpace) -> bool {
        std::ptr::eq(
            self as *const Self as *const (),
            other as *const dyn AddrSpace as *const (),
        )
    }

    /// Orders spaces by their index.
    fn compare_to(&self, other: &dyn AddrSpace) -> i32 {
        self.get_index() - other.get_index()
    }

    /// Wraps `off` into the range representable by this space.
    ///
    /// Since [`AddrSpace::highest`] is always `0` for this class (see its doc comment), this
    /// currently only ever returns `off` unchanged (`off <= 0`) or `0` (`off > 0`); that mirrors
    /// the Java behavior, which its own author flagged as incomplete.
    fn wrap_offset(&self, off: i64) -> i64 {
        if off <= self.highest() {
            return off;
        }
        let modulus = self.highest() + 1;
        let mut res = off % modulus;
        if res < 0 {
            res += modulus;
        }
        res
    }

    /// Encodes the attributes common to every address space kind (name, index, size, etc.).
    fn encode_basic_attributes(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.write_string(ATTRIB_NAME, self.name())?;
        encoder.write_signed_integer(ATTRIB_INDEX, self.get_index() as i64)?;
        encoder.write_bool(ATTRIB_BIGENDIAN, self.is_big_endian())?;
        encoder.write_signed_integer(ATTRIB_DELAY, self.get_delay() as i64)?;
        encoder.write_signed_integer(ATTRIB_SIZE, self.get_addr_size() as i64)?;
        if self.get_word_size() > 1 {
            encoder.write_signed_integer(ATTRIB_WORDSIZE, self.get_word_size() as i64)?;
        }
        encoder.write_bool(ATTRIB_PHYSICAL, self.has_physical())?;
        Ok(())
    }

    /// Encodes this space (implies `type=processor`).
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_SPACE)?;
        self.encode_basic_attributes(encoder)?;
        encoder.close_element(ELEM_SPACE)?;
        Ok(())
    }

    /// Formats `offset` as a zero-padded hexadecimal value, e.g. `0x00001234`.
    fn print_offset(&self, offset: i64) -> String {
        let pad_length = 2 * self.get_addr_size() as usize;
        let hex = format!("{:x}", offset as u64);
        let mut out = String::from("0x");
        if pad_length > hex.len() {
            out.push_str(&"0".repeat(pad_length - hex.len()));
        }
        out.push_str(&hex);
        out
    }

    /// Debug form for raw dumps: the scaled offset (plus any word-alignment remainder), and the
    /// translator's expected default size.
    fn print_raw(&self, offset: i64) -> (String, i32) {
        let expect_size = self.get_trans().get_default_size();
        let scaled = (offset as u64) >> self.get_scale();
        let mut out = self.print_offset(scaled as i64);
        let word_size = self.get_word_size();
        if word_size > 1 {
            let cut = (offset as i32) & (word_size - 1);
            if cut != 0 {
                out.push('+');
                out.push_str(&cut.to_string());
            }
        }
        (out, expect_size)
    }

    /// A short debug label for this space, e.g. `AddrSpace[ram]`.
    fn to_display_string(&self) -> String {
        format!("AddrSpace[{}]", self.name())
    }

    /// Formats `offset` (scaled, plus any word-alignment remainder) without the `AddrSpace[...]`
    /// wrapper or the `0x` prefix.
    fn offset_to_string(&self, offset: i64) -> String {
        let pad_length = 2 * self.get_addr_size() as usize;
        let hex = format!("{:x}", (offset as u64) >> self.get_scale());
        let mut out = String::new();
        if pad_length > hex.len() {
            out.push_str(&"0".repeat(pad_length - hex.len()));
        }
        out.push_str(&hex);
        let word_size = self.get_word_size();
        if word_size > 1 {
            let cut = (offset as i32) & (word_size - 1);
            if cut != 0 {
                out.push('+');
                out.push_str(&cut.to_string());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTranslate;
    impl crate::decompiler::seam_stubs::BasicSpaceProvider for MockTranslate {
        fn get_default_space(&self) -> &dyn AddrSpace {
            unimplemented!("overridden by get_default_size below")
        }

        fn get_constant_space(&self) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }
    }
    impl Translate for MockTranslate {
        fn is_big_endian(&self) -> bool {
            true
        }

        fn alignment(&self) -> i32 {
            1
        }

        fn get_unique_base(&self) -> i64 {
            0
        }

        fn get_iop_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_fspec_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_stack_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn get_unique_space(&self) -> Option<&dyn AddrSpace> {
            None
        }

        fn num_spaces(&self) -> i32 {
            0
        }

        fn get_space(&self, _i: i32) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
        }

        fn no_high_ptr(&self) -> &dyn crate::decompiler::seam_stubs::RangeList {
            unimplemented!("not exercised by these tests")
        }

        fn instruction_length(&self, _baseaddr: &crate::program::model::address::Address) -> i32 {
            0
        }

        fn print_assembly(
            &self,
            _out: &mut dyn std::io::Write,
            _size: i32,
            _baseaddr: &crate::program::model::address::Address,
        ) -> std::io::Result<i32> {
            Ok(0)
        }

        fn get_default_size(&self) -> i32 {
            4
        }
    }

    struct MockAddrSpace {
        name: String,
        index: i32,
        trans: MockTranslate,
    }

    impl AddrSpace for MockAddrSpace {
        fn name(&self) -> &str {
            &self.name
        }

        fn get_trans(&self) -> &dyn Translate {
            &self.trans
        }

        fn get_type(&self) -> SpaceType {
            SpaceType::IptrProcessor
        }

        fn get_delay(&self) -> i32 {
            0
        }

        fn get_index(&self) -> i32 {
            self.index
        }

        fn get_word_size(&self) -> i32 {
            1
        }

        fn get_scale(&self) -> i32 {
            0
        }

        fn get_addr_size(&self) -> i32 {
            4
        }

        fn get_mask(&self) -> i64 {
            0xffff_ffff
        }

        fn get_short_cut(&self) -> char {
            'r'
        }

        fn flags(&self) -> i32 {
            HERITAGED | HASPHYSICAL | BIG_ENDIAN
        }
    }

    fn mock(name: &str, index: i32) -> MockAddrSpace {
        MockAddrSpace {
            name: name.to_string(),
            index,
            trans: MockTranslate,
        }
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let space = mock("ram", 1);
        let dyn_space: &dyn AddrSpace = &space;
        assert_eq!(dyn_space.name(), "ram");
        assert!(dyn_space.is_big_endian());
        assert!(dyn_space.has_physical());
        assert!(dyn_space.is_heritaged());
        assert!(!dyn_space.is_other_space());
    }

    #[test]
    fn identity_equality_ignores_value_equality() {
        let a = mock("ram", 1);
        let b = mock("ram", 1);
        assert!(a.is_same_space_as(&a));
        assert!(!a.is_same_space_as(&b));
    }

    #[test]
    fn contain_walks_up_the_chain_by_identity() {
        let base = mock("ram", 0);
        assert!(base.contain(&base));
        let other = mock("other", 2);
        assert!(!base.contain(&other));
    }

    #[test]
    fn compare_to_orders_by_index() {
        let a = mock("a", 1);
        let b = mock("b", 2);
        assert_eq!(a.compare_to(&b), -1);
        assert_eq!(b.compare_to(&a), 1);
    }

    #[test]
    fn wrap_offset_matches_always_zero_highest() {
        let space = mock("ram", 0);
        assert_eq!(space.wrap_offset(0), 0);
        assert_eq!(space.wrap_offset(5), 0);
        assert_eq!(space.wrap_offset(-3), -3);
    }

    #[test]
    fn print_offset_pads_to_addr_size() {
        let space = mock("ram", 0);
        assert_eq!(space.print_offset(0x1234), "0x00001234");
    }

    #[test]
    fn print_raw_reports_expected_size_from_translate() {
        let space = mock("ram", 0);
        let (text, expect_size) = space.print_raw(0x10);
        assert_eq!(text, "0x00000010");
        assert_eq!(expect_size, 4);
    }

    #[test]
    fn to_display_string_matches_java_format() {
        let space = mock("ram", 0);
        assert_eq!(space.to_display_string(), "AddrSpace[ram]");
    }

    #[test]
    fn encode_basic_attributes_writes_expected_fields() {
        use crate::decompiler::opcodes::op_code::OpCode;
        use crate::program::model::address::AddressSpace;
        use crate::program::model::pcode::ids::{AttributeId, ElementId};

        #[derive(Default)]
        struct RecordingEncoder {
            strings: Vec<(&'static str, String)>,
            ints: Vec<(&'static str, i64)>,
            bools: Vec<(&'static str, bool)>,
        }

        impl Encoder for RecordingEncoder {
            fn open_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
                Ok(())
            }
            fn close_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
                Ok(())
            }
            fn write_bool(&mut self, attrib_id: AttributeId, val: bool) -> io::Result<()> {
                self.bools.push((attrib_id.name, val));
                Ok(())
            }
            fn write_signed_integer(&mut self, attrib_id: AttributeId, val: i64) -> io::Result<()> {
                self.ints.push((attrib_id.name, val));
                Ok(())
            }
            fn write_unsigned_integer(
                &mut self,
                _attrib_id: AttributeId,
                _val: u64,
            ) -> io::Result<()> {
                Ok(())
            }
            fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
                self.strings.push((attrib_id.name, val.to_string()));
                Ok(())
            }
            fn write_string_indexed(
                &mut self,
                _attrib_id: AttributeId,
                _index: i32,
                _val: &str,
            ) -> io::Result<()> {
                Ok(())
            }
            fn write_space(
                &mut self,
                _attrib_id: AttributeId,
                _spc: &AddressSpace,
            ) -> io::Result<()> {
                Ok(())
            }
            fn write_space_indexed(
                &mut self,
                _attrib_id: AttributeId,
                _index: i32,
                _name: &str,
            ) -> io::Result<()> {
                Ok(())
            }
            fn write_opcode(&mut self, _attrib_id: AttributeId, _opcode: OpCode) -> io::Result<()> {
                Ok(())
            }
            fn write_opcode_ordinal(
                &mut self,
                _attrib_id: AttributeId,
                _opcode: i32,
            ) -> io::Result<()> {
                Ok(())
            }
        }

        let space = mock("ram", 3);
        let mut encoder = RecordingEncoder::default();
        space.encode_basic_attributes(&mut encoder).unwrap();
        assert!(encoder.strings.contains(&("name", "ram".to_string())));
        assert!(encoder.ints.contains(&("index", 3)));
        assert!(encoder.bools.contains(&("bigendian", true)));
        assert!(encoder.bools.contains(&("physical", true)));
    }
}
