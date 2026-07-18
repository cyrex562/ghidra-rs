//! Models `ghidra.pcodeCPort.translate.Translate`.

use crate::decompiler::seam_stubs::RangeList;
use crate::decompiler::space::{AddrSpace, SpaceType};
use crate::decompiler::translate::BasicSpaceProvider;
use crate::program::model::address::Address;
use std::io;

/// A translator from machine instructions to p-code, and the owner of a processor's address
/// spaces.
///
/// Models the abstract class `ghidra.pcodeCPort.translate.Translate`, which implements
/// `BasicSpaceProvider`.
///
/// Promoted from the placeholder stub that only covered
/// [`Translate::get_default_size`] (needed by [`AddrSpace::get_trans`] and, transitively,
/// [`AddrSpace::print_raw`]); that method is kept below as a real default implementation, backed
/// by [`BasicSpaceProvider::get_default_space`], so existing implementors keep compiling.
///
/// The Java class carries its address-space bookkeeping (`baselist`, `spacebaselist`, `iopspace`,
/// ...) as private mutable fields with no public mutators beyond construction-time helpers
/// (`insertSpace`, `setDefaultSpace`, `addSpacebase`). A trait has no fields, so that bookkeeping
/// is exposed here as required read accessors instead, mirroring how
/// [`AddrSpace`] already treats its own construction-time state (mask/scale/shortcut) as an
/// implementor concern. The construction-time mutators themselves (`insertSpace`,
/// `setDefaultSpace`, `addSpacebase`, and the spacebase-register lookups they populate) are left
/// unported, matching how [`crate::decompiler::space::unique_space::UniqueSpace`] and
/// [`crate::decompiler::space::constant_space::ConstantSpace`] already treat construction as an
/// implementor concern rather than a trait method.
///
/// `getRegister`, `getRegisterName`, and `getUserOpNames` are also left out of this trait: they
/// are abstract in Java, but the only known Rust implementor
/// ([`crate::decompiler::sleigh_base::SleighBase`]) already declares its own identically-named,
/// identically-signatured methods overriding them, and Rust has no notion of overriding a
/// supertrait's required method — redeclaring them here would make calls through `dyn SleighBase`
/// ambiguous. `getConstant` and `createConstFromSpace` are left out for a similar reason: both
/// construct a `ghidra.pcodeCPort.address.Address`, which was ported by merging into
/// [`crate::program::model::address::Address`] — a type keyed to
/// `crate::program::model::address::AddressSpace`, not to the [`AddrSpace`] trait these spaces
/// implement, so there is no faithful way to construct one from an `&dyn AddrSpace` here.
pub trait Translate: BasicSpaceProvider + Send + Sync {
    /// Whether this processor globally uses big endian encoding.
    fn is_big_endian(&self) -> bool;

    /// The byte modulo on which instructions are aligned (1 if there is no requirement).
    fn alignment(&self) -> i32;

    /// The base offset, within the unique temporary register space, where new registers can be
    /// allocated for the simplification process.
    fn get_unique_base(&self) -> i64;

    /// The special address space reserved for encoding pointers to pcode operations as addresses.
    fn get_iop_space(&self) -> Option<&dyn AddrSpace>;

    /// The special address space reserved for encoding pointers to `FuncCallSpecs` objects as
    /// addresses.
    fn get_fspec_space(&self) -> Option<&dyn AddrSpace>;

    /// The dedicated stack address space, if this processor has one.
    fn get_stack_space(&self) -> Option<&dyn AddrSpace>;

    /// The pool of temporary registers used by both the pcode translation and simplification
    /// processes.
    fn get_unique_space(&self) -> Option<&dyn AddrSpace>;

    /// The total number of address spaces used by the processor, including special spaces like
    /// the constant space and the iop space.
    fn num_spaces(&self) -> i32;

    /// Retrieves a specific address space via its formal index.
    fn get_space(&self, i: i32) -> &dyn AddrSpace;

    /// The ranges for which high-level pointers are not possible (the Java `nohighptr` field).
    fn no_high_ptr(&self) -> &dyn RangeList;

    /// This routine is intended to return a global address size for the processor.
    ///
    /// Mirrors the deprecated `getAddrSize`; use [`Translate::get_default_size`] instead.
    #[deprecated(note = "use get_default_size instead")]
    fn get_addr_size(&self) -> i32 {
        self.get_default_size()
    }

    /// The size, in bytes, of addresses for the processor's official default space.
    fn get_default_size(&self) -> i32 {
        self.get_default_space().get_addr_size()
    }

    /// Converts an address space name to the space itself.
    fn get_space_by_name(&self, nm: &str) -> Option<&dyn AddrSpace> {
        (0..self.num_spaces()).find_map(|i| {
            let space = self.get_space(i);
            (space.name() == nm).then_some(space)
        })
    }

    /// Converts an address space shortcut character to the space itself.
    fn get_space_by_shortcut(&self, sc: char) -> Option<&dyn AddrSpace> {
        (0..self.num_spaces()).find_map(|i| {
            let space = self.get_space(i);
            (space.get_short_cut() == sc).then_some(space)
        })
    }

    /// Returns the space that is next, in the absolute order of addresses, after `spc`, or `None`
    /// if `spc` is the last space (mirrors the Java `AddrSpace.MAX_SPACE` sentinel).
    fn get_next_space_in_order(&self, spc: &dyn AddrSpace) -> Option<&dyn AddrSpace> {
        let next_index = spc.get_index() + 1;
        if next_index >= 0 && next_index < self.num_spaces() {
            Some(self.get_space(next_index))
        } else {
            None
        }
    }

    /// Returns `true` if it is possible to have pointers into `[loc, loc + size)`.
    fn high_ptr_possible(&self, loc: &Address, size: i32) -> bool {
        !self.no_high_ptr().in_range(loc, size)
    }

    /// Picks an unused single-character shortcut for a new space of kind `tp`.
    ///
    /// Panics if every shortcut in the assignable range is already taken, mirroring the
    /// `LowlevelError` the Java method throws in that case.
    fn assign_shortcut(&self, tp: SpaceType) -> char {
        let mut shortcut = match tp {
            SpaceType::IptrConstant => '#',
            SpaceType::IptrProcessor => 'r',
            SpaceType::IptrSpacebase => 's',
            SpaceType::IptrInternal => 'u',
            SpaceType::IptrFspec => 'f',
            SpaceType::IptrIop => 'i',
        };
        for c in b'a'..b'z' {
            let taken = (0..self.num_spaces()).any(|j| self.get_space(j).get_short_cut() == shortcut);
            if !taken {
                return shortcut;
            }
            shortcut = c as char;
        }
        panic!("Unable to assign shortcut");
    }

    /// This routine is intended to return an instruction's length, in bytes, at `baseaddr`.
    fn instruction_length(&self, baseaddr: &Address) -> i32;

    /// Prints the disassembly of the instruction at `baseaddr` to `out`, returning its length in
    /// bytes.
    fn print_assembly(&self, out: &mut dyn io::Write, size: i32, baseaddr: &Address) -> io::Result<i32>;

    /// Base implementation (for compiling) doesn't need to keep track of context symbols.
    fn register_context(&self, _name: &str, _sbit: i32, _ebit: i32) {}

    /// Base implementation is a no-op.
    fn dispose(&self) {}

    /// Base implementation is a no-op.
    fn set_language(&self, _processor_file: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::space::addr_space::{BIG_ENDIAN, HASPHYSICAL, HERITAGED};

    struct MockAddrSpace {
        name: &'static str,
        index: i32,
        short_cut: char,
    }

    impl AddrSpace for MockAddrSpace {
        fn name(&self) -> &str {
            self.name
        }

        fn get_trans(&self) -> &dyn Translate {
            unimplemented!("not exercised by these tests")
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
            self.short_cut
        }

        fn flags(&self) -> i32 {
            HERITAGED | HASPHYSICAL | BIG_ENDIAN
        }
    }

    struct MockRangeList {
        ranges: Vec<(i64, i32)>,
    }

    impl RangeList for MockRangeList {
        fn in_range(&self, loc: &Address, size: i32) -> bool {
            self.ranges
                .iter()
                .any(|&(off, len)| off == loc.offset() && len == size)
        }
    }

    struct MockTranslate {
        default_space: MockAddrSpace,
        constant_space: MockAddrSpace,
        no_high_ptr: MockRangeList,
    }

    impl BasicSpaceProvider for MockTranslate {
        fn get_default_space(&self) -> &dyn AddrSpace {
            &self.default_space
        }

        fn get_constant_space(&self) -> &dyn AddrSpace {
            &self.constant_space
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
            2
        }

        fn get_space(&self, i: i32) -> &dyn AddrSpace {
            match i {
                0 => &self.constant_space,
                1 => &self.default_space,
                _ => panic!("index out of range"),
            }
        }

        fn no_high_ptr(&self) -> &dyn RangeList {
            &self.no_high_ptr
        }

        fn instruction_length(&self, _baseaddr: &Address) -> i32 {
            4
        }

        fn print_assembly(
            &self,
            out: &mut dyn io::Write,
            _size: i32,
            _baseaddr: &Address,
        ) -> io::Result<i32> {
            write!(out, "NOP")?;
            Ok(4)
        }
    }

    fn mock() -> MockTranslate {
        MockTranslate {
            default_space: MockAddrSpace {
                name: "ram",
                index: 1,
                short_cut: 'r',
            },
            constant_space: MockAddrSpace {
                name: "const",
                index: 0,
                short_cut: '#',
            },
            no_high_ptr: MockRangeList {
                ranges: vec![(0x1000, 4)],
            },
        }
    }

    fn address(offset: i64) -> Address {
        use crate::program::model::address::{AddressSpace, AddressSpaceType};

        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        Address::new(space, offset)
    }

    #[test]
    fn trait_is_object_safe_and_usable_via_dyn() {
        let translate = mock();
        let dyn_translate: &dyn Translate = &translate;
        assert!(dyn_translate.is_big_endian());
        assert_eq!(dyn_translate.get_default_size(), 4);
    }

    #[test]
    fn get_space_by_name_finds_registered_space() {
        let translate = mock();
        assert_eq!(translate.get_space_by_name("ram").unwrap().name(), "ram");
        assert!(translate.get_space_by_name("nope").is_none());
    }

    #[test]
    fn get_space_by_shortcut_finds_registered_space() {
        let translate = mock();
        assert_eq!(translate.get_space_by_shortcut('#').unwrap().name(), "const");
        assert!(translate.get_space_by_shortcut('z').is_none());
    }

    #[test]
    fn get_next_space_in_order_walks_by_index() {
        let translate = mock();
        let next = translate.get_next_space_in_order(&translate.constant_space);
        assert_eq!(next.unwrap().name(), "ram");
        let past_end = translate.get_next_space_in_order(&translate.default_space);
        assert!(past_end.is_none());
    }

    #[test]
    fn assign_shortcut_skips_taken_letters() {
        let translate = mock();
        // 'r' is already taken by the default space; the processor-kind default is also 'r'.
        assert_ne!(translate.assign_shortcut(SpaceType::IptrProcessor), 'r');
    }

    #[test]
    fn high_ptr_possible_matches_range_list() {
        let translate = mock();
        assert!(!translate.high_ptr_possible(&address(0x1000), 4));
        assert!(translate.high_ptr_possible(&address(0x2000), 4));
    }

    #[test]
    fn print_assembly_writes_and_returns_length() {
        let translate = mock();
        let mut buf = Vec::new();
        let len = translate
            .print_assembly(&mut buf, 4, &address(0))
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(buf, b"NOP");
    }

    #[test]
    fn no_op_defaults_do_not_panic() {
        let translate = mock();
        translate.register_context("ctx", 0, 7);
        translate.dispose();
        translate.set_language("x86");
    }
}
