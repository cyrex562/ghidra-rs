//! Models `ghidra.pcodeCPort.address.Range`.

use super::unsigned_compare;
use crate::decompiler::space::AddrSpace;
use std::cmp::Ordering;
use std::sync::Arc;

/// A contiguous range of offsets `[first, last]` within a single address space.
///
/// Models `ghidra.pcodeCPort.address.Range`. The Java class also exposes `getFirstAddr`,
/// `getLastAddr`, and `getLastAddrOpen`, each of which constructs a
/// `ghidra.pcodeCPort.address.Address`. That type was ported by merging into
/// [`crate::program::model::address::Address`], which is keyed to
/// `crate::program::model::address::AddressSpace` rather than to the [`AddrSpace`] trait this
/// struct's `spc` field holds. As already documented on
/// [`crate::decompiler::translate::Translate`], there is no faithful way to build one from a
/// `&dyn AddrSpace`, so those three methods are left unported here for the same reason.
#[derive(Clone)]
pub struct Range {
    spc: Option<Arc<dyn AddrSpace>>,
    first: i64,
    last: i64,
}

impl Range {
    /// Creates a range `[first, last]` within `spc`.
    pub fn new(spc: Arc<dyn AddrSpace>, first: i64, last: i64) -> Self {
        Self {
            spc: Some(spc),
            first,
            last,
        }
    }

    /// Creates an empty, unbound range (the Java no-arg constructor).
    pub fn empty() -> Self {
        Self {
            spc: None,
            first: 0,
            last: 0,
        }
    }

    /// The space containing this range.
    pub fn space(&self) -> Option<&Arc<dyn AddrSpace>> {
        self.spc.as_ref()
    }

    /// The inclusive lower bound of this range.
    pub fn first(&self) -> i64 {
        self.first
    }

    /// The inclusive upper bound of this range.
    pub fn last(&self) -> i64 {
        self.last
    }

    /// Debug form: `<space name>: <first>-<last>`, bounds in unpadded hex.
    pub fn print_bounds(&self) -> String {
        let spc = self.spc.as_ref().expect("space must be set");
        format!(
            "{}: {:x}-{:x}",
            spc.name(),
            self.first as u64,
            self.last as u64
        )
    }
}

impl PartialEq for Range {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Range {}

impl PartialOrd for Range {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Range {
    fn cmp(&self, other: &Self) -> Ordering {
        let spc = self.spc.as_ref().expect("space must be set");
        let other_spc = other.spc.as_ref().expect("space must be set");
        let result = spc.compare_to(other_spc.as_ref());
        if result != 0 {
            return result.cmp(&0);
        }
        unsigned_compare(self.first, other.first).cmp(&0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::translate::Translate;

    struct MockTranslate;
    impl crate::decompiler::translate::BasicSpaceProvider for MockTranslate {
        fn get_default_space(&self) -> &dyn AddrSpace {
            unimplemented!("not exercised by these tests")
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
            4
        }

        fn print_assembly(
            &self,
            _out: &mut dyn std::io::Write,
            _size: i32,
            _baseaddr: &crate::program::model::address::Address,
        ) -> std::io::Result<i32> {
            Ok(4)
        }
    }

    struct TestSpace {
        name: &'static str,
        index: i32,
    }

    impl AddrSpace for TestSpace {
        fn name(&self) -> &str {
            self.name
        }

        fn get_trans(&self) -> &dyn Translate {
            static TRANS: MockTranslate = MockTranslate;
            &TRANS
        }

        fn get_type(&self) -> crate::decompiler::space::SpaceType {
            crate::decompiler::space::SpaceType::IptrInternal
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
            8
        }

        fn get_mask(&self) -> i64 {
            i64::MAX
        }

        fn get_short_cut(&self) -> char {
            'r'
        }

        fn flags(&self) -> i32 {
            0
        }
    }

    fn space(name: &'static str, index: i32) -> Arc<dyn AddrSpace> {
        Arc::new(TestSpace { name, index })
    }

    #[test]
    fn new_stores_space_and_bounds() {
        let spc = space("ram", 0);
        let r = Range::new(spc.clone(), 0x1000, 0x2000);
        assert_eq!(r.space().unwrap().name(), "ram");
        assert_eq!(r.first(), 0x1000);
        assert_eq!(r.last(), 0x2000);
    }

    #[test]
    fn empty_has_no_space_and_zero_bounds() {
        let r = Range::empty();
        assert!(r.space().is_none());
        assert_eq!(r.first(), 0);
        assert_eq!(r.last(), 0);
    }

    #[test]
    fn print_bounds_formats_name_and_hex_bounds() {
        let r = Range::new(space("ram", 0), 0x10, 0xff);
        assert_eq!(r.print_bounds(), "ram: 10-ff");
    }

    #[test]
    fn compare_orders_by_space_first() {
        let a = Range::new(space("ram", 0), 0x1000, 0x2000);
        let b = Range::new(space("other", 1), 0, 0);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&a), Ordering::Greater);
    }

    #[test]
    fn compare_orders_by_first_within_same_space() {
        let spc = space("ram", 0);
        let a = Range::new(spc.clone(), 0x1000, 0x2000);
        let b = Range::new(spc.clone(), 0x2000, 0x3000);
        assert_eq!(a.cmp(&b), Ordering::Less);
        assert_eq!(b.cmp(&a), Ordering::Greater);
    }

    #[test]
    fn compare_equal_ranges() {
        let spc = space("ram", 0);
        let a = Range::new(spc.clone(), 0x1000, 0x2000);
        let b = Range::new(spc.clone(), 0x1000, 0x5000);
        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert!(a == b);
    }
}
