//! Port of `ghidra.program.model.block.graph.CodeBlockVertex`.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::program::model::address::AddressSetView;
use crate::program::model::block::CodeBlock;

/// A class for representing a code block within a graph.
///
/// Port of `ghidra.program.model.block.graph.CodeBlockVertex`. Java's `CodeBlock codeBlock`
/// field (an interface reference, possibly `null` for a "dummy" node) becomes
/// `Option<Box<dyn CodeBlock>>` here, matching this crate's convention of representing a nullable
/// interface reference as an `Option` around a trait object.
pub struct CodeBlockVertex {
    code_block: Option<Box<dyn CodeBlock>>,
    name: String,
}

impl CodeBlockVertex {
    /// Constructor. Java: `CodeBlockVertex(CodeBlock codeBlock)`.
    pub fn new(code_block: Box<dyn CodeBlock>) -> Self {
        let name = code_block.get_name();
        CodeBlockVertex { code_block: Some(code_block), name }
    }

    /// A constructor that allows for the creation of dummy nodes. This is useful in graphs where
    /// multiple entry or exit points need to be parented by a single vertex.
    ///
    /// Java: `CodeBlockVertex(String name)`.
    pub fn new_dummy(name: impl Into<String>) -> Self {
        CodeBlockVertex { code_block: None, name: name.into() }
    }

    /// Java: `getCodeBlock()`.
    pub fn get_code_block(&self) -> Option<&dyn CodeBlock> {
        self.code_block.as_deref()
    }

    /// Java: `getName()`.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns true if this vertex is not backed by a code block.
    ///
    /// Java: `isDummy()`.
    pub fn is_dummy(&self) -> bool {
        self.code_block.is_none()
    }
}

impl fmt::Display for CodeBlockVertex {
    /// Java: `toString()`, which returns `getName()`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_name())
    }
}

impl fmt::Debug for CodeBlockVertex {
    /// Manual `Debug` impl: `code_block` is a `Box<dyn CodeBlock>`, and `CodeBlock` carries no
    /// `Debug` supertrait, so this can't be derived. Summarized instead by dummy-ness and name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeBlockVertex")
            .field("is_dummy", &self.is_dummy())
            .field("name", &self.name)
            .finish()
    }
}

impl PartialOrd for CodeBlockVertex {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CodeBlockVertex {
    /// Java: `compareTo(CodeBlockVertex)`.
    ///
    /// # Faithfully-preserved quirk: inconsistent with `Eq`
    ///
    /// If *both* vertices are dummies (`codeBlock == null`), Java's first check
    /// (`if (codeBlock == null) return 1;`) fires and returns `1` -- i.e. `self` compares as
    /// *greater than* `other` -- even when the two are `equal()` (see the `PartialEq` impl
    /// below, which treats two dummies as equal). This is a real inconsistency between
    /// `compareTo` and `equals` in the original Java (violating `Comparable`'s own documented
    /// contract), preserved here rather than "fixed" to return `Ordering::Equal`. See
    /// `two_dummy_vertices_compare_as_greater_despite_being_equal` below.
    fn cmp(&self, other: &Self) -> Ordering {
        let Some(self_block) = &self.code_block else {
            return Ordering::Greater;
        };
        let Some(other_block) = &other.code_block else {
            return Ordering::Less;
        };
        let self_min = self_block
            .min_address()
            .expect("CodeBlockVertex.compareTo: code block has no addresses");
        let other_min = other_block
            .min_address()
            .expect("CodeBlockVertex.compareTo: code block has no addresses");
        self_min.cmp(&other_min)
    }
}

impl PartialEq for CodeBlockVertex {
    /// Java: `equals(Object)`.
    ///
    /// Per the class's own comment: "Assumption: we will not have two code blocks with the same
    /// min address" (in a custom, user-defined block model that assumption could theoretically
    /// be violated, but this port preserves the same assumption Java makes).
    fn eq(&self, other: &Self) -> bool {
        match (&self.code_block, &other.code_block) {
            (None, None) => true,
            (None, Some(_)) | (Some(_), None) => false,
            (Some(a), Some(b)) => {
                let a_min =
                    a.min_address().expect("CodeBlockVertex.equals: code block has no addresses");
                let b_min =
                    b.min_address().expect("CodeBlockVertex.equals: code block has no addresses");
                a_min == b_min
            }
        }
    }
}

impl Eq for CodeBlockVertex {}

impl Hash for CodeBlockVertex {
    /// Java: `hashCode()`, which returns `0` for a dummy vertex, else the min address's hash
    /// code.
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.code_block {
            None => 0i32.hash(state),
            Some(cb) => {
                let min = cb
                    .min_address()
                    .expect("CodeBlockVertex.hashCode: code block has no addresses");
                min.hash(state);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::block::code_block_model::CodeBlockModel;
    use crate::program::model::block::code_block_reference_iterator::CodeBlockReferenceIterator;
    use crate::program::seam_stubs::EmptyCodeBlockReferenceIterator;
    use crate::util::exception::CancelledException;
    use crate::util::task::TaskMonitor;

    /// A minimal `CodeBlock` backed by a single address, used to exercise `CodeBlockVertex`
    /// without needing a real block model. Mirrors the `impl_empty_address_set_view!`-based mocks
    /// used elsewhere in the `block` module's own tests.
    struct SingleAddressBlock {
        addr: Address,
        name: String,
    }

    impl AddressSetView for SingleAddressBlock {
        fn contains(&self, address: &Address) -> bool {
            address == &self.addr
        }
        fn contains_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn contains_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn is_empty(&self) -> bool {
            false
        }
        fn min_address(&self) -> Option<Address> {
            Some(self.addr.clone())
        }
        fn max_address(&self) -> Option<Address> {
            Some(self.addr.clone())
        }
        fn num_address_ranges(&self) -> usize {
            1
        }
        fn address_ranges(&self) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn address_ranges_ordered(
            &self,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn address_ranges_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> Box<dyn crate::program::model::address::AddressRangeIterator> {
            unimplemented!("not exercised by these tests")
        }
        fn num_addresses(&self) -> u64 {
            1
        }
        fn addresses(&self, _forward: bool) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by these tests")
        }
        fn addresses_from(
            &self,
            _start: &Address,
            _forward: bool,
        ) -> crate::program::model::address::BoxedAddressIterator {
            unimplemented!("not exercised by these tests")
        }
        fn intersects_set(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn intersects_range(&self, _start: &Address, _end: &Address) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn intersect(
            &self,
            _set: &dyn AddressSetView,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!("not exercised by these tests")
        }
        fn intersect_range(
            &self,
            _start: &Address,
            _end: &Address,
        ) -> crate::program::model::address::AddressSet {
            unimplemented!("not exercised by these tests")
        }
        fn union(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!("not exercised by these tests")
        }
        fn subtract(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!("not exercised by these tests")
        }
        fn xor(&self, _set: &dyn AddressSetView) -> crate::program::model::address::AddressSet {
            unimplemented!("not exercised by these tests")
        }
        fn has_same_addresses(&self, _set: &dyn AddressSetView) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn first_range(&self) -> Option<crate::program::model::address::AddressRange> {
            unimplemented!("not exercised by these tests")
        }
        fn last_range(&self) -> Option<crate::program::model::address::AddressRange> {
            unimplemented!("not exercised by these tests")
        }
        fn range_containing(
            &self,
            _address: &Address,
        ) -> Option<crate::program::model::address::AddressRange> {
            unimplemented!("not exercised by these tests")
        }
        fn find_first_address_in_common(&self, _set: &dyn AddressSetView) -> Option<Address> {
            unimplemented!("not exercised by these tests")
        }
    }

    impl CodeBlock for SingleAddressBlock {
        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn get_destinations(
            &self,
            _monitor: &dyn TaskMonitor,
        ) -> Result<Box<dyn CodeBlockReferenceIterator>, CancelledException> {
            Ok(Box::new(EmptyCodeBlockReferenceIterator))
        }

        fn get_model(&self) -> Box<dyn CodeBlockModel> {
            unimplemented!("not exercised by these tests")
        }
    }

    fn space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn block_at(offset: i64, name: &str) -> Box<dyn CodeBlock> {
        Box::new(SingleAddressBlock { addr: Address::new(space(), offset), name: name.to_string() })
    }

    #[test]
    fn new_captures_the_block_and_its_name() {
        let v = CodeBlockVertex::new(block_at(0x100, "block1"));
        assert!(!v.is_dummy());
        assert_eq!(v.get_name(), "block1");
        assert!(v.get_code_block().is_some());
    }

    #[test]
    fn new_dummy_has_no_code_block() {
        let v = CodeBlockVertex::new_dummy("entry");
        assert!(v.is_dummy());
        assert_eq!(v.get_name(), "entry");
        assert!(v.get_code_block().is_none());
    }

    #[test]
    fn to_string_is_the_name() {
        let v = CodeBlockVertex::new(block_at(0x100, "block1"));
        assert_eq!(v.to_string(), "block1");

        let d = CodeBlockVertex::new_dummy("dummy1");
        assert_eq!(d.to_string(), "dummy1");
    }

    #[test]
    fn equals_compares_by_min_address_not_name() {
        let a = CodeBlockVertex::new(block_at(0x100, "a-name"));
        let b = CodeBlockVertex::new(block_at(0x100, "different-name"));
        assert_eq!(a, b);
    }

    #[test]
    fn equals_differs_for_different_addresses() {
        let a = CodeBlockVertex::new(block_at(0x100, "a"));
        let b = CodeBlockVertex::new(block_at(0x200, "a"));
        assert_ne!(a, b);
    }

    #[test]
    fn two_dummy_vertices_are_equal() {
        let a = CodeBlockVertex::new_dummy("x");
        let b = CodeBlockVertex::new_dummy("y");
        assert_eq!(a, b);
    }

    #[test]
    fn dummy_and_real_are_never_equal() {
        let a = CodeBlockVertex::new_dummy("x");
        let b = CodeBlockVertex::new(block_at(0x100, "x"));
        assert_ne!(a, b);
        assert_ne!(b, a);
    }

    #[test]
    fn compare_to_orders_by_min_address() {
        let lo = CodeBlockVertex::new(block_at(0x100, "lo"));
        let hi = CodeBlockVertex::new(block_at(0x200, "hi"));
        assert_eq!(lo.cmp(&hi), Ordering::Less);
        assert_eq!(hi.cmp(&lo), Ordering::Greater);
    }

    #[test]
    fn dummy_always_sorts_greater_than_real() {
        let dummy = CodeBlockVertex::new_dummy("d");
        let real = CodeBlockVertex::new(block_at(0x100, "r"));
        assert_eq!(dummy.cmp(&real), Ordering::Greater);
        assert_eq!(real.cmp(&dummy), Ordering::Less);
    }

    #[test]
    fn two_dummy_vertices_compare_as_greater_despite_being_equal() {
        // Faithful to a real inconsistency in Java: `compareTo` on two dummies returns `1`
        // (Greater) because the `codeBlock == null` check on `self` fires first, even though
        // `equals` (tested above) reports the two dummies as equal. See the `Ord` impl's docs.
        let a = CodeBlockVertex::new_dummy("x");
        let b = CodeBlockVertex::new_dummy("y");
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Greater);
        assert_eq!(b.cmp(&a), Ordering::Greater);
    }

    #[test]
    fn hash_is_consistent_with_equals_for_real_blocks() {
        use std::collections::hash_map::DefaultHasher;
        let a = CodeBlockVertex::new(block_at(0x100, "a"));
        let b = CodeBlockVertex::new(block_at(0x100, "b"));
        assert_eq!(a, b);

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn hash_is_consistent_with_equals_for_dummies() {
        use std::collections::hash_map::DefaultHasher;
        let a = CodeBlockVertex::new_dummy("x");
        let b = CodeBlockVertex::new_dummy("y");

        let mut ha = DefaultHasher::new();
        a.hash(&mut ha);
        let mut hb = DefaultHasher::new();
        b.hash(&mut hb);
        assert_eq!(ha.finish(), hb.finish());
    }

    #[test]
    fn debug_does_not_panic_and_summarizes_state() {
        let v = CodeBlockVertex::new(block_at(0x100, "block1"));
        let formatted = format!("{:?}", v);
        assert!(formatted.contains("block1"));
        assert!(formatted.contains("is_dummy"));
    }
}
