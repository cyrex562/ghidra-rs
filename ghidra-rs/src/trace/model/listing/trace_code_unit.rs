use crate::program::model::address::AddressRange;
use crate::program::model::lang::Language;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::trace::model::lifespan::Lifespan;
use crate::trace::model::trace::Trace;
use crate::trace::model::trace_address_snap_range::TraceAddressSnapRange;
use crate::trace::seam_stubs::{TracePlatform, TraceThread};

/// A [`CodeUnit`] in a [`Trace`].
///
/// Port of `ghidra.trace.model.listing.TraceCodeUnit`.
///
/// It was selected as a dependency-cycle cut-point.
///
/// The Java interface overrides several inherited `CodeUnit` members purely to narrow their
/// return types to trace-specific ones. Rust has no notion of covariantly re-overriding an
/// inherited trait method (the same issue documented on
/// [`Trace`](crate::trace::model::trace::Trace) and
/// [`TraceReference`](crate::trace::model::symbol::trace_reference::TraceReference)), so those
/// overrides are not re-declared here; implementations of the inherited [`CodeUnit`] methods must
/// reproduce them directly:
/// - `getProgram()` must return the owning
///   [`TraceProgramView`](crate::trace::model::program::TraceProgramView) (as a `CodeUnit`'s base
///   `Program`).
/// - `getMnemonicReferences()`, `getOperandReferences(int)`, `getPrimaryReference(int)`, and
///   `getReferencesFrom()` must return
///   [`TraceReference`](crate::trace::model::symbol::trace_reference::TraceReference)s (as the
///   base `Reference` type).
///
/// The generic `setProperty`/`setTypedProperty`/`getProperty` methods (parameterized on a Java
/// `Class<T>`) are not object-safe and are not re-declared here either: they are already covered
/// by the inherited `CodeUnit`/`PropertySet`'s typed accessors
/// (`set_object_property`/`set_string_property`/`set_int_property`/`set_void_property` and their
/// `get_*` counterparts), which cover exactly the same supported value kinds (`Saveable`,
/// `String`, `Integer`, and `Void`) that this interface's javadoc documents.
///
/// Likewise, `getBytes(ByteBuffer, int)` -- reading bytes starting at this unit's address plus an
/// offset into a caller-supplied buffer -- is not re-declared: it is already covered by the
/// inherited `MemBuffer::get_bytes_into`, which has the same shape once the Java `ByteBuffer`'s
/// position/limit markers are replaced by an ordinary `&mut [u8]` slice.
pub trait TraceCodeUnit: CodeUnit {
    /// Get the trace in which this code unit exists.
    fn get_trace(&self) -> Box<dyn Trace>;

    /// Get the platform for this unit.
    fn get_platform(&self) -> Box<dyn TracePlatform>;

    /// Get the thread associated with this code unit.
    ///
    /// A thread is associated with a code unit if it exists in a register space.
    fn get_thread(&self) -> Box<dyn TraceThread>;

    /// Get the language of this code unit.
    ///
    /// Currently, for data units, this is always the base or "host" language of the trace. For
    /// instructions, this may be a guest language.
    fn get_language(&self) -> Box<dyn Language>;

    /// Get the bounds of this unit in space and time.
    fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange>;

    /// Get the address range covered by this unit.
    fn get_range(&self) -> AddressRange;

    /// Get the lifespan of this code unit.
    fn get_lifespan(&self) -> Lifespan;

    /// Get the start snap of this code unit: the first snap of this unit's lifespan.
    fn get_start_snap(&self) -> i64;

    /// Set the end snap of this code unit: the last snap of this unit's lifespan.
    ///
    /// # Panics
    /// May panic (mirroring the Java `IllegalArgumentException`) if `end_snap` is less than the
    /// start snap.
    fn set_end_snap(&mut self, end_snap: i64);

    /// Get the end snap of this code unit: the last snap of this unit's lifespan.
    fn get_end_snap(&self) -> i64;

    /// Delete this code unit.
    fn delete(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::listing::program::Program;
    use crate::program::model::mem::MemoryAccessException;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::model::mem::MemBuffer;
use crate::program::model::listing::CommentType;
    use std::sync::Arc;

    struct MockReferenceIterator;
    impl ReferenceIterator for MockReferenceIterator {
        fn has_next(&self) -> bool {
            false
        }
        fn next_reference(&mut self) -> Option<Arc<dyn Reference>> {
            None
        }
    }

    struct MockProgram;
    impl crate::framework::model::DomainObject for MockProgram {}
    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock.bin".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
    }

    struct MockTraceCodeUnit {
        min_address: Address,
        length: i32,
        start_snap: i64,
        end_snap: i64,
        deleted: bool,
    }

    impl MemBuffer for MockTraceCodeUnit {
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize {
            0
        }
        fn get_byte(&self, _offset: i32) -> Result<u8, crate::program::model::mem::MemoryAccessException> {
            unimplemented!("not exercised by these tests")
        }
        fn is_big_endian(&self) -> bool {
            unimplemented!("not exercised by these tests")
        }
        fn get_address(&self) -> Address {
            self.min_address.clone()
        }
    }
    impl PropertySet for MockTraceCodeUnit {}

    impl CodeUnit for MockTraceCodeUnit {
        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String {
            format!("{:08x}", self.min_address.offset())
        }

        fn get_label(&self) -> Option<String> {
            None
        }

        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> {
            Vec::new()
        }

        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> {
            None
        }

        fn get_min_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_max_address(&self) -> Address {
            self.min_address.clone()
        }

        fn get_mnemonic_string(&self) -> String {
            "MOV".to_string()
        }

        fn get_comment(&self, _comment_type: CommentType) -> Option<String> {
            None
        }

        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> {
            Vec::new()
        }

        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) {}

        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) {}

        fn get_length(&self) -> i32 {
            self.length
        }

        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> {
            Ok(vec![0x90; self.length as usize])
        }

        fn get_bytes_in_code_unit(
            &self,
            buffer: &mut [u8],
            _buffer_offset: i32,
        ) -> Result<(), MemoryAccessException> {
            buffer.fill(0x90);
            Ok(())
        }

        fn contains(&self, test_addr: &Address) -> bool {
            test_addr.offset() >= self.min_address.offset()
                && test_addr.offset() < self.min_address.offset() + self.length as i64
        }

        fn compare_to(&self, addr: &Address) -> i32 {
            self.min_address.offset().cmp(&addr.offset()) as i32
        }

        fn add_mnemonic_reference(
            &mut self,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) {}

        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> {
            None
        }

        fn add_operand_reference(
            &mut self,
            _index: i32,
            _ref_addr: Address,
            _ref_type: RefType,
            _source_type: SourceType,
        ) {
        }

        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) {}

        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> {
            Vec::new()
        }

        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> {
            Box::new(MockReferenceIterator)
        }

        fn get_program(&self) -> Arc<dyn Program> {
            Arc::new(MockProgram)
        }

        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> {
            None
        }

        fn remove_external_reference(&mut self, _op_index: i32) {}

        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) {}

        fn set_stack_reference(
            &mut self,
            _op_index: i32,
            _offset: i32,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn set_register_reference(
            &mut self,
            _op_index: i32,
            _reg: &crate::program::model::lang::register::Register,
            _source_type: SourceType,
            _ref_type: RefType,
        ) {
        }

        fn get_num_operands(&self) -> i32 {
            1
        }

        fn get_address(&self, _op_index: i32) -> Option<Address> {
            None
        }

        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> {
            None
        }
    }

    impl TraceCodeUnit for MockTraceCodeUnit {
        fn get_trace(&self) -> Box<dyn Trace> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_platform(&self) -> Box<dyn TracePlatform> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_thread(&self) -> Box<dyn TraceThread> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_language(&self) -> Box<dyn Language> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_bounds(&self) -> Box<dyn TraceAddressSnapRange> {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_range(&self) -> AddressRange {
            AddressRange::new(
                self.min_address.clone(),
                addr(self.min_address.offset() + self.length as i64 - 1),
            )
        }

        fn get_lifespan(&self) -> Lifespan {
            unimplemented!("not exercised by this smoke test")
        }

        fn get_start_snap(&self) -> i64 {
            self.start_snap
        }

        fn set_end_snap(&mut self, end_snap: i64) {
            assert!(
                end_snap >= self.start_snap,
                "end snap must not precede start snap"
            );
            self.end_snap = end_snap;
        }

        fn get_end_snap(&self) -> i64 {
            self.end_snap
        }

        fn delete(&mut self) {
            self.deleted = true;
        }
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    fn make_unit() -> MockTraceCodeUnit {
        MockTraceCodeUnit {
            min_address: addr(0x400),
            length: 4,
            start_snap: 0,
            end_snap: 10,
            deleted: false,
        }
    }

    #[test]
    fn usable_as_trait_object_via_supertrait_and_own_methods() {
        let mut unit: Box<dyn TraceCodeUnit> = Box::new(make_unit());

        // CodeUnit (supertrait) methods remain reachable through the trait object.
        assert_eq!(unit.get_length(), 4);
        assert_eq!(unit.get_min_address(), addr(0x400));

        // TraceCodeUnit's own methods.
        assert_eq!(unit.get_start_snap(), 0);
        assert_eq!(unit.get_end_snap(), 10);
        assert_eq!(unit.get_range(), AddressRange::new(addr(0x400), addr(0x403)));

        unit.set_end_snap(20);
        assert_eq!(unit.get_end_snap(), 20);

        unit.delete();
    }

    #[test]
    #[should_panic(expected = "end snap must not precede start snap")]
    fn set_end_snap_rejects_end_before_start() {
        let mut unit = make_unit();
        unit.set_end_snap(-1);
    }
}
