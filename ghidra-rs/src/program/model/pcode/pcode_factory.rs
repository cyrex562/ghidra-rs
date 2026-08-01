//! Port of `ghidra.program.model.pcode.PcodeFactory`.
//!
//! Interface for classes that build [`PcodeOp`]s and [`Varnode`]s.
//!
//! The Java type is already an interface, so it maps directly onto a Rust trait; it sits at the
//! hub of a dependency cycle with several collaborators
//! ([`AddressXml`](crate::program::model::pcode::address_xml::AddressXml),
//! [`FunctionPrototype`](crate::program::model::pcode::function_prototype::FunctionPrototype),
//! [`PcodeDataTypeManager`](crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager))
//! and was selected as the cut-point. This promotes the minimal placeholder that used to live in
//! `seam_stubs.rs` (see `STUBS.tsv`).
//!
//! [`get_join_storage`](PcodeFactory::get_join_storage) keeps the placeholder's original default
//! body (wrapping the given pieces in a
//! [`VarnodeListStorage`](crate::program::seam_stubs::VarnodeListStorage)) so every pre-existing
//! bare `impl PcodeFactory for Foo {}` keeps compiling, but is given the real Java signature: it
//! now takes ownership of the pieces and returns a `Result`, matching
//! `PcodeFactory.getJoinStorage(Varnode[]) throws InvalidInputException`.
//!
//! Every other method is left as a required method with no default body, mirroring the precedent
//! set by [`PcodeDataTypeManager`]: none of them have a sensible behavior-preserving default
//! without the private registries (`refmap`/`opmap`/join-storage-by-address caches) a real Java
//! implementor holds. The `set*` mutators are a partial exception: in Java they mutate flags
//! stored directly on the `Varnode` object (`Varnode.setInput`, etc.), but this crate's
//! [`Varnode`] carries no such flags yet (see
//! [`VariableStorage`](crate::program::model::listing::variable_storage)'s module docs for the
//! same gap), so they default to identity/no-ops here; a concrete implementor backed by a real
//! flag registry is expected to override them.
//!
//! [`HighSymbol`](crate::program::seam_stubs::HighSymbol) is referenced opaquely by
//! [`get_symbol`](PcodeFactory::get_symbol) and remains the pre-existing placeholder in
//! `seam_stubs.rs`; it is not promoted here since `PcodeFactory` never calls a member on it.

use std::sync::Arc;

use crate::program::model::address::{Address, AddressFactory};
use crate::program::model::data::data_type::DataType;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::pcode_data_type_manager::PcodeDataTypeManager;
use crate::program::model::pcode::{OpCode, PcodeOp, SequenceNumber, Varnode};
use crate::program::seam_stubs::{HighSymbol, VarnodeListStorage};
use crate::util::exception::InvalidInputException;

/// Interface for classes that build [`PcodeOp`]s and [`Varnode`]s.
///
/// Port of `ghidra.program.model.pcode.PcodeFactory`. See the module docs for what was ported
/// with a real default, what was left required, and why.
pub trait PcodeFactory {
    /// Port of `PcodeFactory.getAddressFactory()`.
    fn get_address_factory(&self) -> Arc<dyn AddressFactory>;

    /// Port of `PcodeFactory.getDataTypeManager()`: the pcode data type manager used to convert
    /// strings to Ghidra data types.
    fn get_data_type_manager(&self) -> Arc<dyn PcodeDataTypeManager>;

    /// Create a new Varnode with the given size and location.
    ///
    /// Port of `PcodeFactory.newVarnode(int, Address)`. Defaults to a bare, unregistered
    /// `Varnode`; a concrete implementor with a real reference-id registry should override this
    /// (and [`new_varnode_with_ref`](Self::new_varnode_with_ref)) to register it as Java does.
    fn new_varnode(&self, sz: i32, addr: Address) -> Varnode {
        Varnode::new(addr, sz)
    }

    /// Create a new Varnode with the given size and location, associated with a specific
    /// reference id so it can later be retrieved via [`get_ref`](Self::get_ref).
    ///
    /// Port of `PcodeFactory.newVarnode(int, Address, int)`.
    fn new_varnode_with_ref(&self, sz: i32, addr: Address, ref_id: i32) -> Varnode;

    /// Create a storage object representing a value split across multiple physical locations,
    /// assigning it an address in the join address space.
    ///
    /// Port of `PcodeFactory.getJoinStorage(Varnode[])`. Kept as the placeholder's original
    /// default (see the module docs) so pre-existing bare implementors keep compiling.
    ///
    /// # Errors
    /// Returns an error if a valid storage object cannot be created.
    fn get_join_storage(
        &self,
        pieces: Vec<Varnode>,
    ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
        Ok(Box::new(VarnodeListStorage(pieces)))
    }

    /// Get the address (in the "join" space) corresponding to the given multi-piece storage,
    /// previously registered by [`get_join_storage`](Self::get_join_storage). Returns `None` if
    /// the storage is not multi-piece or was not registered.
    ///
    /// Port of `PcodeFactory.getJoinAddress(VariableStorage)`.
    fn get_join_address(&self, storage: &dyn VariableStorage) -> Option<Address>;

    /// Build a storage object for a particular Varnode.
    ///
    /// Port of `PcodeFactory.buildStorage(Varnode)`.
    ///
    /// # Errors
    /// Returns an error if valid storage cannot be created.
    fn build_storage(&self, vn: &Varnode) -> Result<Box<dyn VariableStorage>, InvalidInputException>;

    /// Return a Varnode given its reference id, previously registered via
    /// [`new_varnode_with_ref`](Self::new_varnode_with_ref), or `None` if the id is not
    /// registered.
    ///
    /// Port of `PcodeFactory.getRef(int)`.
    fn get_ref(&self, refid: i32) -> Option<Varnode>;

    /// Get a PcodeOp given a reference id, corresponding to the op's `SequenceNumber`'s `order`
    /// field. Returns `None` if no op matching the id has been registered via
    /// [`new_op`](Self::new_op).
    ///
    /// Port of `PcodeFactory.getOpRef(int)`.
    fn get_op_ref(&self, refid: i32) -> Option<PcodeOp>;

    /// Get the high symbol matching the given id that has been registered with this object.
    ///
    /// Port of `PcodeFactory.getSymbol(long)`.
    fn get_symbol(&self, symbol_id: i64) -> Option<Arc<dyn HighSymbol>>;

    /// Mark (or unmark) the given Varnode as an input (to its function). Returns the altered
    /// Varnode, which may not be the same object passed in.
    ///
    /// Port of `PcodeFactory.setInput(Varnode, boolean)`. Defaults to identity -- see the module
    /// docs for why this crate's [`Varnode`] has no input flag to alter.
    fn set_input(&self, vn: Varnode, val: bool) -> Varnode {
        let _ = val;
        vn
    }

    /// Mark (or unmark) the given Varnode with the "address tied" property.
    ///
    /// Port of `PcodeFactory.setAddrTied(Varnode, boolean)`. No-op by default -- see the module
    /// docs.
    fn set_addr_tied(&self, vn: &Varnode, val: bool) {
        let _ = (vn, val);
    }

    /// Mark (or unmark) the given Varnode with the "persistent" property.
    ///
    /// Port of `PcodeFactory.setPersistent(Varnode, boolean)`. No-op by default -- see the module
    /// docs.
    fn set_persistent(&self, vn: &Varnode, val: bool) {
        let _ = (vn, val);
    }

    /// Mark (or unmark) the given Varnode with the "unaffected" property.
    ///
    /// Port of `PcodeFactory.setUnaffected(Varnode, boolean)`. No-op by default -- see the module
    /// docs.
    fn set_unaffected(&self, vn: &Varnode, val: bool) {
        let _ = (vn, val);
    }

    /// Mark (or unmark) the given Varnode with the "volatile" property.
    ///
    /// Port of `PcodeFactory.setVolatile(Varnode, boolean)`. No-op by default -- see the module
    /// docs.
    fn set_volatile(&self, vn: &Varnode, val: bool) {
        let _ = (vn, val);
    }

    /// Associate a specific merge group with the given Varnode.
    ///
    /// Port of `PcodeFactory.setMergeGroup(Varnode, short)`. No-op by default -- see the module
    /// docs.
    fn set_merge_group(&self, vn: &Varnode, val: i16) {
        let _ = (vn, val);
    }

    /// Attach a data-type to the given Varnode.
    ///
    /// Port of `PcodeFactory.setDataType(Varnode, DataType)`. No-op by default -- see the module
    /// docs.
    fn set_data_type(&self, vn: &Varnode, data_type: &dyn DataType) {
        let _ = (vn, data_type);
    }

    /// Create a new PcodeOp given its opcode, sequence number, and input and output Varnodes.
    ///
    /// Port of `PcodeFactory.newOp(SequenceNumber, int, ArrayList<Varnode>, Varnode)`.
    fn new_op(
        &self,
        sq: SequenceNumber,
        opc: OpCode,
        inputs: Vec<Varnode>,
        output: Option<Varnode>,
    ) -> PcodeOp;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::pcode::decoder::Decoder;
    use crate::program::model::pcode::decoder_exception::DecoderException;
    use crate::program::model::pcode::encoder::Encoder;
    use std::io;

    struct StubDataTypeManager;
    impl PcodeDataTypeManager for StubDataTypeManager {
        fn get_program(&self) -> Arc<dyn crate::program::model::listing::Program> {
            unimplemented!("not exercised by the PcodeFactory smoke test")
        }
        fn decode_data_type(
            &self,
            _decoder: &dyn Decoder,
        ) -> Result<Box<dyn DataType>, DecoderException> {
            unimplemented!("not exercised by the PcodeFactory smoke test")
        }
        fn encode_name_id_attributes(
            &self,
            _encoder: &mut dyn Encoder,
            _data_type: &dyn DataType,
        ) -> io::Result<()> {
            unimplemented!("not exercised by the PcodeFactory smoke test")
        }
        fn encode_type_ref(
            &self,
            _encoder: &mut dyn Encoder,
            _data_type: &dyn DataType,
            _size: i32,
        ) -> io::Result<()> {
            unimplemented!("not exercised by the PcodeFactory smoke test")
        }
        fn encode_type(
            &self,
            _encoder: &mut dyn Encoder,
            _data_type: &dyn DataType,
            _size: i32,
        ) -> io::Result<()> {
            unimplemented!("not exercised by the PcodeFactory smoke test")
        }
    }

    /// Minimal in-memory implementor proving `PcodeFactory` is object-safe and that a real
    /// (`RefCell`-backed) reference-id registry behaves like Java's `refmap`/`opmap`: values
    /// registered via `new_varnode_with_ref`/`new_op` come back out of `get_ref`/`get_op_ref`,
    /// and unregistered ids report absent.
    struct MockPcodeFactory {
        address_factory: Arc<dyn AddressFactory>,
        varnodes: RefCell<HashMap<i32, Varnode>>,
        ops: RefCell<HashMap<i32, PcodeOp>>,
    }

    impl MockPcodeFactory {
        fn new(space: Arc<AddressSpace>) -> Self {
            Self {
                address_factory: Arc::new(DefaultAddressFactory::new(vec![space])),
                varnodes: RefCell::new(HashMap::new()),
                ops: RefCell::new(HashMap::new()),
            }
        }
    }

    impl PcodeFactory for MockPcodeFactory {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            self.address_factory.clone()
        }

        fn get_data_type_manager(&self) -> Arc<dyn PcodeDataTypeManager> {
            Arc::new(StubDataTypeManager)
        }

        fn new_varnode_with_ref(&self, sz: i32, addr: Address, ref_id: i32) -> Varnode {
            let vn = Varnode::new(addr, sz);
            self.varnodes.borrow_mut().insert(ref_id, vn.clone());
            vn
        }

        fn get_join_address(&self, _storage: &dyn VariableStorage) -> Option<Address> {
            None
        }

        fn build_storage(
            &self,
            vn: &Varnode,
        ) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
            Ok(Box::new(VarnodeListStorage(vec![vn.clone()])))
        }

        fn get_ref(&self, refid: i32) -> Option<Varnode> {
            self.varnodes.borrow().get(&refid).cloned()
        }

        fn get_op_ref(&self, refid: i32) -> Option<PcodeOp> {
            self.ops.borrow().get(&refid).cloned()
        }

        fn get_symbol(&self, _symbol_id: i64) -> Option<Arc<dyn HighSymbol>> {
            None
        }

        fn new_op(
            &self,
            sq: SequenceNumber,
            opc: OpCode,
            inputs: Vec<Varnode>,
            output: Option<Varnode>,
        ) -> PcodeOp {
            let op = PcodeOp::new(opc, sq.clone(), inputs, output);
            self.ops.borrow_mut().insert(sq.order, op.clone());
            op
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn trait_object_usage_registers_and_retrieves_varnodes_and_ops() {
        let space = ram_space();
        let factory: Box<dyn PcodeFactory> = Box::new(MockPcodeFactory::new(space.clone()));

        let vn = factory.new_varnode_with_ref(4, space.address(0x1000), 7);
        assert_eq!(factory.get_ref(7), Some(vn.clone()));
        assert_eq!(factory.get_ref(99), None, "unregistered ref id must report absent");

        let mut sq = SequenceNumber::new(space.address(0x2000), 0);
        sq.order = 42;
        let op = factory.new_op(sq, OpCode::Copy, vec![vn.clone()], None);
        assert_eq!(op.inputs, vec![vn]);
        assert_eq!(factory.get_op_ref(42), Some(op));
        assert_eq!(factory.get_op_ref(43), None);

        assert!(factory.get_symbol(1).is_none());
    }

    #[test]
    fn get_join_storage_default_wraps_pieces_and_set_input_default_is_identity() {
        let space = ram_space();
        let factory = MockPcodeFactory::new(space.clone());

        let v1 = Varnode::new(space.address(0x10), 4);
        let v2 = Varnode::new(space.address(0x20), 4);
        let storage = factory
            .get_join_storage(vec![v1.clone(), v2.clone()])
            .expect("default join storage never fails");
        assert_eq!(storage.get_varnodes(), vec![v1.clone(), v2.clone()]);

        let unchanged = factory.set_input(v1.clone(), true);
        assert_eq!(unchanged, v1);
    }
}
