//! Port of `ghidra.program.model.pcode.HighVariable`.
//!
//! A high-level variable (as in a high-level language like C/C++) built out of Varnodes
//! (low-level variables). This is a base trait for the (not yet ported) `HighConstant`-style
//! subclasses.
//!
//! This was selected as a dependency-cycle cut-point ([`HighSymbol`]'s `get_high_variable`,
//! [`HighFunction`]'s `split_out_merge_group`, and
//! [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)
//! all reference `HighVariable` long before its own dependents are ported), so it is modeled as a
//! trait rather than a concrete struct. This promotes the minimal placeholder that used to live in
//! `seam_stubs.rs` (see `STUBS.tsv`); every existing importer keeps compiling against the methods
//! that placeholder already exposed
//! ([`requires_dynamic_storage`](HighVariable::requires_dynamic_storage),
//! [`get_representative`](HighVariable::get_representative),
//! [`as_param_slot`](HighVariable::as_param_slot),
//! [`get_high_function`](HighVariable::get_high_function),
//! [`get_data_type`](HighVariable::get_data_type), [`get_size`](HighVariable::get_size),
//! [`decode_instances`](HighVariable::decode_instances)), with additional public API filled in
//! below to match the real Java class.
//!
//! The two Java constructors (which wire up the `function` field, and optionally the initial
//! name/data-type/representative/instances) are construction-time plumbing rather than public
//! API, and have no Rust trait equivalent; implementors are expected to perform that setup
//! themselves via their own fields.
//!
//! [`attach_instances`](HighVariable::attach_instances) ports `HighVariable.attachInstances`'s
//! real conditional logic (representative always replaced; instances default to `[rep]` when
//! `None`), but since this trait has no fields of its own, the actual field mutation is delegated
//! to the required [`set_representative`](HighVariable::set_representative)/
//! [`set_instances`](HighVariable::set_instances) setters, following the precedent set by
//! [`HighConstant`](crate::program::model::pcode::high_constant::HighConstant)'s
//! `set_symbol`/`set_pc_address`.
//!
//! The protected `setHighOnInstances` (linking each instance `VarnodeAST` back to this
//! `HighVariable`) is not modeled: it mutates `VarnodeAST`-specific state that this crate's plain
//! [`Varnode`] does not carry (the same convention already followed by
//! [`HighFunction::get_pc_address`](crate::program::model::pcode::high_function::HighFunction::get_pc_address)),
//! so callers backed by a real AST are expected to perform that linkage themselves.
//!
//! [`decode_instances`](HighVariable::decode_instances) (the protected `decodeInstances`) is kept
//! as the placeholder's no-op default: the real method resolves the representative varnode via
//! `HighFunction.getRef(int)`, decodes the data-type via `PcodeDataTypeManager.decodeDataType`, and
//! decodes each instance via the static `Varnode.decode(Decoder, PcodeFactory)` -- none of
//! `get_ref`/a `PcodeDataTypeManager` accessor/a static `Varnode` decoder are exposed by this
//! crate's [`HighFunction`] trait or plain [`Varnode`] yet, so this remains a documented no-op
//! until those capabilities exist.
//!
//! [`requires_dynamic_storage`](HighVariable::requires_dynamic_storage) is ported with real logic
//! for the `represent.isUnique()` check; the second condition
//! (`represent.getAddress().isStackAddress() && !represent.isAddrTied()`) simplifies to just the
//! stack-address check, since `isAddrTied()` is `VarnodeAST`-specific state this crate's plain
//! [`Varnode`] does not carry (matching the same documented limitation on
//! [`HighFunction::get_pc_address`](crate::program::model::pcode::high_function::HighFunction::get_pc_address)).

use std::sync::Arc;

use crate::program::model::data::data_type::DataType;
use crate::program::model::pcode::decoder::Decoder;
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::high_function::HighFunction;
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::{HighSymbol, PlaceholderDataType};

/// Which `HighVariable` subclass a variable stands for, standing in for Java's `instanceof`
/// checks (`hv instanceof HighConstant`, `hv instanceof HighLocal`, ...) while those subclasses
/// (`HighConstant`, `HighLocal`, `HighGlobal`, `HighOther`, `HighParam`, ...) are not ported as
/// distinct concrete types. Follows the same convention as
/// [`ClangTokenKind`](crate::app::decompiler::clang_token::ClangTokenKind). Once a subclass is
/// ported it should carry its identity in its own type and override [`HighVariable::kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighVariableKind {
    Generic,
    Constant,
    Local,
    Global,
    Other,
}

/// A high-level variable (as in a high-level language like C/C++) built out of Varnodes
/// (low-level variables). Port of `ghidra.program.model.pcode.HighVariable`.
pub trait HighVariable: Send + Sync {
    /// Get the high function associated with this variable. Port of
    /// `HighVariable.getHighFunction()`.
    fn get_high_function(&self) -> Arc<dyn HighFunction>;

    /// Get the name of the variable. Port of `HighVariable.getName()`. Defaults to an empty
    /// string, mirroring a `HighVariable` constructed without an explicit name.
    fn get_name(&self) -> String {
        String::new()
    }

    /// Get the size of the variable. Port of `HighVariable.getSize()`. Defaults to the
    /// representative varnode's size, matching the real class's `getSize() ==
    /// getRepresentative().getSize()` invariant.
    fn get_size(&self) -> i32 {
        self.get_representative().get_size()
    }

    /// Get the data type attached to the variable. Port of `HighVariable.getDataType()`.
    fn get_data_type(&self) -> Box<dyn DataType> {
        Box::new(PlaceholderDataType)
    }

    /// Get the varnode that represents this variable. Port of
    /// `HighVariable.getRepresentative()`.
    fn get_representative(&self) -> Varnode;

    /// A variable can reside in different locations at various times. Get all the instances of
    /// the variable. Port of `HighVariable.getInstances()`. Defaults to just the representative,
    /// mirroring a `HighVariable` that has never had additional instances attached.
    fn get_instances(&self) -> Vec<Varnode> {
        vec![self.get_representative()]
    }

    /// Retrieve any underlying `HighSymbol`. Port of the abstract `HighVariable.getSymbol()`.
    fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>>;

    /// Get the offset of this variable into its containing `HighSymbol`. A value of `-1`
    /// indicates that this `HighVariable` matches the size and storage of the symbol. Port of
    /// `HighVariable.getOffset()`. Defaults to `-1`, matching the field's initial value.
    fn get_offset(&self) -> i32 {
        -1
    }

    /// Stand-in for the private `represent` field setter, needed by
    /// [`attach_instances`](HighVariable::attach_instances)'s default body.
    fn set_representative(&mut self, rep: Varnode);

    /// Stand-in for the private `instances` field setter, needed by
    /// [`attach_instances`](HighVariable::attach_instances)'s default body.
    fn set_instances(&mut self, instances: Vec<Varnode>);

    /// Attach an instance or additional location the variable can be found in. `inst` is `None`
    /// when only a single (the representative) location is known. Port of
    /// `HighVariable.attachInstances(Varnode[], Varnode)`.
    fn attach_instances(&mut self, inst: Option<Vec<Varnode>>, rep: Varnode) {
        match inst {
            Some(instances) => self.set_instances(instances),
            None => self.set_instances(vec![rep.clone()]),
        }
        self.set_representative(rep);
    }

    /// Simplified stand-in for `highVar instanceof HighParam ? ((HighParam)
    /// highVar).getSlot() : null`, used by
    /// [`HighFunctionDBUtil`](crate::program::model::pcode::high_function_db_util::HighFunctionDBUtil)'s
    /// private `isValidUniqueVariable` helper. Not a distinct Java method; grown onto the
    /// placeholder before this promotion since the real `HighParam` subtype is not modeled
    /// separately here. Implementors representing a parameter are expected to override this to
    /// return their slot.
    fn as_param_slot(&self) -> Option<i32> {
        None
    }

    /// Which `HighVariable` subclass this variable stands for. See [`HighVariableKind`]; this has
    /// no Java counterpart (Java uses `instanceof`). Defaults to `Generic`.
    fn kind(&self) -> HighVariableKind {
        HighVariableKind::Generic
    }

    /// Decode the data-type and the Varnode instances of this `HighVariable`. The representative
    /// Varnode is also populated. Port of the protected `HighVariable.decodeInstances(Decoder)`.
    /// See the module docs for why this defaults to a no-op that consumes nothing from the
    /// stream.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode_instances(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let _ = decoder;
        Ok(())
    }

    /// Return true when the `HighVariable` should be recorded (in the database) using dynamic
    /// storage rather than using the actual address space and offset of the representative
    /// varnode. Dynamic storage is typically needed if the actual storage is ephemeral (in the
    /// unique space). Port of `HighVariable.requiresDynamicStorage()`. See the module docs for the
    /// simplification of the stack-address branch.
    fn requires_dynamic_storage(&self) -> bool {
        let representative = self.get_representative();
        if representative.is_unique() {
            return true;
        }
        representative.get_address().is_stack_address()
    }

    /// Decode this `HighVariable` from a `<high>` element in the stream. Port of the abstract
    /// `HighVariable.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }

    struct MockHighVariable {
        representative: Varnode,
        instances: Vec<Varnode>,
    }

    impl HighVariable for MockHighVariable {
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_representative(&self) -> Varnode {
            self.representative.clone()
        }
        fn get_instances(&self) -> Vec<Varnode> {
            self.instances.clone()
        }
        fn get_symbol(&self) -> Option<Arc<dyn HighSymbol>> {
            None
        }
        fn set_representative(&mut self, rep: Varnode) {
            self.representative = rep;
        }
        fn set_instances(&mut self, instances: Vec<Varnode>) {
            self.instances = instances;
        }
        fn decode(&mut self, _decoder: &dyn Decoder) -> Result<(), DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// Proves [`HighVariable`] is dyn-object-safe (usable as `Box<dyn HighVariable>`) and that its
    /// default [`HighVariable::attach_instances`] mirrors the real Java conditional: a `None`
    /// instance list collapses to a single-element list containing the new representative, while
    /// the representative is always replaced.
    #[test]
    fn attach_instances_with_no_instances_defaults_to_representative() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let old_rep = Varnode::new(addr(&space, 0x1000), 4);
        let new_rep = Varnode::new(addr(&space, 0x2000), 4);

        let mut high: Box<dyn HighVariable> = Box::new(MockHighVariable {
            representative: old_rep,
            instances: Vec::new(),
        });

        high.attach_instances(None, new_rep.clone());

        assert_eq!(high.get_representative(), new_rep);
        assert_eq!(high.get_instances(), vec![new_rep]);
    }

    /// When an explicit instance list is supplied, it is used verbatim rather than being
    /// collapsed to just the representative.
    #[test]
    fn attach_instances_with_explicit_instances_keeps_them() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let rep = Varnode::new(addr(&space, 0x3000), 4);
        let other = Varnode::new(addr(&space, 0x3100), 4);

        let mut high = MockHighVariable {
            representative: Varnode::new(addr(&space, 0), 1),
            instances: Vec::new(),
        };

        high.attach_instances(Some(vec![rep.clone(), other.clone()]), rep.clone());

        assert_eq!(high.get_representative(), rep);
        assert_eq!(high.get_instances(), vec![rep, other]);
    }

    /// A representative in the unique space always requires dynamic storage, regardless of
    /// address.
    #[test]
    fn requires_dynamic_storage_for_unique_representative() {
        let space = AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 1);
        let high = MockHighVariable {
            representative: Varnode::new(addr(&space, 0), 4),
            instances: Vec::new(),
        };

        assert!(high.requires_dynamic_storage());
    }

    /// A representative in the stack space requires dynamic storage (the `isAddrTied()` half of
    /// the real check is unreachable here; see the module docs).
    #[test]
    fn requires_dynamic_storage_for_stack_representative() {
        let space = AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 1);
        let high = MockHighVariable {
            representative: Varnode::new(addr(&space, 0), 4),
            instances: Vec::new(),
        };

        assert!(high.requires_dynamic_storage());
    }

    /// A representative in an ordinary RAM space does not require dynamic storage.
    #[test]
    fn does_not_require_dynamic_storage_for_ram_representative() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let high = MockHighVariable {
            representative: Varnode::new(addr(&space, 0x4000), 4),
            instances: Vec::new(),
        };

        assert!(!high.requires_dynamic_storage());
    }

    /// `get_size` defaults to the representative's size.
    #[test]
    fn get_size_defaults_to_representative_size() {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let high = MockHighVariable {
            representative: Varnode::new(addr(&space, 0x5000), 8),
            instances: Vec::new(),
        };

        assert_eq!(high.get_size(), 8);
    }
}
