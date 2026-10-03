//! Port of `ghidra.program.model.pcode.SymbolEntry`.
//!
//! A mapping from a `HighSymbol` to the storage that holds the symbol's value.
//!
//! The Java class is `public abstract class SymbolEntry` with two direct subclasses:
//! `MappedEntry`/`MappedDataEntry` (real, address-based mappings -- ported alongside this trait in
//! [`mapped_entry`](crate::program::model::pcode::mapped_entry) and
//! [`mapped_data_entry`](crate::program::model::pcode::mapped_data_entry)) and `DynamicEntry`
//! (hash-based mappings). `DynamicEntry` was ported earlier as its own
//! self-contained trait ([`DynamicEntry`](crate::program::model::pcode::dynamic_entry::DynamicEntry))
//! that flattens `SymbolEntry`'s two public members it actually needed (the `symbol`/`pcaddr`
//! fields and the `decodeRangeList`/`encodeRangelist` protected helpers) directly into its own
//! default method bodies, rather than depending on a real `SymbolEntry`. That module's docs
//! explain this was a deliberate cut-point choice made *before* `SymbolEntry` itself was ported.
//! `DynamicEntry` is intentionally left untouched by this port (still standing on its own, still
//! not implementing this trait) -- unifying it onto this trait now would mean reconciling its use
//! of the lighter-weight [`seam_stubs::HighSymbol`](crate::program::seam_stubs::HighSymbol)
//! placeholder with this trait's dependency on the real, now-ported
//! [`high_symbol::HighSymbol`](crate::program::model::pcode::high_symbol::HighSymbol) (see below),
//! which is a larger, separate change than "port `SymbolEntry`/`MappedEntry`/`MappedDataEntry`".
//!
//! Since Rust has no implementation inheritance, and `MappedEntry`/`MappedDataEntry` are concrete
//! (non-abstract) Java classes each carrying real instance state, this follows the same
//! "abstract base becomes a trait with real default methods for the base class's real shared
//! logic, concrete subclasses become real structs implementing it" shape already used for
//! `HighVariable`->`HighLocal`/`HighOther`/`HighGlobal` elsewhere in this crate, rather than
//! `DynamicEntry`'s field-flattening (that approach was chosen there specifically because
//! `SymbolEntry` did not exist yet; now that it does, `SymbolEntry.decodeRangeList`/
//! `encodeRangelist` -- real, non-trivial shared algorithms -- get a proper home here instead of
//! being re-flattened into each new subclass).
//!
//! [`get_high_symbol`](SymbolEntry::get_high_symbol)/[`get_pc_address`](SymbolEntry::get_pc_address)/
//! [`set_pc_address`](SymbolEntry::set_pc_address) stand in for the protected `symbol`/`pcaddr`
//! fields (the latter exposed publicly in Java only via the (misspelled) `getPCAdress()` getter --
//! preserved here as the correctly-spelled `get_pc_address`, a harmless renaming since nothing
//! depends on the Java method name being reachable from Rust). [`decode_range_list`]/
//! [`encode_rangelist`] are real ports of the protected `decodeRangeList`/`encodeRangelist`
//! helpers, given default bodies here (built only on the trait's own required accessors) so every
//! implementor gets them for free, exactly as `DynamicEntry` already gets an equivalent (currently
//! duplicated) version of the same logic.
//!
//! [`decode`](SymbolEntry::decode), [`encode`](SymbolEntry::encode),
//! [`get_storage`](SymbolEntry::get_storage), [`get_size`](SymbolEntry::get_size), and
//! [`get_mutability`](SymbolEntry::get_mutability) are required with no default, mirroring the
//! Java abstract methods of the same names.
//!
//! [`decode`](SymbolEntry::decode) takes an extra `pcode_factory: &dyn PcodeFactory` parameter not
//! present on the Java method (`SymbolEntry.decode(Decoder)`). In Java, `MappedEntry.decode` calls
//! `AddressXML.decodeStorageFromAttributes(sz, decoder, symbol.function)`, where `symbol.function`
//! (a `HighFunction`) *is* a `PcodeFactory` (`HighFunction extends PcodeSyntaxTree implements
//! PcodeFactory`). This crate's [`HighFunction`](crate::program::model::pcode::high_function::HighFunction)
//! trait does not implement [`PcodeFactory`](crate::program::model::pcode::pcode_factory::PcodeFactory)
//! (the two were ported independently as separate dependency-cycle cut-points, with no supertrait
//! link between them), so there is no way to obtain a `&dyn PcodeFactory` generically from
//! `self.get_high_symbol().get_high_function()` through the trait objects alone. Rather than fake
//! this up with an unsound downcast, the capability is threaded through explicitly as a parameter
//! -- the "prefer changing the signature over `unsafe`" tradeoff. A caller with a concrete
//! `HighFunction` implementation that also happens to implement `PcodeFactory` can simply pass
//! `&that_same_object` for both roles.
//!
//! [`get_storage`](SymbolEntry::get_storage) returns `Option<Box<dyn VariableStorage>>` rather
//! than a bare `Box<dyn VariableStorage>`, faithfully modeling the fact that the real
//! `MappedEntry.storage` field is `null` until `decode`/the storage-carrying constructor runs
//! (Java's `getStorage()` just returns the field verbatim, `null` and all, with no
//! `NullPointerException` at that call site -- the NPE, if any, happens later in a caller that
//! dereferences the result). [`get_size`](SymbolEntry::get_size)/
//! [`get_mutability`](SymbolEntry::get_mutability), by contrast, *do* dereference `storage`
//! (`storage.size()`/`storage.getMinAddress()`) in Java and so *would* NPE there on an unset
//! `storage`; [`MappedEntry`](crate::program::model::pcode::mapped_entry::MappedEntry)'s
//! implementation mirrors that with an `expect()` panic (documented and tested at its own
//! definition) rather than silently returning a placeholder value.

use std::io;
use std::sync::Arc;

use crate::program::model::address::Address;
use crate::program::model::listing::variable_storage::VariableStorage;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::high_symbol::HighSymbol;
use crate::program::model::pcode::ids::{ATTRIB_FIRST, ATTRIB_LAST, ATTRIB_SPACE, ELEM_RANGE, ELEM_RANGELIST};
use crate::program::model::pcode::pcode_factory::PcodeFactory;

/// A mapping from a `HighSymbol` to the storage that holds the symbol's value. Port of the
/// instance contract of `ghidra.program.model.pcode.SymbolEntry`. See the module docs for the
/// shape of this port and its one intentional signature deviation
/// ([`decode`](SymbolEntry::decode)'s extra `pcode_factory` parameter).
///
/// Not `Send + Sync` bounded (unlike, e.g., [`HighSymbol`]): [`VariableStorage`] and
/// [`Data`](crate::program::model::listing::Data), both reachable from this trait's methods,
/// are not themselves `Send + Sync` bounded anywhere else in this crate, so requiring it here
/// would make every real implementor (which necessarily stores an `Arc<dyn VariableStorage>` and,
/// for [`MappedDataEntry`](crate::program::model::pcode::mapped_data_entry::MappedDataEntry), an
/// `Arc<dyn Data>`) fail to compile. This matches
/// [`DynamicEntry`](crate::program::model::pcode::dynamic_entry::DynamicEntry)'s own precedent,
/// which is likewise unbounded.
pub trait SymbolEntry {
    /// The symbol owning this entry. Port of the protected `SymbolEntry.symbol` field.
    fn get_high_symbol(&self) -> Arc<dyn HighSymbol>;

    /// The earliest address in the code where this storage is used for this symbol. Port of
    /// `SymbolEntry.getPCAdress()` (renamed to the correctly spelled `get_pc_address`; see the
    /// module docs).
    fn get_pc_address(&self) -> Option<Address>;

    /// Stands in for direct assignment to the protected `SymbolEntry.pcaddr` field, needed by
    /// [`decode_range_list`](SymbolEntry::decode_range_list)'s default body.
    fn set_pc_address(&mut self, addr: Option<Address>);

    /// Decode this entry from the stream. Typically more than one element is consumed. Port of
    /// `SymbolEntry.decode(Decoder)`. See the module docs for why this takes an extra
    /// `pcode_factory` parameter beyond the Java signature.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode(
        &mut self,
        decoder: &dyn Decoder,
        pcode_factory: &dyn PcodeFactory,
    ) -> Result<(), DecoderException>;

    /// Encode this entry as (a set of) elements to the given stream. Port of
    /// `SymbolEntry.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for errors in the underlying stream.
    fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()>;

    /// Get the storage associated with this particular mapping of the Symbol. Port of
    /// `SymbolEntry.getStorage()`. See the module docs for why this returns an `Option`.
    fn get_storage(&self) -> Option<Box<dyn VariableStorage>>;

    /// Get the number of bytes consumed by the symbol when using this storage. Port of
    /// `SymbolEntry.getSize()`.
    fn get_size(&self) -> i32;

    /// Return one of `MutabilitySettingsDefinition::NORMAL`/`VOLATILE`/`CONSTANT`. Port of
    /// `SymbolEntry.getMutability()`.
    fn get_mutability(&self) -> i32;

    /// Port of the protected `SymbolEntry.decodeRangeList(Decoder)`: decode the (at most
    /// single-entry) range list establishing this entry's first-use address, if any.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    fn decode_range_list(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let rangelistel = decoder.open_element_with_id(ELEM_RANGELIST).map_err(decode_err)?;
        if decoder.peek_element().map_err(decode_err)? != 0 {
            let rangeel = decoder.open_element_with_id(ELEM_RANGE).map_err(decode_err)?;
            let spc = decoder.read_space_with_id(ATTRIB_SPACE).map_err(decode_err)?;
            let offset = decoder.read_unsigned_integer_with_id(ATTRIB_FIRST).map_err(decode_err)?;
            self.set_pc_address(Some(spc.address(offset as i64)));
            decoder.close_element(rangeel).map_err(decode_err)?;
        }
        decoder.close_element(rangelistel).map_err(decode_err)?;
        Ok(())
    }

    /// Port of the protected `SymbolEntry.encodeRangelist(Encoder)`: encode the range list
    /// establishing this entry's first-use address, if any (an empty `<rangelist>` if there is
    /// none, or if it is an external address).
    ///
    /// # Errors
    /// Returns an error for errors in the underlying stream.
    fn encode_rangelist(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_RANGELIST)?;
        if let Some(addr) = self.get_pc_address() {
            if !addr.is_external_address() {
                let off = addr.unsigned_offset();
                encoder.open_element(ELEM_RANGE)?;
                encoder.write_space(ATTRIB_SPACE, addr.space())?;
                encoder.write_unsigned_integer(ATTRIB_FIRST, off)?;
                encoder.write_unsigned_integer(ATTRIB_LAST, off)?;
                encoder.close_element(ELEM_RANGE)?;
            }
        }
        encoder.close_element(ELEM_RANGELIST)
    }
}

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode SymbolEntry", e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressFactory, AddressSpace, AddressSpaceType};
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::listing::Program;
    use crate::program::model::pcode::high_function::HighFunction;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 2)
    }

    struct MockDataType;
    impl DataType for MockDataType {}

    struct MockHighSymbol;
    impl HighSymbol for MockHighSymbol {
        fn get_id(&self) -> i64 {
            1
        }
        fn get_high_function(&self) -> Arc<dyn HighFunction> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_program(&self) -> Arc<dyn Program> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_data_type(&self) -> Box<dyn DataType> {
            Box::new(MockDataType)
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
    }

    /// Minimal `SymbolEntry` used only to exercise the trait's default
    /// [`decode_range_list`](SymbolEntry::decode_range_list)/[`encode_rangelist`](SymbolEntry::encode_rangelist)
    /// bodies (the abstract members are trivial no-ops/unimplemented, mirroring how
    /// `DynamicEntry`'s own tests exercise the equivalent flattened logic).
    struct BareEntry {
        symbol: Arc<dyn HighSymbol>,
        pc_address: Option<Address>,
    }

    impl SymbolEntry for BareEntry {
        fn get_high_symbol(&self) -> Arc<dyn HighSymbol> {
            self.symbol.clone()
        }
        fn get_pc_address(&self) -> Option<Address> {
            self.pc_address.clone()
        }
        fn set_pc_address(&mut self, addr: Option<Address>) {
            self.pc_address = addr;
        }
        fn decode(
            &mut self,
            _decoder: &dyn Decoder,
            _pcode_factory: &dyn PcodeFactory,
        ) -> Result<(), DecoderException> {
            unimplemented!("not needed for this smoke test")
        }
        fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
            unimplemented!("not needed for this smoke test")
        }
        fn get_storage(&self) -> Option<Box<dyn VariableStorage>> {
            None
        }
        fn get_size(&self) -> i32 {
            0
        }
        fn get_mutability(&self) -> i32 {
            0
        }
    }

    struct MockDecoder {
        space: Arc<AddressSpace>,
        offset: u64,
        has_range: bool,
        open_calls: AtomicUsize,
    }

    impl Decoder for MockDecoder {
        fn get_address_factory(&self) -> Arc<dyn AddressFactory> {
            unimplemented!()
        }
        fn set_address_factory(&self, _factory: Arc<dyn AddressFactory>) {}
        fn peek_element(&self) -> Result<i32, DecoderError> {
            Ok(if self.has_range { 1 } else { 0 })
        }
        fn open_element(&self) -> Result<i32, DecoderError> {
            Ok(self.open_calls.fetch_add(1, Ordering::SeqCst) as i32 + 1)
        }
        fn open_element_with_id(&self, _elem_id: ElementId) -> Result<i32, DecoderError> {
            self.open_element()
        }
        fn close_element(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn close_element_skipping(&self, _id: i32) -> Result<(), DecoderError> {
            Ok(())
        }
        fn get_next_attribute_id(&self) -> Result<i32, DecoderError> {
            Ok(0)
        }
        fn rewind_attributes(&self) {}
        fn read_bool(&self) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_bool_with_id(&self, _attrib_id: AttributeId) -> Result<bool, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer(&self) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_signed_integer_with_id(&self, _attrib_id: AttributeId) -> Result<i64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer(&self) -> Result<u64, DecoderError> {
            unimplemented!()
        }
        fn read_unsigned_integer_with_id(&self, attrib_id: AttributeId) -> Result<u64, DecoderError> {
            if attrib_id.id == ATTRIB_FIRST.id {
                Ok(self.offset)
            } else {
                Err(DecoderError::MissingAttribute(attrib_id.name.to_string()))
            }
        }
        fn read_string(&self) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_string_with_id(&self, _attrib_id: AttributeId) -> Result<String, DecoderError> {
            unimplemented!()
        }
        fn read_space(&self) -> Result<Arc<AddressSpace>, DecoderError> {
            unimplemented!()
        }
        fn read_space_with_id(&self, _attrib_id: AttributeId) -> Result<Arc<AddressSpace>, DecoderError> {
            Ok(self.space.clone())
        }
    }

    #[derive(Default)]
    struct RecordingEncoder {
        events: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("open:{}", elem_id.name));
            Ok(())
        }
        fn close_element(&mut self, elem_id: ElementId) -> io::Result<()> {
            self.events.push(format!("close:{}", elem_id.name));
            Ok(())
        }
        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }
        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }
        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, val));
            Ok(())
        }
        fn write_string(&mut self, _attrib_id: AttributeId, _val: &str) -> io::Result<()> {
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
        fn write_space(&mut self, attrib_id: AttributeId, spc: &AddressSpace) -> io::Result<()> {
            self.events.push(format!("attr:{}={}", attrib_id.name, spc.name()));
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
        fn write_opcode(
            &mut self,
            _attrib_id: AttributeId,
            _opcode: crate::decompiler::opcodes::op_code::OpCode,
        ) -> io::Result<()> {
            Ok(())
        }
        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn decode_range_list_reads_pc_address_when_present() {
        let space = ram_space();
        let mut entry = BareEntry { symbol: Arc::new(MockHighSymbol), pc_address: None };
        let decoder = MockDecoder {
            space: space.clone(),
            offset: 0x4000,
            has_range: true,
            open_calls: AtomicUsize::new(0),
        };

        entry.decode_range_list(&decoder).expect("decode_range_list should succeed");

        assert_eq!(entry.get_pc_address(), Some(space.address(0x4000)));
    }

    #[test]
    fn decode_range_list_with_no_range_leaves_pc_address_unset() {
        let space = ram_space();
        let mut entry = BareEntry { symbol: Arc::new(MockHighSymbol), pc_address: None };
        let decoder =
            MockDecoder { space, offset: 0, has_range: false, open_calls: AtomicUsize::new(0) };

        entry.decode_range_list(&decoder).expect("decode_range_list should succeed");

        assert_eq!(entry.get_pc_address(), None);
    }

    #[test]
    fn encode_rangelist_emits_range_matching_pc_address() {
        let space = ram_space();
        let entry =
            BareEntry { symbol: Arc::new(MockHighSymbol), pc_address: Some(space.address(0x5000)) };

        let mut encoder = RecordingEncoder::default();
        entry.encode_rangelist(&mut encoder).expect("encode_rangelist should succeed");

        assert_eq!(
            encoder.events,
            vec![
                "open:rangelist".to_string(),
                "open:range".to_string(),
                "attr:space=ram".to_string(),
                "attr:first=20480".to_string(),
                "attr:last=20480".to_string(),
                "close:range".to_string(),
                "close:rangelist".to_string(),
            ]
        );
    }

    #[test]
    fn encode_rangelist_with_no_pc_address_emits_empty_rangelist() {
        let entry = BareEntry { symbol: Arc::new(MockHighSymbol), pc_address: None };

        let mut encoder = RecordingEncoder::default();
        entry.encode_rangelist(&mut encoder).expect("encode_rangelist should succeed");

        assert_eq!(
            encoder.events,
            vec!["open:rangelist".to_string(), "close:rangelist".to_string()]
        );
    }

    #[test]
    fn symbol_entry_trait_is_object_safe() {
        let boxed: Box<dyn SymbolEntry> =
            Box::new(BareEntry { symbol: Arc::new(MockHighSymbol), pc_address: None });
        assert!(boxed.get_storage().is_none());
        assert_eq!(boxed.get_mutability(), 0);
    }
}
