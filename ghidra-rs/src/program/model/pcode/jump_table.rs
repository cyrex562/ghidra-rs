//! Port of `ghidra.program.model.pcode.JumpTable`.
//!
//! `JumpTable` is the decompiler's recovered switch/jump-table structure for an indirect branch:
//! the address of the branching operation itself, the recovered case-target addresses (and,
//! optionally, the integer case label associated with each one), the in-memory table(s) the
//! decompiler read the targets from, and an optional "basic override" -- a user-supplied
//! replacement destination list used when the decompiler failed to recover the table
//! automatically.
//!
//! # Not ported: the `SymbolTable`/`HighFunction`-backed static/instance methods
//!
//! Real Java's `getSwitchNamespace`, `getFormatOverride`, `writeFormat`, `writeOverride`, and
//! `readOverride` all round-trip jump-table overrides through a dedicated `Namespace` (named
//! `jmp_<address>`, nested under `HighFunction`'s "override" namespace) that stores the override
//! as `CodeSymbol`s named `switch`/`case_N`/`format_X`.
//!
//! // TODO(port): these were left unported because they need APIs this crate's `SymbolTable`
//! // and `HighFunction` don't have yet:
//! //   - `SymbolTable.getSymbols(Namespace)` -- iterate every symbol inside a given namespace.
//! //     This crate's [`SymbolTable`](crate::program::model::symbol::SymbolTable) trait only
//! //     supports looking up symbols by address or by global name, not by containing namespace.
//! //   - `HighFunction.findCreateNamespace`/`findNamespace` -- get-or-create/find a namespace by
//! //     name under a parent. `HighFunction` here only ports `find_create_override_space`/
//! //     `find_override_space` (the top-level "override" namespace itself), not this
//! //     `jmp_<address>`-named child lookup.
//! //   - `HighFunction.deleteSymbol`/`createLabelSymbol`/`clearNamespace` -- none of these
//! //     symbol/namespace-mutation helpers exist in `high_function.rs` yet.
//! // Adding any of the above is a `SymbolTable`/`HighFunction` change, out of scope for this
//! // `JumpTable` port. Everything else in the Java class -- construction, the case/label/
//! // load-table bookkeeping, and the `Decoder`/`Encoder` wire format -- is ported below.

use std::io;

use crate::program::model::address::{Address, SpecialAddress};
use crate::program::model::pcode::address_xml;
use crate::program::model::pcode::decoder::{Decoder, DecoderError};
use crate::program::model::pcode::decoder_exception::DecoderException;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{
    ATTRIB_FORMAT, ATTRIB_LABEL, ATTRIB_NUM, ATTRIB_SIZE, ELEM_BASICOVERRIDE, ELEM_DEST,
    ELEM_JUMPTABLE, ELEM_LOADTABLE,
};

fn decode_err(e: DecoderError) -> DecoderException {
    DecoderException::with_cause("failed to decode JumpTable", e)
}

/// Port of the nested `JumpTable.LoadTable` class: describes a single in-memory table the
/// decompiler read jump-table targets from -- `num` entries of `size` bytes each, starting at
/// `addr`.
///
/// Real Java's `LoadTable` is default-constructed with all fields unset (`addr == null`,
/// `size == 0`, `num == 0`) and only ever populated by immediately calling `decode` on the fresh
/// instance (see `JumpTable.decode`'s loop body: `new LoadTable(); loadtable.decode(decoder);`),
/// so nothing observable is ever able to see the half-constructed state. This port collapses that
/// two-step "construct, then mutate via decode" sequence into a single `decode` associated
/// function that returns a fully populated value, which is behaviorally identical but avoids an
/// artificial `Option`-typed `addr` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadTable {
    /// Starting address of table.
    addr: Address,
    /// Size of a table entry in bytes.
    size: i32,
    /// Number of entries in table.
    num: i32,
}

impl LoadTable {
    /// Starting address of table. Port of `LoadTable.getAddress()`.
    pub fn get_address(&self) -> &Address {
        &self.addr
    }

    /// Size of a table entry in bytes. Port of `LoadTable.getSize()`.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Number of entries in table. Port of `LoadTable.getNum()`.
    pub fn get_num(&self) -> i32 {
        self.num
    }

    /// Decode a `LoadTable` from the stream. Port of `LoadTable.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    pub fn decode(decoder: &dyn Decoder) -> Result<Self, DecoderException> {
        let el = decoder.open_element_with_id(ELEM_LOADTABLE).map_err(decode_err)?;
        let size = decoder.read_signed_integer_with_id(ATTRIB_SIZE).map_err(decode_err)? as i32;
        let num = decoder.read_signed_integer_with_id(ATTRIB_NUM).map_err(decode_err)? as i32;
        let addr = address_xml::decode(decoder)?;
        decoder.close_element(el).map_err(decode_err)?;
        Ok(Self { addr, size, num })
    }
}

/// Port of the nested `JumpTable.BasicOverride` class: a user-supplied list of jump destinations
/// (addresses of instructions) that overrides automatic jump-table recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicOverride {
    /// List of jump destinations, must be addresses of instructions.
    destinations: Vec<Address>,
}

impl BasicOverride {
    /// Port of `BasicOverride(ArrayList<Address>)`.
    pub fn new(destinations: Vec<Address>) -> Self {
        Self { destinations }
    }

    /// Port of `BasicOverride.getDestinations()`.
    pub fn get_destinations(&self) -> &[Address] {
        &self.destinations
    }

    /// Encode this override as a `<basicoverride>` element to the given stream. Port of
    /// `BasicOverride.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_BASICOVERRIDE)?;
        for addr in &self.destinations {
            encoder.open_element(ELEM_DEST)?;
            address_xml::encode_attributes(encoder, addr)?;
            encoder.close_element(ELEM_DEST)?;
        }
        // We could add <normaddr> and <normhash> elements to specify switch variable.
        // We could add a <startval> tag to indicate starting value of the switch variable.
        encoder.close_element(ELEM_BASICOVERRIDE)
    }
}

/// A `JumpTable` found as part of the decompilation of a function. Port of
/// `ghidra.program.model.pcode.JumpTable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpTable {
    op_address: Option<Address>,
    /// Address entries corresponding to case labels. Real Java's field name/comment ("If
    /// DEFAULT_VALUE, then entry is the default guard case, not a jump target") describes a
    /// convention that lives in decompiler-side code not present in this port; nothing here
    /// interprets a particular address value specially.
    address_table: Option<Vec<Address>>,
    label_table: Option<Vec<i32>>,
    load_table: Option<Vec<LoadTable>>,
    basic_override: Option<BasicOverride>,
    /// Default format for displaying integer case values.
    display_format: i32,
}

impl Default for JumpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl JumpTable {
    /// Port of the no-arg `JumpTable()` constructor.
    pub fn new() -> Self {
        Self {
            op_address: None,
            address_table: None,
            label_table: None,
            load_table: None,
            basic_override: None,
            display_format: 0,
        }
    }

    /// Port of `JumpTable(Address, ArrayList<Address>, boolean, int)`. When `is_override` is
    /// true, `destinations` becomes a [`BasicOverride`] and no address table is populated
    /// (matching real Java, which leaves `addressTable` null in that branch); otherwise
    /// `destinations` becomes the address table directly and there is no override.
    pub fn with_destinations(
        addr: Address,
        destinations: Vec<Address>,
        is_override: bool,
        format: i32,
    ) -> Self {
        if is_override {
            Self {
                op_address: Some(addr),
                address_table: None,
                label_table: None,
                load_table: None,
                basic_override: Some(BasicOverride::new(destinations)),
                display_format: format,
            }
        } else {
            Self {
                op_address: Some(addr),
                address_table: Some(destinations),
                label_table: None,
                load_table: None,
                basic_override: None,
                display_format: format,
            }
        }
    }

    /// Port of `JumpTable.isEmpty()`.
    ///
    /// Note a real Java quirk this reproduces faithfully: this only ever looks at `addressTable`,
    /// never at `override`. A `JumpTable` built via [`with_destinations`](Self::with_destinations)
    /// with `is_override = true` leaves `addressTable` null/`None` even when the override itself
    /// has destinations, so `is_empty()` reports `true` for such a table regardless of how many
    /// override destinations it actually holds.
    pub fn is_empty(&self) -> bool {
        match &self.address_table {
            None => true,
            Some(table) => table.is_empty(),
        }
    }

    /// Decode a `JumpTable` object from the stream. Port of `JumpTable.decode(Decoder)`.
    ///
    /// # Errors
    /// Returns an error for invalid encodings.
    pub fn decode(&mut self, decoder: &dyn Decoder) -> Result<(), DecoderException> {
        let el = decoder.open_element_with_id(ELEM_JUMPTABLE).map_err(decode_err)?;
        if decoder.get_next_attribute_id().map_err(decode_err)? == ATTRIB_FORMAT.id {
            self.display_format = decoder.read_unsigned_integer().map_err(decode_err)? as i32;
        }
        if decoder.peek_element().map_err(decode_err)? == 0 {
            // Empty jumptable. Note this leaves every other field (including op_address)
            // untouched -- matching real Java, which returns here without assigning
            // `opAddress`/`addressTable`/`labelTable`/`loadTable` at all.
            decoder.close_element(el).map_err(decode_err)?;
            return Ok(());
        }

        let mut a_table: Vec<Address> = Vec::new();
        let mut l_table: Vec<i32> = Vec::new();
        let mut ld_table: Vec<LoadTable> = Vec::new();

        let switch_addr = address_xml::decode(decoder)?;

        loop {
            let subel = decoder.peek_element().map_err(decode_err)?;
            if subel == 0 {
                break;
            }
            if subel == ELEM_DEST.id {
                decoder.open_element().map_err(decode_err)?;
                let case_addr = address_xml::decode_from_attributes(decoder)?;
                a_table.push(case_addr);
                decoder.rewind_attributes();
                loop {
                    let attrib_id = decoder.get_next_attribute_id().map_err(decode_err)?;
                    if attrib_id == 0 {
                        break;
                    }
                    if attrib_id == ATTRIB_LABEL.id {
                        let label =
                            decoder.read_unsigned_integer().map_err(decode_err)? as i32;
                        l_table.push(label);
                    }
                }
                decoder.close_element(subel).map_err(decode_err)?;
            } else if subel == ELEM_LOADTABLE.id {
                ld_table.push(LoadTable::decode(decoder)?);
            } else {
                // Port of `decoder.skipElement()`: open the unrecognized element, then skip its
                // entire contents.
                let sub_open = decoder.open_element().map_err(decode_err)?;
                decoder.close_element_skipping(sub_open).map_err(decode_err)?;
            }
        }

        self.op_address = Some(switch_addr);
        self.address_table = Some(a_table);
        self.label_table = Some(l_table);
        self.load_table = Some(ld_table);
        decoder.close_element(el).map_err(decode_err)?;
        Ok(())
    }

    /// Encode this `JumpTable` to the given stream. Port of `JumpTable.encode(Encoder)`.
    ///
    /// # Errors
    /// Returns an error for problems writing to the underlying stream.
    pub fn encode(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.open_element(ELEM_JUMPTABLE)?;
        if self.display_format != 0 {
            encoder.write_unsigned_integer(ATTRIB_FORMAT, self.display_format as u64)?;
        }
        // `AddressXML.encode(Encoder, Address)` treats a null address as the "no address"
        // sentinel, writing an empty <addr> element; `op_address == None` is this port's
        // equivalent of that null case.
        let op_addr = self.op_address.clone().unwrap_or_else(SpecialAddress::no_address);
        address_xml::encode_addr(encoder, &op_addr)?;
        if let Some(table) = &self.address_table {
            for addr in table {
                encoder.open_element(ELEM_DEST)?;
                address_xml::encode_attributes(encoder, addr)?;
                encoder.close_element(ELEM_DEST)?;
            }
        }
        if let Some(basic_override) = &self.basic_override {
            basic_override.encode(encoder)?;
        }
        encoder.close_element(ELEM_JUMPTABLE)
    }

    /// Port of `JumpTable.getSwitchAddress()`.
    pub fn get_switch_address(&self) -> Option<&Address> {
        self.op_address.as_ref()
    }

    /// Port of `JumpTable.getCases()`.
    ///
    /// # Panics
    /// Real Java's `getCases()` unconditionally does `addressTable.clone()`, throwing
    /// `NullPointerException` if `addressTable` is still null (i.e. this `JumpTable` was
    /// default-constructed, or decoded from an "empty jumptable" element, and never given an
    /// address table). This port reproduces that crash-on-unpopulated-state behavior with a
    /// `panic!` rather than silently returning an empty list; callers are expected to check
    /// [`is_empty`](Self::is_empty) first, exactly as real Java callers must.
    pub fn get_cases(&self) -> Vec<Address> {
        self.address_table
            .clone()
            .expect("JumpTable.getCases() called with no address table (matches Java NullPointerException)")
    }

    /// Port of `JumpTable.getLabelValues()`.
    ///
    /// # Panics
    /// See [`get_cases`](Self::get_cases)'s panic note; real Java's `getLabelValues()` has the
    /// identical `labelTable.clone()` null-unsafety for `labelTable`.
    pub fn get_label_values(&self) -> Vec<i32> {
        self.label_table
            .clone()
            .expect("JumpTable.getLabelValues() called with no label table (matches Java NullPointerException)")
    }

    /// Port of `JumpTable.getLoadTables()`.
    ///
    /// # Panics
    /// See [`get_cases`](Self::get_cases)'s panic note; real Java's `getLoadTables()` has the
    /// identical `loadTable.clone()` null-unsafety for `loadTable`.
    pub fn get_load_tables(&self) -> Vec<LoadTable> {
        self.load_table
            .clone()
            .expect("JumpTable.getLoadTables() called with no load table (matches Java NullPointerException)")
    }

    /// The default display format for integer case values. Exposed for parity with the
    /// `displayFormat` field read by the (unported, see module docs) `writeFormat`/`writeOverride`
    /// methods; there's no dedicated Java getter for it (`displayFormat` is read directly by
    /// those methods instead).
    pub fn get_display_format(&self) -> i32 {
        self.display_format
    }

    /// The basic override, if this jump table was constructed as one. Not present in real Java
    /// (which reads the private `override` field directly from `writeOverride`), but needed here
    /// since that method isn't ported (see module docs) and callers otherwise have no way to
    /// reach the override at all.
    pub fn get_override(&self) -> Option<&BasicOverride> {
        self.basic_override.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::factory::DefaultAddressFactory;
    use crate::program::model::address::AddressSpaceType;
    use crate::program::model::pcode::packed::{PackedDecode, PackedEncode};
    use std::sync::Arc;

    fn ram_space() -> Arc<crate::program::model::address::AddressSpace> {
        crate::program::model::address::AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    // --- construction ---

    #[test]
    fn new_is_empty_with_no_switch_address() {
        let jt = JumpTable::new();
        assert!(jt.is_empty());
        assert_eq!(jt.get_switch_address(), None);
        assert_eq!(jt.get_display_format(), 0);
        assert!(jt.get_override().is_none());
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(JumpTable::default(), JumpTable::new());
    }

    #[test]
    fn with_destinations_non_override_populates_address_table() {
        let ram = ram_space();
        let switch_addr = ram.address(0x1000);
        let case0 = ram.address(0x2000);
        let case1 = ram.address(0x2010);
        let jt = JumpTable::with_destinations(
            switch_addr.clone(),
            vec![case0.clone(), case1.clone()],
            false,
            0,
        );
        assert!(!jt.is_empty());
        assert_eq!(jt.get_switch_address(), Some(&switch_addr));
        assert_eq!(jt.get_cases(), vec![case0, case1]);
        assert!(jt.get_override().is_none());
    }

    #[test]
    fn with_destinations_override_populates_basic_override_not_address_table() {
        let ram = ram_space();
        let switch_addr = ram.address(0x1000);
        let case0 = ram.address(0x2000);
        let jt = JumpTable::with_destinations(switch_addr, vec![case0.clone()], true, 0);

        // Real Java quirk (preserved here): isEmpty() only ever checks addressTable, so an
        // override-constructed JumpTable always reports empty even though its override actually
        // has a destination.
        assert!(jt.is_empty());
        let ov = jt.get_override().expect("override should be set");
        assert_eq!(ov.get_destinations(), &[case0]);
    }

    #[test]
    #[should_panic(expected = "matches Java NullPointerException")]
    fn get_cases_on_unpopulated_table_panics_like_java_npe() {
        let jt = JumpTable::new();
        let _ = jt.get_cases();
    }

    #[test]
    #[should_panic(expected = "matches Java NullPointerException")]
    fn get_label_values_on_unpopulated_table_panics_like_java_npe() {
        let jt = JumpTable::new();
        let _ = jt.get_label_values();
    }

    #[test]
    #[should_panic(expected = "matches Java NullPointerException")]
    fn get_load_tables_on_unpopulated_table_panics_like_java_npe() {
        let jt = JumpTable::new();
        let _ = jt.get_load_tables();
    }

    // --- BasicOverride::encode ---

    #[test]
    fn basic_override_encode_writes_dest_per_destination() {
        let ram = ram_space();
        let ov = BasicOverride::new(vec![ram.address(0x10), ram.address(0x20)]);
        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        ov.encode(&mut encoder).unwrap();
        let bytes = encoder.into_inner();
        assert!(!bytes.is_empty());
    }

    // --- LoadTable::decode ---

    #[test]
    fn load_table_decode_round_trips_size_num_and_address() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let addr = ram.address(0x4000);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_LOADTABLE).unwrap();
        encoder.write_signed_integer(ATTRIB_SIZE, 4).unwrap();
        encoder.write_signed_integer(ATTRIB_NUM, 12).unwrap();
        address_xml::encode_addr(&mut encoder, &addr).unwrap();
        encoder.close_element(ELEM_LOADTABLE).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(addr_factory, bytes);
        let lt = LoadTable::decode(&decoder).unwrap();
        assert_eq!(lt.get_size(), 4);
        assert_eq!(lt.get_num(), 12);
        assert_eq!(lt.get_address(), &addr);
    }

    // --- JumpTable::decode / encode round trips ---

    #[test]
    fn decode_empty_jumptable_leaves_everything_unset() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram]));

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_JUMPTABLE).unwrap();
        encoder.close_element(ELEM_JUMPTABLE).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(addr_factory, bytes);
        let mut jt = JumpTable::new();
        jt.decode(&decoder).unwrap();

        assert!(jt.is_empty());
        assert_eq!(jt.get_switch_address(), None);
        assert_eq!(jt.get_display_format(), 0);
    }

    #[test]
    fn encode_then_decode_round_trips_switch_address_cases_and_format() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let switch_addr = ram.address(0x1000);
        let case0 = ram.address(0x2000);
        let case1 = ram.address(0x2010);
        let jt = JumpTable::with_destinations(
            switch_addr.clone(),
            vec![case0.clone(), case1.clone()],
            false,
            3,
        );

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        jt.encode(&mut encoder).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(addr_factory, bytes);
        let mut decoded = JumpTable::new();
        decoded.decode(&decoder).unwrap();

        assert!(!decoded.is_empty());
        assert_eq!(decoded.get_switch_address(), Some(&switch_addr));
        assert_eq!(decoded.get_cases(), vec![case0, case1]);
        assert_eq!(decoded.get_display_format(), 3);
        // Real JumpTable::encode doesn't write labelTable/loadTable at all (see JumpTable.java's
        // encode -- it only ever emits <dest> elements and, if present, the override), so a
        // round trip through encode/decode always comes back with empty (not null) label/load
        // tables, never the original ones (there weren't any to begin with here).
        assert_eq!(decoded.get_label_values(), Vec::<i32>::new());
        assert_eq!(decoded.get_load_tables(), Vec::<LoadTable>::new());
    }

    #[test]
    fn decode_reads_label_attribute_on_dest_elements() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let switch_addr = ram.address(0x1000);
        let case0 = ram.address(0x2000);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_JUMPTABLE).unwrap();
        address_xml::encode_addr(&mut encoder, &switch_addr).unwrap();
        encoder.open_element(ELEM_DEST).unwrap();
        address_xml::encode_attributes(&mut encoder, &case0).unwrap();
        encoder.write_unsigned_integer(ATTRIB_LABEL, 7).unwrap();
        encoder.close_element(ELEM_DEST).unwrap();
        encoder.close_element(ELEM_JUMPTABLE).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(addr_factory, bytes);
        let mut jt = JumpTable::new();
        jt.decode(&decoder).unwrap();

        assert_eq!(jt.get_cases(), vec![case0]);
        assert_eq!(jt.get_label_values(), vec![7]);
    }

    #[test]
    fn decode_reads_loadtable_child_elements() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let switch_addr = ram.address(0x1000);
        let load_addr = ram.address(0x5000);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_JUMPTABLE).unwrap();
        address_xml::encode_addr(&mut encoder, &switch_addr).unwrap();
        encoder.open_element(ELEM_LOADTABLE).unwrap();
        encoder.write_signed_integer(ATTRIB_SIZE, 8).unwrap();
        encoder.write_signed_integer(ATTRIB_NUM, 5).unwrap();
        address_xml::encode_addr(&mut encoder, &load_addr).unwrap();
        encoder.close_element(ELEM_LOADTABLE).unwrap();
        encoder.close_element(ELEM_JUMPTABLE).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(addr_factory, bytes);
        let mut jt = JumpTable::new();
        jt.decode(&decoder).unwrap();

        let tables = jt.get_load_tables();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].get_size(), 8);
        assert_eq!(tables[0].get_num(), 5);
        assert_eq!(tables[0].get_address(), &load_addr);
    }

    #[test]
    fn decode_format_attribute_when_present() {
        let ram = ram_space();
        let addr_factory = Arc::new(DefaultAddressFactory::new(vec![ram.clone()]));
        let switch_addr = ram.address(0x1000);

        let mut encoder = PackedEncode::new(Vec::<u8>::new());
        encoder.open_element(ELEM_JUMPTABLE).unwrap();
        encoder.write_unsigned_integer(ATTRIB_FORMAT, 5).unwrap();
        address_xml::encode_addr(&mut encoder, &switch_addr).unwrap();
        encoder.close_element(ELEM_JUMPTABLE).unwrap();
        let bytes = encoder.into_inner();

        let decoder = PackedDecode::new(addr_factory, bytes);
        let mut jt = JumpTable::new();
        jt.decode(&decoder).unwrap();

        assert_eq!(jt.get_display_format(), 5);
    }
}
