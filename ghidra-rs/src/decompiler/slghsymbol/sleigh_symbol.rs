use super::symbol_type::SymbolType;
use crate::program::model::pcode::encoder::Encoder;
use crate::program::model::pcode::ids::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_SCOPE};
use crate::sleigh::grammar::location::Location;
use std::io;

/// Base data shared by every SLEIGH symbol variant.
///
/// Concrete symbol kinds (space, token, varnode, ...) embed this as a header field rather than
/// inheriting from it, since Rust has no class inheritance.
///
/// Models `ghidra.pcodeCPort.slghsymbol.SleighSymbol`.
#[derive(Clone)]
pub struct SleighSymbol {
    name: String,
    /// Unique id across all symbols.
    pub id: i32,
    /// Unique id of the scope this symbol is in.
    pub scope_id: i32,
    was_sought: bool,
    location: Location,
}

impl SleighSymbol {
    /// Creates an unnamed symbol at the given location.
    ///
    /// Mirrors the Java `SleighSymbol(Location)` constructor, used by symbol kinds that never
    /// carry a lookup name of their own.
    pub fn new(location: Location) -> Self {
        Self {
            name: String::new(),
            id: 0,
            scope_id: 0,
            was_sought: false,
            location,
        }
    }

    /// Creates a named symbol at the given location.
    ///
    /// Mirrors the Java `SleighSymbol(Location, String)` constructor.
    pub fn with_name(location: Location, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            id: 0,
            scope_id: 0,
            was_sought: false,
            location,
        }
    }

    pub fn set_was_sought(&mut self, was_sought: bool) {
        self.was_sought = was_sought;
    }

    pub fn was_sought(&self) -> bool {
        self.was_sought
    }

    /// Releases any resources associated with this symbol. The base symbol holds none.
    pub fn dispose(&mut self) {}

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn id(&self) -> i32 {
        self.id
    }

    /// The kind of symbol this is. The base symbol reports itself as a dummy; concrete symbol
    /// kinds report their own variant.
    pub fn symbol_type(&self) -> SymbolType {
        SymbolType::DummySymbol
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    /// No-op, mirroring the Java setter whose body is commented out (the `location` field is
    /// effectively immutable after construction).
    pub fn set_location(&mut self, _location: Location) {}

    /// Encodes this symbol. The base symbol cannot be encoded directly; concrete symbol kinds
    /// override this behavior.
    ///
    /// # Errors
    /// Always returns an error for the base symbol.
    pub fn encode(&self, _encoder: &mut dyn Encoder) -> io::Result<()> {
        Err(io::Error::other(format!(
            "Symbol {} cannot be encoded directly",
            self.name
        )))
    }

    /// Encodes the name/id/scope attributes shared by every symbol kind.
    pub fn encode_sleigh_symbol_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        encoder.write_string(ATTRIB_NAME, &self.name)?;
        encoder.write_unsigned_integer(ATTRIB_ID, self.id as u64)?;
        encoder.write_unsigned_integer(ATTRIB_SCOPE, self.scope_id as u64)?;
        Ok(())
    }

    /// Encodes the basic attributes of this symbol. Concrete symbol kinds override this to add
    /// their own attributes in addition to the shared header.
    pub fn encode_header(&self, encoder: &mut dyn Encoder) -> io::Result<()> {
        self.encode_sleigh_symbol_header(encoder)
    }

    /// A detailed string identifying this symbol by name, scope, and id.
    pub fn to_detailed_string(&self) -> String {
        format!("{}-{}:{}", self.name, self.scope_id, self.id)
    }
}

impl std::fmt::Display for SleighSymbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::pcode::ids::{AttributeId, ElementId};
    use crate::decompiler::opcodes::op_code::OpCode;

    fn loc() -> Location {
        Location::new("test.sla", 7)
    }

    #[derive(Default)]
    struct RecordingEncoder {
        writes: Vec<String>,
    }

    impl Encoder for RecordingEncoder {
        fn open_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
            Ok(())
        }

        fn close_element(&mut self, _elem_id: ElementId) -> io::Result<()> {
            Ok(())
        }

        fn write_bool(&mut self, _attrib_id: AttributeId, _val: bool) -> io::Result<()> {
            Ok(())
        }

        fn write_signed_integer(&mut self, _attrib_id: AttributeId, _val: i64) -> io::Result<()> {
            Ok(())
        }

        fn write_unsigned_integer(&mut self, attrib_id: AttributeId, val: u64) -> io::Result<()> {
            self.writes.push(format!("uint:{}={}", attrib_id.name, val));
            Ok(())
        }

        fn write_string(&mut self, attrib_id: AttributeId, val: &str) -> io::Result<()> {
            self.writes.push(format!("str:{}={}", attrib_id.name, val));
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

        fn write_space(&mut self, _attrib_id: AttributeId, _spc: &AddressSpace) -> io::Result<()> {
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

        fn write_opcode_ordinal(&mut self, _attrib_id: AttributeId, _opcode: i32) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn new_has_no_name_and_zeroed_ids() {
        let sym = SleighSymbol::new(loc());
        assert_eq!(sym.name(), "");
        assert_eq!(sym.id(), 0);
        assert_eq!(sym.scope_id, 0);
        assert!(!sym.was_sought());
    }

    #[test]
    fn with_name_sets_name() {
        let sym = SleighSymbol::with_name(loc(), "foo");
        assert_eq!(sym.name(), "foo");
        assert_eq!(sym.to_string(), "foo");
    }

    #[test]
    fn to_detailed_string_includes_scope_and_id() {
        let mut sym = SleighSymbol::with_name(loc(), "bar");
        sym.id = 5;
        sym.scope_id = 2;
        assert_eq!(sym.to_detailed_string(), "bar-2:5");
    }

    #[test]
    fn was_sought_round_trips() {
        let mut sym = SleighSymbol::new(loc());
        assert!(!sym.was_sought());
        sym.set_was_sought(true);
        assert!(sym.was_sought());
    }

    #[test]
    fn symbol_type_is_dummy() {
        let sym = SleighSymbol::new(loc());
        assert_eq!(sym.symbol_type(), SymbolType::DummySymbol);
    }

    #[test]
    fn location_is_preserved_and_set_location_is_noop() {
        let mut sym = SleighSymbol::with_name(loc(), "baz");
        assert_eq!(sym.location(), &loc());
        sym.set_location(Location::new("other.sla", 99));
        assert_eq!(sym.location(), &loc());
    }

    #[test]
    fn encode_fails_directly() {
        let sym = SleighSymbol::with_name(loc(), "widget");
        let mut encoder = RecordingEncoder::default();
        let err = sym.encode(&mut encoder).unwrap_err();
        assert!(err.to_string().contains("widget"));
        assert!(err.to_string().contains("cannot be encoded directly"));
    }

    #[test]
    fn encode_header_writes_name_id_and_scope() {
        let mut sym = SleighSymbol::with_name(loc(), "widget");
        sym.id = 3;
        sym.scope_id = 1;
        let mut encoder = RecordingEncoder::default();
        sym.encode_header(&mut encoder).unwrap();
        assert_eq!(
            encoder.writes,
            vec!["str:name=widget", "uint:id=3", "uint:scope=1"]
        );
    }

    #[test]
    fn dispose_is_harmless() {
        let mut sym = SleighSymbol::new(loc());
        sym.dispose();
    }
}
