//! Port of `ghidra.program.util.AddressTranslationException`.
//!
//! Java's two-argument constructor (`AddressTranslationException(Address, AddressTranslator)`)
//! is typed against `ghidra.program.util.AddressTranslator`, a six-method interface
//! (`getSourceProgram`/`getDestinationProgram`/`getAddress`/`isOneForOneTranslator`/
//! `getAddressRange`/`getAddressSet`). That interface is marked `DONE` in `PORT_MANIFEST.tsv`,
//! but no real Rust port of it exists anywhere in this crate: the only `AddressTranslator` trait
//! that exists is the unrelated `ghidra.app.util.viewer.multilisting.AddressTranslator` (a
//! different interface, in a different package, with a single `translate` method) at
//! [`crate::app::util::viewer::multilisting::address_translator`]. This is a phantom-`DONE` row
//! (see other comments in this crate, e.g. `program::util::function_merge` and
//! `program::util::program_merge`, which independently note the same gap and deliberately avoid
//! depending on it as a dependency-cycle cut point).
//!
//! Porting the real six-method interface is out of scope for this file. Since every actual call
//! site of `AddressTranslationException` in the original Java codebase (`ExternalsAddressTranslator`,
//! `AbstractDwarfEHDecoder`) only ever uses the message-only constructor, this port defines a
//! minimal local [`AddressTranslator`] seam trait exposing just the two accessors the
//! two-argument constructor's message-building logic actually needs
//! (`getSourceProgram().getDomainFile().getName()` and the destination equivalent), rather than
//! either the full six-method interface or a hard dependency on `Program`/`DomainFile`. A future
//! port of the real `ghidra.program.util.AddressTranslator` can implement this trait (or this
//! trait can be folded into it) without changing this exception's public API.

use std::fmt;

use crate::program::model::address::Address;

/// Minimal seam standing in for `ghidra.program.util.AddressTranslator`, exposing only what
/// [`AddressTranslationException::with_translator`]'s message-building needs. See the module
/// docs for why this isn't the full six-method interface.
pub trait AddressTranslator {
    /// The name of the source program's domain file.
    ///
    /// Stands in for `getSourceProgram().getDomainFile().getName()`.
    fn source_program_name(&self) -> String;

    /// The name of the destination program's domain file.
    ///
    /// Stands in for `getDestinationProgram().getDomainFile().getName()`.
    fn destination_program_name(&self) -> String;
}

/// Exception thrown when an attempt is made to translate an address from one program into an
/// equivalent address in another program.
///
/// Port of `ghidra.program.util.AddressTranslationException`. Note the Java class extends
/// `RuntimeException` directly (not `UsrException`), so unlike some of its `program::util`
/// sibling exceptions, there is no `UsrException` conversion here.
pub struct AddressTranslationException {
    message: String,
    address: Option<Address>,
    translator: Option<Box<dyn AddressTranslator>>,
}

impl AddressTranslationException {
    /// Constructs a new `AddressTranslationException` with no message.
    ///
    /// Port of `AddressTranslationException()`.
    pub fn new() -> Self {
        Self {
            message: String::new(),
            address: None,
            translator: None,
        }
    }

    /// Constructs a new `AddressTranslationException` with the given message.
    ///
    /// Port of `AddressTranslationException(String msg)`.
    pub fn with_message(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
            address: None,
            translator: None,
        }
    }

    /// Constructs a new `AddressTranslationException` for `address`, which could not be
    /// translated by `translator`. The message is built immediately (matching Java, which builds
    /// it once in the constructor rather than lazily).
    ///
    /// Port of `AddressTranslationException(Address address, AddressTranslator translator)`.
    pub fn with_translator(address: Address, translator: Box<dyn AddressTranslator>) -> Self {
        let message = format!(
            "Cannot translate address \"{}\" in program \"{}\" to address in program \"{}\".\n",
            address,
            translator.source_program_name(),
            translator.destination_program_name(),
        );
        Self {
            message,
            address: Some(address),
            translator: Some(translator),
        }
    }

    /// Returns the exception message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the address that could not be translated, if this exception was constructed via
    /// [`with_translator`](Self::with_translator).
    ///
    /// Port of `AddressTranslationException.getAddress()`.
    pub fn address(&self) -> Option<&Address> {
        self.address.as_ref()
    }

    /// Returns the translator that failed to translate [`address`](Self::address), if this
    /// exception was constructed via [`with_translator`](Self::with_translator).
    ///
    /// Port of `AddressTranslationException.getTranslator()`.
    pub fn translator(&self) -> Option<&dyn AddressTranslator> {
        self.translator.as_deref()
    }
}

impl Default for AddressTranslationException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AddressTranslationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl fmt::Debug for AddressTranslationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressTranslationException")
            .field("message", &self.message)
            .field("address", &self.address)
            .field("has_translator", &self.translator.is_some())
            .finish()
    }
}

impl std::error::Error for AddressTranslationException {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_address(offset: i64) -> Address {
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(ram, offset)
    }

    struct FixedTranslator {
        source: &'static str,
        destination: &'static str,
    }

    impl AddressTranslator for FixedTranslator {
        fn source_program_name(&self) -> String {
            self.source.to_string()
        }
        fn destination_program_name(&self) -> String {
            self.destination.to_string()
        }
    }

    #[test]
    fn no_arg_constructor_has_empty_message() {
        let e = AddressTranslationException::new();
        assert_eq!(e.message(), "");
        assert_eq!(e.to_string(), "");
        assert!(e.address().is_none());
        assert!(e.translator().is_none());
    }

    #[test]
    fn message_constructor_preserves_message() {
        let e = AddressTranslationException::with_message("cannot translate");
        assert_eq!(e.message(), "cannot translate");
        assert_eq!(e.to_string(), "cannot translate");
    }

    #[test]
    fn with_translator_builds_the_java_message_format() {
        let addr = ram_address(0x1000);
        let translator = Box::new(FixedTranslator {
            source: "source.exe",
            destination: "dest.exe",
        });
        let e = AddressTranslationException::with_translator(addr.clone(), translator);

        let expected = format!(
            "Cannot translate address \"{}\" in program \"source.exe\" to address in program \"dest.exe\".\n",
            addr
        );
        assert_eq!(e.message(), expected);
        assert_eq!(e.address(), Some(&addr));
    }

    #[test]
    fn translator_accessor_round_trips() {
        let addr = ram_address(0x2000);
        let translator = Box::new(FixedTranslator {
            source: "a",
            destination: "b",
        });
        let e = AddressTranslationException::with_translator(addr, translator);

        let t = e.translator().expect("translator should be present");
        assert_eq!(t.source_program_name(), "a");
        assert_eq!(t.destination_program_name(), "b");
    }

    #[test]
    fn implements_error() {
        let e = AddressTranslationException::new();
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn default_trait_matches_no_arg_constructor() {
        let e = AddressTranslationException::default();
        assert_eq!(e.message(), "");
    }
}
