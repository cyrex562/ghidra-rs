//! Port of `ghidra.program.util.AddressIteratorConverter`.
//!
//! `AddressIteratorConverter` was selected as a dependency-cycle cut-point, so its public API is
//! ported as the [`AddressIteratorConverter`] trait (a marker supertrait of
//! [`AddressIterator`](crate::program::model::address::AddressIterator)) rather than a plain
//! struct: callers can depend on `Box<dyn AddressIteratorConverter>` instead of importing
//! [`DefaultAddressIteratorConverter`] directly. The Java class's public surface is entirely
//! inherited from `AddressIterator`/`Iterator<Address>` (`hasNext()`, `next()`, `remove()`,
//! `iterator()`), which the port's [`AddressIterator`](crate::program::model::address::AddressIterator)
//! trait already models as [`has_next`](crate::program::model::address::AddressIterator::has_next)
//! and [`next_address`](crate::program::model::address::AddressIterator::next_address); `remove()`
//! (which Java unconditionally throws `UnsupportedOperationException` from) and the
//! self-returning `iterator()` are not modeled, matching every other `AddressIterator` implementor
//! in this port.
//!
//! Java's `hasNext()` mutates the `nextAddress` field through a shared method receiver; the port's
//! [`AddressIterator::has_next`](crate::program::model::address::AddressIterator::has_next) takes
//! `&self`, so [`DefaultAddressIteratorConverter`] caches the pending address, the wrapped
//! iterator, and the two `Program`s behind `RefCell` for interior mutability -- the same technique
//! [`AddressIteratorAdapter`](crate::program::model::address::AddressIteratorAdapter) uses to cache
//! its next value.

use std::cell::RefCell;

use crate::program::model::address::{Address, AddressIterator};
use crate::program::model::listing::Program;
use crate::program::util::simple_diff_utility::{DefaultSimpleDiffUtility, SimpleDiffUtility};

/// Port of `ghidra.program.util.AddressIteratorConverter`. See the module docs for why this is a
/// marker supertrait of [`AddressIterator`] rather than adding new trait methods.
pub trait AddressIteratorConverter: AddressIterator {}

/// An `AddressIterator` that converts each address produced by a wrapped iterator (owned by
/// `iterators_program`) into the corresponding address in `other_program`, skipping addresses
/// with no compatible equivalent.
///
/// Port of `ghidra.program.util.AddressIteratorConverter`.
pub struct DefaultAddressIteratorConverter {
    iterators_program: RefCell<Box<dyn Program>>,
    iterator: RefCell<Box<dyn AddressIterator>>,
    other_program: RefCell<Box<dyn Program>>,
    next_address: RefCell<Option<Address>>,
    diff_utility: Box<dyn SimpleDiffUtility>,
}

impl DefaultAddressIteratorConverter {
    /// Constructs a converter that will convert the given address iterator, whose addresses
    /// originate from `iterators_program`, into corresponding addresses in `other_program`.
    ///
    /// Port of `AddressIteratorConverter(Program, AddressIterator, Program)`.
    pub fn new(
        iterators_program: Box<dyn Program>,
        iterator: Box<dyn AddressIterator>,
        other_program: Box<dyn Program>,
    ) -> Self {
        Self {
            iterators_program: RefCell::new(iterators_program),
            iterator: RefCell::new(iterator),
            other_program: RefCell::new(other_program),
            next_address: RefCell::new(None),
            diff_utility: Box::new(DefaultSimpleDiffUtility),
        }
    }
}

impl AddressIterator for DefaultAddressIteratorConverter {
    /// Port of `AddressIteratorConverter.hasNext()`.
    fn has_next(&self) -> bool {
        if self.next_address.borrow().is_some() {
            return true;
        }
        loop {
            if !self.iterator.borrow().has_next() {
                return false;
            }
            let Some(address) = self.iterator.borrow_mut().next_address() else {
                return false;
            };
            let converted = {
                let mut iterators_program = self.iterators_program.borrow_mut();
                let mut other_program = self.other_program.borrow_mut();
                self.diff_utility.get_compatible_address(
                    &mut **iterators_program,
                    &address,
                    &mut **other_program,
                )
            };
            if let Some(converted_address) = converted {
                *self.next_address.borrow_mut() = Some(converted_address);
                return true;
            }
        }
    }

    /// Port of `AddressIteratorConverter.next()`.
    fn next_address(&mut self) -> Option<Address> {
        if let Some(address) = self.next_address.borrow_mut().take() {
            return Some(address);
        }
        if self.has_next() {
            return self.next_address.borrow_mut().take();
        }
        None
    }
}

impl AddressIteratorConverter for DefaultAddressIteratorConverter {}

/// Constructs a boxed [`AddressIteratorConverter`], mirroring the Java class's public
/// constructor while letting callers depend only on the trait.
pub fn new_address_iterator_converter(
    iterators_program: Box<dyn Program>,
    iterator: Box<dyn AddressIterator>,
    other_program: Box<dyn Program>,
) -> Box<dyn AddressIteratorConverter> {
    Box::new(DefaultAddressIteratorConverter::new(
        iterators_program,
        iterator,
        other_program,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::DomainObject;
    use crate::program::model::address::{
        AddressFactory, AddressIteratorAdapter, AddressSpace, AddressSpaceType, DefaultAddressFactory,
    };
    use std::sync::Arc;

    struct MockProgram {
        factory: Arc<dyn AddressFactory>,
        language_id: String,
    }

    impl DomainObject for MockProgram {}

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            self.language_id.clone()
        }

        fn get_address_factory(&self) -> Option<Arc<dyn AddressFactory>> {
            Some(self.factory.clone())
        }
    }

    fn mock_program(space: Arc<AddressSpace>, language_id: &str) -> Box<dyn Program> {
        Box::new(MockProgram {
            factory: Arc::new(DefaultAddressFactory::new(vec![space])),
            language_id: language_id.to_string(),
        })
    }

    #[test]
    fn converts_addresses_present_in_both_programs_and_skips_unmapped_spaces() {
        let ram_a = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let ram_b = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let code_only_in_a = AddressSpace::new("code", 32, 1, AddressSpaceType::Code, 1);

        let source_addresses = vec![
            ram_a.address(0x1000),
            code_only_in_a.address(0x10),
            ram_a.address(0x2000),
        ];
        let wrapped = Box::new(AddressIteratorAdapter::new(source_addresses.into_iter()));

        let mut converter = DefaultAddressIteratorConverter::new(
            mock_program(ram_a.clone(), "lang-A"),
            wrapped,
            mock_program(ram_b.clone(), "lang-B"),
        );

        let mut results = Vec::new();
        while converter.has_next() {
            results.push(converter.next_address().expect("next after has_next"));
        }

        assert_eq!(results, vec![ram_b.address(0x1000), ram_b.address(0x2000)]);
        assert!(converter.next_address().is_none());
    }

    #[test]
    fn address_iterator_converter_is_object_safe_through_a_trait_object() {
        let ram_a = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let ram_b = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0);
        let wrapped = Box::new(AddressIteratorAdapter::new(
            vec![ram_a.address(0x400)].into_iter(),
        ));

        let mut converter: Box<dyn AddressIteratorConverter> = new_address_iterator_converter(
            mock_program(ram_a.clone(), "lang"),
            wrapped,
            mock_program(ram_b.clone(), "lang"),
        );

        assert!(converter.has_next());
        assert_eq!(converter.next_address(), Some(ram_b.address(0x400)));
        assert!(!converter.has_next());
    }
}
