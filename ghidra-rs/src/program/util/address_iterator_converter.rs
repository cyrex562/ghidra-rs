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

use crate::program::model::address::{Address, BoxedAddressIterator};
use crate::program::model::listing::Program;
use crate::program::util::simple_diff_utility::{DefaultSimpleDiffUtility, SimpleDiffUtility};

/// Port of `ghidra.program.util.AddressIteratorConverter`. See the module docs for why this is a
/// marker supertrait of [`AddressIterator`] rather than adding new trait methods.
pub trait AddressIteratorConverter: Iterator<Item = Address> {}

/// An `AddressIterator` that converts each address produced by a wrapped iterator (owned by
/// `iterators_program`) into the corresponding address in `other_program`, skipping addresses
/// with no compatible equivalent.
///
/// Port of `ghidra.program.util.AddressIteratorConverter`.
pub struct DefaultAddressIteratorConverter {
    iterators_program: Box<dyn Program>,
    iterator: BoxedAddressIterator,
    other_program: Box<dyn Program>,
    diff_utility: Box<dyn SimpleDiffUtility>,
}

impl DefaultAddressIteratorConverter {
    /// Constructs a converter that will convert the given address iterator, whose addresses
    /// originate from `iterators_program`, into corresponding addresses in `other_program`.
    ///
    /// Port of `AddressIteratorConverter(Program, BoxedAddressIterator, Program)`.
    pub fn new(
        iterators_program: Box<dyn Program>,
        iterator: BoxedAddressIterator,
        other_program: Box<dyn Program>,
    ) -> Self {
        Self {
            iterators_program,
            iterator,
            other_program,
            diff_utility: Box::new(DefaultSimpleDiffUtility),
        }
    }
}

impl Iterator for DefaultAddressIteratorConverter {
    type Item = Address;

    /// Port of `AddressIteratorConverter.hasNext()` + `next()`, which collapse into one method.
    ///
    /// Java needed the pair because `hasNext()` had to *find* the next convertible address in
    /// order to answer, then stash it in a field for `next()` to return. `Iterator::next`
    /// returns `Option`, so the lookahead buffer -- and the `RefCell`s that existed only so the
    /// `&self` signature of `hasNext` could mutate the wrapped iterator -- are all unnecessary.
    /// Addresses with no counterpart in the other program are skipped, as before.
    fn next(&mut self) -> Option<Address> {
        loop {
            let address = self.iterator.next()?;
            if let Some(converted) = self.diff_utility.get_compatible_address(
                &mut *self.iterators_program,
                &address,
                &mut *self.other_program,
            ) {
                return Some(converted);
            }
        }
    }
}

impl AddressIteratorConverter for DefaultAddressIteratorConverter {}

/// Constructs a boxed [`AddressIteratorConverter`], mirroring the Java class's public
/// constructor while letting callers depend only on the trait.
pub fn new_address_iterator_converter(
    iterators_program: Box<dyn Program>,
    iterator: BoxedAddressIterator,
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
        while let Some(address) = converter.next() {
            results.push(address);
        }

        assert_eq!(results, vec![ram_b.address(0x1000), ram_b.address(0x2000)]);
        assert!(converter.next().is_none());
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
        assert_eq!(converter.next(), Some(ram_b.address(0x400)));
        assert_eq!(converter.next(), None);
    }
}
