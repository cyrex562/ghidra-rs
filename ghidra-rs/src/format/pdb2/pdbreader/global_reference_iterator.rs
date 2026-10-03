use crate::format::pdb2::pdbreader::global_reference_offset_iterator::GlobalReferenceOffsetIterator;
use crate::format::pdb2::pdbreader::ms_symbol_iterator::MsSymbolIterator;
use crate::format::pdb2::pdbreader::parsing_iterator::{ParsingIterator, ParsingIteratorError};
use crate::format::pdb2::pdbreader::pdb_exception::PdbException;
use crate::format::seam_stubs::{PdbDebugInfo, MAX_STREAM_LENGTH, NIL_STREAM_NUMBER};
use crate::util::exception::CancelledException;

/// Resolves and validates the symbol records stream number from a module's `PdbDebugInfo`,
/// mirroring the validation performed by `GlobalReferenceIterator`'s Java constructor.
///
/// A concrete implementor of [`GlobalReferenceIterator`] calls this with the `PdbDebugInfo` it
/// obtained from whatever `AbstractPdb` it holds, and stores the result as the value returned by
/// [`GlobalReferenceIterator::symbols_stream_number`].
///
/// # Errors
/// Returns [`PdbException`] if `debug_info` is `None` (mirrors the Java constructor's null check
/// on `pdb.getDebugInfo()`), or if the resolved stream number is `NIL_STREAM_NUMBER` (mirrors the
/// Java constructor's check that a symbol stream actually exists).
pub fn resolve_symbols_stream_number(
    debug_info: Option<&dyn PdbDebugInfo>,
) -> Result<i32, PdbException> {
    let debug_info = debug_info.ok_or_else(|| {
        PdbException::new("Cannot create GlobalReferenceIterator because PDB Debug Info is null")
    })?;
    let stream_number = debug_info.get_symbol_records_stream_number();
    if stream_number == NIL_STREAM_NUMBER {
        return Err(PdbException::new(
            "Cannot create GlobalReferenceIterator because there is no symbol stream",
        ));
    }
    Ok(stream_number)
}

/// Iterator of Global Reference Symbol Iterators (an iterator of iterators) over the Global
/// Reference Offsets section of a module stream. Each element is an [`MsSymbolIterator`] from
/// the global symbols section, initialized at the offset specified in this module's global
/// reference offset section.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.GlobalReferenceIterator`. Modeled as a
/// trait (rather than a concrete struct) because this type was selected as a dependency-cycle
/// cut-point: the Java constructor pulls in `AbstractPdb` (via `PdbDebugInfo` and, per element,
/// the concrete `MsSymbolIterator` constructor), which in turn pulls in collaborators that would
/// recreate the cycle this port needs to break.
///
/// The Java constructor's validation of `pdb.getDebugInfo()` and the resolved stream number is
/// exposed instead as the free function [`resolve_symbols_stream_number`], for a concrete
/// implementor's own constructor to call with whatever `AbstractPdb`/`PdbDebugInfo` it holds.
/// [`Self::make_symbol_iterator`] stands in for the Java constructor's per-element
/// `new MsSymbolIterator(pdb, symbolsStreamNumber, offset, MsfStream.MAX_STREAM_LENGTH)` call,
/// since [`MsSymbolIterator`] is itself a trait (no single concrete constructor to call
/// generically).
pub trait GlobalReferenceIterator {
    /// Returns the symbol records stream number resolved at construction (mirrors the private
    /// field `symbolsStreamNumber`, typically computed once via [`resolve_symbols_stream_number`]).
    fn symbols_stream_number(&self) -> i32;

    /// Mutable access to the offset iterator driving [`Self::find`] (mirrors the private field
    /// `offsetIterator`).
    fn offset_iterator_mut(&mut self) -> &mut GlobalReferenceOffsetIterator;

    /// Mutable access to the currently cached global symbol iterator slot (mirrors the private
    /// field `currentGlobalSymbolIterator`).
    fn cached_mut(&mut self) -> &mut Option<Box<dyn MsSymbolIterator>>;

    /// Constructs a new [`MsSymbolIterator`] over the global symbols section, initialized at
    /// `offset` within the symbols stream. Stands in for the Java constructor call
    /// `new MsSymbolIterator(pdb, streamNumber, offset, maxLength)`.
    fn make_symbol_iterator(
        &self,
        stream_number: i32,
        offset: u32,
        max_length: i32,
    ) -> Box<dyn MsSymbolIterator>;

    /// Advances to and caches the next global symbol iterator, or clears the cache if the
    /// offset iterator is exhausted.
    ///
    /// Mirrors the private method `GlobalReferenceIterator.find()`.
    ///
    /// # Errors
    /// Returns [`CancelledException`] upon user cancellation.
    fn find(&mut self) -> Result<(), CancelledException> {
        match self.offset_iterator_mut().next() {
            Ok(offset) => {
                let stream_number = self.symbols_stream_number();
                let iter = self.make_symbol_iterator(stream_number, offset, MAX_STREAM_LENGTH);
                *self.cached_mut() = Some(iter);
                Ok(())
            }
            Err(ParsingIteratorError::NoSuchElement) => {
                *self.cached_mut() = None;
                Ok(())
            }
            Err(ParsingIteratorError::Cancelled(e)) => Err(e),
        }
    }

    /// Returns `true` if there is a next global symbol iterator available.
    ///
    /// # Errors
    /// Returns [`CancelledException`] upon user cancellation.
    fn has_next(&mut self) -> Result<bool, CancelledException> {
        if self.cached_mut().is_none() {
            self.find()?;
        }
        Ok(self.cached_mut().is_some())
    }

    /// Returns the next global symbol iterator, advancing this iterator.
    ///
    /// # Errors
    /// - Returns [`ParsingIteratorError::Cancelled`] upon user cancellation.
    /// - Returns [`ParsingIteratorError::NoSuchElement`] if there are no more elements.
    fn next(&mut self) -> Result<Box<dyn MsSymbolIterator>, ParsingIteratorError> {
        if self.has_next().map_err(ParsingIteratorError::Cancelled)? {
            return Ok(self.cached_mut().take().unwrap());
        }
        Err(ParsingIteratorError::NoSuchElement)
    }

    /// Returns the next global symbol iterator without advancing this iterator.
    ///
    /// # Errors
    /// - Returns [`ParsingIteratorError::Cancelled`] upon user cancellation.
    /// - Returns [`ParsingIteratorError::NoSuchElement`] if there are no more elements.
    fn peek(&mut self) -> Result<&dyn MsSymbolIterator, ParsingIteratorError> {
        if self.has_next().map_err(ParsingIteratorError::Cancelled)? {
            return Ok(self.cached_mut().as_deref().unwrap());
        }
        Err(ParsingIteratorError::NoSuchElement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::pdb2::pdbreader::ms_symbol_iterator::NoSuchElementError;
    use crate::format::pdb2::pdbreader::pdb_byte_reader::PdbByteReader;
    use crate::format::seam_stubs::AbstractMsSymbol;
    use std::cell::RefCell;

    fn reader_with_offsets(offsets: &[u32]) -> PdbByteReader {
        let mut bytes = Vec::new();
        let size_field = (offsets.len() as u32) * 4;
        bytes.extend_from_slice(&size_field.to_le_bytes());
        for offset in offsets {
            bytes.extend_from_slice(&offset.to_le_bytes());
        }
        PdbByteReader::new(bytes)
    }

    /// Minimal [`MsSymbolIterator`] fixture: only [`get_stream_number`](MsSymbolIterator::get_stream_number)
    /// and [`get_current_offset`](MsSymbolIterator::get_current_offset) are exercised by these
    /// tests, since `GlobalReferenceIterator` only ever passes the constructed iterator through.
    struct FixtureSymbolIterator {
        stream_number: i32,
        offset: i64,
    }

    impl MsSymbolIterator for FixtureSymbolIterator {
        fn has_next(&self) -> bool {
            false
        }

        fn peek(&self) -> Result<&dyn AbstractMsSymbol, NoSuchElementError> {
            Err(NoSuchElementError)
        }

        fn next(&mut self) -> Result<Box<dyn AbstractMsSymbol>, NoSuchElementError> {
            Err(NoSuchElementError)
        }

        fn get_current_offset(&self) -> i64 {
            self.offset
        }

        fn init_get(&mut self) {}

        fn init_get_by_offset(&mut self, _offset: i64) {}

        fn get_stream_number(&self) -> i32 {
            self.stream_number
        }
    }

    struct MockDebugInfo {
        stream_number: i32,
    }

    impl PdbDebugInfo for MockDebugInfo {
        fn get_symbol_records_stream_number(&self) -> i32 {
            self.stream_number
        }
    }

    #[test]
    fn resolve_symbols_stream_number_errors_on_missing_debug_info() {
        let result = resolve_symbols_stream_number(None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_symbols_stream_number_errors_on_nil_stream_number() {
        let debug_info = MockDebugInfo { stream_number: NIL_STREAM_NUMBER };
        let result = resolve_symbols_stream_number(Some(&debug_info as &dyn PdbDebugInfo));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_symbols_stream_number_returns_stream_number() {
        let debug_info = MockDebugInfo { stream_number: 42 };
        let result = resolve_symbols_stream_number(Some(&debug_info as &dyn PdbDebugInfo));
        assert_eq!(result.unwrap(), 42);
    }

    /// A minimal implementor, holding a real [`GlobalReferenceOffsetIterator`] plus a call log,
    /// used to prove [`GlobalReferenceIterator`] is object-safe (usable as
    /// `Box<dyn GlobalReferenceIterator>`) while exercising real iteration and offset-threading
    /// behavior.
    struct TestGlobalReferenceIterator {
        symbols_stream_number: i32,
        offset_iterator: GlobalReferenceOffsetIterator,
        cached: Option<Box<dyn MsSymbolIterator>>,
        calls: RefCell<Vec<(i32, u32, i32)>>,
    }

    impl GlobalReferenceIterator for TestGlobalReferenceIterator {
        fn symbols_stream_number(&self) -> i32 {
            self.symbols_stream_number
        }

        fn offset_iterator_mut(&mut self) -> &mut GlobalReferenceOffsetIterator {
            &mut self.offset_iterator
        }

        fn cached_mut(&mut self) -> &mut Option<Box<dyn MsSymbolIterator>> {
            &mut self.cached
        }

        fn make_symbol_iterator(
            &self,
            stream_number: i32,
            offset: u32,
            max_length: i32,
        ) -> Box<dyn MsSymbolIterator> {
            self.calls.borrow_mut().push((stream_number, offset, max_length));
            Box::new(FixtureSymbolIterator { stream_number, offset: offset as i64 })
        }
    }

    #[test]
    fn boxed_trait_object_iterates_a_symbol_iterator_per_offset_and_exhausts() {
        let offset_iterator =
            GlobalReferenceOffsetIterator::new(reader_with_offsets(&[10, 20])).unwrap();
        let mut iter: Box<dyn GlobalReferenceIterator> = Box::new(TestGlobalReferenceIterator {
            symbols_stream_number: 7,
            offset_iterator,
            cached: None,
            calls: RefCell::new(Vec::new()),
        });

        assert!(iter.has_next().unwrap());
        let first = iter.next().unwrap();
        assert_eq!(first.get_stream_number(), 7);
        assert_eq!(first.get_current_offset(), 10);

        assert!(iter.has_next().unwrap());
        let peeked = iter.peek().unwrap();
        assert_eq!(peeked.get_current_offset(), 20);
        // peek() must not advance the iterator.
        assert!(iter.has_next().unwrap());
        let second = iter.next().unwrap();
        assert_eq!(second.get_stream_number(), 7);
        assert_eq!(second.get_current_offset(), 20);

        assert!(!iter.has_next().unwrap());
        assert!(matches!(iter.next(), Err(ParsingIteratorError::NoSuchElement)));
        assert!(matches!(iter.peek(), Err(ParsingIteratorError::NoSuchElement)));
    }

    #[test]
    fn make_symbol_iterator_receives_stream_number_offset_and_max_length() {
        let offset_iterator =
            GlobalReferenceOffsetIterator::new(reader_with_offsets(&[0x100, 0x200])).unwrap();
        let mut iter = TestGlobalReferenceIterator {
            symbols_stream_number: 3,
            offset_iterator,
            cached: None,
            calls: RefCell::new(Vec::new()),
        };

        let _ = iter.next().unwrap();
        let _ = iter.next().unwrap();
        assert!(!iter.has_next().unwrap());

        assert_eq!(
            iter.calls.into_inner(),
            vec![(3, 0x100, MAX_STREAM_LENGTH), (3, 0x200, MAX_STREAM_LENGTH)]
        );
    }

    #[test]
    fn has_next_false_for_empty_offset_iterator() {
        let offset_iterator = GlobalReferenceOffsetIterator::new(reader_with_offsets(&[])).unwrap();
        let mut iter = TestGlobalReferenceIterator {
            symbols_stream_number: 1,
            offset_iterator,
            cached: None,
            calls: RefCell::new(Vec::new()),
        };
        assert!(!iter.has_next().unwrap());
        assert!(matches!(iter.next(), Err(ParsingIteratorError::NoSuchElement)));
        assert!(iter.calls.into_inner().is_empty());
    }
}
