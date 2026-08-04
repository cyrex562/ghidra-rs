use crate::format::seam_stubs::AbstractMsSymbol;

/// Error raised by [`MsSymbolIterator::peek`] and [`MsSymbolIterator::next`] when no more
/// symbols remain.
///
/// Mirrors Java's `NoSuchElementException`, as thrown by `MsSymbolIterator.peek()` and
/// `MsSymbolIterator.next()`.
#[derive(Debug)]
pub struct NoSuchElementError;

impl std::fmt::Display for NoSuchElementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "No such element")
    }
}

impl std::error::Error for NoSuchElementError {}

/// Iterator over the [`AbstractMsSymbol`] records of a symbol stream.
///
/// Mirrors `ghidra.app.util.bin.format.pdb2.pdbreader.MsSymbolIterator`. Modeled as a trait
/// (rather than a concrete struct) because this type was selected as a dependency-cycle
/// cut-point: the Java constructor pulls in `AbstractPdb` (via its `SymbolRecords`), which in
/// turn pulls in the applicator's `SymbolGroup` -- the very cycle this port needs to break.
///
/// The Java class's private retrieval state (`nextRetrieveOffset`, `currentOffset`, cached
/// `SymLen`) is an implementation detail of however a concrete implementor sources its records
/// (e.g. from a real `SymbolRecords`, or a canned test fixture), so it is left out of the trait
/// entirely -- only the public iteration surface is required, matching the pattern already used
/// by [`ParsingIterator`](crate::format::pdb2::pdbreader::parsing_iterator::ParsingIterator).
pub trait MsSymbolIterator {
    /// Returns `true` if there is a next symbol available.
    fn has_next(&self) -> bool;

    /// Peeks at and returns the next symbol without advancing the iterator.
    ///
    /// # Errors
    /// Returns [`NoSuchElementError`] if there are no more elements.
    fn peek(&self) -> Result<&dyn AbstractMsSymbol, NoSuchElementError>;

    /// Returns the next symbol and advances the iterator.
    ///
    /// # Errors
    /// Returns [`NoSuchElementError`] if there are no more elements.
    fn next(&mut self) -> Result<Box<dyn AbstractMsSymbol>, NoSuchElementError>;

    /// Returns the buffer offset of the symbol currently cached for retrieval (i.e. the offset
    /// that [`Self::peek`] or the next call to [`Self::next`] would return).
    fn get_current_offset(&self) -> i64;

    /// Initializes the mechanism for requesting the symbols in sequence, starting from the
    /// iterator's original start offset.
    fn init_get(&mut self);

    /// Initializes the mechanism for requesting the symbols in sequence, starting from `offset`.
    fn init_get_by_offset(&mut self, offset: i64);

    /// Returns the stream number this iterator reads from.
    fn get_stream_number(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MockSymbol {
        name: String,
    }

    impl AbstractMsSymbol for MockSymbol {}

    /// A minimal implementor that replicates the Java class's retrieval algorithm (including its
    /// `getCurrentOffset()` quirk of tracking the *cached* record's offset, not the offset of the
    /// record just returned by `next()`) against an in-memory offset -> (length, name) table.
    /// Proves [`MsSymbolIterator`] is object-safe (usable as `Box<dyn MsSymbolIterator>`) while
    /// exercising real offset-tracking behavior.
    struct FixtureIterator {
        stream_number: i32,
        start_offset: i64,
        length_symbols: i64,
        records: BTreeMap<i64, (i64, String)>,
        next_retrieve_offset: i64,
        current_offset: i64,
        cached: Option<(i64, Box<dyn AbstractMsSymbol>)>,
    }

    impl FixtureIterator {
        fn new(
            stream_number: i32,
            start_offset: i64,
            length_symbols: i64,
            records: Vec<(i64, i64, &str)>,
        ) -> Self {
            let records =
                records.into_iter().map(|(o, l, n)| (o, (l, n.to_string()))).collect();
            let mut iter = FixtureIterator {
                stream_number,
                start_offset,
                length_symbols,
                records,
                next_retrieve_offset: 0,
                current_offset: 0,
                cached: None,
            };
            iter.init_get();
            iter
        }

        fn retrieve_record(&mut self) -> Option<(i64, Box<dyn AbstractMsSymbol>)> {
            if self.next_retrieve_offset >= self.length_symbols {
                return None;
            }
            let (length, name) = {
                let entry = self.records.get(&self.next_retrieve_offset)?;
                (entry.0, entry.1.clone())
            };
            let offset = self.next_retrieve_offset;
            self.next_retrieve_offset += length;
            Some((offset, Box::new(MockSymbol { name })))
        }

        /// Test-only accessor for the cached symbol's name, bypassing the trait's opaque
        /// `dyn AbstractMsSymbol` to verify iteration order.
        fn peek_name(&self) -> Option<&str> {
            self.cached.as_ref().map(|(_, sym)| {
                // Downcast unavailable on this minimal marker trait; identify the record by its
                // cached offset instead, which is unique per record in these fixtures.
                let _ = sym;
                self.records[&self.current_offset].1.as_str()
            })
        }
    }

    impl MsSymbolIterator for FixtureIterator {
        fn has_next(&self) -> bool {
            self.cached.is_some()
        }

        fn peek(&self) -> Result<&dyn AbstractMsSymbol, NoSuchElementError> {
            self.cached.as_ref().map(|(_, sym)| sym.as_ref()).ok_or(NoSuchElementError)
        }

        fn next(&mut self) -> Result<Box<dyn AbstractMsSymbol>, NoSuchElementError> {
            let (_, offer) = self.cached.take().ok_or(NoSuchElementError)?;
            self.current_offset = self.next_retrieve_offset;
            self.cached = self.retrieve_record();
            Ok(offer)
        }

        fn get_current_offset(&self) -> i64 {
            self.current_offset
        }

        fn init_get(&mut self) {
            self.next_retrieve_offset = self.start_offset;
            self.current_offset = self.next_retrieve_offset;
            self.cached = self.retrieve_record();
        }

        fn init_get_by_offset(&mut self, offset: i64) {
            self.next_retrieve_offset = offset;
            self.current_offset = self.next_retrieve_offset;
            self.cached = self.retrieve_record();
        }

        fn get_stream_number(&self) -> i32 {
            self.stream_number
        }
    }

    fn three_records() -> Vec<(i64, i64, &'static str)> {
        vec![(0, 4, "Sym0"), (4, 4, "Sym4"), (8, 4, "Sym8")]
    }

    #[test]
    fn boxed_trait_object_iterates_records_in_order_and_tracks_offsets() {
        let mut iter: Box<dyn MsSymbolIterator> =
            Box::new(FixtureIterator::new(7, 0, 12, three_records()));

        assert_eq!(iter.get_stream_number(), 7);
        assert!(iter.has_next());
        // Right after init, the cached (peekable) record is the one at the start offset.
        assert_eq!(iter.get_current_offset(), 0);

        let _ = iter.next().unwrap();
        // Mirrors the Java class's quirk: getCurrentOffset() after next() reports the offset of
        // the *newly cached* record (the one the next call will return), not the one just
        // returned.
        assert_eq!(iter.get_current_offset(), 4);
        assert!(iter.has_next());

        let _ = iter.next().unwrap();
        assert_eq!(iter.get_current_offset(), 8);
        assert!(iter.has_next());

        let _ = iter.next().unwrap();
        assert_eq!(iter.get_current_offset(), 12);
        assert!(!iter.has_next());
    }

    #[test]
    fn next_errors_when_exhausted() {
        let mut iter = FixtureIterator::new(1, 0, 0, vec![]);
        assert!(!iter.has_next());
        assert!(matches!(iter.next(), Err(NoSuchElementError)));
    }

    #[test]
    fn peek_errors_when_exhausted() {
        let iter = FixtureIterator::new(1, 0, 0, vec![]);
        assert!(matches!(iter.peek(), Err(NoSuchElementError)));
    }

    #[test]
    fn peek_does_not_advance_iterator() {
        let mut iter = FixtureIterator::new(1, 0, 8, three_records());
        assert!(iter.peek().is_ok());
        assert_eq!(iter.peek_name(), Some("Sym0"));
        assert!(iter.peek().is_ok());
        assert_eq!(iter.peek_name(), Some("Sym0"));
        let _ = iter.next().unwrap();
        assert_eq!(iter.peek_name(), Some("Sym4"));
    }

    #[test]
    fn init_get_by_offset_repositions_iterator() {
        let mut iter = FixtureIterator::new(1, 0, 12, three_records());
        iter.init_get_by_offset(4);
        assert_eq!(iter.get_current_offset(), 4);
        assert_eq!(iter.peek_name(), Some("Sym4"));
    }

    #[test]
    fn init_get_resets_to_original_start_offset() {
        let mut iter = FixtureIterator::new(1, 4, 12, three_records());
        assert_eq!(iter.get_current_offset(), 4);
        let _ = iter.next().unwrap();
        assert_eq!(iter.get_current_offset(), 8);
        iter.init_get();
        assert_eq!(iter.get_current_offset(), 4);
        assert_eq!(iter.peek_name(), Some("Sym4"));
    }

    #[test]
    fn no_such_element_error_display() {
        assert_eq!(NoSuchElementError.to_string(), "No such element");
    }
}
