use crate::program::seam_stubs::CodeBlock;
use crate::util::exception::CancelledException;

/// An iterator interface over [`CodeBlock`]s.
///
/// Note: this iterator is also adaptable to a standard Rust `Iterator` via [`CodeBlockIter`].
/// The [`has_next`](CodeBlockIterator::has_next) and [`next`](CodeBlockIterator::next) methods
/// of this trait return a [`CancelledException`] if the monitor is cancelled. The `Iterator`
/// returned from [`iter`](CodeBlockIterator::iter) does *not* surface that error; if you need to
/// know the cancelled state, check the monitor that was passed into this iterator via the
/// `CodeBlockModel` directly.
///
/// Port of `ghidra.program.model.block.CodeBlockIterator`.
pub trait CodeBlockIterator {
    /// Return true if `next()` will return a `CodeBlock`.
    fn has_next(&mut self) -> Result<bool, CancelledException>;

    /// Return the next `CodeBlock`.
    fn next(&mut self) -> Result<Box<dyn CodeBlock>, CancelledException>;

    /// Adapts this iterator to a standard Rust `Iterator`, mirroring the Java default
    /// `iterator()` method. A `CancelledException` raised while iterating stops iteration
    /// (yields `None`), matching Java's `catch (CancelledException e) { return false/null; }`.
    fn iter(&mut self) -> CodeBlockIter<'_>
    where
        Self: Sized,
    {
        CodeBlockIter { inner: self }
    }
}

/// Standard Rust `Iterator` adapter over a [`CodeBlockIterator`].
///
/// Port of the anonymous `Iterator<CodeBlock>` returned from
/// `CodeBlockIterator.iterator()` in Java.
pub struct CodeBlockIter<'a> {
    inner: &'a mut dyn CodeBlockIterator,
}

impl<'a> CodeBlockIter<'a> {
    /// Wraps the given `CodeBlockIterator` as a standard Rust `Iterator`.
    pub fn new(inner: &'a mut dyn CodeBlockIterator) -> Self {
        Self { inner }
    }
}

impl<'a> Iterator for CodeBlockIter<'a> {
    type Item = Box<dyn CodeBlock>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.has_next() {
            Ok(true) => self.inner.next().ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCodeBlock;

    impl CodeBlock for MockCodeBlock {}

    /// A mock iterator over a fixed count of blocks, proving `CodeBlockIterator` is object-safe
    /// and that a `CancelledException` from `has_next`/`next` behaves like the Java contract.
    struct CountingCodeBlockIterator {
        remaining: usize,
        cancel_after: Option<usize>,
    }

    impl CodeBlockIterator for CountingCodeBlockIterator {
        fn has_next(&mut self) -> Result<bool, CancelledException> {
            if let Some(0) = self.cancel_after {
                return Err(CancelledException("cancelled".to_string()));
            }
            Ok(self.remaining > 0)
        }

        fn next(&mut self) -> Result<Box<dyn CodeBlock>, CancelledException> {
            if let Some(n) = self.cancel_after {
                if n == 0 {
                    return Err(CancelledException("cancelled".to_string()));
                }
                self.cancel_after = Some(n - 1);
            }
            if self.remaining == 0 {
                return Err(CancelledException("no more blocks".to_string()));
            }
            self.remaining -= 1;
            Ok(Box::new(MockCodeBlock))
        }
    }

    #[test]
    fn has_next_and_next_walk_all_blocks() {
        let mut iter: Box<dyn CodeBlockIterator> = Box::new(CountingCodeBlockIterator {
            remaining: 3,
            cancel_after: None,
        });

        let mut count = 0;
        while iter.has_next().unwrap() {
            iter.next().unwrap();
            count += 1;
        }
        assert_eq!(count, 3);
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn std_iterator_adapter_yields_expected_count() {
        let mut iter = CountingCodeBlockIterator {
            remaining: 4,
            cancel_after: None,
        };

        let collected: Vec<_> = iter.iter().collect();
        assert_eq!(collected.len(), 4);
    }

    #[test]
    fn std_iterator_adapter_stops_on_cancellation_without_propagating_error() {
        let mut iter = CountingCodeBlockIterator {
            remaining: 5,
            cancel_after: Some(2),
        };

        let collected: Vec<_> = iter.iter().collect();
        assert_eq!(collected.len(), 2);
    }
}
