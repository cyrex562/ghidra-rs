use std::marker::PhantomData;

/// A do-nothing stub implementation of a queue.
///
/// Every mutating operation is a no-op; every query reports the collection as
/// permanently empty.  Intended as a safe placeholder wherever a queue is
/// required but no actual queuing behaviour is wanted.
///
/// Port of `ghidra.util.datastruct.QueueStub`.
pub struct QueueStub<E> {
    _phantom: PhantomData<E>,
}

impl<E> QueueStub<E> {
    /// Creates a new `QueueStub`.
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    /// Always returns `0`.
    pub fn size(&self) -> usize {
        0
    }

    /// Always returns `true`.
    pub fn is_empty(&self) -> bool {
        true
    }

    /// Always returns `false`.
    pub fn contains(&self, _o: &E) -> bool {
        false
    }

    /// Returns an iterator that yields no elements.
    pub fn iter(&self) -> std::iter::Empty<&E> {
        std::iter::empty()
    }

    /// No-op; always returns `false`.
    pub fn remove_item(&mut self, _o: &E) -> bool {
        false
    }

    /// Always returns `false`.
    pub fn contains_all(&self, _c: &[E]) -> bool {
        false
    }

    /// No-op; always returns `false`.
    pub fn add_all(&mut self, _c: impl IntoIterator<Item = E>) -> bool {
        false
    }

    /// No-op; always returns `false`.
    pub fn remove_all(&mut self, _c: &[E]) -> bool {
        false
    }

    /// No-op; always returns `false`.
    pub fn retain_all(&mut self, _c: &[E]) -> bool {
        false
    }

    /// No-op.
    pub fn clear(&mut self) {}

    /// No-op; always returns `false`.
    pub fn add(&mut self, _e: E) -> bool {
        false
    }

    /// No-op; always returns `false`.
    pub fn offer(&mut self, _e: E) -> bool {
        false
    }

    /// Always returns `None`.
    pub fn remove(&mut self) -> Option<E> {
        None
    }

    /// Always returns `None`.
    pub fn poll(&mut self) -> Option<E> {
        None
    }

    /// Always returns `None`.
    pub fn element(&self) -> Option<&E> {
        None
    }

    /// Always returns `None`.
    pub fn peek(&self) -> Option<&E> {
        None
    }
}

impl<E> Default for QueueStub<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stub_is_empty() {
        let q: QueueStub<i32> = QueueStub::new();
        assert!(q.is_empty());
        assert_eq!(q.size(), 0);
    }

    #[test]
    fn contains_always_false() {
        let q: QueueStub<i32> = QueueStub::new();
        assert!(!q.contains(&42));
    }

    #[test]
    fn iter_yields_nothing() {
        let q: QueueStub<i32> = QueueStub::new();
        assert_eq!(q.iter().count(), 0);
    }

    #[test]
    fn add_and_offer_return_false() {
        let mut q: QueueStub<i32> = QueueStub::new();
        assert!(!q.add(1));
        assert!(!q.offer(2));
        assert!(q.is_empty());
    }

    #[test]
    fn remove_and_poll_return_none() {
        let mut q: QueueStub<i32> = QueueStub::new();
        assert!(q.remove().is_none());
        assert!(q.poll().is_none());
    }

    #[test]
    fn element_and_peek_return_none() {
        let q: QueueStub<i32> = QueueStub::new();
        assert!(q.element().is_none());
        assert!(q.peek().is_none());
    }

    #[test]
    fn remove_item_always_false() {
        let mut q: QueueStub<i32> = QueueStub::new();
        assert!(!q.remove_item(&99));
    }

    #[test]
    fn bulk_operations_always_false() {
        let mut q: QueueStub<i32> = QueueStub::new();
        assert!(!q.contains_all(&[1, 2]));
        assert!(!q.add_all(vec![1, 2, 3]));
        assert!(!q.remove_all(&[1]));
        assert!(!q.retain_all(&[1]));
    }

    #[test]
    fn clear_is_no_op() {
        let mut q: QueueStub<i32> = QueueStub::new();
        q.clear();
        assert!(q.is_empty());
    }

    #[test]
    fn default_creates_empty_stub() {
        let q: QueueStub<String> = QueueStub::default();
        assert!(q.is_empty());
    }
}
