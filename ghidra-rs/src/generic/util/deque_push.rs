use std::collections::VecDeque;

/// RAII guard that pushes an element onto a deque on construction and pops it on drop.
///
/// Mirrors `generic.util.DequePush` from Ghidra. Use [`DequePush::push`] inside a
/// scoped block to ensure the element is popped even if the block exits early.
///
/// ```
/// use std::collections::VecDeque;
/// use ghidra_rs::generic::util::deque_push::DequePush;
///
/// let mut stack: VecDeque<&str> = VecDeque::new();
/// {
///     let guard = DequePush::push(&mut stack, "hello");
///     assert_eq!(guard.stack().front(), Some(&"hello"));
/// }
/// assert!(stack.is_empty());
/// ```
pub struct DequePush<'a, E> {
    stack: &'a mut VecDeque<E>,
}

impl<'a, E> DequePush<'a, E> {
    /// Push `elem` onto the front of `stack` and return a guard that pops it on drop.
    pub fn push(stack: &'a mut VecDeque<E>, elem: E) -> Self {
        stack.push_front(elem);
        DequePush { stack }
    }

    /// Borrow the underlying deque while the guard is alive.
    ///
    /// The guard holds an exclusive (`&mut`) borrow of the deque for its whole
    /// lifetime, so the original binding cannot be read until the guard is
    /// dropped; this accessor exposes the deque through the guard instead.
    pub fn stack(&self) -> &VecDeque<E> {
        self.stack
    }

    /// Mutably borrow the underlying deque while the guard is alive.
    ///
    /// Useful for nesting a further [`DequePush`] on top of this guard's deque.
    pub fn stack_mut(&mut self) -> &mut VecDeque<E> {
        self.stack
    }
}

impl<E> Drop for DequePush<'_, E> {
    fn drop(&mut self) {
        self.stack.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_adds_element_to_front() {
        let mut stack: VecDeque<i32> = VecDeque::new();
        let guard = DequePush::push(&mut stack, 42);
        assert_eq!(guard.stack().front(), Some(&42));
    }

    #[test]
    fn drop_removes_element() {
        let mut stack: VecDeque<i32> = VecDeque::new();
        {
            let guard = DequePush::push(&mut stack, 1);
            assert_eq!(guard.stack().len(), 1);
        }
        assert!(stack.is_empty());
    }

    #[test]
    fn nested_push_restores_previous_top() {
        let mut stack: VecDeque<&str> = VecDeque::new();
        let mut outer = DequePush::push(&mut stack, "outer");
        {
            let inner = DequePush::push(outer.stack_mut(), "inner");
            assert_eq!(inner.stack().front(), Some(&"inner"));
        }
        assert_eq!(outer.stack().front(), Some(&"outer"));
        assert_eq!(outer.stack().len(), 1);
    }

    #[test]
    fn push_to_existing_stack_preserves_prior_elements() {
        let mut stack: VecDeque<i32> = VecDeque::from([10, 20]);
        {
            let guard = DequePush::push(&mut stack, 5);
            assert_eq!(guard.stack().front(), Some(&5));
            assert_eq!(guard.stack().len(), 3);
        }
        assert_eq!(stack.front(), Some(&10));
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn multiple_sequential_pushes() {
        let mut stack: VecDeque<u8> = VecDeque::new();
        {
            let mut a = DequePush::push(&mut stack, 1u8);
            {
                let b = DequePush::push(a.stack_mut(), 2u8);
                assert_eq!(b.stack().front(), Some(&2u8));
            }
            assert_eq!(a.stack().front(), Some(&1u8));
        }
        assert!(stack.is_empty());
    }
}
