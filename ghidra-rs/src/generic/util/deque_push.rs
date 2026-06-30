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
///     let _guard = DequePush::push(&mut stack, "hello");
///     assert_eq!(stack.front(), Some(&"hello"));
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
        let _guard = DequePush::push(&mut stack, 42);
        assert_eq!(stack.front(), Some(&42));
    }

    #[test]
    fn drop_removes_element() {
        let mut stack: VecDeque<i32> = VecDeque::new();
        {
            let _guard = DequePush::push(&mut stack, 1);
            assert_eq!(stack.len(), 1);
        }
        assert!(stack.is_empty());
    }

    #[test]
    fn nested_push_restores_previous_top() {
        let mut stack: VecDeque<&str> = VecDeque::new();
        let _outer = DequePush::push(&mut stack, "outer");
        {
            let _inner = DequePush::push(&mut stack, "inner");
            assert_eq!(stack.front(), Some(&"inner"));
        }
        assert_eq!(stack.front(), Some(&"outer"));
        assert_eq!(stack.len(), 1);
    }

    #[test]
    fn push_to_existing_stack_preserves_prior_elements() {
        let mut stack: VecDeque<i32> = VecDeque::from([10, 20]);
        {
            let _guard = DequePush::push(&mut stack, 5);
            assert_eq!(stack.front(), Some(&5));
            assert_eq!(stack.len(), 3);
        }
        assert_eq!(stack.front(), Some(&10));
        assert_eq!(stack.len(), 2);
    }

    #[test]
    fn multiple_sequential_pushes() {
        let mut stack: VecDeque<u8> = VecDeque::new();
        {
            let _a = DequePush::push(&mut stack, 1u8);
            {
                let _b = DequePush::push(&mut stack, 2u8);
                assert_eq!(stack.front(), Some(&2u8));
            }
            assert_eq!(stack.front(), Some(&1u8));
        }
        assert!(stack.is_empty());
    }
}
