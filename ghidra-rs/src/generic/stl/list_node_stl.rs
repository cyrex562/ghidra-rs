use std::ptr::NonNull;

/// Internal doubly-linked list node, mirroring `generic.stl.ListNodeSTL<T>`.
///
/// Both link fields are raw non-owning pointers because the circular structure
/// of the list cannot be expressed with Rust's reference types without leaking.
/// The containing list owns every node through a [`Box`] and is responsible for
/// calling [`ListNodeStl::dealloc`] on every node when the list is dropped.
pub struct ListNodeStl<T> {
    pub(super) next: Option<NonNull<ListNodeStl<T>>>,
    pub(super) prev: Option<NonNull<ListNodeStl<T>>>,
    /// Element stored at this position; `None` for sentinel header nodes.
    pub value: Option<T>,
    /// Optional debug stack-frame capture. Mirrors the `stackUse` field from the
    /// Java source; set externally by callers for diagnostic purposes.
    pub stack_use: Option<Vec<String>>,
}

impl<T> ListNodeStl<T> {
    /// Allocates a sentinel (header) node whose `next` and `prev` both reference
    /// itself, forming an empty circular list.
    ///
    /// Mirrors the Java default constructor `new ListNodeSTL<>()`.
    pub fn alloc_sentinel() -> NonNull<Self> {
        let raw = Box::into_raw(Box::new(Self {
            next: None,
            prev: None,
            value: None,
            stack_use: None,
        }));
        // SAFETY: Box::into_raw never returns null.
        let ptr = unsafe { NonNull::new_unchecked(raw) };
        // SAFETY: `raw` is uniquely owned at this point; wiring the self-references is safe.
        unsafe {
            (*raw).next = Some(ptr);
            (*raw).prev = Some(ptr);
        }
        ptr
    }

    /// Allocates a data node with explicit predecessor and successor links.
    ///
    /// Mirrors the Java constructor `new ListNodeSTL<>(prev, next, value)`.
    pub fn alloc(prev: NonNull<Self>, next: NonNull<Self>, value: T) -> NonNull<Self> {
        let raw = Box::into_raw(Box::new(Self {
            next: Some(next),
            prev: Some(prev),
            value: Some(value),
            stack_use: None,
        }));
        // SAFETY: Box::into_raw never returns null.
        unsafe { NonNull::new_unchecked(raw) }
    }

    /// Frees the memory for `ptr`.
    ///
    /// # Safety
    /// - `ptr` must originate from [`Self::alloc_sentinel`] or [`Self::alloc`].
    /// - `ptr` must still be valid and not yet freed.
    /// - After this call, no other raw pointer into this allocation may be dereferenced.
    pub unsafe fn dealloc(ptr: NonNull<Self>) {
        drop(Box::from_raw(ptr.as_ptr()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn sentinel_links_point_to_itself() {
        let s = ListNodeStl::<i32>::alloc_sentinel();
        unsafe {
            let p = s.as_ptr();
            assert!(ptr::eq((*p).next.unwrap().as_ptr(), p), "next must point to sentinel");
            assert!(ptr::eq((*p).prev.unwrap().as_ptr(), p), "prev must point to sentinel");
            assert!((*p).value.is_none());
            assert!((*p).stack_use.is_none());
            ListNodeStl::dealloc(s);
        }
    }

    #[test]
    fn alloc_node_links_and_value() {
        let sentinel = ListNodeStl::<i32>::alloc_sentinel();
        unsafe {
            let node = ListNodeStl::alloc(sentinel, sentinel, 42);
            let np = node.as_ptr();
            assert!(ptr::eq((*np).prev.unwrap().as_ptr(), sentinel.as_ptr()));
            assert!(ptr::eq((*np).next.unwrap().as_ptr(), sentinel.as_ptr()));
            assert_eq!((*np).value, Some(42));
            assert!((*np).stack_use.is_none());
            ListNodeStl::dealloc(node);
            ListNodeStl::dealloc(sentinel);
        }
    }

    #[test]
    fn stack_use_field_can_be_set() {
        let s = ListNodeStl::<i32>::alloc_sentinel();
        unsafe {
            (*s.as_ptr()).stack_use =
                Some(vec!["frame0".to_string(), "frame1".to_string()]);
            let frames = (*s.as_ptr()).stack_use.as_ref().unwrap();
            assert_eq!(frames.len(), 2);
            assert_eq!(frames[0], "frame0");
            ListNodeStl::dealloc(s);
        }
    }

    #[test]
    fn pointer_manipulation_two_element_list() {
        // Build: sentinel <-> a(1) <-> b(2) <-> sentinel
        let sentinel = ListNodeStl::<i32>::alloc_sentinel();
        unsafe {
            let a = ListNodeStl::alloc(sentinel, sentinel, 1);
            (*sentinel.as_ptr()).next = Some(a);
            (*sentinel.as_ptr()).prev = Some(a);

            let b = ListNodeStl::alloc(a, sentinel, 2);
            (*a.as_ptr()).next = Some(b);
            (*sentinel.as_ptr()).prev = Some(b);

            // Verify forward traversal: sentinel -> a -> b -> sentinel
            let n0 = (*sentinel.as_ptr()).next.unwrap();
            let n1 = (*n0.as_ptr()).next.unwrap();
            let n2 = (*n1.as_ptr()).next.unwrap();
            assert!(ptr::eq(n0.as_ptr(), a.as_ptr()));
            assert!(ptr::eq(n1.as_ptr(), b.as_ptr()));
            assert!(ptr::eq(n2.as_ptr(), sentinel.as_ptr()));

            // Verify values
            assert_eq!((*a.as_ptr()).value, Some(1));
            assert_eq!((*b.as_ptr()).value, Some(2));

            // Remove a: sentinel <-> b <-> sentinel
            (*sentinel.as_ptr()).next = (*a.as_ptr()).next;
            (*b.as_ptr()).prev = Some(sentinel);
            ListNodeStl::dealloc(a);

            let after = (*sentinel.as_ptr()).next.unwrap();
            assert!(ptr::eq(after.as_ptr(), b.as_ptr()));
            assert_eq!((*after.as_ptr()).value, Some(2));

            ListNodeStl::dealloc(b);
            ListNodeStl::dealloc(sentinel);
        }
    }
}
