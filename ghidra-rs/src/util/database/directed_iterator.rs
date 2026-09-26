use std::io;

/// The direction of iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Backward,
}

impl Direction {
    /// Get the reverse of this direction.
    pub fn reverse(self) -> Direction {
        match self {
            Direction::Forward => Direction::Backward,
            Direction::Backward => Direction::Forward,
        }
    }
}

/// An iterator over some component of a
/// [`Table`](crate::framework::db::table::Table) -- a key or a record.
///
/// Unlike [`RemovableIterator`](super::db_synchronized_iterator::RemovableIterator), `next`
/// itself can fail with a real I/O error (not merely "no more elements"), so this stays a
/// `has_next`/`next` pair returning `io::Result` rather than `std::iter::Iterator`, mirroring
/// [`DBLongIterator`](crate::framework::db::DBLongIterator)'s convention for the same situation.
pub trait DirectedIterator<T> {
    /// Check if the table has another record.
    fn has_next(&mut self) -> io::Result<bool>;

    /// Get the component of the next record.
    fn next(&mut self) -> io::Result<T>;

    /// Delete the current record.
    fn delete(&mut self) -> io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_reverse_round_trips() {
        assert_eq!(Direction::Forward.reverse(), Direction::Backward);
        assert_eq!(Direction::Backward.reverse(), Direction::Forward);
        assert_eq!(Direction::Forward.reverse().reverse(), Direction::Forward);
    }

    /// A mock over a `Vec<i64>`, proving the trait is object-safe and that deletion
    /// removes the most recently yielded element (mirroring the Java contract).
    struct VecIterator {
        items: Vec<i64>,
        pos: usize,
        yielded: bool,
    }

    impl DirectedIterator<i64> for VecIterator {
        fn has_next(&mut self) -> io::Result<bool> {
            Ok(self.pos < self.items.len())
        }

        fn next(&mut self) -> io::Result<i64> {
            if self.pos >= self.items.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no more elements"));
            }
            let value = self.items[self.pos];
            self.pos += 1;
            self.yielded = true;
            Ok(value)
        }

        fn delete(&mut self) -> io::Result<bool> {
            if !self.yielded {
                return Ok(false);
            }
            self.items.remove(self.pos - 1);
            self.pos -= 1;
            self.yielded = false;
            Ok(true)
        }
    }

    #[test]
    fn object_safe_and_walks_a_backing_vec() {
        let mut iter: Box<dyn DirectedIterator<i64>> =
            Box::new(VecIterator { items: vec![10, 20, 30], pos: 0, yielded: false });

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 10);
        assert_eq!(iter.next().unwrap(), 20);
        assert_eq!(iter.next().unwrap(), 30);
        assert!(!iter.has_next().unwrap());
        assert!(iter.next().is_err());
    }

    #[test]
    fn delete_removes_the_last_yielded_element() {
        let mut iter =
            VecIterator { items: vec![1, 2, 3], pos: 0, yielded: false };

        assert_eq!(iter.next().unwrap(), 1);
        assert_eq!(iter.next().unwrap(), 2);
        assert!(iter.delete().unwrap());
        assert_eq!(iter.items, vec![1, 3]);
        assert_eq!(iter.next().unwrap(), 3);
    }
}
