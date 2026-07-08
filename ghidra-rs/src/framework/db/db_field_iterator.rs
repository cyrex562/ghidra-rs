use super::field::Field;

/// Bidirectional iterator over `Field` values within a database table.
///
/// All methods may return `Err` if an I/O error occurs. `next` and `previous` return `Ok(None)`
/// when no further value is available, rather than an error.
pub trait DBFieldIterator {
    /// Return `true` if a Field is available in the forward direction.
    fn has_next(&mut self) -> std::io::Result<bool>;

    /// Return `true` if a Field is available in the reverse direction.
    fn has_previous(&mut self) -> std::io::Result<bool>;

    /// Return the next Field value or `None` if one is not available.
    fn next(&mut self) -> std::io::Result<Option<Field>>;

    /// Return the previous Field value or `None` if one is not available.
    fn previous(&mut self) -> std::io::Result<Option<Field>>;

    /// Delete the last record(s) associated with the last Field value read via `next` or
    /// `previous`.
    ///
    /// Returns `true` if the record(s) were successfully deleted.
    fn delete(&mut self) -> std::io::Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VecFieldIterator {
        values: Vec<Field>,
        pos: isize,
        last_dir: Option<bool>,
        deleted: Vec<bool>,
    }

    impl VecFieldIterator {
        fn new(values: Vec<Field>) -> Self {
            let len = values.len();
            Self { values, pos: -1, last_dir: None, deleted: vec![false; len] }
        }
    }

    impl DBFieldIterator for VecFieldIterator {
        fn has_next(&mut self) -> std::io::Result<bool> {
            let next = self.pos + 1;
            Ok(next < self.values.len() as isize)
        }

        fn has_previous(&mut self) -> std::io::Result<bool> {
            Ok(self.pos >= 0)
        }

        fn next(&mut self) -> std::io::Result<Option<Field>> {
            let next = self.pos + 1;
            if next >= self.values.len() as isize {
                return Ok(None);
            }
            self.pos = next;
            self.last_dir = Some(true);
            Ok(Some(self.values[self.pos as usize].clone()))
        }

        fn previous(&mut self) -> std::io::Result<Option<Field>> {
            if self.pos < 0 {
                return Ok(None);
            }
            let val = self.values[self.pos as usize].clone();
            self.last_dir = Some(false);
            self.pos -= 1;
            Ok(Some(val))
        }

        fn delete(&mut self) -> std::io::Result<bool> {
            let idx = match self.last_dir {
                Some(true) => self.pos as usize,
                Some(false) => (self.pos + 1) as usize,
                None => return Ok(false),
            };
            if idx < self.deleted.len() && !self.deleted[idx] {
                self.deleted[idx] = true;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    #[test]
    fn test_forward_iteration() {
        let mut it = VecFieldIterator::new(vec![
            Field::Int(Some(1)),
            Field::Int(Some(2)),
            Field::Int(Some(3)),
        ]);
        assert!(it.has_next().unwrap());
        assert!(!it.has_previous().unwrap());
        assert_eq!(it.next().unwrap(), Some(Field::Int(Some(1))));
        assert_eq!(it.next().unwrap(), Some(Field::Int(Some(2))));
        assert_eq!(it.next().unwrap(), Some(Field::Int(Some(3))));
        assert!(!it.has_next().unwrap());
        assert_eq!(it.next().unwrap(), None);
    }

    #[test]
    fn test_backward_iteration() {
        let mut it = VecFieldIterator::new(vec![Field::Int(Some(10)), Field::Int(Some(20))]);
        it.next().unwrap();
        it.next().unwrap();
        assert_eq!(it.previous().unwrap(), Some(Field::Int(Some(20))));
        assert_eq!(it.previous().unwrap(), Some(Field::Int(Some(10))));
        assert!(!it.has_previous().unwrap());
        assert_eq!(it.previous().unwrap(), None);
    }

    #[test]
    fn test_delete() {
        let mut it = VecFieldIterator::new(vec![Field::Int(Some(1))]);
        it.next().unwrap();
        assert!(it.delete().unwrap());
        assert!(!it.delete().unwrap());
    }

    #[test]
    fn test_empty() {
        let mut it = VecFieldIterator::new(vec![]);
        assert!(!it.has_next().unwrap());
        assert!(!it.has_previous().unwrap());
        assert_eq!(it.next().unwrap(), None);
        assert_eq!(it.previous().unwrap(), None);
    }

    // Object-safety smoke check: DBFieldIterator must be usable as a trait object.
    #[test]
    fn test_object_safe() {
        let mut it: Box<dyn DBFieldIterator> =
            Box::new(VecFieldIterator::new(vec![Field::Int(Some(7))]));
        assert_eq!(it.next().unwrap(), Some(Field::Int(Some(7))));
    }
}
