use crate::framework::db::DBFieldIterator;

/// Adapter to get an iterator over fields in a table where the Field is the primary key.
///
/// Port of `ghidra.program.database.util.DBFieldAdapter`.
pub trait DBFieldAdapter {
    /// Get an iterator over the primary keys as fields within the given range.
    ///
    /// # Arguments
    /// * `start` - start of range
    /// * `end` - end of range
    ///
    /// # Errors
    /// Returns an error if there was a problem accessing the database.
    fn get_fields(
        &mut self,
        start: i64,
        end: i64,
    ) -> std::io::Result<Box<dyn DBFieldIterator>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::Field;

    struct MockFieldAdapter {
        fields: Vec<Field>,
    }

    impl DBFieldAdapter for MockFieldAdapter {
        fn get_fields(
            &mut self,
            _start: i64,
            _end: i64,
        ) -> std::io::Result<Box<dyn DBFieldIterator>> {
            Ok(Box::new(VecIterator {
                values: self.fields.clone(),
                pos: -1,
                last_dir: None,
                deleted: vec![false; self.fields.len()],
            }))
        }
    }

    struct VecIterator {
        values: Vec<Field>,
        pos: isize,
        last_dir: Option<bool>,
        deleted: Vec<bool>,
    }

    impl DBFieldIterator for VecIterator {
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
    fn test_mock_adapter_returns_iterator() {
        let mut adapter = MockFieldAdapter {
            fields: vec![
                Field::Int(Some(1)),
                Field::Int(Some(2)),
                Field::Int(Some(3)),
            ],
        };

        let mut iter = adapter.get_fields(0, 100).unwrap();
        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(1))));
    }

    #[test]
    fn test_iterator_forward() {
        let mut adapter = MockFieldAdapter {
            fields: vec![Field::Int(Some(10)), Field::Int(Some(20)), Field::Int(Some(30))],
        };

        let mut iter = adapter.get_fields(0, 100).unwrap();

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(10))));

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(20))));

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(30))));

        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn test_iterator_backward() {
        let mut adapter = MockFieldAdapter {
            fields: vec![Field::Int(Some(5)), Field::Int(Some(15))],
        };

        let mut iter = adapter.get_fields(0, 100).unwrap();

        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(5))));
        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(15))));
        assert_eq!(iter.previous().unwrap(), Some(Field::Int(Some(15))));
        assert_eq!(iter.previous().unwrap(), Some(Field::Int(Some(5))));
    }

    #[test]
    fn test_empty_iterator() {
        let mut adapter = MockFieldAdapter { fields: vec![] };

        let mut iter = adapter.get_fields(0, 100).unwrap();
        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn test_delete_after_next() {
        let mut adapter = MockFieldAdapter {
            fields: vec![Field::Int(Some(42))],
        };

        let mut iter = adapter.get_fields(0, 100).unwrap();
        iter.next().unwrap();
        assert!(iter.delete().unwrap());
        assert!(!iter.delete().unwrap());
    }

    #[test]
    fn test_object_safe() {
        let mut adapter = MockFieldAdapter {
            fields: vec![Field::Int(Some(7))],
        };

        let mut iter: Box<dyn DBFieldIterator> = adapter.get_fields(0, 100).unwrap();
        assert_eq!(iter.next().unwrap(), Some(Field::Int(Some(7))));
    }
}
