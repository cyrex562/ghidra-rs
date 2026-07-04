use crate::framework::db::DBLongIterator;
use crate::program::model::address::Address;

/// Adapter to get an iterator over keys in a table.
///
/// Port of `ghidra.program.database.util.DBKeyAdapter`.
pub trait DBKeyAdapter {
    /// Get an iterator over the keys in the given range.
    ///
    /// # Arguments
    /// * `start` - start of range
    /// * `end` - end of range (inclusive)
    ///
    /// # Errors
    /// Returns an error if there was a problem accessing the database.
    fn get_keys(
        &mut self,
        start: Address,
        end: Address,
    ) -> std::io::Result<Box<dyn DBLongIterator>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockKeyAdapter {
        keys: Vec<i64>,
    }

    impl DBKeyAdapter for MockKeyAdapter {
        fn get_keys(
            &mut self,
            _start: Address,
            _end: Address,
        ) -> std::io::Result<Box<dyn DBLongIterator>> {
            Ok(Box::new(VecIterator {
                values: self.keys.clone(),
                pos: 0,
            }))
        }
    }

    struct VecIterator {
        values: Vec<i64>,
        pos: usize,
    }

    impl DBLongIterator for VecIterator {
        fn has_next(&mut self) -> std::io::Result<bool> {
            Ok(self.pos < self.values.len())
        }

        fn has_previous(&mut self) -> std::io::Result<bool> {
            Ok(self.pos > 0)
        }

        fn next(&mut self) -> std::io::Result<i64> {
            if self.pos < self.values.len() {
                let val = self.values[self.pos];
                self.pos += 1;
                Ok(val)
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No next value",
                ))
            }
        }

        fn previous(&mut self) -> std::io::Result<i64> {
            if self.pos > 0 {
                self.pos -= 1;
                Ok(self.values[self.pos])
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "No previous value",
                ))
            }
        }

        fn delete(&mut self) -> std::io::Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_mock_adapter_returns_iterator() {
        let mut adapter = MockKeyAdapter {
            keys: vec![1, 2, 3, 4, 5],
        };

        let addr_space = crate::program::model::address::AddressSpace::new("test", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let start = Address::new(addr_space.clone(), 0);
        let end = Address::new(addr_space, 100);

        let mut iter = adapter.get_keys(start, end).unwrap();
        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 1);
    }

    #[test]
    fn test_iterator_iteration() {
        let mut adapter = MockKeyAdapter {
            keys: vec![10, 20, 30],
        };

        let addr_space = crate::program::model::address::AddressSpace::new("test", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let start = Address::new(addr_space.clone(), 0);
        let end = Address::new(addr_space, 100);

        let mut iter = adapter.get_keys(start, end).unwrap();

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 10);

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 20);

        assert!(iter.has_next().unwrap());
        assert_eq!(iter.next().unwrap(), 30);

        assert!(!iter.has_next().unwrap());
    }

    #[test]
    fn test_iterator_previous() {
        let mut adapter = MockKeyAdapter {
            keys: vec![5, 15, 25],
        };

        let addr_space = crate::program::model::address::AddressSpace::new("test", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let start = Address::new(addr_space.clone(), 0);
        let end = Address::new(addr_space, 100);

        let mut iter = adapter.get_keys(start, end).unwrap();

        assert_eq!(iter.next().unwrap(), 5);
        assert_eq!(iter.next().unwrap(), 15);
        assert!(iter.has_previous().unwrap());
        assert_eq!(iter.previous().unwrap(), 15);
        assert!(iter.has_previous().unwrap());
        assert_eq!(iter.previous().unwrap(), 5);
    }

    #[test]
    fn test_empty_iterator() {
        let mut adapter = MockKeyAdapter { keys: vec![] };

        let addr_space = crate::program::model::address::AddressSpace::new("test", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let start = Address::new(addr_space.clone(), 0);
        let end = Address::new(addr_space, 100);

        let mut iter = adapter.get_keys(start, end).unwrap();
        assert!(!iter.has_next().unwrap());
    }
}
