use crate::program::model::address::{AddressRange, AddressRangeIterator};

/// Splits a single address range into smaller ranges of a maximum size.
///
/// This mirrors Ghidra's `AddressRangeSplitter`.
#[derive(Debug, Clone)]
pub struct AddressRangeSplitter {
    remaining_range: Option<AddressRange>,
    split_size: u64,
    forward: bool,
}

impl AddressRangeSplitter {
    pub fn new(range: AddressRange, split_size: u64, forward: bool) -> Self {
        assert!(split_size > 0, "split size must be greater than 0");
        Self {
            remaining_range: Some(range),
            split_size,
            forward,
        }
    }

    fn range_is_small_enough(&self) -> bool {
        self.remaining_range
            .as_ref()
            .map(|range| range.length() <= self.split_size)
            .unwrap_or(false)
    }

    fn extract_chunk_from_start(&mut self) -> AddressRange {
        let remaining = self.remaining_range.as_ref().unwrap();
        let start = remaining.min_address().clone();
        let end = start.add((self.split_size - 1) as i64).unwrap();
        let next_start = end.next().unwrap();
        let max = remaining.max_address().clone();
        self.remaining_range = Some(AddressRange::new(next_start, max));
        AddressRange::new(start, end)
    }

    fn extract_chunk_from_end(&mut self) -> AddressRange {
        let remaining = self.remaining_range.as_ref().unwrap();
        let end = remaining.max_address().clone();
        let start = end.add(-((self.split_size - 1) as i64)).unwrap();
        let previous_end = start.previous().unwrap();
        let min = remaining.min_address().clone();
        self.remaining_range = Some(AddressRange::new(min, previous_end));
        AddressRange::new(start, end)
    }
}

impl AddressRangeIterator for AddressRangeSplitter {
    fn has_next(&self) -> bool {
        self.remaining_range.is_some()
    }

    fn next_range(&mut self) -> Option<AddressRange> {
        self.remaining_range.as_ref()?;
        if self.range_is_small_enough() {
            return self.remaining_range.take();
        }
        Some(if self.forward {
            self.extract_chunk_from_start()
        } else {
            self.extract_chunk_from_end()
        })
    }
}

impl Iterator for AddressRangeSplitter {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_range()
    }
}

/// Breaks an address range into fixed-size chunks in forward order.
///
/// This mirrors Ghidra's `AddressRangeChunker`.
#[derive(Debug, Clone)]
pub struct AddressRangeChunker {
    end: crate::program::model::address::Address,
    next_start_address: Option<crate::program::model::address::Address>,
    chunk_size: u64,
}

impl AddressRangeChunker {
    pub fn new(range: AddressRange, chunk_size: u64) -> Self {
        Self::from_start_end(
            range.min_address().clone(),
            range.max_address().clone(),
            chunk_size,
        )
    }

    pub fn from_start_end(
        start: crate::program::model::address::Address,
        end: crate::program::model::address::Address,
        chunk_size: u64,
    ) -> Self {
        assert!(
            start <= end,
            "start address cannot be greater than end address"
        );
        assert!(
            start.space() == end.space(),
            "addresses must be in the same address space"
        );
        assert!(chunk_size > 0, "chunk size must be greater than 0");
        Self {
            end,
            next_start_address: Some(start),
            chunk_size,
        }
    }
}

impl Iterator for AddressRangeChunker {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        let current_start = self.next_start_address.clone()?;
        let available_less_one = self.end.subtract(&current_start) as u64;
        let size_less_one = (self.chunk_size - 1).min(available_less_one);
        let current_end = current_start.add(size_less_one as i64).unwrap();
        self.next_start_address = if current_end == self.end {
            None
        } else {
            Some(current_end.next().unwrap())
        };
        Some(AddressRange::new(current_start, current_end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};

    #[test]
    fn splitter_splits_forward() {
        let range = AddressRange::new(addr(0x1000), addr(0x1009));
        let chunks: Vec<_> = AddressRangeSplitter::new(range, 4, true).collect();

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], AddressRange::new(addr(0x1000), addr(0x1003)));
        assert_eq!(chunks[1], AddressRange::new(addr(0x1004), addr(0x1007)));
        assert_eq!(chunks[2], AddressRange::new(addr(0x1008), addr(0x1009)));
    }

    #[test]
    fn splitter_splits_backward() {
        let range = AddressRange::new(addr(0x1000), addr(0x1009));
        let chunks: Vec<_> = AddressRangeSplitter::new(range, 4, false).collect();

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0], AddressRange::new(addr(0x1006), addr(0x1009)));
        assert_eq!(chunks[1], AddressRange::new(addr(0x1002), addr(0x1005)));
        assert_eq!(chunks[2], AddressRange::new(addr(0x1000), addr(0x1001)));
    }

    #[test]
    fn chunker_splits_forward() {
        let range = AddressRange::new(addr(0x2000), addr(0x2008));
        let chunks: Vec<_> = AddressRangeChunker::new(range, 4).collect();

        assert_eq!(
            chunks,
            vec![
                AddressRange::new(addr(0x2000), addr(0x2003)),
                AddressRange::new(addr(0x2004), addr(0x2007)),
                AddressRange::new(addr(0x2008), addr(0x2008)),
            ]
        );
    }

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }
}
