use crate::program::model::address::{Address, AddressMapImpl, AddressSetView};

/// Maps address ranges to one or more associated objects.
///
/// This mirrors Ghidra's `AddressObjectMap` public behavior.  The Java
/// implementation stores start/end marker entries; this Rust port stores
/// normalized key intervals with object vectors.
#[derive(Debug, Clone)]
pub struct AddressObjectMap<T> {
    addr_map: AddressMapImpl,
    ranges: Vec<ObjectRange<T>>,
}

impl<T> Default for AddressObjectMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AddressObjectMap<T> {
    pub fn new() -> Self {
        Self {
            addr_map: AddressMapImpl::new(),
            ranges: Vec::new(),
        }
    }
}

impl<T: Clone + Eq> AddressObjectMap<T> {
    pub fn get_objects(&mut self, address: &Address) -> Vec<T> {
        let key = self.addr_map.key(address);
        self.ranges
            .iter()
            .find(|range| range.contains(key))
            .map(|range| range.objects.clone())
            .unwrap_or_default()
    }

    pub fn add_object_to_set(&mut self, object: T, set: &dyn AddressSetView) {
        let mut ranges = set.address_ranges();
        while let Some(range) = ranges.next_range() {
            self.add_object(object.clone(), range.min_address(), range.max_address());
        }
    }

    pub fn add_object(&mut self, object: T, start_address: &Address, end_address: &Address) {
        let start = self.addr_map.key(start_address);
        let end = self.addr_map.key(end_address);
        self.add_range(object, start.min(end), start.max(end));
    }

    pub fn remove_object_from_set(&mut self, object: &T, set: &dyn AddressSetView) {
        let mut ranges = set.address_ranges();
        while let Some(range) = ranges.next_range() {
            self.remove_object(object, range.min_address(), range.max_address());
        }
    }

    pub fn remove_object(&mut self, object: &T, start_address: &Address, end_address: &Address) {
        let start = self.addr_map.key(start_address);
        let end = self.addr_map.key(end_address);
        self.remove_range(object, start.min(end), start.max(end));
    }

    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    fn add_range(&mut self, object: T, start: i64, end: i64) {
        let mut rebuilt = Vec::new();
        let mut cursor = Some(start);
        let mut inserted_tail = false;

        for range in &self.ranges {
            if range.end < start {
                rebuilt.push(range.clone());
                continue;
            }
            if range.start > end {
                if !inserted_tail {
                    if let Some(cursor_value) = cursor {
                        if cursor_value <= end {
                            rebuilt.push(ObjectRange::new(cursor_value, end, vec![object.clone()]));
                        }
                    }
                    inserted_tail = true;
                }
                rebuilt.push(range.clone());
                continue;
            }

            if let Some(cursor_value) = cursor {
                if cursor_value < range.start {
                    let gap_end = range.start.saturating_sub(1).min(end);
                    rebuilt.push(ObjectRange::new(
                        cursor_value,
                        gap_end,
                        vec![object.clone()],
                    ));
                }
            }

            if range.start < start {
                rebuilt.push(ObjectRange::new(
                    range.start,
                    start.saturating_sub(1),
                    range.objects.clone(),
                ));
            }

            let overlap_start = range.start.max(start);
            let overlap_end = range.end.min(end);
            let mut objects = range.objects.clone();
            if !objects.contains(&object) {
                objects.push(object.clone());
            }
            rebuilt.push(ObjectRange::new(overlap_start, overlap_end, objects));
            cursor = next_key(overlap_end);

            if range.end > overlap_end {
                rebuilt.push(ObjectRange::new(
                    overlap_end.saturating_add(1),
                    range.end,
                    range.objects.clone(),
                ));
            }
        }

        if !inserted_tail {
            if let Some(cursor_value) = cursor {
                if cursor_value <= end {
                    rebuilt.push(ObjectRange::new(cursor_value, end, vec![object]));
                }
            }
        }

        self.ranges = rebuilt;
        self.coalesce();
    }

    fn remove_range(&mut self, object: &T, start: i64, end: i64) {
        let mut rebuilt = Vec::new();

        for range in &self.ranges {
            if range.end < start || range.start > end {
                rebuilt.push(range.clone());
                continue;
            }

            if range.start < start {
                rebuilt.push(ObjectRange::new(
                    range.start,
                    start.saturating_sub(1),
                    range.objects.clone(),
                ));
            }

            let overlap_start = range.start.max(start);
            let overlap_end = range.end.min(end);
            let mut objects = range.objects.clone();
            objects.retain(|existing| existing != object);
            if !objects.is_empty() {
                rebuilt.push(ObjectRange::new(overlap_start, overlap_end, objects));
            }

            if range.end > overlap_end {
                rebuilt.push(ObjectRange::new(
                    overlap_end.saturating_add(1),
                    range.end,
                    range.objects.clone(),
                ));
            }
        }

        self.ranges = rebuilt;
        self.coalesce();
    }

    fn coalesce(&mut self) {
        if self.ranges.is_empty() {
            return;
        }
        self.ranges.sort_by_key(|range| range.start);
        let mut normalized: Vec<ObjectRange<T>> = Vec::new();
        for range in self.ranges.drain(..) {
            if let Some(last) = normalized.last_mut() {
                if last.objects == range.objects && next_key(last.end) == Some(range.start) {
                    last.end = range.end;
                    continue;
                }
            }
            normalized.push(range);
        }
        self.ranges = normalized;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectRange<T> {
    start: i64,
    end: i64,
    objects: Vec<T>,
}

impl<T> ObjectRange<T> {
    fn new(start: i64, end: i64, objects: Vec<T>) -> Self {
        Self {
            start,
            end,
            objects,
        }
    }

    fn contains(&self, key: i64) -> bool {
        self.start <= key && key <= self.end
    }
}

fn next_key(key: i64) -> Option<i64> {
    key.checked_add(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    #[test]
    fn add_single_range_returns_object_inside_only() {
        let space = space();
        let mut map = AddressObjectMap::new();

        map.add_object("Set1", &addr(&space, 0), &addr(&space, 4));

        assert_eq!(map.get_objects(&addr(&space, 0)), vec!["Set1"]);
        assert_eq!(map.get_objects(&addr(&space, 2)), vec!["Set1"]);
        assert_eq!(map.get_objects(&addr(&space, 4)), vec!["Set1"]);
        assert!(map.get_objects(&addr(&space, 5)).is_empty());
    }

    #[test]
    fn overlapping_adds_preserve_existing_object_order() {
        let space = space();
        let mut map = AddressObjectMap::new();

        map.add_object("Set1", &addr(&space, 0), &addr(&space, 4));
        map.add_object("Set2", &addr(&space, 22), &addr(&space, 44));
        map.add_object("Set3", &addr(&space, 45), &addr(&space, 45));
        map.add_object("Set4", &addr(&space, 4), &addr(&space, 32));
        map.add_object("Set5", &addr(&space, 2), &addr(&space, 22));

        assert_eq!(map.get_objects(&addr(&space, 2)), vec!["Set1", "Set5"]);
        assert_eq!(
            map.get_objects(&addr(&space, 4)),
            vec!["Set1", "Set4", "Set5"]
        );
        assert_eq!(map.get_objects(&addr(&space, 6)), vec!["Set4", "Set5"]);
        assert_eq!(
            map.get_objects(&addr(&space, 22)),
            vec!["Set2", "Set4", "Set5"]
        );
        assert_eq!(map.get_objects(&addr(&space, 24)), vec!["Set2", "Set4"]);
        assert_eq!(map.get_objects(&addr(&space, 45)), vec!["Set3"]);
    }

    #[test]
    fn adding_address_set_associates_each_range() {
        let space = space();
        let mut set = AddressSet::new();
        set.add_range(&addr(&space, 10), &addr(&space, 12));
        set.add_range(&addr(&space, 20), &addr(&space, 20));
        let mut map = AddressObjectMap::new();

        map.add_object_to_set("multi", &set);

        assert_eq!(map.get_objects(&addr(&space, 10)), vec!["multi"]);
        assert_eq!(map.get_objects(&addr(&space, 12)), vec!["multi"]);
        assert!(map.get_objects(&addr(&space, 13)).is_empty());
        assert_eq!(map.get_objects(&addr(&space, 20)), vec!["multi"]);
    }

    #[test]
    fn remove_deletes_only_requested_object_from_overlap() {
        let space = space();
        let mut map = AddressObjectMap::new();

        map.add_object("one", &addr(&space, 10), &addr(&space, 30));
        map.add_object("two", &addr(&space, 20), &addr(&space, 40));
        map.remove_object(&"two", &addr(&space, 20), &addr(&space, 40));

        assert_eq!(map.get_objects(&addr(&space, 10)), vec!["one"]);
        assert_eq!(map.get_objects(&addr(&space, 20)), vec!["one"]);
        assert_eq!(map.get_objects(&addr(&space, 30)), vec!["one"]);
        assert!(map.get_objects(&addr(&space, 31)).is_empty());
    }

    #[test]
    fn remove_from_middle_splits_range() {
        let space = space();
        let mut map = AddressObjectMap::new();

        map.add_object("one", &addr(&space, 10), &addr(&space, 30));
        map.remove_object(&"one", &addr(&space, 15), &addr(&space, 20));

        assert_eq!(map.get_objects(&addr(&space, 14)), vec!["one"]);
        assert!(map.get_objects(&addr(&space, 15)).is_empty());
        assert!(map.get_objects(&addr(&space, 20)).is_empty());
        assert_eq!(map.get_objects(&addr(&space, 21)), vec!["one"]);
        assert_eq!(map.num_ranges(), 2);
    }

    #[test]
    fn adjacent_ranges_with_same_objects_are_coalesced() {
        let space = space();
        let mut map = AddressObjectMap::new();

        map.add_object("one", &addr(&space, 10), &addr(&space, 20));
        map.add_object("one", &addr(&space, 21), &addr(&space, 30));

        assert_eq!(map.get_objects(&addr(&space, 25)), vec!["one"]);
        assert_eq!(map.num_ranges(), 1);
    }

    fn space() -> Arc<AddressSpace> {
        AddressSpace::new("Test", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        Address::new(space.clone(), offset)
    }
}
