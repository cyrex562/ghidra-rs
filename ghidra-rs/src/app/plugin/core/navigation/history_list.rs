//! Port of `NavigationHistoryPlugin.HistoryList`: a capped back/forward list
//! of location mementos for one navigatable.

/// Default history size (Java `MAX_HISTORY_SIZE`).
pub const MAX_HISTORY_SIZE: usize = 30;

/// Back/forward history; the current entry is `list[current]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryList<T> {
    list: Vec<T>,
    current: usize,
    max: usize,
}

impl<T: PartialEq + Clone> HistoryList<T> {
    /// An empty list keeping at most `max` entries (at least 1).
    pub fn new(max: usize) -> Self {
        Self { list: Vec::new(), current: 0, max: max.max(1) }
    }

    /// Adds `location` after the current entry, dropping any forward entries;
    /// a location equal to the last entry replaces it.
    pub fn add(&mut self, location: T) {
        if self.list.is_empty() {
            self.list.push(location);
            self.current = 0;
            return;
        }
        self.list.truncate(self.current + 1);
        if self.list.last() == Some(&location) {
            *self.list.last_mut().expect("non-empty") = location;
        } else {
            self.list.push(location);
        }
        if self.list.len() > self.max {
            self.list.remove(0);
        }
        self.current = self.list.len() - 1;
    }

    /// Whether `next` would move.
    pub fn has_next(&self) -> bool {
        !self.list.is_empty() && self.current < self.list.len() - 1
    }

    /// Whether `previous` would move.
    pub fn has_previous(&self) -> bool {
        !self.list.is_empty() && self.current > 0
    }

    /// Steps forward.
    pub fn next(&mut self) -> Option<T> {
        if !self.has_next() {
            return None;
        }
        self.current += 1;
        Some(self.list[self.current].clone())
    }

    /// Steps back.
    pub fn previous(&mut self) -> Option<T> {
        if !self.has_previous() {
            return None;
        }
        self.current -= 1;
        Some(self.list[self.current].clone())
    }

    /// The current entry.
    pub fn current(&self) -> Option<&T> {
        self.list.get(self.current)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Changes the cap; extra oldest entries go on the next `add`, as in Java.
    pub fn set_max(&mut self, max: usize) {
        self.max = max.max(1);
    }

    /// Entries before the current one, nearest first.
    pub fn previous_locations(&self) -> Vec<T> {
        self.list[..self.current.min(self.list.len())].iter().rev().cloned().collect()
    }

    /// Entries after the current one, nearest first.
    pub fn next_locations(&self) -> Vec<T> {
        self.list.iter().skip(self.current + 1).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[u32]) -> HistoryList<u32> {
        let mut h = HistoryList::new(MAX_HISTORY_SIZE);
        for &i in items {
            h.add(i);
        }
        h
    }

    #[test]
    fn adding_after_going_back_drops_forward_entries() {
        let mut h = list(&[1, 2, 3]);
        assert_eq!(h.previous(), Some(2));
        h.add(9);
        assert_eq!(h.len(), 3);
        assert!(!h.has_next());
        assert_eq!(h.previous_locations(), vec![2, 1]);
        assert_eq!(h.current(), Some(&9));
    }

    #[test]
    fn an_equal_last_entry_is_replaced_not_duplicated() {
        let h = list(&[1, 2, 2]);
        assert_eq!(h.len(), 2);
        assert_eq!(h.current(), Some(&2));
    }

    #[test]
    fn the_cap_drops_the_oldest() {
        let mut h = HistoryList::new(3);
        for i in 0..5 {
            h.add(i);
        }
        assert_eq!(h.len(), 3);
        assert_eq!(h.previous_locations(), vec![3, 2]);
        assert_eq!(h.current(), Some(&4));
    }

    #[test]
    fn next_and_previous_stop_at_the_ends() {
        let mut h = list(&[1, 2]);
        assert_eq!(h.next(), None);
        assert_eq!(h.previous(), Some(1));
        assert_eq!(h.previous(), None);
        assert_eq!(h.next_locations(), vec![2]);
        assert_eq!(h.next(), Some(2));
        let empty: HistoryList<u32> = HistoryList::new(0);
        assert!(empty.is_empty() && !empty.has_next() && !empty.has_previous() && empty.current().is_none());
    }
}
