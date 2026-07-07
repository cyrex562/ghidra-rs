use std::cmp::Ordering;

/// An item (character) in a sequence at a specific index position.
///
/// The index is part of the item's identity — `"A"` at position 0 is not the same
/// item as `"A"` at position 1.
///
/// Mirrors `ghidra.closedpatternmining.SequenceItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceItem {
    symbol: String,
    index: i32,
}

impl SequenceItem {
    /// Creates a new [`SequenceItem`].
    ///
    /// # Panics
    /// Panics if `item` does not have exactly one character.
    pub fn new(item: &str, index: i32) -> Self {
        if item.chars().count() != 1 {
            panic!("frequent item '{}' must be of length 1", item);
        }
        Self {
            symbol: item.to_owned(),
            index,
        }
    }

    /// Returns the symbol associated with this item.
    pub fn get_symbol(&self) -> &str {
        &self.symbol
    }

    /// Returns the index associated with this item.
    pub fn get_index(&self) -> i32 {
        self.index
    }

    /// Generates a string from a list of [`SequenceItem`]s, replacing missing positions with `'.'`.
    ///
    /// `item_list` must be in ascending order of index. `total_length` must be at least as large
    /// as the highest index + 1.
    ///
    /// # Panics
    /// Panics if `item_list` is not in ascending order, or if `total_length` is too small.
    pub fn get_ditted_string(item_list: &[SequenceItem], total_length: usize) -> String {
        let mut sb = String::new();
        let mut symbols_written: usize = 0;
        for current_item in item_list {
            let item_index = current_item.index as usize;
            if item_index < symbols_written {
                panic!("itemList must be in ascending order of item index");
            }
            while item_index > symbols_written {
                sb.push('.');
                symbols_written += 1;
            }
            sb.push_str(&current_item.symbol);
            symbols_written += 1;
        }
        if symbols_written > total_length {
            panic!("mismatch between itemList and totalLength");
        }
        while symbols_written < total_length {
            sb.push('.');
            symbols_written += 1;
        }
        sb
    }
}

impl std::hash::Hash for SequenceItem {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.symbol.hash(state);
        self.index.hash(state);
    }
}

impl PartialOrd for SequenceItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SequenceItem {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.index != other.index {
            return self.index.cmp(&other.index);
        }
        self.symbol.cmp(&other.symbol)
    }
}

impl std::fmt::Display for SequenceItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "item: {}, index: {}", self.symbol, self.index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_symbol_and_index() {
        let item = SequenceItem::new("A", 3);
        assert_eq!(item.get_symbol(), "A");
        assert_eq!(item.get_index(), 3);
    }

    #[test]
    #[should_panic(expected = "must be of length 1")]
    fn new_panics_on_empty_symbol() {
        SequenceItem::new("", 0);
    }

    #[test]
    #[should_panic(expected = "must be of length 1")]
    fn new_panics_on_multi_char_symbol() {
        SequenceItem::new("AB", 0);
    }

    #[test]
    fn equality_requires_same_index_and_symbol() {
        let a = SequenceItem::new("A", 1);
        let b = SequenceItem::new("A", 1);
        let c = SequenceItem::new("A", 2);
        let d = SequenceItem::new("B", 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn ordering_by_index_then_symbol() {
        let a = SequenceItem::new("B", 1);
        let b = SequenceItem::new("A", 2);
        assert!(a < b);

        let c = SequenceItem::new("A", 1);
        let d = SequenceItem::new("B", 1);
        assert!(c < d);
    }

    #[test]
    fn display_format() {
        let item = SequenceItem::new("X", 5);
        assert_eq!(format!("{}", item), "item: X, index: 5");
    }

    #[test]
    fn get_ditted_string_contiguous() {
        let items = vec![
            SequenceItem::new("A", 0),
            SequenceItem::new("B", 1),
            SequenceItem::new("C", 2),
        ];
        assert_eq!(SequenceItem::get_ditted_string(&items, 3), "ABC");
    }

    #[test]
    fn get_ditted_string_with_gaps() {
        let items = vec![SequenceItem::new("A", 0), SequenceItem::new("C", 2)];
        assert_eq!(SequenceItem::get_ditted_string(&items, 4), "A.C.");
    }

    #[test]
    fn get_ditted_string_all_dits() {
        assert_eq!(SequenceItem::get_ditted_string(&[], 3), "...");
    }

    #[test]
    #[should_panic(expected = "ascending order")]
    fn get_ditted_string_panics_on_unsorted() {
        let items = vec![SequenceItem::new("B", 2), SequenceItem::new("A", 1)];
        SequenceItem::get_ditted_string(&items, 3);
    }

    #[test]
    #[should_panic(expected = "mismatch")]
    fn get_ditted_string_panics_on_too_small_total_length() {
        let items = vec![
            SequenceItem::new("A", 0),
            SequenceItem::new("B", 1),
            SequenceItem::new("C", 2),
        ];
        SequenceItem::get_ditted_string(&items, 2);
    }
}
