use std::cmp::Ordering;

use super::sequence_item::SequenceItem;

/// A frequent item in a sequence: an item along with its support (the number
/// of sequences containing the item).
///
/// Mirrors `ghidra.closedpatternmining.FrequentSequenceItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrequentSequenceItem {
    support: i32,
    frequent_item: SequenceItem,
}

impl FrequentSequenceItem {
    /// Creates a new [`FrequentSequenceItem`] with the given support and underlying [`SequenceItem`].
    ///
    /// # Panics
    /// Panics if `support` is not positive.
    pub fn new(support: i32, frequent_item: SequenceItem) -> Self {
        if support <= 0 {
            panic!("support must be positive");
        }
        Self {
            support,
            frequent_item,
        }
    }

    /// Returns the support (number of sequences which contain the item).
    pub fn get_support(&self) -> i32 {
        self.support
    }

    /// Returns the item.
    pub fn get_item(&self) -> &SequenceItem {
        &self.frequent_item
    }

    /// Returns a pretty string representation of a collection of [`FrequentSequenceItem`]s.
    pub fn get_pretty_string<'a, I>(items: I) -> String
    where
        I: IntoIterator<Item = &'a FrequentSequenceItem>,
    {
        let mut sb = String::new();
        sb.push('\n');
        let mut any = false;
        for f_item in items {
            sb.push_str(&f_item.to_string());
            any = true;
        }
        if !any {
            sb.push_str("empty!");
        }
        sb
    }
}

impl std::fmt::Display for FrequentSequenceItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "support (number of sequences containing the item): {}, {}\n",
            self.support, self.frequent_item
        )
    }
}

impl PartialOrd for FrequentSequenceItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FrequentSequenceItem {
    /// Compares based on the item first, then the support (number of
    /// sequences which contain the item).
    fn cmp(&self, other: &Self) -> Ordering {
        let item_compare = self.frequent_item.cmp(&other.frequent_item);
        if item_compare != Ordering::Equal {
            return item_compare;
        }
        self.support.cmp(&other.support)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_stores_support_and_item() {
        let item = FrequentSequenceItem::new(3, SequenceItem::new("A", 0));
        assert_eq!(item.get_support(), 3);
        assert_eq!(item.get_item(), &SequenceItem::new("A", 0));
    }

    #[test]
    #[should_panic(expected = "support must be positive")]
    fn new_panics_on_zero_support() {
        FrequentSequenceItem::new(0, SequenceItem::new("A", 0));
    }

    #[test]
    #[should_panic(expected = "support must be positive")]
    fn new_panics_on_negative_support() {
        FrequentSequenceItem::new(-1, SequenceItem::new("A", 0));
    }

    #[test]
    fn equality_requires_same_item_and_support() {
        let a = FrequentSequenceItem::new(2, SequenceItem::new("A", 0));
        let b = FrequentSequenceItem::new(2, SequenceItem::new("A", 0));
        let c = FrequentSequenceItem::new(3, SequenceItem::new("A", 0));
        let d = FrequentSequenceItem::new(2, SequenceItem::new("B", 0));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn ordering_by_item_then_support() {
        let a = FrequentSequenceItem::new(5, SequenceItem::new("A", 0));
        let b = FrequentSequenceItem::new(1, SequenceItem::new("B", 0));
        assert!(a < b);

        let c = FrequentSequenceItem::new(1, SequenceItem::new("A", 0));
        let d = FrequentSequenceItem::new(2, SequenceItem::new("A", 0));
        assert!(c < d);
    }

    #[test]
    fn display_format() {
        let item = FrequentSequenceItem::new(4, SequenceItem::new("X", 2));
        assert_eq!(
            format!("{}", item),
            "support (number of sequences containing the item): 4, item: X, index: 2\n"
        );
    }

    #[test]
    fn get_pretty_string_empty() {
        let items: Vec<FrequentSequenceItem> = Vec::new();
        assert_eq!(FrequentSequenceItem::get_pretty_string(&items), "\nempty!");
    }

    #[test]
    fn get_pretty_string_non_empty() {
        let items = vec![
            FrequentSequenceItem::new(1, SequenceItem::new("A", 0)),
            FrequentSequenceItem::new(2, SequenceItem::new("B", 1)),
        ];
        let pretty = FrequentSequenceItem::get_pretty_string(&items);
        assert_eq!(
            pretty,
            "\nsupport (number of sequences containing the item): 1, item: A, index: 0\nsupport (number of sequences containing the item): 2, item: B, index: 1\n"
        );
    }
}
