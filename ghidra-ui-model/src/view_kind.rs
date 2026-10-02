//! The generic view kinds the renderer provides (Qt6 UI spec §2).

/// Which generic renderer widget shows a provider. Mirrors
/// `ghidra_rs::docking::ProviderViewKind`; the mapping between them is added
/// when this crate gains its `ghidra-rs` dependency (U1b).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ViewKind {
    /// Sortable, filterable rows and columns.
    Table,
    /// Hierarchical nodes.
    Tree,
    /// Styled lines with hyperlinks.
    Text,
    /// Option / edit fields.
    Form,
    /// The code listing.
    Listing,
    /// A bespoke widget, by id.
    Custom(String),
}

impl ViewKind {
    /// The five fixed kinds, in spec order.
    pub fn all_fixed() -> [ViewKind; 5] {
        [ViewKind::Table, ViewKind::Tree, ViewKind::Text, ViewKind::Form, ViewKind::Listing]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_kinds_in_spec_order() {
        assert_eq!(
            ViewKind::all_fixed(),
            [ViewKind::Table, ViewKind::Tree, ViewKind::Text, ViewKind::Form, ViewKind::Listing]
        );
        assert_ne!(ViewKind::Custom("graph".into()), ViewKind::Table);
    }
}
