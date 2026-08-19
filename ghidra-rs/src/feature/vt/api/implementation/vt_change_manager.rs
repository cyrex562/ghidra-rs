use super::vt_event::VtEvent;

/// Deprecated event type constants for version tracking.
///
/// These constants are provided for backward compatibility. Previously (before 11.1),
/// version tracking event types were defined as integer constants. Event ids have since
/// been converted to enum types. These constants point to the corresponding enum values
/// to facilitate migration to the new enum-based approach.
///
/// In new code, use [`VtEvent`] directly instead of these constants.
pub mod deprecated {
    use super::VtEvent;

    /// A version tracking match set was added
    #[deprecated]
    pub const DOCR_VT_MATCH_SET_ADDED: VtEvent = VtEvent::MatchSetAdded;

    /// The association status of a match item in the version tracking results has changed
    #[deprecated]
    pub const DOCR_VT_ASSOCIATION_STATUS_CHANGED: VtEvent = VtEvent::AssociationStatusChanged;

    /// The markup status of a match item in the version tracking results has changed
    #[deprecated]
    pub const DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED: VtEvent =
        VtEvent::AssociationMarkupStatusChanged;

    /// A match result was added
    #[deprecated]
    pub const DOCR_VT_MATCH_ADDED: VtEvent = VtEvent::MatchAdded;

    /// A match result was deleted
    #[deprecated]
    pub const DOCR_VT_MATCH_DELETED: VtEvent = VtEvent::MatchDeleted;

    /// The tag for a match was changed
    #[deprecated]
    pub const DOCR_VT_MATCH_TAG_CHANGED: VtEvent = VtEvent::MatchTagChanged;

    /// A version tracking association was added
    #[deprecated]
    pub const DOCR_VT_ASSOCIATION_ADDED: VtEvent = VtEvent::AssociationAdded;

    /// A version tracking association was removed
    #[deprecated]
    pub const DOCR_VT_ASSOCIATION_REMOVED: VtEvent = VtEvent::AssociationRemoved;

    /// A markup item status was changed
    #[deprecated]
    pub const DOCR_VT_MARKUP_ITEM_STATUS_CHANGED: VtEvent = VtEvent::MarkupItemStatusChanged;

    /// A markup item's destination changed
    #[deprecated]
    pub const DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED: VtEvent =
        VtEvent::MarkupItemDestinationChanged;

    /// A version tracking tag was added
    #[deprecated]
    pub const DOCR_VT_TAG_ADDED: VtEvent = VtEvent::TagAdded;

    /// A version tracking tag was removed
    #[deprecated]
    pub const DOCR_VT_TAG_REMOVED: VtEvent = VtEvent::TagRemoved;

    /// The vote count of a match was changed
    #[deprecated]
    pub const DOCR_VT_VOTE_COUNT_CHANGED: VtEvent = VtEvent::VoteCountChanged;
}

#[cfg(test)]
mod tests {
    use super::deprecated::*;
    use super::VtEvent;

    #[test]
    fn match_set_added_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_MATCH_SET_ADDED, VtEvent::MatchSetAdded);
    }

    #[test]
    fn association_status_changed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(
            DOCR_VT_ASSOCIATION_STATUS_CHANGED,
            VtEvent::AssociationStatusChanged
        );
    }

    #[test]
    fn association_markup_status_changed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(
            DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED,
            VtEvent::AssociationMarkupStatusChanged
        );
    }

    #[test]
    fn match_added_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_MATCH_ADDED, VtEvent::MatchAdded);
    }

    #[test]
    fn match_deleted_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_MATCH_DELETED, VtEvent::MatchDeleted);
    }

    #[test]
    fn match_tag_changed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_MATCH_TAG_CHANGED, VtEvent::MatchTagChanged);
    }

    #[test]
    fn association_added_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_ASSOCIATION_ADDED, VtEvent::AssociationAdded);
    }

    #[test]
    fn association_removed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_ASSOCIATION_REMOVED, VtEvent::AssociationRemoved);
    }

    #[test]
    fn markup_item_status_changed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(
            DOCR_VT_MARKUP_ITEM_STATUS_CHANGED,
            VtEvent::MarkupItemStatusChanged
        );
    }

    #[test]
    fn markup_item_destination_changed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(
            DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED,
            VtEvent::MarkupItemDestinationChanged
        );
    }

    #[test]
    fn tag_added_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_TAG_ADDED, VtEvent::TagAdded);
    }

    #[test]
    fn tag_removed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_TAG_REMOVED, VtEvent::TagRemoved);
    }

    #[test]
    fn vote_count_changed_maps_correctly() {
        #[allow(deprecated)]
        assert_eq!(DOCR_VT_VOTE_COUNT_CHANGED, VtEvent::VoteCountChanged);
    }

    #[test]
    fn all_constants_have_unique_values() {
        #[allow(deprecated)]
        let constants = [
            DOCR_VT_MATCH_SET_ADDED,
            DOCR_VT_ASSOCIATION_STATUS_CHANGED,
            DOCR_VT_ASSOCIATION_MARKUP_STATUS_CHANGED,
            DOCR_VT_MATCH_ADDED,
            DOCR_VT_MATCH_DELETED,
            DOCR_VT_MATCH_TAG_CHANGED,
            DOCR_VT_ASSOCIATION_ADDED,
            DOCR_VT_ASSOCIATION_REMOVED,
            DOCR_VT_MARKUP_ITEM_STATUS_CHANGED,
            DOCR_VT_MARKUP_ITEM_DESTINATION_CHANGED,
            DOCR_VT_TAG_ADDED,
            DOCR_VT_TAG_REMOVED,
            DOCR_VT_VOTE_COUNT_CHANGED,
        ];

        assert_eq!(constants.len(), 13, "All 13 constants should be defined");

        let mut sorted = constants.to_vec();
        sorted.sort_by_key(|e| e.id());
        sorted.dedup_by_key(|e| e.id());
        assert_eq!(
            constants.len(),
            sorted.len(),
            "All constants should map to unique event IDs"
        );
    }
}
