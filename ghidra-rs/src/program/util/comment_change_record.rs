use std::any::Any;
use std::fmt;

use crate::program::model::address::Address;
use crate::program::seam_stubs::CommentType;
use crate::program::util::{ProgramChangeRecord, ProgramEvent};

/// Change record generated when a comment is modified.
///
/// Port of `ghidra.program.util.CommentChangeRecord`. Wraps a [`ProgramChangeRecord`]
/// and adds the specific type of comment that was changed.
pub struct CommentChangeRecord {
    base: ProgramChangeRecord,
    comment_type: CommentType,
}

impl CommentChangeRecord {
    /// Constructs a new comment change record.
    ///
    /// # Arguments
    /// * `comment_type` - the type of comment that changed
    /// * `address` - the address of the comment change
    /// * `old_value` - the old comment (may be None for a new comment)
    /// * `new_value` - the new comment (may be None if the comment was deleted)
    pub fn new(
        comment_type: CommentType,
        address: Address,
        old_value: Option<String>,
        new_value: Option<String>,
    ) -> Self {
        Self {
            base: ProgramChangeRecord::new(
                ProgramEvent::CommentChanged,
                Some(address.clone()),
                Some(address),
                None,
                old_value.map(|v| Box::new(v) as Box<dyn Any + Send + Sync>),
                new_value.map(|v| Box::new(v) as Box<dyn Any + Send + Sync>),
            ),
            comment_type,
        }
    }

    /// Returns the comment type.
    pub fn get_comment_type(&self) -> CommentType {
        self.comment_type.clone()
    }

    /// Returns the previous comment or None if there was no previous comment.
    pub fn get_old_comment(&self) -> Option<String> {
        self.base
            .change_record()
            .old_value()
            .and_then(|v| v.downcast_ref::<String>().map(|s| s.clone()))
    }

    /// Returns the new comment or None if this is a result of deleting the comment.
    pub fn get_new_comment(&self) -> Option<String> {
        self.base
            .change_record()
            .new_value()
            .and_then(|v| v.downcast_ref::<String>().map(|s| s.clone()))
    }

    /// Returns a reference to the underlying [`ProgramChangeRecord`].
    pub fn base(&self) -> &ProgramChangeRecord {
        &self.base
    }
}

impl std::ops::Deref for CommentChangeRecord {
    type Target = ProgramChangeRecord;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}

impl fmt::Display for CommentChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let comment_type_str = match self.comment_type {
            CommentType::Eol => "EOL",
            CommentType::Pre => "PRE",
            CommentType::Post => "POST",
            CommentType::Plate => "PLATE",
            CommentType::Repeatable => "REPEATABLE",
        };
        write!(f, "{}, commentType = {}", self.base, comment_type_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::model::event_type::EventType;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn new_stores_comment_type() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Eol, address, None, None);
        assert_eq!(record.get_comment_type(), CommentType::Eol);
    }

    #[test]
    fn new_uses_address_for_both_start_and_end() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Pre, address.clone(), None, None);
        assert_eq!(record.start(), Some(&address));
        assert_eq!(record.end(), Some(&address));
    }

    #[test]
    fn new_stores_old_comment() {
        let address = addr(0x1000);
        let old = Some("old comment".to_string());
        let record = CommentChangeRecord::new(CommentType::Post, address, old.clone(), None);
        assert_eq!(record.get_old_comment(), old);
    }

    #[test]
    fn new_stores_new_comment() {
        let address = addr(0x1000);
        let new = Some("new comment".to_string());
        let record = CommentChangeRecord::new(CommentType::Plate, address, None, new.clone());
        assert_eq!(record.get_new_comment(), new);
    }

    #[test]
    fn new_with_both_old_and_new_comments() {
        let address = addr(0x1000);
        let old = Some("old comment".to_string());
        let new = Some("new comment".to_string());
        let record = CommentChangeRecord::new(CommentType::Repeatable, address, old.clone(), new.clone());
        assert_eq!(record.get_old_comment(), old);
        assert_eq!(record.get_new_comment(), new);
    }

    #[test]
    fn get_old_comment_returns_none_for_new_comment() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Eol, address, None, Some("new".to_string()));
        assert_eq!(record.get_old_comment(), None);
    }

    #[test]
    fn get_new_comment_returns_none_for_deleted_comment() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Pre, address, Some("old".to_string()), None);
        assert_eq!(record.get_new_comment(), None);
    }

    #[test]
    fn new_sets_event_type_to_comment_changed() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Post, address, None, None);
        assert_eq!(
            record.change_record().event_type().get_id(),
            ProgramEvent::CommentChanged.get_id()
        );
    }

    #[test]
    fn display_includes_comment_type() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Eol, address, None, None);
        let s = format!("{}", record);
        assert!(s.contains("commentType = EOL"));
    }

    #[test]
    fn display_includes_all_comment_types() {
        let addr_val = addr(0x1000);
        let types = [
            (CommentType::Eol, "EOL"),
            (CommentType::Pre, "PRE"),
            (CommentType::Post, "POST"),
            (CommentType::Plate, "PLATE"),
            (CommentType::Repeatable, "REPEATABLE"),
        ];
        for (comment_type, type_str) in &types {
            let record = CommentChangeRecord::new(*comment_type, addr_val.clone(), None, None);
            let s = format!("{}", record);
            assert!(s.contains(&format!("commentType = {}", type_str)));
        }
    }

    #[test]
    fn display_includes_base_record_info() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Plate, address, None, None);
        let s = format!("{}", record);
        assert!(s.contains("DomainObjectChangeRecord"));
    }

    #[test]
    fn deref_exposes_program_change_record_methods() {
        let address = addr(0x1000);
        let record = CommentChangeRecord::new(CommentType::Pre, address, None, None);
        assert_eq!(
            record.change_record().event_type().get_id(),
            ProgramEvent::CommentChanged.get_id()
        );
    }
}
