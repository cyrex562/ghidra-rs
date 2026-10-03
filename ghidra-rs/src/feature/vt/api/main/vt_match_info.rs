//! Port of `ghidra.feature.vt.api.main.VTMatchInfo`.

use std::fmt;

use crate::program::model::address::Address;

use super::vt_association_type::VtAssociationType;
use super::vt_match_tag::VtMatchTag;
use super::vt_score::VtScore;

/// The description of a match a correlator wants added to a match set: its association type,
/// scores, source/destination addresses and lengths, and tag.
///
/// Java holds a reference to the owning `VTMatchSet`; here that back-reference is the match
/// set's id ([`VTMatchSet::get_id`](super::vt_match_set::VTMatchSet::get_id)), which a session
/// resolves to the match set. Fields Java leaves `null` until set are `Option`s.
#[derive(Debug, Clone, Default)]
pub struct VtMatchInfo {
    match_set_id: i32,
    association_type: Option<VtAssociationType>,
    tag: Option<VtMatchTag>,
    similarity_score: Option<VtScore>,
    confidence_score: Option<VtScore>,
    source_address: Option<Address>,
    destination_address: Option<Address>,
    source_length: i32,
    destination_length: i32,
}

impl VtMatchInfo {
    /// Creates an empty match description for the match set with the given id.
    pub fn new(match_set_id: i32) -> Self {
        Self { match_set_id, ..Self::default() }
    }

    /// Returns the id of the match set this match is for (Java `getMatchSet()`).
    pub fn match_set_id(&self) -> i32 {
        self.match_set_id
    }

    /// Returns the association type, if set.
    pub fn association_type(&self) -> Option<VtAssociationType> {
        self.association_type
    }

    /// Sets the association type.
    pub fn set_association_type(&mut self, association_type: VtAssociationType) {
        self.association_type = Some(association_type);
    }

    /// Returns the tag, if set.
    pub fn tag(&self) -> Option<&VtMatchTag> {
        self.tag.as_ref()
    }

    /// Sets the tag.
    pub fn set_tag(&mut self, tag: Option<VtMatchTag>) {
        self.tag = tag;
    }

    /// Returns the similarity score, if set.
    pub fn similarity_score(&self) -> Option<&VtScore> {
        self.similarity_score.as_ref()
    }

    /// Sets the similarity score.
    pub fn set_similarity_score(&mut self, score: VtScore) {
        self.similarity_score = Some(score);
    }

    /// Returns the confidence score, if set.
    pub fn confidence_score(&self) -> Option<&VtScore> {
        self.confidence_score.as_ref()
    }

    /// Sets the confidence score.
    pub fn set_confidence_score(&mut self, score: VtScore) {
        self.confidence_score = Some(score);
    }

    /// Returns the source address, if set.
    pub fn source_address(&self) -> Option<&Address> {
        self.source_address.as_ref()
    }

    /// Sets the source address.
    pub fn set_source_address(&mut self, source_address: Address) {
        self.source_address = Some(source_address);
    }

    /// Returns the destination address, if set.
    pub fn destination_address(&self) -> Option<&Address> {
        self.destination_address.as_ref()
    }

    /// Sets the destination address.
    pub fn set_destination_address(&mut self, destination_address: Address) {
        self.destination_address = Some(destination_address);
    }

    /// Returns the source length.
    pub fn source_length(&self) -> i32 {
        self.source_length
    }

    /// Sets the source length.
    pub fn set_source_length(&mut self, source_length: i32) {
        self.source_length = source_length;
    }

    /// Returns the destination length.
    pub fn destination_length(&self) -> i32 {
        self.destination_length
    }

    /// Sets the destination length.
    pub fn set_destination_length(&mut self, destination_length: i32) {
        self.destination_length = destination_length;
    }
}

/// Java `VTMatchInfo.equals`: compares the lengths, association type, scores and tag, but
/// deliberately *not* the addresses or match set. (Java's `hashCode` hashes the source address,
/// which is inconsistent with that `equals`; no `Hash` impl is provided for that reason.)
impl PartialEq for VtMatchInfo {
    fn eq(&self, other: &Self) -> bool {
        self.destination_length == other.destination_length
            && self.association_type == other.association_type
            && self.similarity_score == other.similarity_score
            && self.confidence_score == other.confidence_score
            && self.source_length == other.source_length
            && self.tag == other.tag
    }
}

impl fmt::Display for VtMatchInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn or_null<T: fmt::Display>(value: Option<&T>) -> String {
            value.map_or_else(|| "null".to_string(), ToString::to_string)
        }
        let sim = self.similarity_score.as_ref().map_or(0.0, VtScore::score);
        let conf = self.confidence_score.as_ref().map_or(0.0, VtScore::score);
        write!(f, "\nMatchInfo: ")?;
        write!(f, "\n  Type               = {}", or_null(self.association_type.as_ref()))?;
        // `{:?}` renders whole numbers with a trailing ".0", like Java's Double.toString
        write!(f, "\n  Similarity Score   = {sim:?}")?;
        write!(f, "\n  Confidence Score   = {conf:?}")?;
        write!(f, "\n  SourceAddress      = {}", or_null(self.source_address.as_ref()))?;
        write!(f, "\n  DestinationAddress = {}", or_null(self.destination_address.as_ref()))?;
        write!(f, "\n  SourceLength       = {}", self.source_length)?;
        write!(f, "\n  DestinationLength  = {}", self.destination_length)?;
        write!(f, "\n  Tagged             = {}", or_null(self.tag.as_ref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    #[test]
    fn new_is_empty_except_for_match_set() {
        let info = VtMatchInfo::new(7);
        assert_eq!(info.match_set_id(), 7);
        assert!(info.association_type().is_none());
        assert!(info.similarity_score().is_none());
        assert!(info.source_address().is_none());
        assert_eq!((info.source_length(), info.destination_length()), (0, 0));
    }

    #[test]
    fn equality_ignores_addresses_and_match_set() {
        let mut a = VtMatchInfo::new(1);
        a.set_association_type(VtAssociationType::Function);
        a.set_similarity_score(VtScore::new(0.9));
        a.set_source_length(10);
        let mut b = a.clone();
        b.match_set_id = 2;
        let ram = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        b.set_source_address(Address::new(ram, 0x1000));
        assert_eq!(a, b);

        b.set_destination_length(3);
        assert_ne!(a, b);
        let mut c = a.clone();
        c.set_tag(Some(VtMatchTag::Named("t".into())));
        assert_ne!(a, c);
    }

    #[test]
    fn display_matches_java_to_string() {
        let mut info = VtMatchInfo::new(1);
        info.set_association_type(VtAssociationType::Function);
        info.set_similarity_score(VtScore::new(1.0));
        info.set_source_length(4);
        assert_eq!(
            info.to_string(),
            "\nMatchInfo: \n  Type               = Function\n  Similarity Score   = 1.0\
             \n  Confidence Score   = 0.0\n  SourceAddress      = null\
             \n  DestinationAddress = null\n  SourceLength       = 4\
             \n  DestinationLength  = 0\n  Tagged             = null"
        );
    }
}
