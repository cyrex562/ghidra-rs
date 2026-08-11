//! Port of `ghidra.feature.vt.api.main.VTMatch`.
//!
//! A `VTMatch` is a scoring by some algorithm that indicates a possibility that one function or
//! data item on one program matches a function or data item in another program. It consists of
//! an association (a pairing of functions or data from one program to another) and a scoring of
//! how likely the pairing is correct.
//!
//! `VTMatch` sits on a dependency cycle with `VTMatchSet` (a match set hands back the matches it
//! contains, and a match points back at the match set that contains it); `VTMatchSet` is already
//! ported, so this trait speaks it directly. `VTAssociation`, `VTMatchTag`, and `VTScore` are also
//! already ported, so this trait speaks them directly as well.

use crate::feature::vt::api::main::vt_association::VtAssociation;
use crate::feature::vt::api::main::vt_match_set::VTMatchSet;
use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use crate::feature::vt::api::main::vt_score::VtScore;
use crate::program::model::address::Address;

/// Java: `VTMatch.BYTES_LENGTH_TYPE`.
pub const BYTES_LENGTH_TYPE: &str = "bytes";

/// Java: `VTMatch.INSTRUCTIONS_LENGTH_TYPE`.
pub const INSTRUCTIONS_LENGTH_TYPE: &str = "instructions";

/// Java: `VTMatch.AL_LINES_LENGTH_TYPE`.
pub const AL_LINES_LENGTH_TYPE: &str = "AL lines";

/// Port of the `ghidra.feature.vt.api.main.VTMatch` interface.
pub trait VtMatch: Send + Sync {
    /// Java: `getMatchSet()`. Returns the VTMatchSet that contains this match.
    fn get_match_set(&self) -> Box<dyn VTMatchSet>;

    /// Java: `getAssociation()`. Returns the VTAssociation that this match is suggesting.
    fn get_association(&self) -> Box<dyn VtAssociation>;

    /// Java: `getTag()`. Returns the tag that has been applied to this match, or
    /// [`VtMatchTag::Untagged`] if not tagged (mirroring the Java `null`/`UNTAGGED` sentinel; see
    /// [`VtMatchTag`]'s docs).
    fn get_tag(&self) -> VtMatchTag;

    /// Java: `setTag(VTMatchTag)`. Sets the tag for this match. Any previous tag is replaced. A
    /// value of [`VtMatchTag::Untagged`] removes any existing tag.
    fn set_tag(&self, tag: VtMatchTag);

    /// Java: `getSimilarityScore()`. Returns a score that attempts to indicate how similar the
    /// associated items are to each other, normalized between 0 and 1. Note that short functions
    /// may have high similarity scores even though they are not really a match.
    fn get_similarity_score(&self) -> VtScore;

    /// Java: `getConfidenceScore()`. Returns a confidence score which is generally a combination
    /// of the similarity score and some measure of the length of the functions. This score is not
    /// normalized; higher numbers are more likely to be correct than lower numbers. Comparing
    /// scores from different algorithms is meaningless.
    fn get_confidence_score(&self) -> VtScore;

    /// Java: `getSourceAddress()`. Returns the address in the source program for a match.
    fn get_source_address(&self) -> Address;

    /// Java: `getDestinationAddress()`. Returns the address in the destination program for a
    /// match.
    fn get_destination_address(&self) -> Address;

    /// Java: `getSourceLength()`. Returns the length of the source function or data.
    fn get_source_length(&self) -> i32;

    /// Java: `getDestinationLength()`. Returns the length of the destination function or data.
    fn get_destination_length(&self) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Mutex;

    fn address(offset: i64) -> Address {
        Address::new(AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1), offset)
    }

    struct FixedMatch {
        tag: Mutex<VtMatchTag>,
        similarity: f64,
        confidence: f64,
        source_length: i32,
        destination_length: i32,
    }

    impl VtMatch for FixedMatch {
        fn get_match_set(&self) -> Box<dyn VTMatchSet> {
            unimplemented!("not exercised by this test")
        }

        fn get_association(&self) -> Box<dyn VtAssociation> {
            unimplemented!("not exercised by this test")
        }

        fn get_tag(&self) -> VtMatchTag {
            self.tag.lock().unwrap().clone()
        }

        fn set_tag(&self, tag: VtMatchTag) {
            *self.tag.lock().unwrap() = tag;
        }

        fn get_similarity_score(&self) -> VtScore {
            VtScore::new(self.similarity)
        }

        fn get_confidence_score(&self) -> VtScore {
            VtScore::new(self.confidence)
        }

        fn get_source_address(&self) -> Address {
            address(0x1000)
        }

        fn get_destination_address(&self) -> Address {
            address(0x2000)
        }

        fn get_source_length(&self) -> i32 {
            self.source_length
        }

        fn get_destination_length(&self) -> i32 {
            self.destination_length
        }
    }

    fn fixed_match() -> FixedMatch {
        FixedMatch {
            tag: Mutex::new(VtMatchTag::Untagged),
            similarity: 0.9999,
            confidence: 12.5,
            source_length: 42,
            destination_length: 24,
        }
    }

    /// Java: `VTMatch.BYTES_LENGTH_TYPE` / `INSTRUCTIONS_LENGTH_TYPE` / `AL_LINES_LENGTH_TYPE`.
    #[test]
    fn length_type_constants_match_java() {
        assert_eq!(BYTES_LENGTH_TYPE, "bytes");
        assert_eq!(INSTRUCTIONS_LENGTH_TYPE, "instructions");
        assert_eq!(AL_LINES_LENGTH_TYPE, "AL lines");
    }

    #[test]
    fn get_tag_defaults_to_untagged() {
        let m = fixed_match();
        assert_eq!(m.get_tag(), VtMatchTag::Untagged);
    }

    #[test]
    fn set_tag_replaces_previous_tag() {
        let m = fixed_match();
        m.set_tag(VtMatchTag::Named("foo".into()));
        assert_eq!(m.get_tag(), VtMatchTag::Named("foo".into()));

        m.set_tag(VtMatchTag::Untagged);
        assert_eq!(m.get_tag(), VtMatchTag::Untagged);
    }

    /// `VTScore` construction rounds to three decimal places (see `VtScore::new`), matching Java's
    /// `DecimalFormat("0.000")` round-trip.
    #[test]
    fn similarity_score_is_normalized_similarity() {
        let m = fixed_match();
        assert_eq!(m.get_similarity_score().score(), 1.0);
    }

    #[test]
    fn confidence_score_is_not_normalized() {
        let m = fixed_match();
        assert_eq!(m.get_confidence_score().score(), 12.5);
    }

    #[test]
    fn source_and_destination_lengths_round_trip() {
        let m = fixed_match();
        assert_eq!(m.get_source_length(), 42);
        assert_eq!(m.get_destination_length(), 24);
    }

    #[test]
    fn usable_as_trait_object() {
        let m: Box<dyn VtMatch> = Box::new(fixed_match());
        assert_eq!(m.get_source_length(), 42);
        assert_eq!(m.get_destination_length(), 24);
    }
}
