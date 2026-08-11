use crate::feature::seam_stubs::{VtAssociation, VtMatch, VtMatchInfo};
use crate::feature::vt::api::implementation::vt_program_correlator_info::VtProgramCorrelatorInfo;
use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
use crate::feature::vt::api::main::vt_session::VTSession;
use crate::program::model::address::Address;

/// Interface for all the matches generated from a single program correlator run.
///
/// Port of `ghidra.feature.vt.api.main.VTMatchSet`. Java overloads `getMatches` three ways;
/// since Rust has no overloading, they are disambiguated by name: [`VTMatchSet::get_matches`]
/// (no args), [`VTMatchSet::get_matches_for_association`], and
/// [`VTMatchSet::get_matches_for_addresses`] (documented in Java as equivalent to the
/// association-based overload). `removeMatch` and its always-`true` default
/// `hasRemovableMatches` are ported as `#[deprecated]`, mirroring the Java
/// `@Deprecated(since = "11.2", forRemoval = true)` annotations; prefer
/// [`VTMatchSet::delete_match`].
pub trait VTMatchSet: Send + Sync {
    /// Returns the VTSession that contains this match set.
    fn get_session(&self) -> Box<dyn VTSession>;

    /// Creates a match based on the given info and adds it to this match set.
    fn add_match(&mut self, info: VtMatchInfo) -> Box<dyn VtMatch>;

    /// Returns a collection of all VTMatches contained in this match set.
    fn get_matches(&self) -> Vec<Box<dyn VtMatch>>;

    /// Returns information about the program correlator that was used to generate the matches
    /// for this match set.
    fn get_program_correlator_info(&self) -> &dyn VtProgramCorrelatorInfo;

    /// Returns the number of matches contained in this match set.
    fn get_match_count(&self) -> i32;

    /// Returns a unique id for this match set. The ids are one-up numbers indicating the order
    /// this match set was generated in relation to other match sets in the VTSession.
    fn get_id(&self) -> i32;

    /// Returns a collection of all matches for the given association.
    fn get_matches_for_association(
        &self,
        association: &dyn VtAssociation,
    ) -> Vec<Box<dyn VtMatch>>;

    /// Returns a collection of matches for the given source and destination address. Equivalent
    /// to calling [`VTMatchSet::get_matches_for_association`].
    fn get_matches_for_addresses(
        &self,
        source_address: &Address,
        destination_address: &Address,
    ) -> Vec<Box<dyn VtMatch>>;

    /// Deletes the given match from this match set.
    ///
    /// Note: deleting an **ACCEPTED** match removes potentially useful corroborating evidence
    /// from future correlation. If this is the last match that shares the match's association,
    /// then the association will also be removed, along with any markup items in the database.
    fn delete_match(&mut self, match_item: &dyn VtMatch);

    /// Removes a match from this match set.
    #[deprecated(since = "11.2", note = "use `delete_match` instead")]
    fn remove_match(&mut self, match_item: &dyn VtMatch) -> bool;

    /// Returns true.
    #[deprecated(since = "11.2", note = "this method now always returns true")]
    fn has_removable_matches(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
    use crate::feature::vt::api::main::vt_score::VtScore;
    use crate::framework::model::DomainObject;
    use crate::framework::options::Options;
    use crate::program::model::address::AddressSetView;

    #[derive(Clone)]
    struct MockMatch {
        // Reused as a stand-in identifier for the mock's own bookkeeping; not a faithful port of
        // VTMatch's real source-length semantics.
        id: i32,
    }

    impl VtMatch for MockMatch {
        fn get_match_set(&self) -> Box<dyn crate::feature::seam_stubs::VtMatchSet> {
            unimplemented!("not exercised by this test")
        }

        fn get_association(&self) -> Box<dyn VtAssociation> {
            unimplemented!("not exercised by this test")
        }

        fn get_tag(&self) -> VtMatchTag {
            VtMatchTag::Untagged
        }

        fn set_tag(&self, _tag: VtMatchTag) {}

        fn get_similarity_score(&self) -> VtScore {
            VtScore::new(0.0)
        }

        fn get_confidence_score(&self) -> VtScore {
            VtScore::new(0.0)
        }

        fn get_source_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_address(&self) -> Address {
            unimplemented!("not exercised by this test")
        }

        fn get_source_length(&self) -> i32 {
            self.id
        }

        fn get_destination_length(&self) -> i32 {
            0
        }
    }

    struct MockCorrelatorInfo {
        name: String,
    }

    impl VtProgramCorrelatorInfo for MockCorrelatorInfo {
        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_correlator_class_name(&self) -> &str {
            "MockCorrelator"
        }

        fn get_options(&self) -> &dyn Options {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_address_set(&self) -> &dyn AddressSetView {
            unimplemented!("not exercised by this test")
        }

        fn get_source_address_set(&self) -> &dyn AddressSetView {
            unimplemented!("not exercised by this test")
        }
    }

    struct MockSession;

    impl DomainObject for MockSession {}

    impl crate::framework::db::util::ErrorHandler for MockSession {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl VTSession for MockSession {
        fn get_association_manager(
            &self,
        ) -> &dyn crate::feature::vt::api::main::vt_association_manager::VtAssociationManager
        {
            unimplemented!("not exercised by this test")
        }

        fn create_match_set(
            &mut self,
            _correlator: &dyn VTProgramCorrelator,
        ) -> Box<dyn crate::feature::seam_stubs::VtMatchSet> {
            unimplemented!("not exercised by this test")
        }

        fn get_match_sets(&self) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatchSet>> {
            unimplemented!("not exercised by this test")
        }

        fn get_source_program(
            &self,
        ) -> std::sync::Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_program(
            &self,
        ) -> std::sync::Arc<dyn crate::program::model::listing::program::Program> {
            unimplemented!("not exercised by this test")
        }

        fn save_session(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn create_match_tag(&mut self, _name: &str) -> VtMatchTag {
            unimplemented!("not exercised by this test")
        }

        fn delete_match_tag(&mut self, _tag: &VtMatchTag) {}

        fn get_match_tags(&self) -> std::collections::HashSet<VtMatchTag> {
            std::collections::HashSet::new()
        }

        fn get_manual_match_set(&self) -> &dyn crate::feature::seam_stubs::VtMatchSet {
            unimplemented!("not exercised by this test")
        }

        fn get_implied_match_set(&self) -> &dyn crate::feature::seam_stubs::VtMatchSet {
            unimplemented!("not exercised by this test")
        }

        fn get_matches(
            &self,
            _association: &dyn VtAssociation,
        ) -> Vec<Box<dyn crate::feature::seam_stubs::VtMatch>> {
            Vec::new()
        }

        fn add_association_hook(
            &mut self,
            _hook: Box<dyn crate::feature::vt::api::main::association_hook::AssociationHook>,
        ) {
        }

        fn remove_association_hook(
            &mut self,
            _hook: &dyn crate::feature::vt::api::main::association_hook::AssociationHook,
        ) {
        }

        fn update_source_program(
            &mut self,
            _new_program: std::sync::Arc<dyn crate::program::model::listing::program::Program>,
        ) {
        }

        fn update_destination_program(
            &mut self,
            _new_program: std::sync::Arc<dyn crate::program::model::listing::program::Program>,
        ) {
        }
    }

    struct MockMatchSet {
        id: i32,
        matches: Vec<MockMatch>,
        next_match_id: i32,
        correlator_info: MockCorrelatorInfo,
    }

    impl MockMatchSet {
        fn new(id: i32) -> Self {
            Self {
                id,
                matches: Vec::new(),
                next_match_id: 0,
                correlator_info: MockCorrelatorInfo { name: "Mock".to_string() },
            }
        }
    }

    impl VTMatchSet for MockMatchSet {
        fn get_session(&self) -> Box<dyn VTSession> {
            Box::new(MockSession)
        }

        fn add_match(&mut self, _info: VtMatchInfo) -> Box<dyn VtMatch> {
            let m = MockMatch { id: self.next_match_id };
            self.next_match_id += 1;
            self.matches.push(m.clone());
            Box::new(m)
        }

        fn get_matches(&self) -> Vec<Box<dyn VtMatch>> {
            self.matches
                .iter()
                .cloned()
                .map(|m| Box::new(m) as Box<dyn VtMatch>)
                .collect()
        }

        fn get_program_correlator_info(&self) -> &dyn VtProgramCorrelatorInfo {
            &self.correlator_info
        }

        fn get_match_count(&self) -> i32 {
            self.matches.len() as i32
        }

        fn get_id(&self) -> i32 {
            self.id
        }

        fn get_matches_for_association(
            &self,
            _association: &dyn VtAssociation,
        ) -> Vec<Box<dyn VtMatch>> {
            self.get_matches()
        }

        fn get_matches_for_addresses(
            &self,
            _source_address: &Address,
            _destination_address: &Address,
        ) -> Vec<Box<dyn VtMatch>> {
            self.get_matches()
        }

        fn delete_match(&mut self, match_item: &dyn VtMatch) {
            let target = match_item.get_source_length();
            self.matches.retain(|m| m.id != target);
        }

        fn remove_match(&mut self, match_item: &dyn VtMatch) -> bool {
            let target = match_item.get_source_length();
            let before = self.matches.len();
            self.matches.retain(|m| m.id != target);
            self.matches.len() != before
        }
    }

    #[test]
    fn has_removable_matches_defaults_to_true() {
        // Matches the Java default method, which unconditionally `return`s `true`.
        let match_set = MockMatchSet::new(1);
        assert!(match_set.has_removable_matches());
    }

    #[test]
    fn get_id_returns_assigned_id() {
        let match_set = MockMatchSet::new(7);
        assert_eq!(match_set.get_id(), 7);
    }

    #[test]
    fn add_match_increments_match_count_and_is_returned_by_get_matches() {
        let mut match_set = MockMatchSet::new(1);
        assert_eq!(match_set.get_match_count(), 0);

        let added = match_set.add_match(VtMatchInfo::default());
        assert_eq!(match_set.get_match_count(), 1);
        assert_eq!(match_set.get_matches().len(), 1);
        assert_eq!(match_set.get_matches()[0].get_source_length(), added.get_source_length());
    }

    #[test]
    fn delete_match_removes_it_from_the_set() {
        let mut match_set = MockMatchSet::new(1);
        let added = match_set.add_match(VtMatchInfo::default());
        assert_eq!(match_set.get_match_count(), 1);

        match_set.delete_match(added.as_ref());
        assert_eq!(match_set.get_match_count(), 0);
    }

    #[test]
    fn remove_match_returns_false_when_match_is_absent() {
        let mut match_set = MockMatchSet::new(1);
        let not_present = MockMatch { id: 42 };
        assert!(!match_set.remove_match(&not_present));
    }

    #[test]
    fn remove_match_returns_true_when_match_is_removed() {
        let mut match_set = MockMatchSet::new(1);
        let added = match_set.add_match(VtMatchInfo::default());
        assert!(match_set.remove_match(added.as_ref()));
        assert_eq!(match_set.get_match_count(), 0);
    }

    #[test]
    fn get_program_correlator_info_exposes_name() {
        let match_set = MockMatchSet::new(1);
        assert_eq!(match_set.get_program_correlator_info().get_name(), "Mock");
    }

    #[test]
    fn get_session_is_usable_as_trait_object() {
        let match_set = MockMatchSet::new(1);
        let mut session = match_set.get_session();
        assert!(session.save_session().is_ok());
    }

    #[test]
    fn usable_as_trait_object() {
        let mut match_set: Box<dyn VTMatchSet> = Box::new(MockMatchSet::new(3));
        assert_eq!(match_set.get_id(), 3);
        match_set.add_match(VtMatchInfo::default());
        assert_eq!(match_set.get_match_count(), 1);
    }
}
