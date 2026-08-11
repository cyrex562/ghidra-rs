use std::collections::HashSet;
use std::sync::Arc;

use crate::feature::seam_stubs::{VtAssociation, VtMatch, VtMatchSet};
use crate::feature::vt::api::main::association_hook::AssociationHook;
use crate::feature::vt::api::main::vt_association_manager::VtAssociationManager;
use crate::feature::vt::api::main::vt_match_tag::VtMatchTag;
use crate::feature::vt::api::main::vt_program_correlator::VTProgramCorrelator;
use crate::framework::db::util::ErrorHandler;
use crate::framework::model::DomainObject;
use crate::program::model::listing::program::Program;

/// Main trait for a Version Tracking session.
///
/// Port of `ghidra.feature.vt.api.main.VTSession`. `getName`, `addListener`, and
/// `removeListener` are re-declared with `@Override` in the Java interface purely for
/// documentation and carry no new semantics, so they are not redeclared here -- implementors
/// get them from the [`DomainObject`] supertrait, mirroring the `DomainObjectAdapterDB`
/// precedent. The zero-argument `VTSession.save()` is a genuine Java overload of
/// `DomainObject.save(String, TaskMonitor)` (different arity, same name); since Rust has no
/// overloading, it is ported as [`VTSession::save_session`] to avoid colliding with
/// [`DomainObject::save`].
pub trait VTSession: DomainObject + ErrorHandler + Send + Sync {
    /// Returns the association manager for this session.
    fn get_association_manager(&self) -> &dyn VtAssociationManager;

    /// Creates a new match set that will contain all matches discovered by a program-correlator
    /// run, and adds it to this session.
    fn create_match_set(&mut self, correlator: &dyn VTProgramCorrelator) -> Box<dyn VtMatchSet>;

    /// Returns all match sets contained in this session.
    fn get_match_sets(&self) -> Vec<Box<dyn VtMatchSet>>;

    /// Returns the source program associated with this session.
    fn get_source_program(&self) -> Arc<dyn Program>;

    /// Returns the destination program associated with this session.
    fn get_destination_program(&self) -> Arc<dyn Program>;

    /// Saves this session. Distinct from [`DomainObject::save`]; see the trait-level docs.
    fn save_session(&mut self) -> std::io::Result<()>;

    /// Creates a new match tag with the given name.
    fn create_match_tag(&mut self, name: &str) -> VtMatchTag;

    /// Deletes the given match tag from this session.
    fn delete_match_tag(&mut self, tag: &VtMatchTag);

    /// Returns all match tags defined in this session.
    fn get_match_tags(&self) -> HashSet<VtMatchTag>;

    /// Returns the built-in match set used to store manually created matches.
    fn get_manual_match_set(&self) -> &dyn VtMatchSet;

    /// Returns the built-in match set used to store implied matches.
    fn get_implied_match_set(&self) -> &dyn VtMatchSet;

    /// Returns all matches for the given association.
    fn get_matches(&self, association: &dyn VtAssociation) -> Vec<Box<dyn VtMatch>>;

    /// Adds an association hook that will be called whenever an association is accepted or
    /// cleared.
    fn add_association_hook(&mut self, hook: Box<dyn AssociationHook>);

    /// Removes the given association hook.
    fn remove_association_hook(&mut self, hook: &dyn AssociationHook);

    /// Replaces the source program associated with this session.
    fn update_source_program(&mut self, new_program: Arc<dyn Program>);

    /// Replaces the destination program associated with this session.
    fn update_destination_program(&mut self, new_program: Arc<dyn Program>);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAssociationManager;

    impl VtAssociationManager for MockAssociationManager {
        fn get_association_count(&self) -> usize {
            0
        }

        fn get_associations(&self) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn get_association(
            &self,
            _source_address: &crate::program::model::address::Address,
            _destination_address: &crate::program::model::address::Address,
        ) -> Option<Box<dyn VtAssociation>> {
            None
        }

        fn get_related_associations_by_source_address(
            &self,
            _source_address: &crate::program::model::address::Address,
        ) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn get_related_associations_by_destination_address(
            &self,
            _destination_address: &crate::program::model::address::Address,
        ) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }

        fn get_related_associations_by_source_and_destination_address(
            &self,
            _source_address: &crate::program::model::address::Address,
            _destination_address: &crate::program::model::address::Address,
        ) -> Vec<Box<dyn VtAssociation>> {
            Vec::new()
        }
    }

    #[derive(Default)]
    struct MockVtSession {
        name: String,
        tags: HashSet<VtMatchTag>,
        association_manager: MockAssociationManager,
        hook_count: usize,
    }

    impl Default for MockAssociationManager {
        fn default() -> Self {
            MockAssociationManager
        }
    }

    impl DomainObject for MockVtSession {
        fn is_changed(&self) -> bool {
            false
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        fn set_name(&mut self, name: &str) {
            self.name = name.to_string();
        }
    }

    impl ErrorHandler for MockVtSession {
        fn db_error(&self, _e: std::io::Error) {}
    }

    impl VTSession for MockVtSession {
        fn get_association_manager(&self) -> &dyn VtAssociationManager {
            &self.association_manager
        }

        fn create_match_set(&mut self, _correlator: &dyn VTProgramCorrelator) -> Box<dyn VtMatchSet> {
            unimplemented!("not exercised by this test")
        }

        fn get_match_sets(&self) -> Vec<Box<dyn VtMatchSet>> {
            Vec::new()
        }

        fn get_source_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this test")
        }

        fn get_destination_program(&self) -> Arc<dyn Program> {
            unimplemented!("not exercised by this test")
        }

        fn save_session(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn create_match_tag(&mut self, name: &str) -> VtMatchTag {
            let tag = VtMatchTag::Named(name.to_string());
            self.tags.insert(tag.clone());
            tag
        }

        fn delete_match_tag(&mut self, tag: &VtMatchTag) {
            self.tags.remove(tag);
        }

        fn get_match_tags(&self) -> HashSet<VtMatchTag> {
            self.tags.clone()
        }

        fn get_manual_match_set(&self) -> &dyn VtMatchSet {
            unimplemented!("not exercised by this test")
        }

        fn get_implied_match_set(&self) -> &dyn VtMatchSet {
            unimplemented!("not exercised by this test")
        }

        fn get_matches(&self, _association: &dyn VtAssociation) -> Vec<Box<dyn VtMatch>> {
            Vec::new()
        }

        fn add_association_hook(&mut self, _hook: Box<dyn AssociationHook>) {
            self.hook_count += 1;
        }

        fn remove_association_hook(&mut self, _hook: &dyn AssociationHook) {
            self.hook_count -= 1;
        }

        fn update_source_program(&mut self, _new_program: Arc<dyn Program>) {}

        fn update_destination_program(&mut self, _new_program: Arc<dyn Program>) {}
    }

    #[test]
    fn usable_as_trait_object() {
        let mut session = MockVtSession::default();
        let dyn_session: &mut dyn VTSession = &mut session;
        assert_eq!(dyn_session.get_association_manager().get_association_count(), 0);
        assert!(dyn_session.save_session().is_ok());
    }

    #[test]
    fn create_match_tag_adds_named_tag() {
        let mut session = MockVtSession::default();
        let tag = session.create_match_tag("alpha");
        assert_eq!(tag, VtMatchTag::Named("alpha".to_string()));
        assert!(session.get_match_tags().contains(&tag));
    }

    #[test]
    fn delete_match_tag_removes_it() {
        let mut session = MockVtSession::default();
        let tag = session.create_match_tag("beta");
        assert_eq!(session.get_match_tags().len(), 1);
        session.delete_match_tag(&tag);
        assert!(session.get_match_tags().is_empty());
    }

    #[test]
    fn inherits_domain_object_name_accessor() {
        let mut session = MockVtSession::default();
        // getName()/addListener()/removeListener() are inherited from DomainObject, matching
        // VTSession's @Override-but-unchanged Java declarations.
        session.set_name("MySession");
        assert_eq!(session.get_name(), "MySession");
        assert!(session.is_sending_events());
    }

    #[test]
    fn association_hook_registration_tracks_count() {
        struct NoopHook;
        impl AssociationHook for NoopHook {
            fn association_accepted(&self, _association: &dyn VtAssociation) {}
            fn association_cleared(&self, _association: &dyn VtAssociation) {}
            fn markup_item_status_changed(&self, _markup_item: &dyn crate::feature::seam_stubs::VtMarkupItem) {}
        }

        let mut session = MockVtSession::default();
        session.add_association_hook(Box::new(NoopHook));
        assert_eq!(session.hook_count, 1);
    }
}
