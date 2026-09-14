//! Port of `ghidra.trace.database.DBTraceChangeSet`.
//!
//! # Faithfully preserved: this is a literal stub in the Java source
//!
//! Every method body in the Java class reads `// TODO Auto-generated method stub` -- it is an
//! IDE-generated skeleton implementing `TraceChangeSet`/`DomainObjectDBChangeSet` that nobody
//! ever filled in. Every mutator is a no-op, `read`/`write` do nothing, and every getter (`long[]
//! getDataTypeChanges()`, etc.) returns `null`.
//!
//! This port keeps that behavior rather than fleshing it out into a real change set: every
//! mutator here is likewise a no-op, so a value passed to e.g. [`Self::data_type_changed`] is
//! never recorded and never appears in [`Self::get_data_type_changes`].
//!
//! The one unavoidable deviation is the `null` array returns: [`DataTypeChangeSet`]'s getters are
//! already established project-wide as returning `&[i64]` (non-nullable, since a `record`/`enum`
//! can't need a nullable slice the way Java's array-typed field can be `null`), so `null` has no
//! representation here. Since every mutator is *also* a no-op, the observable behavior is
//! identical either way: a caller can never get a real value out of this type, whether the getter
//! returns `null` (Java) or an always-empty slice (here it would need to trip on a
//! `NullPointerException` to notice the difference, which cannot happen against this
//! non-nullable, always-empty slice).
use std::io;

use crate::framework::data::domain_object_db_change_set::DomainObjectDBChangeSet;
use crate::framework::db::{DBChangeSet, DBHandle};
use crate::framework::model::ChangeSet;
use crate::program::model::listing::DataTypeChangeSet;
use crate::trace::model::trace_change_set::TraceChangeSet;

/// Port of `ghidra.trace.database.DBTraceChangeSet`.
///
/// See the module docs: every method here mirrors an unfilled `// TODO Auto-generated method
/// stub` body in the Java source, so this type can never actually track a change.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DBTraceChangeSet;

impl DBTraceChangeSet {
    /// Constructs a new, permanently-empty change set. Mirrors the implicit no-arg constructor.
    pub fn new() -> Self {
        Self
    }
}

impl ChangeSet for DBTraceChangeSet {}

impl DataTypeChangeSet for DBTraceChangeSet {
    fn data_type_changed(&mut self, _id: i64) {
        // Stub: TODO Auto-generated method stub.
    }

    fn data_type_added(&mut self, _id: i64) {
        // Stub: TODO Auto-generated method stub.
    }

    fn get_data_type_changes(&self) -> &[i64] {
        // Stub: Java returns `null` here; see the module docs for why this is `&[]` instead.
        &[]
    }

    fn get_data_type_additions(&self) -> &[i64] {
        &[]
    }

    fn category_changed(&mut self, _id: i64) {
        // Stub: TODO Auto-generated method stub.
    }

    fn category_added(&mut self, _id: i64) {
        // Stub: TODO Auto-generated method stub.
    }

    fn get_category_changes(&self) -> &[i64] {
        &[]
    }

    fn get_category_additions(&self) -> &[i64] {
        &[]
    }

    fn source_archive_changed(&mut self, _id: i64) {
        // Stub: TODO Auto-generated method stub.
    }

    fn source_archive_added(&mut self, _id: i64) {
        // Stub: TODO Auto-generated method stub.
    }

    fn get_source_archive_changes(&self) -> &[i64] {
        &[]
    }

    fn get_source_archive_additions(&self) -> &[i64] {
        &[]
    }
}

impl TraceChangeSet for DBTraceChangeSet {}

impl DBChangeSet for DBTraceChangeSet {
    fn read(&mut self, _dbh: &DBHandle) -> io::Result<()> {
        // Stub: TODO Auto-generated method stub.
        Ok(())
    }

    fn write(&mut self, _dbh: &DBHandle, _is_recovery_save: bool) -> io::Result<()> {
        // Stub: TODO Auto-generated method stub.
        Ok(())
    }
}

impl DomainObjectDBChangeSet for DBTraceChangeSet {
    fn clear_undo(&mut self, _is_checked_out: bool) {
        // Stub: TODO Auto-generated method stub.
    }

    fn undo(&mut self) {
        // Stub: TODO Auto-generated method stub.
    }

    fn redo(&mut self) {
        // Stub: TODO Auto-generated method stub.
    }

    fn set_max_undos(&mut self, _max_undos: i32) {
        // Stub: TODO Auto-generated method stub.
    }

    fn clear_undo_stack(&mut self) {
        // Stub: mirrors the Java class's other, no-arg `clearUndo()` override.
    }

    fn start_transaction(&mut self) {
        // Stub: TODO Auto-generated method stub.
    }

    fn end_transaction(&mut self, _commit: bool) {
        // Stub: TODO Auto-generated method stub.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutators_never_change_observable_state() {
        let mut cs = DBTraceChangeSet::new();
        cs.data_type_changed(42);
        cs.data_type_added(100);
        cs.category_changed(7);
        cs.category_added(8);
        cs.source_archive_changed(1);
        cs.source_archive_added(2);

        assert_eq!(cs.get_data_type_changes(), &[] as &[i64]);
        assert_eq!(cs.get_data_type_additions(), &[] as &[i64]);
        assert_eq!(cs.get_category_changes(), &[] as &[i64]);
        assert_eq!(cs.get_category_additions(), &[] as &[i64]);
        assert_eq!(cs.get_source_archive_changes(), &[] as &[i64]);
        assert_eq!(cs.get_source_archive_additions(), &[] as &[i64]);
    }

    #[test]
    fn read_and_write_are_no_op_successes() {
        let mut cs = DBTraceChangeSet::new();
        let dbh = DBHandle::new().unwrap();
        assert!(cs.read(&dbh).is_ok());
        assert!(cs.write(&dbh, true).is_ok());
        assert!(cs.write(&dbh, false).is_ok());
    }

    #[test]
    fn undo_redo_and_transaction_controls_are_callable_no_ops() {
        let mut cs = DBTraceChangeSet::new();
        cs.clear_undo(true);
        cs.clear_undo(false);
        cs.undo();
        cs.redo();
        cs.set_max_undos(10);
        cs.clear_undo_stack();
        cs.start_transaction();
        cs.end_transaction(true);
        cs.end_transaction(false);
        // No panics, and (per the module docs) no way to observe any of this having done
        // anything: the type carries no state to inspect.
        assert_eq!(cs, DBTraceChangeSet::new());
    }

    #[test]
    fn usable_as_trait_objects() {
        let mut cs: Box<dyn TraceChangeSet> = Box::new(DBTraceChangeSet::new());
        cs.data_type_changed(1);
        assert_eq!(cs.get_data_type_changes(), &[] as &[i64]);

        let mut cs: Box<dyn DomainObjectDBChangeSet> = Box::new(DBTraceChangeSet::new());
        cs.start_transaction();
        cs.end_transaction(true);
    }
}
