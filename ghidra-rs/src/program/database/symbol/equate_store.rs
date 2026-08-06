//! Pilot for the **snapshot + transaction** convention (see `OWNERSHIP_MIGRATION.md`).
//!
//! Ghidra's DB-backed domain objects cache their fields, compare a stored modification count
//! against the cache's to decide whether they are stale, call `refreshIfNeeded()` before most
//! reads, and guard the whole arrangement with a reentrant read/write lock. That machinery is
//! not incidental: it exists *because* the store is mutable and every object holds a stale copy
//! of part of it. It is also where this port's two worst bugs came from — a `set_name` →
//! `get_name` self-deadlock (the lock was reentrant in Java, not in Rust), and a cached name
//! that outlived its own invalidation.
//!
//! This module shows what those types look like without it, on equates (a name ↔ value mapping
//! plus the operand references that use it). It is deliberately additive — no existing trait or
//! call site changes — exactly as `group_tree.rs` piloted the arena convention before the
//! high-fan-in types adopted it.
//!
//! # The model
//!
//! - A **snapshot** ([`EquateStore`]) is an immutable version of all equate state, handed out as
//!   `Arc<EquateStore>`. Readers resolve [`EquateId`]s against the snapshot they hold. There is
//!   no staleness check, because a snapshot cannot become stale: an older version is a
//!   *consistent* version, not a wrong one. `needs_refreshing`/`refresh_if_needed` have no
//!   analogue here, and reads take no lock on the data.
//! - A **transaction** ([`EquateDatabase::transaction`]) is the only way to mutate. It takes the
//!   single-writer lock, applies changes to a store it uniquely owns, and publishes the new
//!   version atomically at commit. This is Ghidra's `startTransaction`/`endTransaction`.
//! - **Undo/redo is a delta log**: each transaction records the reversible [`Change`]s it made,
//!   and undo applies their inverses. See below for why this, and not retained versions.
//! - The **version number** replaces `modification_count`.
//!
//! # Why undo is a delta log and not a stack of snapshots
//!
//! The first cut of this pilot retained a bounded ring of prior `Arc<EquateStore>` versions,
//! which reads naturally and is wrong for the write path. Holding the previous version makes the
//! writer a non-sole owner of every arena, so `Arc::make_mut` copies on the next write — and a
//! plain map copy is O(n) in entries, not a cheap structural share. With undo enabled, *every*
//! transaction copied the whole store. On a program with millions of code units that is not
//! viable, and auto-analysis is exactly that workload.
//!
//! Recording the inverse operations instead keeps the writer the sole owner, so a transaction
//! mutates in place and copies nothing. The log's memory is proportional to the number of
//! *edits*, not the size of the store. This is also what Ghidra itself does: a transaction
//! records the changed records for its checkpoint rather than duplicating the database.
//!
//! **The cost that remains, and cannot be removed at this layer:** a reader holding a snapshot
//! across a write still forces exactly one copy-on-write, which is what keeps that reader's
//! version immutable. That is inherent to snapshot isolation over non-persistent maps — a GUI
//! holding a snapshot while analysis runs will pay it per transaction. If that becomes the
//! bottleneck, the fix is persistent arenas (`im`/`rpds`: O(1) clone, structural sharing) at the
//! cost of a dependency and slower point access. Both behaviours are pinned by tests below
//! (`transaction_mutates_in_place_with_undo_enabled`, `a_live_reader_forces_one_copy_on_write`)
//! so the tradeoff stays visible instead of being rediscovered.
//!
//! # Why ids are an explicit counter rather than `slotmap`
//!
//! Undoing a deletion has to restore the entry under the *same* [`EquateId`], or every id held
//! elsewhere (a code unit referring to this equate) would dangle after an undo. `SlotMap::insert`
//! always mints a fresh key and offers no insert-at-key, so it cannot express that. A monotonic
//! counter can, and it is what the database layer already has — the DB record key. Ids are never
//! reused, so a stale id simply resolves to `None`, which is the same safety a generational key
//! provides.
//!
//! # Persistence
//!
//! Out of scope for the pilot, and unchanged by the convention: commit is where a write-through
//! to the storage layer belongs. `framework/db` remains the reader for legacy Ghidra-format
//! projects.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};

use thiserror::Error;

use crate::program::model::address::Address;

/// A `Copy` handle to an equate, stable across versions and across undo/redo.
///
/// Resolving an id against a snapshot is how reads work; the id carries no data and cannot go
/// stale. Ids are allocated from a monotonic counter and never reused, so an id from a version
/// where the equate no longer exists simply resolves to `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EquateId(u64);

impl EquateId {
    /// The underlying key, which corresponds to the database record key.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// A reference from an equate to an operand at some address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquateReference {
    /// Address of the referring instruction.
    pub address: Address,
    /// Operand index the equate applies to, or `None` for a dynamic (hash-based) reference.
    pub op_index: Option<i16>,
    /// Dynamic hash for references not tied to a fixed operand index.
    pub dynamic_hash: Option<i64>,
}

/// The stored state of one equate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquateData {
    name: String,
    value: i64,
    references: Vec<EquateReference>,
}

impl EquateData {
    /// The equate's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The scalar value this equate names.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// References to this equate, in insertion order.
    pub fn references(&self) -> &[EquateReference] {
        &self.references
    }
}

/// Rejections a transaction can produce. A failed operation leaves the store untouched and
/// records no change.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EquateError {
    /// Another equate in this store already uses the name.
    #[error("an equate named '{0}' already exists")]
    DuplicateName(String),
    /// The name was empty or otherwise unusable.
    #[error("invalid equate name: '{0}'")]
    InvalidName(String),
    /// The id does not resolve in this version.
    #[error("no such equate")]
    NoSuchEquate,
}

/// One reversible mutation.
///
/// Variants come in symmetric pairs so that [`EquateStore::apply`] and [`EquateStore::revert`]
/// are exact inverses: this is what makes redo the forward replay of the same log that undo
/// walks backwards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// An equate was created under `id`.
    Inserted {
        /// The equate's id.
        id: EquateId,
        /// Its full state, so a redo can restore it exactly.
        data: EquateData,
    },
    /// An equate was deleted; `data` is what it held, so an undo restores it under the same id.
    Deleted {
        /// The equate's id.
        id: EquateId,
        /// The state it held when deleted.
        data: EquateData,
    },
    /// An equate was renamed.
    Renamed {
        /// The equate's id.
        id: EquateId,
        /// The name before the rename.
        from: String,
        /// The name after the rename.
        to: String,
    },
    /// A reference was added at `index` in the equate's reference list.
    RefInserted {
        /// The equate's id.
        id: EquateId,
        /// Position in the reference list.
        index: usize,
        /// The reference added.
        reference: EquateReference,
    },
    /// A reference was removed from `index` in the equate's reference list.
    RefDeleted {
        /// The equate's id.
        id: EquateId,
        /// Position it occupied.
        index: usize,
        /// The reference removed.
        reference: EquateReference,
    },
}

/// An immutable version of all equate state: the snapshot readers hold.
#[derive(Debug, Clone, Default)]
pub struct EquateStore {
    version: u64,
    next_id: u64,
    equates: Arc<HashMap<EquateId, EquateData>>,
    by_name: Arc<HashMap<String, EquateId>>,
}

impl EquateStore {
    /// The version this snapshot represents. Replaces Ghidra's `modification_count`.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Number of equates in this version.
    pub fn len(&self) -> usize {
        self.equates.len()
    }

    /// Whether this version holds no equates.
    pub fn is_empty(&self) -> bool {
        self.equates.is_empty()
    }

    /// Resolves an id against this version, or `None` if it does not exist here.
    pub fn get(&self, id: EquateId) -> Option<&EquateData> {
        self.equates.get(&id)
    }

    /// Looks an equate up by name within this version.
    pub fn by_name(&self, name: &str) -> Option<EquateId> {
        self.by_name.get(name).copied()
    }

    /// Every equate in this version. Iteration order is unspecified.
    pub fn iter(&self) -> impl Iterator<Item = (EquateId, &EquateData)> {
        self.equates.iter().map(|(id, data)| (*id, data))
    }

    // --- primitives shared by transactions, undo and redo ---

    fn insert_at(&mut self, id: EquateId, data: EquateData) {
        Arc::make_mut(&mut self.by_name).insert(data.name.clone(), id);
        Arc::make_mut(&mut self.equates).insert(id, data);
        self.next_id = self.next_id.max(id.0 + 1);
    }

    fn delete(&mut self, id: EquateId) -> Option<EquateData> {
        let data = Arc::make_mut(&mut self.equates).remove(&id)?;
        Arc::make_mut(&mut self.by_name).remove(&data.name);
        Some(data)
    }

    fn set_name(&mut self, id: EquateId, from: &str, to: &str) {
        if let Some(data) = Arc::make_mut(&mut self.equates).get_mut(&id) {
            data.name = to.to_string();
        }
        let names = Arc::make_mut(&mut self.by_name);
        names.remove(from);
        names.insert(to.to_string(), id);
    }

    /// Replays a change forward. Used by redo, and by a transaction as it records.
    fn apply(&mut self, change: &Change) {
        match change {
            Change::Inserted { id, data } => self.insert_at(*id, data.clone()),
            Change::Deleted { id, .. } => {
                self.delete(*id);
            }
            Change::Renamed { id, from, to } => self.set_name(*id, from, to),
            Change::RefInserted { id, index, reference } => {
                if let Some(data) = Arc::make_mut(&mut self.equates).get_mut(id) {
                    data.references.insert(*index, reference.clone());
                }
            }
            Change::RefDeleted { id, index, .. } => {
                if let Some(data) = Arc::make_mut(&mut self.equates).get_mut(id) {
                    if *index < data.references.len() {
                        data.references.remove(*index);
                    }
                }
            }
        }
    }

    /// Applies a change's exact inverse. Used by undo.
    fn revert(&mut self, change: &Change) {
        match change {
            Change::Inserted { id, .. } => {
                self.delete(*id);
            }
            // Restores under the SAME id -- ids held elsewhere stay valid across an undo.
            Change::Deleted { id, data } => self.insert_at(*id, data.clone()),
            Change::Renamed { id, from, to } => self.set_name(*id, to, from),
            Change::RefInserted { id, index, .. } => {
                if let Some(data) = Arc::make_mut(&mut self.equates).get_mut(id) {
                    if *index < data.references.len() {
                        data.references.remove(*index);
                    }
                }
            }
            Change::RefDeleted { id, index, reference } => {
                if let Some(data) = Arc::make_mut(&mut self.equates).get_mut(id) {
                    data.references.insert(*index, reference.clone());
                }
            }
        }
    }
}

/// The mutation API, handed to the closure passed to [`EquateDatabase::transaction`].
///
/// Every successful operation records a [`Change`]; a rejected one records nothing, so a failed
/// operation is invisible to undo as well as to readers.
pub struct Transaction<'a> {
    store: &'a mut EquateStore,
    changes: Vec<Change>,
}

impl Transaction<'_> {
    /// Reads within the transaction see the changes made so far.
    pub fn store(&self) -> &EquateStore {
        self.store
    }

    /// The changes recorded so far.
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    fn record(&mut self, change: Change) {
        self.store.apply(&change);
        self.changes.push(change);
    }

    /// Creates an equate, returning its new id.
    pub fn create(&mut self, name: &str, value: i64) -> Result<EquateId, EquateError> {
        if name.trim().is_empty() {
            return Err(EquateError::InvalidName(name.to_string()));
        }
        if self.store.by_name.contains_key(name) {
            return Err(EquateError::DuplicateName(name.to_string()));
        }
        let id = EquateId(self.store.next_id);
        self.record(Change::Inserted {
            id,
            data: EquateData {
                name: name.to_string(),
                value,
                references: Vec::new(),
            },
        });
        Ok(id)
    }

    /// Renames an equate.
    pub fn rename(&mut self, id: EquateId, new_name: &str) -> Result<(), EquateError> {
        if new_name.trim().is_empty() {
            return Err(EquateError::InvalidName(new_name.to_string()));
        }
        let old_name = self
            .store
            .get(id)
            .ok_or(EquateError::NoSuchEquate)?
            .name
            .clone();
        if old_name == new_name {
            return Ok(());
        }
        if self.store.by_name.contains_key(new_name) {
            return Err(EquateError::DuplicateName(new_name.to_string()));
        }
        self.record(Change::Renamed {
            id,
            from: old_name,
            to: new_name.to_string(),
        });
        Ok(())
    }

    /// Appends a reference to an equate.
    pub fn add_reference(
        &mut self,
        id: EquateId,
        reference: EquateReference,
    ) -> Result<(), EquateError> {
        let index = self
            .store
            .get(id)
            .ok_or(EquateError::NoSuchEquate)?
            .references
            .len();
        self.record(Change::RefInserted { id, index, reference });
        Ok(())
    }

    /// Removes the reference at `index` from an equate.
    pub fn remove_reference(&mut self, id: EquateId, index: usize) -> Result<(), EquateError> {
        let reference = self
            .store
            .get(id)
            .ok_or(EquateError::NoSuchEquate)?
            .references
            .get(index)
            .ok_or(EquateError::NoSuchEquate)?
            .clone();
        self.record(Change::RefDeleted { id, index, reference });
        Ok(())
    }

    /// Deletes an equate.
    pub fn remove(&mut self, id: EquateId) -> Result<(), EquateError> {
        let data = self.store.get(id).ok_or(EquateError::NoSuchEquate)?.clone();
        self.record(Change::Deleted { id, data });
        Ok(())
    }
}

/// The handle every thread shares: hands out snapshots, and serializes writers.
///
/// The `RwLock` guards only the *pointer* to the current version, never the data, so a reader
/// holds it just long enough to clone an `Arc`. (`arc_swap::ArcSwap` would make that wait-free;
/// it is deliberately not used yet, to keep the pilot dependency-free.)
#[derive(Debug)]
pub struct EquateDatabase {
    current: RwLock<Arc<EquateStore>>,
    history: Mutex<History>,
    undo_limit: usize,
}

/// Undo/redo state: change-sets, not versions. Memory is proportional to edits.
#[derive(Debug, Default)]
struct History {
    undo: VecDeque<Vec<Change>>,
    redo: Vec<Vec<Change>>,
}

impl Default for EquateDatabase {
    fn default() -> Self {
        Self::new(50)
    }
}

impl EquateDatabase {
    /// Creates an empty database retaining at most `undo_limit` transactions' worth of changes.
    pub fn new(undo_limit: usize) -> Self {
        Self {
            current: RwLock::new(Arc::new(EquateStore::default())),
            history: Mutex::new(History::default()),
            undo_limit,
        }
    }

    /// Takes an atomic, read-only snapshot of the current version.
    ///
    /// This is the read path in full: no refresh, no staleness check, and no lock held beyond
    /// cloning the pointer. The returned version is internally consistent forever.
    pub fn snapshot(&self) -> Arc<EquateStore> {
        Arc::clone(&self.current.read().unwrap())
    }

    /// The current version number.
    pub fn version(&self) -> u64 {
        self.current.read().unwrap().version()
    }

    /// Number of transactions that can currently be undone.
    pub fn undo_depth(&self) -> usize {
        self.history.lock().unwrap().undo.len()
    }

    /// Runs `f` as a transaction and publishes the result atomically.
    ///
    /// Ghidra's `startTransaction`/`endTransaction`. Readers continue to see the previous version
    /// until commit and then see the new one, never anything in between. Nothing retains the old
    /// version, so when no reader holds a snapshot this mutates entirely in place.
    pub fn transaction<R>(&self, _name: &str, f: impl FnOnce(&mut Transaction) -> R) -> R {
        let (result, changes) = self.mutate(f);
        if !changes.is_empty() && self.undo_limit > 0 {
            let mut history = self.history.lock().unwrap();
            history.undo.push_back(changes);
            if history.undo.len() > self.undo_limit {
                history.undo.pop_front();
            }
            history.redo.clear();
        }
        result
    }

    /// Applies `f` to a new version and publishes it, returning the recorded changes.
    fn mutate<R>(&self, f: impl FnOnce(&mut Transaction) -> R) -> (R, Vec<Change>) {
        let mut current = self.current.write().unwrap();

        // Take the store out of its Arc. When nothing else holds this version -- the normal case
        // now that undo keeps changes rather than snapshots -- this moves, and the arenas below
        // are never copied.
        let taken = std::mem::replace(&mut *current, Arc::new(EquateStore::default()));
        let mut next = match Arc::try_unwrap(taken) {
            Ok(owned) => owned,
            Err(shared) => (*shared).clone(), // a reader still holds this version
        };
        next.version += 1;

        let mut txn = Transaction {
            store: &mut next,
            changes: Vec::new(),
        };
        let result = f(&mut txn);
        let changes = txn.changes;

        *current = Arc::new(next);
        (result, changes)
    }

    /// Reverts the most recent transaction, returning whether anything was undone.
    pub fn undo(&self) -> bool {
        let changes = match self.history.lock().unwrap().undo.pop_back() {
            Some(changes) => changes,
            None => return false,
        };
        // Inverses, applied in reverse order.
        self.mutate(|txn| {
            for change in changes.iter().rev() {
                txn.store.revert(change);
            }
        });
        self.history.lock().unwrap().redo.push(changes);
        true
    }

    /// Re-applies the most recently undone transaction, returning whether anything was redone.
    pub fn redo(&self) -> bool {
        let changes = match self.history.lock().unwrap().redo.pop() {
            Some(changes) => changes,
            None => return false,
        };
        self.mutate(|txn| {
            for change in changes.iter() {
                txn.store.apply(change);
            }
        });
        self.history.lock().unwrap().undo.push_back(changes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    fn addr(offset: i64) -> Address {
        Address::new(
            AddressSpace::new("ram", 64, 1, AddressSpaceType::Ram, 1),
            offset,
        )
    }

    fn reference(offset: i64) -> EquateReference {
        EquateReference {
            address: addr(offset),
            op_index: Some(0),
            dynamic_hash: None,
        }
    }

    fn db_with(entries: &[(&str, i64)]) -> EquateDatabase {
        let db = EquateDatabase::default();
        db.transaction("seed", |txn| {
            for (name, value) in entries {
                txn.create(name, *value).expect("seed");
            }
        });
        db
    }

    #[test]
    fn snapshot_reads_resolve_ids_without_any_refresh() {
        let db = db_with(&[("MAX_PATH", 260)]);
        let snap = db.snapshot();
        let id = snap.by_name("MAX_PATH").expect("present");
        assert_eq!(snap.get(id).unwrap().name(), "MAX_PATH");
        assert_eq!(snap.get(id).unwrap().value(), 260);
    }

    /// The property the whole convention rests on: a reader holding a snapshot is completely
    /// unaffected by later writes, so there is nothing to invalidate and nothing to check.
    #[test]
    fn a_held_snapshot_is_unaffected_by_later_writes() {
        let db = db_with(&[("FLAG", 1)]);
        let before = db.snapshot();
        let id = before.by_name("FLAG").unwrap();

        db.transaction("rename", |txn| txn.rename(id, "RENAMED").unwrap());

        assert_eq!(before.get(id).unwrap().name(), "FLAG");
        assert!(before.by_name("RENAMED").is_none());

        let after = db.snapshot();
        assert_eq!(after.get(id).unwrap().name(), "RENAMED");
        assert_eq!(after.version(), before.version() + 1);
    }

    #[test]
    fn commit_publishes_atomically() {
        let db = db_with(&[]);
        let before = db.snapshot();
        db.transaction("bulk", |txn| {
            txn.create("A", 1).unwrap();
            txn.create("B", 2).unwrap();
            txn.create("C", 3).unwrap();
        });
        assert_eq!(before.len(), 0);
        assert_eq!(db.snapshot().len(), 3);
    }

    #[test]
    fn failed_operation_records_no_change_and_leaves_the_store_unchanged() {
        let db = db_with(&[("TAKEN", 1)]);
        let before_depth = db.undo_depth();

        let result = db.transaction("dup", |txn| txn.create("TAKEN", 2));

        assert_eq!(result, Err(EquateError::DuplicateName("TAKEN".into())));
        let snap = db.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.get(snap.by_name("TAKEN").unwrap()).unwrap().value(), 1);
        assert_eq!(
            db.undo_depth(),
            before_depth,
            "a rejected operation must not enter the undo log"
        );
    }

    #[test]
    fn invalid_name_is_rejected() {
        let db = db_with(&[]);
        let result = db.transaction("bad", |txn| txn.create("   ", 1));
        assert_eq!(result, Err(EquateError::InvalidName("   ".into())));
        assert!(db.snapshot().is_empty());
    }

    // --- the delta log ---

    /// The headline fix. Under snapshot-retained undo this was impossible: keeping the previous
    /// version made the writer a non-sole owner, so every transaction copied the arenas. With a
    /// delta log there is no second owner, so the write happens in place -- with undo ENABLED.
    #[test]
    fn transaction_mutates_in_place_with_undo_enabled() {
        let db = EquateDatabase::new(50);
        db.transaction("first", |txn| {
            txn.create("A", 1).unwrap();
        });

        let arena_before = Arc::as_ptr(&db.snapshot().equates);
        db.transaction("second", |txn| {
            txn.create("B", 2).unwrap();
        });
        let arena_after = Arc::as_ptr(&db.snapshot().equates);

        assert_eq!(
            arena_before, arena_after,
            "undo retention must not force a copy any more"
        );
        assert_eq!(db.undo_depth(), 2, "...while undo is still available");
    }

    /// The cost that remains and cannot be removed at this layer: a reader holding a snapshot
    /// across a write forces one copy, which is what keeps that reader's version immutable.
    #[test]
    fn a_live_reader_forces_one_copy_on_write() {
        let db = db_with(&[("A", 1)]);
        let held = db.snapshot();
        let arena_before = Arc::as_ptr(&held.equates);

        db.transaction("write", |txn| {
            txn.create("B", 2).unwrap();
        });

        assert_ne!(
            arena_before,
            Arc::as_ptr(&db.snapshot().equates),
            "the held snapshot must not have been mutated underneath its reader"
        );
        assert_eq!(held.len(), 1);
    }

    /// Undo log size tracks edits, not store size -- the point of the delta log.
    #[test]
    fn undo_log_holds_changes_not_versions() {
        let db = EquateDatabase::new(50);
        db.transaction("bulk", |txn| {
            for n in 0..100 {
                txn.create(&format!("E{n}"), n).unwrap();
            }
        });
        db.transaction("one_edit", |txn| {
            let id = txn.store().by_name("E0").unwrap();
            txn.rename(id, "RENAMED").unwrap();
        });

        let history = db.history.lock().unwrap();
        assert_eq!(history.undo.len(), 2, "two transactions recorded");
        assert_eq!(history.undo[0].len(), 100, "bulk transaction: one change per create");
        assert_eq!(
            history.undo[1].len(),
            1,
            "a one-edit transaction costs one change, not a copy of 100 equates"
        );
    }

    #[test]
    fn undo_and_redo_move_across_transactions() {
        let db = db_with(&[("ONE", 1)]);
        db.transaction("add", |txn| {
            txn.create("TWO", 2).unwrap();
        });
        assert_eq!(db.snapshot().len(), 2);

        assert!(db.undo());
        assert_eq!(db.snapshot().len(), 1);
        assert!(db.snapshot().by_name("TWO").is_none());

        assert!(db.redo());
        assert_eq!(db.snapshot().len(), 2);
        assert!(db.snapshot().by_name("TWO").is_some());
    }

    /// The constraint that dictated the explicit id space: undoing a deletion must restore the
    /// entry under the SAME id, or every id held elsewhere would dangle.
    #[test]
    fn undoing_a_deletion_restores_the_same_id() {
        let db = db_with(&[("GONE", 7)]);
        let id = db.snapshot().by_name("GONE").unwrap();

        db.transaction("remove", |txn| txn.remove(id).unwrap());
        assert!(db.snapshot().get(id).is_none());

        assert!(db.undo());
        let snap = db.snapshot();
        assert_eq!(snap.by_name("GONE"), Some(id), "id must be preserved across undo");
        assert_eq!(snap.get(id).unwrap().value(), 7);
    }

    #[test]
    fn undo_restores_references_exactly() {
        let db = db_with(&[("E", 1)]);
        let id = db.snapshot().by_name("E").unwrap();
        db.transaction("refs", |txn| {
            txn.add_reference(id, reference(0x1000)).unwrap();
            txn.add_reference(id, reference(0x2000)).unwrap();
            txn.add_reference(id, reference(0x3000)).unwrap();
        });

        db.transaction("drop_middle", |txn| txn.remove_reference(id, 1).unwrap());
        assert_eq!(db.snapshot().get(id).unwrap().references().len(), 2);

        assert!(db.undo());
        let refs = db.snapshot().get(id).unwrap().references().to_vec();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[1], reference(0x2000), "the reference returns to its original index");
    }

    #[test]
    fn a_multi_operation_transaction_undoes_as_one_unit() {
        let db = db_with(&[("KEEP", 1)]);
        let keep = db.snapshot().by_name("KEEP").unwrap();

        db.transaction("compound", |txn| {
            txn.create("NEW", 2).unwrap();
            txn.rename(keep, "KEEP2").unwrap();
            txn.add_reference(keep, reference(0x40)).unwrap();
        });

        assert!(db.undo());
        let snap = db.snapshot();
        assert_eq!(snap.len(), 1, "all three operations reverted together");
        assert_eq!(snap.get(keep).unwrap().name(), "KEEP");
        assert!(snap.get(keep).unwrap().references().is_empty());
    }

    #[test]
    fn repeated_undo_redo_is_stable() {
        let db = db_with(&[("A", 1)]);
        db.transaction("add", |txn| {
            txn.create("B", 2).unwrap();
        });
        for _ in 0..5 {
            assert!(db.undo());
            assert_eq!(db.snapshot().len(), 1);
            assert!(db.redo());
            assert_eq!(db.snapshot().len(), 2);
        }
        let snap = db.snapshot();
        assert!(snap.by_name("A").is_some() && snap.by_name("B").is_some());
    }

    #[test]
    fn undo_stops_at_the_beginning_and_a_new_write_clears_redo() {
        let db = db_with(&[("ONE", 1)]);
        assert!(db.undo());
        assert!(!db.undo());
        db.transaction("diverge", |txn| {
            txn.create("OTHER", 9).unwrap();
        });
        assert!(!db.redo(), "a new write must discard the redo branch");
    }

    #[test]
    fn undo_depth_is_bounded() {
        let db = EquateDatabase::new(2);
        for n in 0..5 {
            db.transaction("add", |txn| {
                txn.create(&format!("E{n}"), n).unwrap();
            });
        }
        assert_eq!(db.snapshot().len(), 5);
        assert_eq!(db.undo_depth(), 2);
        assert!(db.undo());
        assert!(db.undo());
        assert!(!db.undo(), "only the two most recent transactions are retained");
    }

    #[test]
    fn ids_are_never_reused_so_a_stale_id_resolves_to_none() {
        let db = db_with(&[("GONE", 1)]);
        let old = db.snapshot().by_name("GONE").unwrap();
        db.transaction("remove", |txn| txn.remove(old).unwrap());
        db.transaction("recreate", |txn| {
            txn.create("GONE", 2).unwrap();
        });

        let snap = db.snapshot();
        let new = snap.by_name("GONE").unwrap();
        assert_ne!(old, new, "a fresh equate must not inherit a retired id");
        assert!(snap.get(old).is_none());
    }

    #[test]
    fn references_accumulate_within_a_transaction() {
        let db = db_with(&[("E", 7)]);
        let id = db.snapshot().by_name("E").unwrap();
        db.transaction("refs", |txn| {
            txn.add_reference(
                id,
                EquateReference { address: addr(0x1000), op_index: Some(1), dynamic_hash: None },
            )
            .unwrap();
            txn.add_reference(
                id,
                EquateReference { address: addr(0x2000), op_index: None, dynamic_hash: Some(42) },
            )
            .unwrap();
        });
        let snap = db.snapshot();
        let refs = snap.get(id).unwrap().references();
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].op_index, Some(1));
        assert_eq!(refs[1].dynamic_hash, Some(42));
    }

    #[test]
    fn removing_an_equate_frees_its_name() {
        let db = db_with(&[("GONE", 1)]);
        let id = db.snapshot().by_name("GONE").unwrap();
        db.transaction("remove", |txn| txn.remove(id).unwrap());

        let snap = db.snapshot();
        assert!(snap.get(id).is_none());
        assert!(snap.by_name("GONE").is_none());

        db.transaction("reuse", |txn| {
            txn.create("GONE", 2).unwrap();
        });
        assert_eq!(db.snapshot().len(), 1);
    }

    /// Readers run concurrently with a writer and never block on it, each seeing some
    /// internally-consistent version. Under the cached-field model this is precisely where the
    /// reentrant-lock deadlock lived.
    #[test]
    fn concurrent_readers_are_never_blocked_by_a_writer() {
        let db = Arc::new(db_with(&[("SEED", 0)]));
        let stop = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..4)
            .map(|_| {
                let db = Arc::clone(&db);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    let mut seen = 0usize;
                    while !stop.load(Ordering::SeqCst) {
                        let snap = db.snapshot();
                        for (id, data) in snap.iter() {
                            assert_eq!(snap.by_name(data.name()), Some(id));
                        }
                        seen += 1;
                    }
                    seen
                })
            })
            .collect();

        for n in 0..200 {
            db.transaction("churn", |txn| {
                txn.create(&format!("E{n}"), n).unwrap();
            });
        }
        stop.store(true, Ordering::SeqCst);

        for r in readers {
            assert!(r.join().unwrap() > 0, "reader made no progress");
        }
        assert_eq!(db.snapshot().len(), 201);
    }

    /// Undo/redo racing with readers must never expose a torn version either.
    #[test]
    fn readers_see_consistent_versions_across_undo_and_redo() {
        let db = Arc::new(db_with(&[("A", 1)]));
        for n in 0..20 {
            db.transaction("add", |txn| {
                txn.create(&format!("E{n}"), n).unwrap();
            });
        }
        let stop = Arc::new(AtomicBool::new(false));
        let reader = {
            let db = Arc::clone(&db);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let snap = db.snapshot();
                    for (id, data) in snap.iter() {
                        assert_eq!(snap.by_name(data.name()), Some(id));
                    }
                }
            })
        };

        for _ in 0..50 {
            db.undo();
            db.redo();
        }
        stop.store(true, Ordering::SeqCst);
        reader.join().unwrap();
        assert_eq!(db.snapshot().len(), 21);
    }

    /// Scaling check for the delta log, kept `#[ignore]`d so the suite stays fast and free of
    /// timing flakes. Run with:
    ///   cargo test --lib equate_store::tests::write_cost_is_independent_of_store_size -- --ignored --nocapture
    ///
    /// Under the previous snapshot-retained undo, per-transaction cost grew with store size
    /// (every write copied the whole arena). With the delta log it should stay flat.
    #[test]
    #[ignore]
    fn write_cost_is_independent_of_store_size() {
        use std::time::Instant;

        for size in [100usize, 1_000, 10_000, 100_000] {
            let db = EquateDatabase::new(50);
            db.transaction("seed", |txn| {
                for n in 0..size {
                    txn.create(&format!("E{n}"), n as i64).unwrap();
                }
            });

            let edits = 200;
            let start = Instant::now();
            for n in 0..edits {
                db.transaction("edit", |txn| {
                    txn.create(&format!("X{n}"), n as i64).unwrap();
                });
            }
            let in_place = start.elapsed().as_nanos() / edits as u128;

            // Holding a snapshot across each write forces the copy-on-write path -- which is
            // also exactly the cost profile the old snapshot-retained undo had on EVERY write.
            let start = Instant::now();
            for n in 0..edits {
                let _held = db.snapshot();
                db.transaction("edit", |txn| {
                    txn.create(&format!("Y{n}"), n as i64).unwrap();
                });
            }
            let copying = start.elapsed().as_nanos() / edits as u128;

            println!(
                "store={size:>7} entries -> in-place {in_place:>9} ns | copy-on-write {copying:>10} ns                  ({:.0}x)",
                copying as f64 / in_place.max(1) as f64
            );
        }
    }
}
