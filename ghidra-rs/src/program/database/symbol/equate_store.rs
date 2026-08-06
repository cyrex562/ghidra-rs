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
//! - **Undo/redo** is a bounded ring of retained versions, which is what Ghidra's undo already
//!   is — implemented there by hand over database checkpoints.
//! - The **version number** replaces `modification_count`.
//!
//! # Why the arenas are individually `Arc`
//!
//! Auto-analysis is write-heavy: a naive "clone the world per edit" design would be far too
//! slow. Each arena is its own `Arc`, and mutation goes through [`Arc::make_mut`], so a
//! transaction copies only the arenas it actually touches, and copies *nothing at all* when it
//! is the sole owner of the version it is mutating.
//!
//! **The pilot found the limit of that, and it matters for the real implementation.** `SlotMap`
//! is not a persistent structure: copying an arena is O(n) in its entries, not a cheap
//! structural share. So "sole owner" is doing a lot of work in that sentence — and *retaining
//! the previous version for undo makes the writer a non-sole owner by construction*. With undo
//! enabled, every transaction copies each touched arena in full. On a program with millions of
//! code units that is not viable.
//!
//! Both behaviours are pinned by tests below (`transaction_does_not_copy_arenas_when_sole_owner`
//! and `retaining_a_version_for_undo_forces_a_copy`) so the tradeoff is visible rather than
//! discovered later. Two ways out, for whichever type adopts this beyond the pilot:
//!
//! 1. **Delta-log undo** — retain the *operations* needed to invert a transaction rather than
//!    whole versions. This is what Ghidra already does (a transaction records changed records
//!    for its checkpoint), and it keeps the writer the sole owner, so writes stay in-place.
//! 2. **Persistent arenas** (`im`/`rpds`) — O(1) clone with structural sharing, at the cost of a
//!    dependency and slower point access.
//!
//! Snapshot *reads* are unaffected either way; this is purely about what a write costs.
//!
//! # Persistence
//!
//! Out of scope for the pilot, and unchanged by the convention: commit is where a write-through
//! to the storage layer belongs. `framework/db` remains the reader for legacy Ghidra-format
//! projects.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};

use slotmap::{new_key_type, SlotMap};
use thiserror::Error;

use crate::program::model::address::Address;

new_key_type! {
    /// A `Copy` handle to an equate, stable across versions.
    ///
    /// Resolving an id against a snapshot is how reads work; the id itself carries no data and
    /// cannot go stale. An id created in one version and resolved against an older snapshot
    /// simply reports `None`, which is the honest answer.
    pub struct EquateId;
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

/// Rejections a transaction can produce. A failed operation leaves the store untouched.
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

/// An immutable version of all equate state: the snapshot readers hold.
///
/// Cloning is cheap — the arenas are shared until a transaction touches them.
#[derive(Debug, Clone, Default)]
pub struct EquateStore {
    version: u64,
    equates: Arc<SlotMap<EquateId, EquateData>>,
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
        self.equates.get(id)
    }

    /// Looks an equate up by name within this version.
    pub fn by_name(&self, name: &str) -> Option<EquateId> {
        self.by_name.get(name).copied()
    }

    /// Every equate in this version, in arena order.
    pub fn iter(&self) -> impl Iterator<Item = (EquateId, &EquateData)> {
        self.equates.iter()
    }

    // --- mutation, reachable only from inside a transaction ---

    fn create(&mut self, name: &str, value: i64) -> Result<EquateId, EquateError> {
        if name.trim().is_empty() {
            return Err(EquateError::InvalidName(name.to_string()));
        }
        if self.by_name.contains_key(name) {
            return Err(EquateError::DuplicateName(name.to_string()));
        }
        let id = Arc::make_mut(&mut self.equates).insert(EquateData {
            name: name.to_string(),
            value,
            references: Vec::new(),
        });
        Arc::make_mut(&mut self.by_name).insert(name.to_string(), id);
        Ok(id)
    }

    fn rename(&mut self, id: EquateId, new_name: &str) -> Result<(), EquateError> {
        if new_name.trim().is_empty() {
            return Err(EquateError::InvalidName(new_name.to_string()));
        }
        let old_name = self
            .equates
            .get(id)
            .ok_or(EquateError::NoSuchEquate)?
            .name
            .clone();
        if old_name == new_name {
            return Ok(());
        }
        if self.by_name.contains_key(new_name) {
            return Err(EquateError::DuplicateName(new_name.to_string()));
        }
        Arc::make_mut(&mut self.equates)
            .get_mut(id)
            .ok_or(EquateError::NoSuchEquate)?
            .name = new_name.to_string();
        let names = Arc::make_mut(&mut self.by_name);
        names.remove(&old_name);
        names.insert(new_name.to_string(), id);
        Ok(())
    }

    fn add_reference(&mut self, id: EquateId, reference: EquateReference) -> Result<(), EquateError> {
        Arc::make_mut(&mut self.equates)
            .get_mut(id)
            .ok_or(EquateError::NoSuchEquate)?
            .references
            .push(reference);
        Ok(())
    }

    fn remove(&mut self, id: EquateId) -> Result<(), EquateError> {
        let data = Arc::make_mut(&mut self.equates)
            .remove(id)
            .ok_or(EquateError::NoSuchEquate)?;
        Arc::make_mut(&mut self.by_name).remove(&data.name);
        Ok(())
    }
}

/// The handle every thread shares: hands out snapshots, and serializes writers.
///
/// The `RwLock` here guards only the *pointer* to the current version, never the data, so a
/// reader holds it just long enough to clone an `Arc`. (`arc_swap::ArcSwap` would make that
/// wait-free; it is deliberately not used yet, to keep the pilot dependency-free.)
#[derive(Debug)]
pub struct EquateDatabase {
    current: RwLock<Arc<EquateStore>>,
    history: Mutex<History>,
    undo_limit: usize,
}

#[derive(Debug, Default)]
struct History {
    undo: VecDeque<Arc<EquateStore>>,
    redo: Vec<Arc<EquateStore>>,
}

impl Default for EquateDatabase {
    fn default() -> Self {
        Self::new(50)
    }
}

impl EquateDatabase {
    /// Creates an empty database retaining at most `undo_limit` prior versions.
    ///
    /// The bound matters: retained snapshots pin memory, which is why Ghidra bounds undo depth
    /// too.
    pub fn new(undo_limit: usize) -> Self {
        Self {
            current: RwLock::new(Arc::new(EquateStore::default())),
            history: Mutex::new(History::default()),
            undo_limit,
        }
    }

    /// Takes an atomic, read-only snapshot of the current version.
    ///
    /// This is the read path in full. There is no refresh, no staleness check and no lock held
    /// beyond cloning the pointer — the returned version is internally consistent forever.
    pub fn snapshot(&self) -> Arc<EquateStore> {
        Arc::clone(&self.current.read().unwrap())
    }

    /// The current version number.
    pub fn version(&self) -> u64 {
        self.current.read().unwrap().version()
    }

    /// Runs `f` as a transaction and publishes the result atomically.
    ///
    /// Ghidra's `startTransaction`/`endTransaction`. The closure mutates a store this
    /// transaction uniquely owns; readers continue to see the previous version until commit, and
    /// then see the new one — never anything in between.
    ///
    /// A transaction that returns `Err` still publishes, because individual operations already
    /// leave the store untouched when they fail; see `failed_operation_leaves_store_unchanged`.
    pub fn transaction<R>(&self, _name: &str, f: impl FnOnce(&mut EquateStore) -> R) -> R {
        let mut current = self.current.write().unwrap();

        // Retain the prior version for undo only if undo is enabled. Holding it is not free: it
        // is a second owner of every arena, which forces `make_mut` below to copy. When undo is
        // disabled and no reader holds the version, `try_unwrap` moves the store out and the
        // transaction mutates genuinely in place.
        let previous = if self.undo_limit > 0 {
            Some(Arc::clone(&current))
        } else {
            None
        };

        let taken = std::mem::replace(&mut *current, Arc::new(EquateStore::default()));
        let mut next = match Arc::try_unwrap(taken) {
            Ok(owned) => owned,                 // sole owner: no arena is copied at all
            Err(shared) => (*shared).clone(),   // a reader or the undo ring still holds it
        };
        next.version += 1;
        let result = f(&mut next);

        *current = Arc::new(next);

        if let Some(previous) = previous {
            let mut history = self.history.lock().unwrap();
            history.undo.push_back(previous);
            if history.undo.len() > self.undo_limit {
                history.undo.pop_front();
            }
            history.redo.clear();
        }
        result
    }

    /// Reverts to the previous version, returning whether anything was undone.
    pub fn undo(&self) -> bool {
        let mut current = self.current.write().unwrap();
        let mut history = self.history.lock().unwrap();
        match history.undo.pop_back() {
            Some(previous) => {
                history.redo.push(Arc::clone(&current));
                *current = previous;
                true
            }
            None => false,
        }
    }

    /// Re-applies the most recently undone version, returning whether anything was redone.
    pub fn redo(&self) -> bool {
        let mut current = self.current.write().unwrap();
        let mut history = self.history.lock().unwrap();
        match history.redo.pop() {
            Some(next) => {
                history.undo.push_back(Arc::clone(&current));
                *current = next;
                true
            }
            None => false,
        }
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

    fn db_with(entries: &[(&str, i64)]) -> EquateDatabase {
        let db = EquateDatabase::default();
        db.transaction("seed", |store| {
            for (name, value) in entries {
                store.create(name, *value).expect("seed");
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
    /// This is the case the cached-field + modification-count machinery exists to handle.
    #[test]
    fn a_held_snapshot_is_unaffected_by_later_writes() {
        let db = db_with(&[("FLAG", 1)]);
        let before = db.snapshot();
        let id = before.by_name("FLAG").unwrap();

        db.transaction("rename", |store| store.rename(id, "RENAMED").unwrap());

        // The old snapshot still reads the old name -- consistently, not stalely.
        assert_eq!(before.get(id).unwrap().name(), "FLAG");
        assert!(before.by_name("RENAMED").is_none());

        // A new snapshot sees the change.
        let after = db.snapshot();
        assert_eq!(after.get(id).unwrap().name(), "RENAMED");
        assert_eq!(after.version(), before.version() + 1);
    }

    #[test]
    fn commit_publishes_atomically() {
        let db = db_with(&[]);
        let before = db.snapshot();
        db.transaction("bulk", |store| {
            store.create("A", 1).unwrap();
            store.create("B", 2).unwrap();
            store.create("C", 3).unwrap();
        });
        // Readers never observe a partially-applied transaction: the old version has none of
        // them, the new version has all three.
        assert_eq!(before.len(), 0);
        assert_eq!(db.snapshot().len(), 3);
    }

    #[test]
    fn failed_operation_leaves_store_unchanged() {
        let db = db_with(&[("TAKEN", 1)]);
        let result = db.transaction("dup", |store| store.create("TAKEN", 2));
        assert_eq!(result, Err(EquateError::DuplicateName("TAKEN".into())));
        let snap = db.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.get(snap.by_name("TAKEN").unwrap()).unwrap().value(), 1);
    }

    #[test]
    fn invalid_name_is_rejected() {
        let db = db_with(&[]);
        let result = db.transaction("bad", |store| store.create("   ", 1));
        assert_eq!(result, Err(EquateError::InvalidName("   ".into())));
        assert!(db.snapshot().is_empty());
    }

    #[test]
    fn undo_and_redo_move_between_retained_versions() {
        let db = db_with(&[("ONE", 1)]);
        db.transaction("add", |store| {
            store.create("TWO", 2).unwrap();
        });
        assert_eq!(db.snapshot().len(), 2);

        assert!(db.undo());
        assert_eq!(db.snapshot().len(), 1);
        assert!(db.snapshot().by_name("TWO").is_none());

        assert!(db.redo());
        assert_eq!(db.snapshot().len(), 2);
        assert!(db.snapshot().by_name("TWO").is_some());
    }

    #[test]
    fn undo_stops_at_the_beginning_and_redo_is_cleared_by_a_new_write() {
        let db = db_with(&[("ONE", 1)]);
        assert!(db.undo()); // back to empty
        assert!(!db.undo()); // nothing further retained
        db.transaction("diverge", |store| {
            store.create("OTHER", 9).unwrap();
        });
        assert!(!db.redo(), "a new write must discard the redo branch");
    }

    #[test]
    fn undo_depth_is_bounded_so_snapshots_cannot_pin_memory_forever() {
        let db = EquateDatabase::new(2);
        for n in 0..5 {
            db.transaction("add", |store| {
                store.create(&format!("E{n}"), n).unwrap();
            });
        }
        assert_eq!(db.snapshot().len(), 5);
        assert!(db.undo());
        assert!(db.undo());
        assert!(!db.undo(), "only the two most recent versions are retained");
    }

    /// The performance property the write-heavy path depends on: when the writer is the sole
    /// owner of the version, a transaction mutates in place and copies no arena at all.
    #[test]
    fn transaction_does_not_copy_arenas_when_sole_owner() {
        let db = EquateDatabase::new(0); // undo disabled, so nothing else retains the version
        db.transaction("first", |store| {
            store.create("A", 1).unwrap();
        });

        let arena_before = Arc::as_ptr(&db.snapshot().equates);
        db.transaction("second", |store| {
            store.create("B", 2).unwrap();
        });
        let arena_after = Arc::as_ptr(&db.snapshot().equates);

        assert_eq!(
            arena_before, arena_after,
            "arena was copied despite the writer being its sole owner"
        );
    }

    /// The converse, and the limit this pilot surfaced: retaining the previous version for undo
    /// makes the writer a non-sole owner, so every transaction copies each touched arena in
    /// full. `SlotMap` copies are O(n), so this is the thing a real implementation must avoid --
    /// by logging deltas for undo, or by using persistent arenas. Pinned here so the cost cannot
    /// be forgotten.
    #[test]
    fn retaining_a_version_for_undo_forces_a_copy() {
        let db = EquateDatabase::new(10); // undo enabled
        db.transaction("first", |store| {
            store.create("A", 1).unwrap();
        });

        let arena_before = Arc::as_ptr(&db.snapshot().equates);
        db.transaction("second", |store| {
            store.create("B", 2).unwrap();
        });

        assert_ne!(
            arena_before,
            Arc::as_ptr(&db.snapshot().equates),
            "undo retention must keep the old arena intact for the retained version"
        );
        assert!(db.undo());
        assert_eq!(db.snapshot().len(), 1, "the retained version is still readable");
    }

    /// ...and conversely, a reader holding the old version forces exactly one clone, which is
    /// what keeps that reader's snapshot immutable.
    #[test]
    fn a_live_reader_forces_a_copy_on_write() {
        let db = db_with(&[("A", 1)]);
        let held = db.snapshot();
        let arena_before = Arc::as_ptr(&held.equates);

        db.transaction("write", |store| {
            store.create("B", 2).unwrap();
        });

        assert_ne!(
            arena_before,
            Arc::as_ptr(&db.snapshot().equates),
            "the held snapshot must not have been mutated underneath its reader"
        );
        assert_eq!(held.len(), 1);
    }

    #[test]
    fn references_accumulate_within_a_transaction() {
        let db = db_with(&[("E", 7)]);
        let id = db.snapshot().by_name("E").unwrap();
        db.transaction("refs", |store| {
            store
                .add_reference(
                    id,
                    EquateReference { address: addr(0x1000), op_index: Some(1), dynamic_hash: None },
                )
                .unwrap();
            store
                .add_reference(
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
        db.transaction("remove", |store| store.remove(id).unwrap());

        let snap = db.snapshot();
        assert!(snap.get(id).is_none(), "a removed id resolves to None, which is the honest answer");
        assert!(snap.by_name("GONE").is_none());

        db.transaction("reuse", |store| {
            store.create("GONE", 2).unwrap();
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
                        // Every version must be self-consistent: each name resolves to an id
                        // that exists in that same version.
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
            db.transaction("churn", |store| {
                store.create(&format!("E{n}"), n).unwrap();
            });
        }
        stop.store(true, Ordering::SeqCst);

        for r in readers {
            assert!(r.join().unwrap() > 0, "reader made no progress");
        }
        assert_eq!(db.snapshot().len(), 201);
    }
}
