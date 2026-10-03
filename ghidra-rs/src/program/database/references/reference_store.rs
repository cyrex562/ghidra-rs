//! The program's reference store: the concrete half of Java's `ReferenceDBManager` that holds the
//! memory references of a `ProgramDB`, on an arena of [`ReferenceRecord`]s named by `Copy`
//! [`ReferenceId`]s (assigned in creation order, never reused), with from- and to-address
//! indexes.
//!
//! # What of `ReferenceDBManager` is here
//!
//! `addMemoryReference` with the private `addRef` rules -- an existing reference with the same
//! from address, to address and operand is replaced, its type combined with the new one
//! (`combineReferenceType`) and its primary flag kept; the first reference on an operand of a
//! memory address becomes primary -- `setPrimary`, `delete` / `removeReference`,
//! `removeAllReferencesFrom` (one address or a range), `getReferencesFrom` (all, per operand,
//! flow only), `getReference`, `getPrimaryReferenceFrom`, `getReferencesTo`, the reference counts
//! and `hasReferencesTo` / `hasReferencesFrom`, and the source / destination address walks.
//!
//! References are kept in the order they were added per from (and per to) address, as Java's
//! `RefListV0` appends. Deleting a primary reference does not promote another, as in Java.
//!
//! Not here yet: offset and shifted references, stack / register / external references (their
//! own `add*Reference` entry points), symbol association (`setAssociation`), overlay to-address
//! translation, and the change events Java fires through the program.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use crate::program::model::address::Address;
use crate::program::model::symbol::{RefType, Reference, SourceType};

/// Names a reference in a [`ReferenceStore`]: assigned in creation order and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReferenceId(u64);

/// One stored reference. It is a value: the store hands out copies, so a record read before a
/// change does not see the change (re-query by [`ReferenceRecord::id`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceRecord {
    id: ReferenceId,
    from: Address,
    to: Address,
    ref_type: RefType,
    op_index: i32,
    source: SourceType,
    primary: bool,
    symbol_id: i64,
}

impl ReferenceRecord {
    /// The record's key in its store.
    pub fn id(&self) -> ReferenceId {
        self.id
    }
}

impl Reference for ReferenceRecord {
    fn from_address(&self) -> Address {
        self.from.clone()
    }

    fn to_address(&self) -> Address {
        self.to.clone()
    }

    fn is_primary(&self) -> bool {
        self.primary
    }

    fn symbol_id(&self) -> i64 {
        self.symbol_id
    }

    fn reference_type(&self) -> RefType {
        self.ref_type
    }

    fn operand_index(&self) -> i32 {
        self.op_index
    }

    fn is_mnemonic_reference(&self) -> bool {
        !self.is_operand_reference()
    }

    fn is_operand_reference(&self) -> bool {
        self.op_index >= 0
    }

    fn is_stack_reference(&self) -> bool {
        self.to.is_stack_address()
    }

    fn is_external_reference(&self) -> bool {
        false
    }

    fn is_entry_point_reference(&self) -> bool {
        false
    }

    fn is_memory_reference(&self) -> bool {
        self.to.is_memory_address()
    }

    fn is_register_reference(&self) -> bool {
        self.to.is_register_address()
    }

    fn is_offset_reference(&self) -> bool {
        false
    }

    fn is_shifted_reference(&self) -> bool {
        false
    }

    fn source(&self) -> SourceType {
        self.source
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Why a reference could not be added (Java's `IllegalArgumentException`s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceError {
    /// "From address must be memory addresses".
    FromNotMemory(Address),
    /// "Invalid opIndex specified: n" (below [`RefType::MNEMONIC`]).
    InvalidOperandIndex(i32),
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferenceError::FromNotMemory(_) => write!(f, "From address must be memory addresses"),
            ReferenceError::InvalidOperandIndex(i) => write!(f, "Invalid opIndex specified: {i}"),
        }
    }
}

impl std::error::Error for ReferenceError {}

/// The references of one program. See the module docs.
#[derive(Default)]
pub struct ReferenceStore {
    next_id: u64,
    records: HashMap<ReferenceId, ReferenceRecord>,
    /// Per from address, its references in the order they were added.
    from: BTreeMap<Address, Vec<ReferenceId>>,
    /// Per memory to address, its references in the order they were added (stack and register
    /// destinations are not indexed, as in Java).
    to: BTreeMap<Address, Vec<ReferenceId>>,
}

impl ReferenceStore {
    /// An empty store.
    pub fn new() -> Self {
        ReferenceStore { next_id: 1, ..Default::default() }
    }

    /// Adds a memory reference from `from` (operand `op_index`, or [`RefType::MNEMONIC`]) to
    /// `to`, and returns it as stored. Port of `ReferenceDBManager.addMemoryReference` and the
    /// private `addRef`:
    ///
    /// - a reference to a non-memory `to` replaces every reference on the operand; a memory one
    ///   replaces the operand's non-memory references;
    /// - an existing reference with the same `from`, `to` and operand is returned as-is when the
    ///   combined type (`combineReferenceType`) is its type, else replaced by one of the combined
    ///   type that keeps its primary flag (and `source` is the new one, as in Java);
    /// - the first reference on an operand of a memory `from` is primary.
    ///
    /// # Errors
    /// `from` not a memory address, or `op_index` below [`RefType::MNEMONIC`].
    pub fn add_memory_reference(
        &mut self,
        from: Address,
        to: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> Result<ReferenceRecord, ReferenceError> {
        if !from.is_memory_address() {
            return Err(ReferenceError::FromNotMemory(from));
        }
        if op_index < RefType::MNEMONIC {
            return Err(ReferenceError::InvalidOperandIndex(op_index));
        }
        if to.is_memory_address() {
            self.remove_matching_from(&from, |r| r.op_index == op_index && !r.to.is_memory_address());
        } else {
            self.remove_matching_from(&from, |r| r.op_index == op_index);
        }
        Ok(self.add_ref(from, to, ref_type, source, op_index))
    }

    fn add_ref(&mut self, from: Address, to: Address, ref_type: RefType, source: SourceType, op_index: i32) -> ReferenceRecord {
        let mut ref_type = ref_type;
        let mut primary = false;
        if let Some(old) = self.reference(&from, &to, op_index).cloned() {
            ref_type = combine_reference_type(ref_type, old.ref_type);
            if ref_type == old.ref_type {
                return old;
            }
            self.delete(old.id);
            primary = old.primary;
        }
        let from_refs = self.from.get(&from);
        // make the 1st reference primary...
        primary |= from_refs.is_none()
            || (from.is_memory_address()
                && !from_refs.is_some_and(|ids| ids.iter().any(|id| self.records[id].op_index == op_index)));

        let id = ReferenceId(self.next_id);
        self.next_id += 1;
        let record = ReferenceRecord { id, from: from.clone(), to: to.clone(), ref_type, op_index, source, primary, symbol_id: -1 };
        self.records.insert(id, record.clone());
        self.from.entry(from).or_default().push(id);
        if !(to.is_stack_address() || to.is_register_address()) {
            self.to.entry(to).or_default().push(id);
        }
        record
    }

    fn remove_matching_from(&mut self, from: &Address, matches: impl Fn(&ReferenceRecord) -> bool) {
        let doomed: Vec<ReferenceId> = self
            .from
            .get(from)
            .map(|ids| ids.iter().copied().filter(|id| matches(&self.records[id])).collect())
            .unwrap_or_default();
        for id in doomed {
            self.delete(id);
        }
    }

    /// The reference `id`, if it is (still) stored.
    pub fn get(&self, id: ReferenceId) -> Option<&ReferenceRecord> {
        self.records.get(&id)
    }

    /// The reference from `from` operand `op_index` to `to`. Port of `getReference`.
    pub fn reference(&self, from: &Address, to: &Address, op_index: i32) -> Option<&ReferenceRecord> {
        self.from_records(from).find(|r| r.op_index == op_index && &r.to == to)
    }

    fn from_records<'a>(&'a self, from: &Address) -> impl Iterator<Item = &'a ReferenceRecord> + 'a {
        self.from.get(from).into_iter().flatten().map(|id| &self.records[id])
    }

    /// Every reference from `from`, in the order added. Port of `getReferencesFrom(Address)`.
    pub fn references_from(&self, from: &Address) -> Vec<ReferenceRecord> {
        self.from_records(from).cloned().collect()
    }

    /// The references from operand `op_index` of `from` ([`RefType::MNEMONIC`] for the
    /// mnemonic). Port of `getReferencesFrom(Address, int)`.
    pub fn references_from_operand(&self, from: &Address, op_index: i32) -> Vec<ReferenceRecord> {
        self.from_records(from).filter(|r| r.op_index == op_index).cloned().collect()
    }

    /// The flow references from `from`. Port of `getFlowReferencesFrom`.
    pub fn flow_references_from(&self, from: &Address) -> Vec<ReferenceRecord> {
        self.from_records(from).filter(|r| r.ref_type.is_flow()).cloned().collect()
    }

    /// The primary reference on operand `op_index` of `from`. Port of
    /// `getPrimaryReferenceFrom`.
    pub fn primary_reference_from(&self, from: &Address, op_index: i32) -> Option<ReferenceRecord> {
        self.from_records(from).find(|r| r.op_index == op_index && r.primary).cloned()
    }

    /// Every reference to the memory address `to`, in the order added. Port of
    /// `getReferencesTo(Address)` for memory addresses.
    pub fn references_to(&self, to: &Address) -> Vec<ReferenceRecord> {
        self.to.get(to).into_iter().flatten().map(|id| self.records[id].clone()).collect()
    }

    /// The number of references from `from`. Port of `getReferenceCountFrom`.
    pub fn reference_count_from(&self, from: &Address) -> usize {
        self.from.get(from).map_or(0, Vec::len)
    }

    /// The number of references to `to`. Port of `getReferenceCountTo`.
    pub fn reference_count_to(&self, to: &Address) -> usize {
        self.to.get(to).map_or(0, Vec::len)
    }

    /// Whether anything references `to`. Port of `hasReferencesTo`.
    pub fn has_references_to(&self, to: &Address) -> bool {
        self.to.contains_key(to)
    }

    /// Whether `from` has references. Port of `hasReferencesFrom(Address)`.
    pub fn has_references_from(&self, from: &Address) -> bool {
        self.from.contains_key(from)
    }

    /// The addresses in `[start, end]` with references from them, ascending. Port of
    /// `getReferenceSourceIterator(AddressSetView, true)` for one range.
    pub fn source_addresses<'a>(&'a self, start: &Address, end: &Address) -> impl Iterator<Item = &'a Address> + 'a {
        self.from.range(start.clone()..=end.clone()).map(|(a, _)| a)
    }

    /// The addresses in `[start, end]` referenced from somewhere, ascending. Port of
    /// `getReferenceDestinationIterator(AddressSetView, true)` for one range.
    pub fn destination_addresses<'a>(&'a self, start: &Address, end: &Address) -> impl Iterator<Item = &'a Address> + 'a {
        self.to.range(start.clone()..=end.clone()).map(|(a, _)| a)
    }

    /// The number of stored references.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Makes reference `id` the primary reference of its operand (demoting the current one), or
    /// clears its primary flag. Port of `setPrimary`; returns whether anything changed.
    pub fn set_primary(&mut self, id: ReferenceId, primary: bool) -> bool {
        let Some(record) = self.records.get(&id) else { return false };
        if record.primary == primary {
            return false;
        }
        if primary {
            let current = self.primary_reference_from(&record.from, record.op_index).map(|r| r.id);
            if let Some(current) = current {
                self.records.get_mut(&current).expect("indexed").primary = false;
            }
        }
        self.records.get_mut(&id).expect("checked").primary = primary;
        true
    }

    /// Removes reference `id`, returning it. Port of `delete(Reference)`.
    pub fn delete(&mut self, id: ReferenceId) -> Option<ReferenceRecord> {
        let record = self.records.remove(&id)?;
        unindex(&mut self.from, &record.from, id);
        unindex(&mut self.to, &record.to, id);
        Some(record)
    }

    /// Removes the reference from `from` operand `op_index` to `to`, if any. Port of
    /// `removeReference`.
    pub fn remove_reference(&mut self, from: &Address, to: &Address, op_index: i32) -> Option<ReferenceRecord> {
        let id = self.reference(from, to, op_index)?.id;
        self.delete(id)
    }

    /// Removes every reference from `from`. Port of `removeAllReferencesFrom(Address)`.
    pub fn remove_all_references_from(&mut self, from: &Address) {
        if let Some(ids) = self.from.remove(from) {
            for id in ids {
                if let Some(record) = self.records.remove(&id) {
                    unindex(&mut self.to, &record.to, id);
                }
            }
        }
    }

    /// Removes every reference from an address in `[start, end]`. Port of
    /// `removeAllReferencesFrom(Address, Address)`.
    pub fn remove_all_references_from_range(&mut self, start: &Address, end: &Address) {
        let sources: Vec<Address> = self.source_addresses(start, end).cloned().collect();
        for from in sources {
            self.remove_all_references_from(&from);
        }
    }
}

fn unindex(index: &mut BTreeMap<Address, Vec<ReferenceId>>, key: &Address, id: ReferenceId) {
    if let Some(ids) = index.get_mut(key) {
        ids.retain(|i| *i != id);
        if ids.is_empty() {
            index.remove(key);
        }
    }
}

/// Port of the private `ReferenceDBManager.combineReferenceType`: when a reference is added on
/// top of an existing one, the most specific type wins.
pub fn combine_reference_type(new_type: RefType, old_type: RefType) -> RefType {
    use RefType::*;
    if new_type == old_type {
        return old_type;
    }
    // any flow reference should be used over the existing ref to the same location
    if new_type.is_flow() {
        return new_type;
    }
    if old_type.is_flow() {
        return old_type; // always keep flow over new data ref
    }
    if new_type == Data && old_type.is_data() {
        return old_type;
    }
    if new_type == DataInd {
        if old_type.is_indirect() {
            return old_type;
        }
    } else if new_type == Read {
        if old_type == Write || old_type == ReadWrite {
            return ReadWrite;
        }
    } else if new_type == Write && (old_type == Read || old_type == ReadWrite) {
        return ReadWrite;
    }
    if new_type == ReadInd && (old_type == WriteInd || old_type == ReadWriteInd) {
        return ReadWriteInd;
    }
    if new_type == WriteInd && (old_type == ReadInd || old_type == ReadWriteInd) {
        return ReadWriteInd;
    }
    new_type
}

#[cfg(test)]
mod tests;
