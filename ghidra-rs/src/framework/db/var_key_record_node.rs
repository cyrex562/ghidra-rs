use std::io;

use super::field::Field;
use super::field_key_record_node::FieldKeyRecordNode;
use super::record::DBRecord;
use super::schema::Schema;
use super::var_key_interior_node::VarKeyInteriorNode;
use super::var_key_node::VarKeyNode;
use crate::util::msg::Msg;
use crate::util::task::TaskMonitor;

/// Fixed byte width of a stored buffer id (`PrevLeafId`/`NextLeafId`). Mirrors
/// `VarKeyRecordNode.ID_SIZE`.
const ID_SIZE: i32 = 4;

/// `VarKeyNode`'s own header: `NodeType(1) + KeyType(1) + KeyCount(4)`. Mirrors
/// `VarKeyNode.VARKEY_NODE_HEADER_SIZE` (`NodeMgr.NODE_HEADER_SIZE` (1) + `KEY_TYPE_SIZE` (1) +
/// `KEY_COUNT_SIZE` (4)); that constant lives on the (already-ported)
/// [`VarKeyNode`](crate::framework::db::var_key_node::VarKeyNode) trait's Java counterpart rather
/// than being exposed by the Rust trait itself, so it is redeclared here for use by this module's
/// own layout math -- mirroring the identically-motivated
/// [`RECORD_LEAF_HEADER_SIZE`](crate::framework::db::var_rec_node::RECORD_LEAF_HEADER_SIZE).
const VARKEY_NODE_HEADER_SIZE: i32 = 6;

/// Header size preceding the key/offset entries within a leaf buffer:
/// `VARKEY_NODE_HEADER_SIZE + PrevLeafId(4) + NextLeafId(4)`. Mirrors `VarKeyRecordNode.HEADER_SIZE`.
pub const HEADER_SIZE: i32 = VARKEY_NODE_HEADER_SIZE + 2 * ID_SIZE;

/// Byte offset of the previous-leaf sibling buffer id within a `VarKeyRecordNode` buffer. Mirrors
/// `VarKeyRecordNode.PREV_LEAF_ID_OFFSET`.
pub const PREV_LEAF_ID_OFFSET: i32 = VARKEY_NODE_HEADER_SIZE;

/// Byte offset of the next-leaf sibling buffer id within a `VarKeyRecordNode` buffer. Mirrors
/// `VarKeyRecordNode.NEXT_LEAF_ID_OFFSET`.
pub const NEXT_LEAF_ID_OFFSET: i32 = PREV_LEAF_ID_OFFSET + ID_SIZE;

const OFFSET_SIZE: i32 = 4;
const INDIRECT_OPTION_SIZE: i32 = 1;

/// Per-key entry size within a `VarKeyRecordNode` buffer: `KeyOffset(4) + IndFlag(1)`. Mirrors
/// `VarKeyRecordNode.ENTRY_SIZE`.
pub const ENTRY_SIZE: i32 = OFFSET_SIZE + INDIRECT_OPTION_SIZE;

/// An implementation of a BTree leaf node which utilizes variable-length `Field` key values and
/// stores variable-length records.
///
/// Mirrors `db.VarKeyRecordNode`, a *concrete* leaf implementation of the abstract
/// [`VarKeyNode`](crate::framework::db::var_key_node::VarKeyNode) that also implements
/// [`FieldKeyRecordNode`]. Unlike the long-key and fixed-key families -- where an intermediate
/// abstract class (`LongKeyRecordNode`/`FixedKeyRecordNode`) sits between the key-family node type
/// and the concrete leaf, carrying `putRecord`/`deleteRecord`/leaf-navigation orchestration logic
/// shared by multiple concrete siblings (`FixedRecNode`+`VarRecNode`;
/// `FixedKeyFixedRecNode`+`FixedKeyVarRecNode`) -- Java's `VarKeyNode` has no such intermediate
/// layer: `VarKeyRecordNode` is the *sole* concrete leaf type for variable-length-key trees, and
/// every real class member lives directly on it. This trait therefore has to carry more of its own
/// weight than [`VarRecNode`](crate::framework::db::var_rec_node::VarRecNode) (its closest
/// structural analog -- same buffer format shape, minus the fixed-width key) had to.
///
/// Members already declared abstractly on the [`FieldKeyRecordNode`] supertrait (`putRecord`,
/// `deleteRecord`, `remove`, `removeLeaf`, leaf-sibling accessors, `getRecord`/`getRecordAtIndex`)
/// are inherited as-is rather than redeclared here -- Rust has no covariant override for a
/// same-named supertrait method. `putRecord`/`deleteRecord` specifically are left fully abstract
/// (not defaulted) even though `VarKeyRecordNode.java`'s versions have real, non-trivial logic:
/// that logic calls `Table.updatedRecord`/`insertedRecord`/`deletedRecord` to keep indexed columns
/// in sync, and this port's [`Table`](crate::framework::db::table::Table) does not expose those
/// notification hooks -- the identical wall [`LongKeyRecordNode`]'s and
/// [`FixedKeyRecordNode`]'s ports hit for the same two methods.
///
/// `getRecordBefore`/`getRecordAfter`/`getRecordAtOrBefore`/`getRecordAtOrAfter`/`getRecord(Field,
/// Schema)`/`isConsistent` *are* modeled with real logic below, as free functions rather than
/// default trait methods: [`FieldKeyRecordNode`] and
/// [`VarKeyNode`](crate::framework::db::var_key_node::VarKeyNode) already declare these exact
/// method names abstractly, and Rust does not allow a subtrait to supply a default body for a
/// method its supertrait already declares -- the same constraint that makes
/// [`var_key_interior_node::check_consistency`](crate::framework::db::var_key_interior_node::check_consistency)
/// a free function rather than a `VarKeyNode::is_consistent` default. A concrete implementer's own
/// supertrait method bodies are expected to delegate to these free functions.
///
/// [`LongKeyRecordNode`]: crate::framework::db::long_key_record_node::LongKeyRecordNode
/// [`FixedKeyRecordNode`]: crate::framework::db::fixed_key_record_node::FixedKeyRecordNode
pub trait VarKeyRecordNode: FieldKeyRecordNode + VarKeyNode {
    /// Length of this node's underlying data buffer, in bytes. Mirrors `DataBuffer.length()` as
    /// called throughout `VarKeyRecordNode`.
    fn buffer_length(&self) -> i32;

    /// Store the key offset within the buffer for the specified key index; the record data for
    /// that key immediately follows the stored key. Paired setter for the already-required
    /// [`RecordNode::get_key_offset`](crate::framework::db::record_node::RecordNode::get_key_offset)
    /// getter -- which, true to the Java original, does double duty
    /// as both `VarKeyRecordNode.getKeyOffset` (the public `RecordNode` override) *and* the
    /// private `VarKeyRecordNode.getRecordKeyOffset` (both Java methods read the identical buffer
    /// location, `HEADER_SIZE + index * ENTRY_SIZE`, byte-for-byte). This port keeps only the one
    /// getter and adds just the setter half that was missing, `putRecordKeyOffset`.
    fn put_key_offset(&mut self, index: i32, offset: i32);

    /// Move `len` bytes of this node's buffer contents from `from` to `to`. Mirrors the
    /// `DataBuffer.move(int, int, int)` calls made throughout `VarKeyRecordNode`.
    fn move_buffer_data(&mut self, from: i32, to: i32, len: i32);

    /// Get this leaf's parent interior node, or `None` if this is the root. Distinct from
    /// [`FieldKeyNode::get_parent`](crate::framework::db::field_key_node::FieldKeyNode::get_parent),
    /// which can only expose the weaker `FieldKeyInteriorNode`
    /// supertrait type; the consistency check's parent-callback logic (`isLeftmostKey`/
    /// `isRightmostKey`) needs the richer [`VarKeyInteriorNode`] type, mirroring the
    /// identically-motivated
    /// [`FixedKeyRecordNode::get_fixed_parent`](crate::framework::db::fixed_key_record_node::FixedKeyRecordNode::get_fixed_parent).
    fn get_var_parent(&self) -> Option<Box<dyn VarKeyInteriorNode>>;

    /// Create a new leaf and add it to the node manager. The new leaf's parent is unknown. Mirrors
    /// `VarKeyRecordNode.createNewLeaf`.
    fn create_new_leaf(
        &self,
        prev_leaf_id: i32,
        next_leaf_id: i32,
    ) -> io::Result<Box<dyn VarKeyRecordNode>>;

    /// Split the contents of this leaf node, placing the right half of the records into the empty
    /// leaf node provided. Mirrors the private `VarKeyRecordNode.splitData`.
    fn split_data(&mut self, new_right_leaf: &mut dyn VarKeyRecordNode);

    /// Insert the record at the given index if there is sufficient space in the buffer. Returns
    /// `true` if the record was successfully inserted. Mirrors the private
    /// `VarKeyRecordNode.insertRecord`, including its `AssertException` if the record's key
    /// exceeds this node's `maxKeyLength` -- a check callers implementing this trait method are
    /// expected to preserve (this port has no generic home for `maxKeyLength`, since it is not
    /// exposed by the [`VarKeyNode`] trait).
    fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool>;

    /// Update the record at the given index, switching to (or away from) indirect chained-buffer
    /// storage as needed to fit the updated record. Returns the root node, which may have changed.
    /// Mirrors the private `VarKeyRecordNode.updateRecord`, which contains a documented assumption
    /// (`// assumes old len is always > 4`) that a record being switched to indirect storage was
    /// already at least `keyLen + 4` bytes long -- preserved here as an implementation obligation
    /// rather than modeled, since this trait method is otherwise left abstract.
    fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn VarKeyNode>>;

    /// Split this leaf node in half and update the tree. When a split is performed, the next
    /// operation must be performed from the root node since the tree may have been restructured.
    /// Returns the root node, which may have changed. Mirrors `VarKeyRecordNode.split`.
    fn split(&mut self) -> io::Result<Box<dyn VarKeyNode>>;

    /// Append a leaf which contains one or more keys and update the tree. `leaf` is inserted as
    /// the new right sibling of this leaf (must be the same node type as this leaf). Returns the
    /// root node, which may have changed. Mirrors `VarKeyRecordNode.appendLeaf`.
    fn append_leaf(&mut self, leaf: Box<dyn VarKeyRecordNode>) -> io::Result<Box<dyn VarKeyNode>>;

    /// Delete this node (and any chained buffers used for indirect record storage) from the node
    /// manager. Mirrors `VarKeyRecordNode.delete()` (an override of `BTreeNode.delete()`, not
    /// carried by the [`BTreeNode`](crate::framework::db::nodes::BTreeNode) trait in this port).
    fn delete(&mut self) -> io::Result<()>;

    /// Get the buffer ids of any chained buffers used for indirect record storage by this node.
    /// Mirrors `VarKeyRecordNode.getBufferReferences()` (an override of
    /// `BTreeNode.getBufferReferences()`).
    fn get_buffer_references(&self) -> Vec<i32>;

    /// Perform a binary search to locate the specified key.
    ///
    /// Returns the key index if found, else `-(key_index + 1)` indicating the insertion point.
    /// Mirrors `VarKeyRecordNode.getKeyIndex`.
    fn get_key_index(&self, key: &Field) -> i32 {
        let mut min: i32 = 0;
        let mut max: i32 = self.get_key_count() - 1;
        while min <= max {
            let i = (min + max) / 2;
            let rc = self.compare_key_field(key, i);
            if rc == 0 {
                return i;
            } else if rc > 0 {
                min = i + 1;
            } else {
                max = i - 1;
            }
        }
        -(min + 1)
    }

    /// Maximum length a record may have before it must be relocated to indirect (chained-buffer)
    /// storage, given a key of length `key_len`, ensuring at least 4 records fit per node. Mirrors
    /// the `maxRecordLength` local computed identically at the top of both
    /// `VarKeyRecordNode.insertRecord` and `VarKeyRecordNode.updateRecord`.
    fn max_record_length(&self, key_len: i32) -> i32 {
        ((self.buffer_length() - HEADER_SIZE) >> 2) - ENTRY_SIZE - key_len
    }

    /// Unused free space within this node, in bytes. Mirrors the private
    /// `VarKeyRecordNode.getFreeSpace()`.
    fn get_free_space(&self) -> io::Result<i32> {
        let count = self.get_key_count();
        let data_start =
            if count == 0 { self.buffer_length() } else { self.get_key_offset(count - 1)? };
        Ok(data_start - (count * ENTRY_SIZE) - HEADER_SIZE)
    }

    /// Length of the stored record (including its key) at `index`. Mirrors the private
    /// `VarKeyRecordNode.getFullRecordLength(int)`.
    fn get_full_record_length(&self, index: i32) -> io::Result<i32> {
        if index == 0 {
            Ok(self.buffer_length() - self.get_key_offset(0)?)
        } else {
            Ok(self.get_key_offset(index - 1)? - self.get_key_offset(index)?)
        }
    }

    /// Move all records from `index` to the end by the specified `offset`, adjusting the stored
    /// per-key offsets to match. Returns the insertion offset immediately following the moved
    /// block. Mirrors the private `VarKeyRecordNode.moveRecords(int, int)`.
    fn move_records(&mut self, index: i32, offset: i32) -> io::Result<i32> {
        let count = self.get_key_count();
        let last_index = count - 1;

        // No movement needed for appended record.
        if index == count {
            return if index == 0 {
                Ok(self.buffer_length() + offset)
            } else {
                Ok(self.get_key_offset(last_index)? + offset)
            };
        }

        // Determine block to be moved.
        let start = self.get_key_offset(last_index)?;
        let end = if index == 0 { self.buffer_length() } else { self.get_key_offset(index - 1)? };
        let len = end - start;

        // Move record data.
        self.move_buffer_data(start, start + offset, len);

        // Adjust stored offsets.
        for i in index..count {
            let current = self.get_key_offset(i)?;
            self.put_key_offset(i, current + offset);
        }
        Ok(end + offset)
    }

    /// Find the key index which represents the halfway point within the record data, used when
    /// splitting this leaf. Mirrors the private `VarKeyRecordNode.getSplitIndex()`.
    ///
    /// Quirk preserved from Java: unlike its long-key structural sibling
    /// [`VarRecNode::get_split_index`](crate::framework::db::var_rec_node::VarRecNode::get_split_index)
    /// (whose binary search starts at `min = 1` with a strict `min < max` loop, so it can never
    /// return index 0), `VarKeyRecordNode.getSplitIndex()` starts at `min = 0` with an inclusive
    /// `min <= max` loop -- in principle this search could settle on index 0, which would make
    /// [`Self::split_data`] move *every* record to the new right leaf and leave this node empty.
    /// This difference from the sibling's tighter bound is reproduced here verbatim rather than
    /// "fixed"; see `test_get_split_index_bounds_differ_from_var_rec_node` for why it is not
    /// believed to be reachable with realistic data (the computed halfway point is always at or
    /// past the midpoint of the occupied data region, which -- for more than one record -- lies
    /// strictly beyond `getKeyOffset(0)`).
    fn get_split_index(&self) -> io::Result<i32> {
        let count = self.get_key_count();
        let data_start =
            if count == 0 { self.buffer_length() } else { self.get_key_offset(count - 1)? };
        let halfway = (data_start + self.buffer_length()) / 2;

        let mut min = 0;
        let mut max = count - 1;
        while min <= max {
            let i = (min + max) / 2;
            let offset = self.get_key_offset(i)?;
            if offset == halfway {
                return Ok(i);
            } else if offset < halfway {
                max = i - 1;
            } else {
                min = i + 1;
            }
        }
        Ok(min)
    }

    /// Append a new leaf and insert the specified record. Returns the root node, which may have
    /// changed. Mirrors `VarKeyRecordNode.appendNewLeaf`.
    fn append_new_leaf(&mut self, record: DBRecord) -> io::Result<Box<dyn VarKeyNode>> {
        let mut new_leaf = self.create_new_leaf(-1, -1)?;
        new_leaf.insert_record(0, &record)?;
        self.append_leaf(new_leaf)
    }

    /// Log a BTree consistency error for the named table via [`Msg`]. Mirrors
    /// `VarKeyRecordNode.logConsistencyError`.
    fn log_consistency_error(
        &self,
        table_name: &str,
        msg: &str,
        cause: Option<&dyn std::error::Error>,
    ) -> io::Result<()> {
        Msg::debug("VarKeyRecordNode", &format!("Consistency Error ({}): {}", table_name, msg));
        let key0 = self.get_key_field(0)?;
        Msg::debug(
            "VarKeyRecordNode",
            &format!("  bufferID={} key[0]={:?}", self.get_buffer_id(), key0),
        );
        if let Some(err) = cause {
            Msg::error_with_error(
                "VarKeyRecordNode",
                &format!("Consistency Error ({})", table_name),
                err,
            );
        }
        Ok(())
    }
}

/// Check the consistency of this leaf node. Mirrors `VarKeyRecordNode.isConsistent`.
///
/// A free function rather than a default trait method because it must satisfy
/// [`VarKeyNode::is_consistent`], a distinct supertrait method already declared abstractly with
/// this same name -- a subtrait cannot supply a default body for a method its supertrait already
/// declares. A concrete implementer's own `VarKeyNode::is_consistent` override is expected to call
/// this helper, mirroring the identically-motivated
/// [`var_key_interior_node::check_consistency`](crate::framework::db::var_key_interior_node::check_consistency).
/// Node identity (Java's `me != this`) is approximated via buffer id equality, since trait objects
/// returned from sibling lookups do not preserve object identity -- the same simplification made
/// throughout this port's other `isConsistent` ports
/// ([`LongKeyRecordNode`](crate::framework::db::long_key_record_node::LongKeyRecordNode),
/// [`FixedKeyRecordNode`](crate::framework::db::fixed_key_record_node::FixedKeyRecordNode)).
pub fn check_consistency(
    node: &dyn VarKeyRecordNode,
    table_name: &str,
    monitor: &dyn TaskMonitor,
) -> io::Result<bool> {
    let _ = monitor; // Unused: Java's VarKeyRecordNode.isConsistent never calls checkCancelled().

    let mut consistent = true;
    let mut prev_key: Option<Field> = None;
    for i in 0..node.get_key_count() {
        let key = node.get_key_field(i)?;
        if i != 0 {
            if let Some(prev) = &prev_key {
                if key <= *prev {
                    consistent = false;
                    node.log_consistency_error(
                        table_name,
                        &format!("key[{}] <= key[{}]", i, i - 1),
                        None,
                    )?;
                }
            }
        }
        prev_key = Some(key);
    }

    let key0 = node.get_key_field(0)?;
    let parent = node.get_var_parent();
    let is_leftmost = match &parent {
        Some(p) => p.is_leftmost_key(&key0)?,
        None => true,
    };
    if is_leftmost && node.get_previous_leaf()?.is_some() {
        consistent = false;
        node.log_consistency_error(table_name, "previous-leaf should not exist", None)?;
    }

    match node.get_next_leaf()? {
        Some(next) => {
            let is_rightmost = match &parent {
                Some(p) => p.is_rightmost_key(&key0)?,
                None => true,
            };
            if is_rightmost {
                consistent = false;
                node.log_consistency_error(table_name, "next-leaf should not exist", None)?;
            } else {
                let linked_back = next
                    .get_previous_leaf()?
                    .map(|me| me.get_buffer_id() == node.get_buffer_id())
                    .unwrap_or(false);
                if !linked_back {
                    consistent = false;
                    node.log_consistency_error(
                        table_name,
                        "next-leaf is not linked to this leaf",
                        None,
                    )?;
                }
            }
        }
        None => {
            let is_rightmost = match &parent {
                Some(p) => p.is_rightmost_key(&key0)?,
                None => true,
            };
            if !is_rightmost {
                consistent = false;
                node.log_consistency_error(
                    table_name,
                    "this leaf is not linked to next-leaf",
                    None,
                )?;
            }
        }
    }

    Ok(consistent)
}

/// Get the record identified by the specified key, or `None` if not found. Mirrors
/// `VarKeyRecordNode.getRecord(Field, Schema)`.
///
/// A free function for the same reason as [`check_consistency`]:
/// [`FieldKeyRecordNode::get_record`] already declares this exact signature abstractly.
pub fn get_record(
    node: &dyn VarKeyRecordNode,
    key: &Field,
    schema: &Schema,
) -> io::Result<Option<DBRecord>> {
    let index = node.get_key_index(key);
    if index < 0 {
        return Ok(None);
    }
    node.get_record_at_index(schema, index).map(Some)
}

/// Get the first record whose key is less than the specified key, or `None` if not found. Mirrors
/// `VarKeyRecordNode.getRecordBefore`.
///
/// A free function for the same reason as [`check_consistency`]. Trivia preserved from Java: the
/// original names its "previous leaf" local `nextLeaf` (a copy-paste artifact from
/// `getRecordAfter`) -- cosmetic only, not reproduced here since this port has no local variable
/// to misname.
pub fn get_record_before(
    node: &dyn VarKeyRecordNode,
    key: &Field,
    schema: &Schema,
) -> io::Result<Option<DBRecord>> {
    let mut index = node.get_key_index(key);
    if index < 0 {
        index = -index - 2;
    } else {
        index -= 1;
    }
    if index < 0 {
        return match node.get_previous_leaf()? {
            Some(prev) => {
                let last = prev.get_key_count() - 1;
                Ok(Some(prev.get_record_at_index(schema, last)?))
            }
            None => Ok(None),
        };
    }
    Ok(Some(node.get_record_at_index(schema, index)?))
}

/// Get the first record whose key is greater than the specified key, or `None` if not found.
/// Mirrors `VarKeyRecordNode.getRecordAfter`.
///
/// A free function for the same reason as [`check_consistency`].
pub fn get_record_after(
    node: &dyn VarKeyRecordNode,
    key: &Field,
    schema: &Schema,
) -> io::Result<Option<DBRecord>> {
    let mut index = node.get_key_index(key);
    if index < 0 {
        index = -(index + 1);
    } else {
        index += 1;
    }
    if index == node.get_key_count() {
        return match node.get_next_leaf()? {
            Some(next) => Ok(Some(next.get_record_at_index(schema, 0)?)),
            None => Ok(None),
        };
    }
    Ok(Some(node.get_record_at_index(schema, index)?))
}

/// Get the first record whose key is less than or equal to the specified key, or `None` if not
/// found. Mirrors `VarKeyRecordNode.getRecordAtOrBefore`.
///
/// A free function for the same reason as [`check_consistency`].
pub fn get_record_at_or_before(
    node: &dyn VarKeyRecordNode,
    key: &Field,
    schema: &Schema,
) -> io::Result<Option<DBRecord>> {
    let mut index = node.get_key_index(key);
    if index < 0 {
        index = -index - 2;
    }
    if index < 0 {
        return match node.get_previous_leaf()? {
            Some(prev) => {
                let last = prev.get_key_count() - 1;
                Ok(Some(prev.get_record_at_index(schema, last)?))
            }
            None => Ok(None),
        };
    }
    Ok(Some(node.get_record_at_index(schema, index)?))
}

/// Get the first record whose key is greater than or equal to the specified key, or `None` if not
/// found. Mirrors `VarKeyRecordNode.getRecordAtOrAfter`.
///
/// A free function for the same reason as [`check_consistency`].
pub fn get_record_at_or_after(
    node: &dyn VarKeyRecordNode,
    key: &Field,
    schema: &Schema,
) -> io::Result<Option<DBRecord>> {
    let mut index = node.get_key_index(key);
    if index < 0 {
        index = -(index + 1);
    }
    if index == node.get_key_count() {
        return match node.get_next_leaf()? {
            Some(next) => Ok(Some(next.get_record_at_index(schema, 0)?)),
            None => Ok(None),
        };
    }
    Ok(Some(node.get_record_at_index(schema, index)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::db::buffer::{Buffer, DataBuffer};
    use crate::framework::db::field_key_interior_node::FieldKeyInteriorNode;
    use crate::framework::db::field_key_node::FieldKeyNode;
    use crate::framework::db::interior_node::InteriorNode;
    use crate::framework::db::nodes::BTreeNode;
    use crate::framework::db::record_node::RecordNode;
    use crate::framework::db::table::Table;
    use crate::framework::db::{DBHandle, FieldType};
    use crate::util::task::DummyMonitor;
    use std::cmp::Ordering;
    use std::sync::Arc;

    // ---------------------------------------------------------------------------------------
    // Real buffer-backed leaf: exercises the pure-arithmetic default template methods and a
    // faithful `insert_record`/`remove` against genuine variable-length-key buffer layout (not a
    // toy Vec-based stand-in), the same way `var_rec_node::tests::TestVarRecNode` does for its
    // fixed-width-key sibling.
    // ---------------------------------------------------------------------------------------

    struct TestVarKeyRecordNode {
        buffer: DataBuffer,
        key_type: FieldType,
        schema: Arc<Schema>,
    }

    impl TestVarKeyRecordNode {
        fn new(buffer_id: i32, size: usize, key_type: FieldType, schema: Arc<Schema>) -> Self {
            let mut buffer = DataBuffer::new(buffer_id, size);
            buffer.put_int(2, 0); // KeyCount, at KEY_COUNT_OFFSET (NodeType(1) + KeyType(1))
            buffer.put_int(PREV_LEAF_ID_OFFSET as usize, -1);
            buffer.put_int(NEXT_LEAF_ID_OFFSET as usize, -1);
            Self { buffer, key_type, schema }
        }
    }

    // `DataBuffer` intentionally has no `Clone` impl in production code; cloned here by raw bytes
    // purely so this test double can hand back `Box<dyn VarKeyNode>`/`Box<dyn FieldKeyNode>`
    // "copies" of itself the way real node-manager-backed lookups would, mirroring
    // `var_rec_node::tests::TestVarRecNode`'s identical `Clone` impl.
    impl Clone for TestVarKeyRecordNode {
        fn clone(&self) -> Self {
            Self {
                buffer: DataBuffer::from_data(self.buffer.get_id(), self.buffer.get_data().to_vec()),
                key_type: self.key_type,
                schema: self.schema.clone(),
            }
        }
    }

    impl BTreeNode for TestVarKeyRecordNode {
        fn get_buffer_id(&self) -> i32 {
            self.buffer.get_id()
        }

        fn get_key_count(&self) -> i32 {
            self.buffer.get_int(2)
        }

        fn set_key_count(&mut self, count: i32) {
            self.buffer.put_int(2, count);
        }
    }

    impl RecordNode for TestVarKeyRecordNode {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            let key_off = self.get_key_offset(index)?;
            let key = self.get_key_field(index)?;
            Ok(key_off + key.length() as i32)
        }

        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(self.buffer.get_int((HEADER_SIZE + index * ENTRY_SIZE) as usize))
        }
    }

    impl FieldKeyNode for TestVarKeyRecordNode {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }

        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }

        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }

        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }

        fn compare_key_field(&self, k: &Field, key_index: i32) -> i32 {
            let stored = self.get_key_field(key_index).expect("test buffer key read");
            match k.cmp(&stored) {
                Ordering::Less => -1,
                Ordering::Greater => 1,
                Ordering::Equal => 0,
            }
        }
    }

    impl VarKeyNode for TestVarKeyRecordNode {
        fn get_key_field(&self, index: i32) -> io::Result<Field> {
            let offset = self.get_key_offset(index)?;
            let (field, _) = Field::read(&self.buffer, offset as usize, self.key_type);
            Ok(field)
        }

        fn get_root(&self) -> Box<dyn VarKeyNode> {
            Box::new(self.clone())
        }

        fn is_consistent(&self, table_name: &str, monitor: &dyn TaskMonitor) -> io::Result<bool> {
            check_consistency(self, table_name, monitor)
        }
    }

    impl FieldKeyRecordNode for TestVarKeyRecordNode {
        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            // `schema` is retained directly on the struct (rather than relying on the `&Schema`
            // parameter) purely so a fresh `DBRecord` can be constructed, which requires an
            // `Arc<Schema>`; `Schema` has no `Clone` impl to rebuild one from a bare `&Schema`.
            // Mirrors `var_rec_node::tests::TestVarRecNode::get_record_at_index`.
            let key = self.get_key_field(index)?;
            let mut record = DBRecord::new(self.schema.clone(), key);
            let data_off = self.get_record_offset(index)?;
            record.read(&self.buffer, data_off as usize);
            Ok(record)
        }

        fn put_record(
            &mut self,
            record: DBRecord,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            let key = record.get_key().clone();
            let index = self.get_key_index(&key);
            let index = if index < 0 { -index - 1 } else { index };
            self.insert_record(index, &record)?;
            Ok(Box::new(self.clone()))
        }

        fn remove(&mut self, index: i32) -> io::Result<()> {
            let len = self.get_full_record_length(index)?;
            self.move_records(index + 1, len)?;

            let count = self.get_key_count();
            let start = (HEADER_SIZE + (index + 1) * ENTRY_SIZE) as usize;
            let move_len = ((count - index - 1) * ENTRY_SIZE) as usize;
            self.buffer.move_data(start, start - ENTRY_SIZE as usize, move_len);
            self.set_key_count(count - 1);
            Ok(())
        }

        fn has_next_leaf(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_next_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(None)
        }

        fn has_previous_leaf(&self) -> io::Result<bool> {
            Ok(false)
        }

        fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(None)
        }

        fn remove_leaf(&mut self) -> io::Result<Box<dyn FieldKeyNode>> {
            Ok(Box::new(self.clone()))
        }

        fn delete_record(
            &mut self,
            key: &Field,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            let index = self.get_key_index(key);
            if index >= 0 {
                self.remove(index)?;
            }
            Ok(Box::new(self.clone()))
        }

        fn get_record_at_or_after(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record_at_or_after(self, key, schema)
        }

        fn get_record_at_or_before(
            &self,
            key: &Field,
            schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            get_record_at_or_before(self, key, schema)
        }

        fn get_record_after(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record_after(self, key, schema)
        }

        fn get_record_before(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record_before(self, key, schema)
        }

        fn get_record(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record(self, key, schema)
        }
    }

    impl VarKeyRecordNode for TestVarKeyRecordNode {
        fn buffer_length(&self) -> i32 {
            self.buffer.length() as i32
        }

        fn put_key_offset(&mut self, index: i32, offset: i32) {
            self.buffer.put_int((HEADER_SIZE + index * ENTRY_SIZE) as usize, offset);
        }

        fn move_buffer_data(&mut self, from: i32, to: i32, len: i32) {
            self.buffer.move_data(from as usize, to as usize, len as usize);
        }

        fn get_var_parent(&self) -> Option<Box<dyn VarKeyInteriorNode>> {
            None
        }

        fn create_new_leaf(
            &self,
            _prev_leaf_id: i32,
            _next_leaf_id: i32,
        ) -> io::Result<Box<dyn VarKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in test double"))
        }

        fn split_data(&mut self, _new_right_leaf: &mut dyn VarKeyRecordNode) {}

        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            let key = record.get_key();
            let key_len = key.length() as i32;
            let rec_len = record.length() as i32;

            if (rec_len + key_len + ENTRY_SIZE) > self.get_free_space()? {
                return Ok(false); // insufficient space for record storage
            }

            // Make room for new record.
            let offset = self.move_records(index, -(rec_len + key_len))?;

            // Make room for new key/offset entry.
            let start = HEADER_SIZE + index * ENTRY_SIZE;
            let count = self.get_key_count();
            let shift_len = ((count - index) * ENTRY_SIZE) as usize;
            self.buffer.move_data(start as usize, (start + ENTRY_SIZE) as usize, shift_len);

            // Store new record key/offset.
            self.put_key_offset(index, offset);
            self.set_key_count(count + 1);
            key.write(&mut self.buffer, offset as usize);

            // Store record data (indirect chained-buffer storage is not modeled by this test
            // double -- every record here fits directly in the node's own buffer).
            record.write(&mut self.buffer, (offset + key_len) as usize);
            Ok(true)
        }

        fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn VarKeyNode>> {
            // Real, but simplified: only supports same-key, same-or-shorter-length updates, which
            // is all this module's tests exercise. A full port would additionally shift trailing
            // record data (see `Self::move_records`) when the new length differs from the old.
            let offset = self.get_key_offset(index)?;
            let key = record.get_key();
            record.write(&mut self.buffer, (offset + key.length() as i32) as usize);
            Ok(Box::new(self.clone()))
        }

        fn split(&mut self) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in test double"))
        }

        fn append_leaf(&mut self, _leaf: Box<dyn VarKeyRecordNode>) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in test double"))
        }

        fn delete(&mut self) -> io::Result<()> {
            self.set_key_count(0);
            Ok(())
        }

        fn get_buffer_references(&self) -> Vec<i32> {
            Vec::new()
        }
    }

    fn make_schema() -> Arc<Schema> {
        // The key itself is `FieldType::String` -- genuinely variable-length, unlike
        // `var_rec_node::tests`' fixed-8-byte `Long` keys -- so these tests exercise the one
        // aspect of this leaf format that its long-key sibling cannot.
        Arc::new(Schema::new(
            1,
            FieldType::String,
            "Name".to_string(),
            vec![FieldType::String],
            vec!["Value".to_string()],
            vec![],
        ))
    }

    fn make_table(schema: Arc<Schema>) -> (DBHandle, Arc<std::sync::RwLock<Table>>) {
        let mut dbh = DBHandle::new().unwrap();
        let table = dbh.create_table("MyTable".to_string(), schema).unwrap();
        (dbh, table)
    }

    #[test]
    fn test_insert_and_get_records_round_trip_with_variable_length_keys() {
        let schema = make_schema();
        let mut node = TestVarKeyRecordNode::new(1, 512, FieldType::String, schema.clone());
        let (_dbh, table) = make_table(schema.clone());
        let mut t = table.write().unwrap();

        // Deliberately different-length keys -- "a", "bb", "ccc" -- to prove this leaf format
        // genuinely supports variable-length keys, not merely fixed-width ones dressed up as
        // `Field`s.
        for (key, value) in [("bb", "second"), ("a", "first"), ("ccc", "third")] {
            let mut rec = DBRecord::new(schema.clone(), Field::String(Some(key.to_string())));
            rec.set_string(0, Some(value.to_string()));
            node.put_record(rec, &mut t).unwrap();
        }

        assert_eq!(node.get_key_count(), 3);
        // Records are kept in ascending key order by `put_record`'s insertion-point lookup.
        assert_eq!(node.get_key_field(0).unwrap(), Field::String(Some("a".to_string())));
        assert_eq!(node.get_key_field(1).unwrap(), Field::String(Some("bb".to_string())));
        assert_eq!(node.get_key_field(2).unwrap(), Field::String(Some("ccc".to_string())));

        let rec_bb = node.get_record(&Field::String(Some("bb".to_string())), &schema).unwrap().unwrap();
        assert_eq!(rec_bb.get_string(0), Some("second"));

        let free = node.get_free_space().unwrap();
        assert!(free > 0 && free < 512);
    }

    #[test]
    fn test_get_free_space_matches_hand_computed_layout() {
        // Buffer of 100 bytes, no records: all space beyond the header is free.
        let node = TestVarKeyRecordNode::new(1, 100, FieldType::String, make_schema());
        assert_eq!(node.get_free_space().unwrap(), 100 - HEADER_SIZE);
    }

    #[test]
    fn test_remove_record_reclaims_space_and_reindexes() {
        let schema = make_schema();
        let mut node = TestVarKeyRecordNode::new(1, 256, FieldType::String, schema.clone());
        let (_dbh, table) = make_table(schema.clone());
        let mut t = table.write().unwrap();

        for key in ["k1", "k2", "k3"] {
            let mut rec = DBRecord::new(schema.clone(), Field::String(Some(key.to_string())));
            rec.set_string(0, Some(format!("v-{}", key)));
            node.put_record(rec, &mut t).unwrap();
        }

        FieldKeyRecordNode::remove(&mut node, 1).unwrap(); // remove "k2"
        assert_eq!(node.get_key_count(), 2);
        assert_eq!(node.get_key_field(0).unwrap(), Field::String(Some("k1".to_string())));
        assert_eq!(node.get_key_field(1).unwrap(), Field::String(Some("k3".to_string())));
        assert!(node.get_record(&Field::String(Some("k2".to_string())), &schema).unwrap().is_none());
        assert_eq!(
            node.get_record(&Field::String(Some("k3".to_string())), &schema)
                .unwrap()
                .unwrap()
                .get_string(0),
            Some("v-k3")
        );
    }

    #[test]
    fn test_move_records_and_get_split_index_against_real_buffer() {
        let schema = make_schema();
        let mut node = TestVarKeyRecordNode::new(1, 400, FieldType::String, schema.clone());
        let (_dbh, table) = make_table(schema.clone());
        let mut t = table.write().unwrap();

        for i in 0..6 {
            let key = format!("key-{:02}", i);
            let mut rec = DBRecord::new(schema.clone(), Field::String(Some(key)));
            rec.set_string(0, Some(format!("record-value-{}", i)));
            node.put_record(rec, &mut t).unwrap();
        }

        let split_index = node.get_split_index().unwrap();
        assert!(split_index > 0 && split_index < node.get_key_count());

        // `move_records` at the append position (index == keyCount) is a pure arithmetic
        // shortcut with no actual data movement -- verify it matches Java's early-return formula.
        let count = node.get_key_count();
        let last_offset = node.get_key_offset(count - 1).unwrap();
        assert_eq!(node.move_records(count, -7).unwrap(), last_offset - 7);
    }

    #[test]
    fn test_get_split_index_bounds_differ_from_var_rec_node() {
        // Documents (rather than merely asserting) the quirk described on
        // `VarKeyRecordNode::get_split_index`: with a single record, Java's algorithm can only
        // ever return `min == 0` (the loop body never runs, since `max = keyCount - 1 == 0` and
        // `min <= max` holds only for `min = 0`), which the long-key sibling's tighter `min = 1`
        // starting bound would never produce for *any* input. This is inert here (a one-record
        // leaf is never actually split in practice -- `VarKeyRecordNode.split()` is only called
        // on a leaf that just failed to fit an additional record), but demonstrates the bound
        // really is reachable, not merely theoretical.
        let schema = make_schema();
        let mut node = TestVarKeyRecordNode::new(1, 128, FieldType::String, schema.clone());
        let (_dbh, table) = make_table(schema.clone());
        let mut t = table.write().unwrap();

        let mut rec = DBRecord::new(schema.clone(), Field::String(Some("only".to_string())));
        rec.set_string(0, Some("value".to_string()));
        node.put_record(rec, &mut t).unwrap();

        assert_eq!(node.get_key_count(), 1);
        assert_eq!(node.get_split_index().unwrap(), 0);
    }

    #[test]
    fn test_max_record_length_leaves_room_for_at_least_four_records() {
        let node = TestVarKeyRecordNode::new(1, 256, FieldType::String, make_schema());
        let key_len = 4; // e.g. a 0-byte string field's encoded length (just the 4-byte length prefix)
        let max_len = node.max_record_length(key_len);
        // Mirrors VarKeyRecordNode's own "min 4 records per node" comment: 4 empty-payload
        // entries plus the computed max-length payload (each with a `key_len`-byte key) must
        // still fit within the buffer.
        assert!(4 * (ENTRY_SIZE + key_len + max_len) <= 256);
    }

    #[test]
    fn test_delete_and_get_buffer_references_are_object_safe() {
        let schema = make_schema();
        let mut node = TestVarKeyRecordNode::new(1, 200, FieldType::String, schema.clone());
        let (_dbh, table) = make_table(schema.clone());
        let mut t = table.write().unwrap();

        let mut rec = DBRecord::new(schema.clone(), Field::String(Some("x".to_string())));
        rec.set_string(0, Some("y".to_string()));
        node.put_record(rec, &mut t).unwrap();

        let boxed: Box<dyn VarKeyRecordNode> = Box::new(node);
        assert!(boxed.get_buffer_references().is_empty()); // no indirect storage used

        let mut boxed = boxed;
        boxed.delete().unwrap();
        assert_eq!(boxed.get_key_count(), 0);
    }

    // ---------------------------------------------------------------------------------------
    // Vec-based mock leaves with real sibling/parent linkage: exercises `get_key_index`, the
    // leaf-crossing `get_record_before`/`get_record_after`/`get_record_at_or_before`/
    // `get_record_at_or_after` free functions, and `check_consistency`, mirroring
    // `long_key_record_node::tests::MockLeaf`'s approach for the identical family of concerns.
    // ---------------------------------------------------------------------------------------

    #[derive(Clone)]
    struct MockParent {
        buffer_id: i32,
        leftmost_key: Field,
        rightmost_key: Field,
    }

    impl BTreeNode for MockParent {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }
        fn get_key_count(&self) -> i32 {
            2
        }
        fn set_key_count(&mut self, _count: i32) {}
    }

    impl InteriorNode for MockParent {}

    impl FieldKeyNode for MockParent {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            None
        }
        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn compare_key_field(&self, k: &Field, _key_index: i32) -> i32 {
            match k.cmp(&self.leftmost_key) {
                Ordering::Less => -1,
                Ordering::Greater => 1,
                Ordering::Equal => 0,
            }
        }
    }

    impl FieldKeyInteriorNode for MockParent {
        fn key_changed(
            &mut self,
            _old_key: &Field,
            _new_key: &Field,
            _child_node: Option<&dyn FieldKeyNode>,
        ) -> io::Result<()> {
            Ok(())
        }
    }

    impl VarKeyNode for MockParent {
        fn get_key_field(&self, _index: i32) -> io::Result<Field> {
            Ok(self.leftmost_key.clone())
        }
        fn get_root(&self) -> Box<dyn VarKeyNode> {
            Box::new(self.clone())
        }
        fn is_consistent(&self, _table_name: &str, _monitor: &dyn TaskMonitor) -> io::Result<bool> {
            Ok(true)
        }
    }

    impl VarKeyInteriorNode for MockParent {
        fn get_child_buffer_id(&self, _index: i32) -> i32 {
            0
        }
        fn get_child(&self, _index: i32) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn insert(&mut self, _node: Box<dyn VarKeyNode>) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn delete_child(&mut self, _key: &Field) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn delete(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn is_leftmost_key(&self, key: &Field) -> io::Result<bool> {
            Ok(key == &self.leftmost_key)
        }
        fn is_rightmost_key(&self, key: &Field) -> io::Result<bool> {
            Ok(key == &self.rightmost_key)
        }
    }

    #[derive(Clone)]
    struct MockLeaf {
        buffer_id: i32,
        keys: Vec<Field>,
        records: Vec<DBRecord>,
        parent: Option<MockParent>,
        next: Option<Box<MockLeaf>>,
        prev: Option<Box<MockLeaf>>,
    }

    impl BTreeNode for MockLeaf {
        fn get_buffer_id(&self) -> i32 {
            self.buffer_id
        }
        fn get_key_count(&self) -> i32 {
            self.keys.len() as i32
        }
        fn set_key_count(&mut self, count: i32) {
            self.keys.truncate(count as usize);
            self.records.truncate(count as usize);
        }
    }

    impl RecordNode for MockLeaf {
        fn get_record_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }
        fn get_key_offset(&self, index: i32) -> io::Result<i32> {
            Ok(index)
        }
    }

    impl FieldKeyNode for MockLeaf {
        fn get_parent(&self) -> Option<Box<dyn FieldKeyInteriorNode>> {
            self.parent.clone().map(|p| Box::new(p) as Box<dyn FieldKeyInteriorNode>)
        }
        fn get_leaf_node(&self, _key: &Field) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }
        fn get_leftmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }
        fn get_rightmost_leaf_node(&self) -> io::Result<Box<dyn FieldKeyRecordNode>> {
            Ok(Box::new(self.clone()))
        }
        fn compare_key_field(&self, k: &Field, key_index: i32) -> i32 {
            match k.cmp(&self.keys[key_index as usize]) {
                Ordering::Less => -1,
                Ordering::Greater => 1,
                Ordering::Equal => 0,
            }
        }
    }

    impl VarKeyNode for MockLeaf {
        fn get_key_field(&self, index: i32) -> io::Result<Field> {
            Ok(self.keys[index as usize].clone())
        }
        fn get_root(&self) -> Box<dyn VarKeyNode> {
            Box::new(self.clone())
        }
        fn is_consistent(&self, table_name: &str, monitor: &dyn TaskMonitor) -> io::Result<bool> {
            check_consistency(self, table_name, monitor)
        }
    }

    impl FieldKeyRecordNode for MockLeaf {
        fn get_record_at_index(&self, _schema: &Schema, index: i32) -> io::Result<DBRecord> {
            Ok(self.records[index as usize].clone())
        }
        fn put_record(
            &mut self,
            record: DBRecord,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.keys.push(record.get_key().clone());
            self.records.push(record);
            Ok(Box::new(self.clone()))
        }
        fn remove(&mut self, index: i32) -> io::Result<()> {
            self.keys.remove(index as usize);
            self.records.remove(index as usize);
            Ok(())
        }
        fn has_next_leaf(&self) -> io::Result<bool> {
            Ok(self.next.is_some())
        }
        fn get_next_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(self.next.clone().map(|n| Box::new(*n) as Box<dyn FieldKeyRecordNode>))
        }
        fn has_previous_leaf(&self) -> io::Result<bool> {
            Ok(self.prev.is_some())
        }
        fn get_previous_leaf(&self) -> io::Result<Option<Box<dyn FieldKeyRecordNode>>> {
            Ok(self.prev.clone().map(|n| Box::new(*n) as Box<dyn FieldKeyRecordNode>))
        }
        fn remove_leaf(&mut self) -> io::Result<Box<dyn FieldKeyNode>> {
            Ok(Box::new(self.clone()))
        }
        fn delete_record(
            &mut self,
            key: &Field,
            _table: &mut Table,
        ) -> io::Result<Box<dyn FieldKeyNode>> {
            self.keys.retain(|k| k != key);
            Ok(Box::new(self.clone()))
        }
        fn get_record_at_or_after(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record_at_or_after(self, key, schema)
        }
        fn get_record_at_or_before(
            &self,
            key: &Field,
            schema: &Schema,
        ) -> io::Result<Option<DBRecord>> {
            get_record_at_or_before(self, key, schema)
        }
        fn get_record_after(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record_after(self, key, schema)
        }
        fn get_record_before(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record_before(self, key, schema)
        }
        fn get_record(&self, key: &Field, schema: &Schema) -> io::Result<Option<DBRecord>> {
            get_record(self, key, schema)
        }
    }

    impl VarKeyRecordNode for MockLeaf {
        fn buffer_length(&self) -> i32 {
            0
        }
        fn put_key_offset(&mut self, _index: i32, _offset: i32) {}
        fn move_buffer_data(&mut self, _from: i32, _to: i32, _len: i32) {}
        fn get_var_parent(&self) -> Option<Box<dyn VarKeyInteriorNode>> {
            self.parent.clone().map(|p| Box::new(p) as Box<dyn VarKeyInteriorNode>)
        }
        fn create_new_leaf(
            &self,
            _prev_leaf_id: i32,
            _next_leaf_id: i32,
        ) -> io::Result<Box<dyn VarKeyRecordNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn split_data(&mut self, _new_right_leaf: &mut dyn VarKeyRecordNode) {}
        fn insert_record(&mut self, index: i32, record: &DBRecord) -> io::Result<bool> {
            self.keys.insert(index as usize, record.get_key().clone());
            self.records.insert(index as usize, record.clone());
            Ok(true)
        }
        fn update_record(&mut self, index: i32, record: &DBRecord) -> io::Result<Box<dyn VarKeyNode>> {
            self.records[index as usize] = record.clone();
            Ok(Box::new(self.clone()))
        }
        fn split(&mut self) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn append_leaf(&mut self, _leaf: Box<dyn VarKeyRecordNode>) -> io::Result<Box<dyn VarKeyNode>> {
            Err(io::Error::new(io::ErrorKind::Other, "not supported in mock"))
        }
        fn delete(&mut self) -> io::Result<()> {
            self.keys.clear();
            self.records.clear();
            Ok(())
        }
        fn get_buffer_references(&self) -> Vec<i32> {
            Vec::new()
        }
    }

    fn mock_schema() -> Arc<Schema> {
        Arc::new(Schema::new(1, FieldType::Long, "ID".to_string(), vec![], vec![], vec![]))
    }

    fn mock_record(schema: &Arc<Schema>, key: i64) -> DBRecord {
        DBRecord::new(schema.clone(), Field::Long(Some(key)))
    }

    #[test]
    fn test_get_key_index_binary_search() {
        let schema = mock_schema();
        let leaf = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10)), Field::Long(Some(20)), Field::Long(Some(30))],
            records: vec![
                mock_record(&schema, 10),
                mock_record(&schema, 20),
                mock_record(&schema, 30),
            ],
            parent: None,
            next: None,
            prev: None,
        };

        assert_eq!(leaf.get_key_index(&Field::Long(Some(20))), 1);
        assert_eq!(leaf.get_key_index(&Field::Long(Some(15))), -2);
        assert_eq!(leaf.get_key_index(&Field::Long(Some(99))), -4);
    }

    #[test]
    fn test_get_record_before_after_cross_leaf_boundaries() {
        let schema = mock_schema();

        let leaf1_stub = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10))],
            records: vec![mock_record(&schema, 10)],
            parent: None,
            next: None,
            prev: None,
        };

        let leaf2 = MockLeaf {
            buffer_id: 2,
            keys: vec![Field::Long(Some(30)), Field::Long(Some(40))],
            records: vec![mock_record(&schema, 30), mock_record(&schema, 40)],
            parent: Some(MockParent {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: None,
            prev: Some(Box::new(leaf1_stub)),
        };

        let leaf1 = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10)), Field::Long(Some(20))],
            records: vec![mock_record(&schema, 10), mock_record(&schema, 20)],
            parent: Some(MockParent {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: Some(Box::new(leaf2.clone())),
            prev: None,
        };

        // Crosses into the sibling leaf via `get_next_leaf`/`get_previous_leaf`.
        let after = get_record_after(&leaf1, &Field::Long(Some(20)), &schema).unwrap().unwrap();
        assert_eq!(after.get_key(), &Field::Long(Some(30)));

        let before = get_record_before(&leaf2, &Field::Long(Some(30)), &schema).unwrap().unwrap();
        assert_eq!(before.get_key(), &Field::Long(Some(10)));

        let at_or_after = get_record_at_or_after(&leaf1, &Field::Long(Some(20)), &schema).unwrap().unwrap();
        assert_eq!(at_or_after.get_key(), &Field::Long(Some(20)));

        let at_or_before = get_record_at_or_before(&leaf2, &Field::Long(Some(25)), &schema).unwrap().unwrap();
        assert_eq!(at_or_before.get_key(), &Field::Long(Some(10)));

        // No further leaf to cross into: falls back to `None`.
        assert!(get_record_after(&leaf2, &Field::Long(Some(40)), &schema).unwrap().is_none());
        assert!(get_record_before(&leaf1, &Field::Long(Some(10)), &schema).unwrap().is_none());
    }

    #[test]
    fn test_check_consistency_well_linked_and_broken() {
        let schema = mock_schema();
        let monitor = DummyMonitor;

        let leaf1_stub = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10))],
            records: vec![mock_record(&schema, 10)],
            parent: None,
            next: None,
            prev: None,
        };

        let leaf2 = MockLeaf {
            buffer_id: 2,
            keys: vec![Field::Long(Some(30)), Field::Long(Some(40))],
            records: vec![mock_record(&schema, 30), mock_record(&schema, 40)],
            parent: Some(MockParent {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: None,
            prev: Some(Box::new(leaf1_stub)),
        };

        let leaf1 = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10)), Field::Long(Some(20))],
            records: vec![mock_record(&schema, 10), mock_record(&schema, 20)],
            parent: Some(MockParent {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: Some(Box::new(leaf2.clone())),
            prev: None,
        };

        // A well-linked leaf (correctly ordered keys, correctly linked to its right sibling)
        // reports itself consistent.
        assert!(check_consistency(&leaf1, "MyTable", &monitor).unwrap());
        // The rightmost leaf, correctly linked back to its left sibling, also reports consistent.
        assert!(check_consistency(&leaf2, "MyTable", &monitor).unwrap());

        // Out-of-order keys are reported inconsistent.
        let unordered = MockLeaf {
            buffer_id: 3,
            keys: vec![Field::Long(Some(20)), Field::Long(Some(10))],
            records: vec![mock_record(&schema, 20), mock_record(&schema, 10)],
            parent: None,
            next: None,
            prev: None,
        };
        assert!(!check_consistency(&unordered, "MyTable", &monitor).unwrap());

        // A leaf claiming a `next` sibling that does not link back is reported inconsistent.
        let unlinked_next = MockLeaf {
            buffer_id: 5,
            keys: vec![Field::Long(Some(10)), Field::Long(Some(20))],
            records: vec![mock_record(&schema, 10), mock_record(&schema, 20)],
            parent: Some(MockParent {
                buffer_id: 99,
                leftmost_key: Field::Long(Some(10)),
                rightmost_key: Field::Long(Some(30)),
            }),
            next: Some(Box::new(leaf2.clone())), // leaf2.prev points to buffer_id 1, not 5
            prev: None,
        };
        assert!(!check_consistency(&unlinked_next, "MyTable", &monitor).unwrap());
    }

    #[test]
    fn test_var_key_record_node_is_object_safe() {
        let schema = mock_schema();
        let leaf = MockLeaf {
            buffer_id: 1,
            keys: vec![Field::Long(Some(10))],
            records: vec![mock_record(&schema, 10)],
            parent: None,
            next: None,
            prev: None,
        };

        let boxed: Box<dyn VarKeyRecordNode> = Box::new(leaf);
        assert_eq!(boxed.get_buffer_id(), 1);
        assert_eq!(boxed.get_key_count(), 1);
        assert_eq!(boxed.get_key_field(0).unwrap(), Field::Long(Some(10)));

        let mut boxed = boxed;
        let rec = mock_record(&schema, 99);
        boxed.insert_record(1, &rec).unwrap();
        assert_eq!(boxed.get_key_count(), 2);
        assert!(boxed.append_new_leaf(mock_record(&schema, 5)).is_err()); // create_new_leaf stubbed
    }
}
