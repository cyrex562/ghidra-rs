//! Port of `ghidra.app.plugin.processors.sleigh.FixedHandle`.
//!
//! The resolved data for a `HandleTemplate` once all placeholders have been resolved through
//! context, produced while a Sleigh [`Constructor`](super::constructor) is being matched against
//! an instruction.
//!
//! ```text
//! Dynamic Case: *[space]:size offset
//!               load/store offset specified by fields: offset_space, offset_offset, offset_size
//!               load/store space-id corresponds to space field
//!               load/store temp (associated with related loads/stores specified by fields:
//!               temp_space, temp_offset, size
//!
//!               constant address location identified by fields: space, size, offset_offset;
//!               when offset_space=constant
//!
//! Static Case (memory, register, constant or unique space:
//!               offset_space = null
//!               varnode specified by fields: space, size, offset_offset
//! ```

use std::sync::Arc;

use crate::program::model::address::{AddressSpace, AddressSpaceType};
use crate::program::model::pcode::Varnode;

/// See the module docs. Port of `ghidra.app.plugin.processors.sleigh.FixedHandle`.
#[derive(Clone, Debug)]
pub struct FixedHandle {
    pub space: Option<Arc<AddressSpace>>,
    pub size: i32,
    pub offset_space: Option<Arc<AddressSpace>>,
    pub offset_offset: i64,
    pub offset_size: i32,
    pub temp_space: Option<Arc<AddressSpace>>,
    pub temp_offset: i64,
    pub fixable: bool,
}

impl FixedHandle {
    /// Port of the implicit no-arg constructor. Java's field initializers leave every reference
    /// field `null` and every numeric field `0`/`0L`, with `fixable` explicitly initialized to
    /// `true` (FixedHandle.java:54).
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `isInvalid()`.
    pub fn is_invalid(&self) -> bool {
        self.space.is_none()
    }

    /// Port of `setInvalid()`.
    pub fn set_invalid(&mut self) {
        self.space = None;
    }

    /// Port of `isDynamic()`.
    pub fn is_dynamic(&self) -> bool {
        self.offset_space.is_some()
    }

    /// Port of `getDynamicOffset()`.
    pub fn get_dynamic_offset(&self) -> Option<Varnode> {
        let offset_space = match (&self.space, &self.offset_space) {
            (Some(_), Some(offset_space)) => offset_space,
            _ => return None,
        };
        Some(Varnode::new(
            offset_space.address(self.offset_offset),
            self.offset_size,
        ))
    }

    /// Port of `getDynamicTemp()`.
    ///
    /// Faithfully reproduces a genuine null-safety gap in the Java source
    /// (`FixedHandle.java:75-80`): the guard only checks `space`/`offset_space` for `null`, then
    /// unconditionally dereferences `temp_space.getAddress(...)` -- so a `FixedHandle` with
    /// `space`/`offset_space` set but `temp_space` left `null` throws a `NullPointerException`
    /// in Java. We reproduce the crash (via `.expect`) instead of silently returning `None` for
    /// that specific, presumably-never-valid combination.
    pub fn get_dynamic_temp(&self) -> Option<Varnode> {
        if self.space.is_none() || self.offset_space.is_none() {
            return None;
        }
        let temp_space = self.temp_space.as_ref().expect(
            "FixedHandle.getDynamicTemp(): temp_space is None while space/offset_space are \
             set -- mirrors a NullPointerException in FixedHandle.java:75-80",
        );
        Some(Varnode::new(temp_space.address(self.temp_offset), self.size))
    }

    /// Port of `getStaticVarnode()`.
    pub fn get_static_varnode(&self) -> Option<Varnode> {
        let space = self.space.as_ref()?;
        if let Some(offset_space) = &self.offset_space {
            if offset_space.space_type() != AddressSpaceType::Constant {
                return None;
            }
        }
        Some(Varnode::new(space.address(self.offset_offset), self.size))
    }
}

impl Default for FixedHandle {
    fn default() -> Self {
        Self {
            space: None,
            size: 0,
            offset_space: None,
            offset_offset: 0,
            offset_size: 0,
            temp_space: None,
            temp_offset: 0,
            fixable: true,
        }
    }
}

impl PartialEq for FixedHandle {
    fn eq(&self, other: &Self) -> bool {
        // Port of `FixedHandle.equals(Object)` (FixedHandle.java:97-110). Note that `fixable`
        // is deliberately NOT part of the comparison, mirroring the Java source, which never
        // reads `this.fixable`/`other.fixable` in `equals`.
        //
        // Java compares `space`/`offset_space`/`temp_space` with reference equality (`==`).
        // `AddressSpace`'s `PartialEq` here compares `(space_id, name)` rather than pointer
        // identity, which is the idiomatic Rust stand-in for "the same interned space" used
        // throughout this codebase (see e.g. `program::model::lang::sleigh::handle::FixedHandle`).
        self.space == other.space
            && self.size == other.size
            && self.offset_space == other.offset_space
            && self.offset_offset == other.offset_offset
            && self.offset_size == other.offset_size
            && self.temp_space == other.temp_space
            && self.temp_offset == other.temp_offset
    }
}

impl Eq for FixedHandle {}

impl std::hash::Hash for FixedHandle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Port of `FixedHandle.hashCode()` (FixedHandle.java:92-95):
        //   `return (int) (offset_offset ^ (offset_offset >>> 32));`
        // Only `offset_offset` contributes to the hash -- every other field (space, size,
        // offset_space, offset_size, temp_space, temp_offset, fixable) is ignored. This is a
        // legal (if weak) hash under Java's `equals`/`hashCode` contract, since `equals`
        // requires `offset_offset` equality too, so equal handles still hash equal; it just
        // means two handles that differ only in, say, `space` collide.
        state.write_i64(self.offset_offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn unique() -> Arc<AddressSpace> {
        AddressSpace::new("unique", 32, 1, AddressSpaceType::Unique, 1)
    }

    fn constant() -> Arc<AddressSpace> {
        AddressSpace::new("const", 64, 1, AddressSpaceType::Constant, 2)
    }

    fn hash_of(handle: &FixedHandle) -> u64 {
        let mut hasher = DefaultHasher::new();
        handle.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn new_defaults_match_java_field_initializers() {
        let h = FixedHandle::new();
        assert!(h.space.is_none());
        assert_eq!(h.size, 0);
        assert!(h.offset_space.is_none());
        assert_eq!(h.offset_offset, 0);
        assert_eq!(h.offset_size, 0);
        assert!(h.temp_space.is_none());
        assert_eq!(h.temp_offset, 0);
        // fixable starts true (FixedHandle.java:54), unlike every other field.
        assert!(h.fixable);
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(FixedHandle::default(), FixedHandle::new());
    }

    #[test]
    fn is_invalid_tracks_space_presence() {
        let mut h = FixedHandle::new();
        assert!(h.is_invalid());
        h.space = Some(ram());
        assert!(!h.is_invalid());
        h.set_invalid();
        assert!(h.is_invalid());
        assert!(h.space.is_none());
    }

    #[test]
    fn is_dynamic_tracks_offset_space_presence() {
        let mut h = FixedHandle::new();
        assert!(!h.is_dynamic());
        h.offset_space = Some(unique());
        assert!(h.is_dynamic());
    }

    #[test]
    fn get_dynamic_offset_none_when_static() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        // offset_space is None -> static case -> None.
        assert!(h.get_dynamic_offset().is_none());
    }

    #[test]
    fn get_dynamic_offset_none_when_space_missing() {
        let mut h = FixedHandle::new();
        h.offset_space = Some(unique());
        // space is None even though offset_space is set -> still None.
        assert!(h.get_dynamic_offset().is_none());
    }

    #[test]
    fn get_dynamic_offset_builds_varnode_from_offset_space() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_space = Some(unique());
        h.offset_offset = 0x40;
        h.offset_size = 4;

        let vn = h.get_dynamic_offset().expect("dynamic case");
        assert_eq!(vn.get_address().offset(), 0x40);
        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.get_address().space().name(), "unique");
    }

    #[test]
    fn get_dynamic_temp_none_when_static() {
        let h = FixedHandle::new();
        assert!(h.get_dynamic_temp().is_none());
    }

    #[test]
    fn get_dynamic_temp_builds_varnode_from_temp_space() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_space = Some(unique());
        h.temp_space = Some(unique());
        h.temp_offset = 0x80;
        h.size = 8;

        let vn = h.get_dynamic_temp().expect("dynamic case with temp set");
        assert_eq!(vn.get_address().offset(), 0x80);
        assert_eq!(vn.get_size(), 8);
    }

    /// Proves the faithfully-reproduced Java NPE quirk: `getDynamicTemp()` panics (mirroring a
    /// `NullPointerException`) when `space`/`offset_space` are set but `temp_space` is not, since
    /// `FixedHandle.java:75-80` never null-checks `temp_space` before dereferencing it. Uses
    /// `catch_unwind` scoped tightly around just the call under test, per house rules on
    /// `#[should_panic]` only proving *a* panic occurred rather than *this* one.
    #[test]
    fn get_dynamic_temp_panics_when_temp_space_missing() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_space = Some(unique());
        // temp_space left None -- this is the exact combination Java would NPE on.
        assert!(h.temp_space.is_none());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            h.get_dynamic_temp()
        }));
        assert!(
            result.is_err(),
            "expected get_dynamic_temp() to panic when temp_space is None"
        );
    }

    #[test]
    fn get_static_varnode_none_when_space_missing() {
        let h = FixedHandle::new();
        assert!(h.get_static_varnode().is_none());
    }

    #[test]
    fn get_static_varnode_none_when_offset_space_non_constant() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_space = Some(unique());
        // offset_space is set but not TYPE_CONSTANT -> static varnode is undefined -> None.
        assert!(h.get_static_varnode().is_none());
    }

    #[test]
    fn get_static_varnode_builds_when_offset_space_absent() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_offset = 0x1000;
        h.size = 4;

        let vn = h.get_static_varnode().expect("plain static case");
        assert_eq!(vn.get_address().offset(), 0x1000);
        assert_eq!(vn.get_size(), 4);
        assert_eq!(vn.get_address().space().name(), "ram");
    }

    #[test]
    fn get_static_varnode_builds_when_offset_space_is_constant() {
        let mut h = FixedHandle::new();
        h.space = Some(ram());
        h.offset_space = Some(constant());
        h.offset_offset = 7;
        h.size = 1;

        let vn = h.get_static_varnode().expect("constant offset_space case");
        assert_eq!(vn.get_address().offset(), 7);
        assert_eq!(vn.get_address().space().name(), "ram");
    }

    #[test]
    fn equals_ignores_fixable() {
        let mut a = FixedHandle::new();
        a.space = Some(ram());
        a.offset_offset = 5;
        a.fixable = true;

        let mut b = a.clone();
        b.fixable = false;

        assert_eq!(a, b, "fixable must not participate in equality");
    }

    #[test]
    fn equals_requires_all_other_fields_to_match() {
        let mut a = FixedHandle::new();
        a.space = Some(ram());
        a.size = 4;

        let mut b = a.clone();
        b.size = 8;

        assert_ne!(a, b);
    }

    #[test]
    fn hash_quirk_only_depends_on_offset_offset() {
        let mut a = FixedHandle::new();
        a.space = Some(ram());
        a.size = 4;
        a.offset_offset = 42;

        let mut b = FixedHandle::new();
        b.space = Some(constant());
        b.size = 999;
        b.offset_offset = 42;

        // Faithfully mirrors FixedHandle.hashCode()'s narrow contract: two handles that differ
        // in every field except offset_offset still collide, since only offset_offset feeds the
        // hash.
        assert_eq!(hash_of(&a), hash_of(&b));
        // But they are NOT equal, because equals() does compare space/size.
        assert_ne!(a, b);
    }

    #[test]
    fn clone_is_independent() {
        let mut a = FixedHandle::new();
        a.space = Some(ram());
        a.size = 4;

        let mut b = a.clone();
        b.size = 16;

        assert_eq!(a.size, 4);
        assert_eq!(b.size, 16);
    }
}
