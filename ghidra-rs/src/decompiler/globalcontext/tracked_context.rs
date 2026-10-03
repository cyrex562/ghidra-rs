use crate::program::model::pcode::VarnodeData;

/// Tracks a context value associated with a storage location (varnode).
///
/// Corresponds to `ghidra.pcodeCPort.globalcontext.TrackedContext`.
#[derive(Clone, Debug)]
pub struct TrackedContext {
    /// The storage location (address space, offset, size) where this context value resides.
    pub loc: VarnodeData,
    /// The context value.
    pub val: i64,
}

impl TrackedContext {
    /// Creates a new `TrackedContext` with the given location and value.
    pub fn new(loc: VarnodeData, val: i64) -> Self {
        Self { loc, val }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use std::sync::Arc;

    #[test]
    fn create_tracked_context() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let loc = VarnodeData {
            space: space.clone(),
            offset: 0x1000,
            size: 4,
        };
        let val = 42i64;
        let ctx = TrackedContext::new(loc.clone(), val);
        assert_eq!(ctx.val, 42);
        assert_eq!(ctx.loc.offset, 0x1000);
        assert_eq!(ctx.loc.size, 4);
    }

    #[test]
    fn tracked_context_clone() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let loc = VarnodeData {
            space,
            offset: 0x2000,
            size: 8,
        };
        let ctx1 = TrackedContext::new(loc, 123i64);
        let ctx2 = ctx1.clone();
        assert_eq!(ctx1.val, ctx2.val);
        assert_eq!(ctx1.loc.offset, ctx2.loc.offset);
    }

    #[test]
    fn tracked_context_negative_value() {
        let space = AddressSpace::new("ram", 32, 1, crate::program::model::address::AddressSpaceType::Ram, 0);
        let loc = VarnodeData {
            space,
            offset: 0x0,
            size: 8,
        };
        let val = -1i64;
        let ctx = TrackedContext::new(loc, val);
        assert_eq!(ctx.val, -1i64);
    }
}
