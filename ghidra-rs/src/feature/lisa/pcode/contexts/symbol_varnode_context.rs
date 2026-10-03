//! Port of `ghidra.lisa.pcode.contexts.SymbolVarnodeContext`.

use crate::program::model::address::Address;

/// A dummy [`VarnodeContext`](super::varnode_context::VarnodeContext)-like context for the case
/// where the varnode's id is a memory address rather than a real varnode.
///
/// Corresponds to `ghidra.lisa.pcode.contexts.SymbolVarnodeContext` in the Java source, which
/// `extends VarnodeContext` but always calls `super(null)` -- there is no real wrapped `Varnode`,
/// ever, for any instance of this class -- and overrides every single method
/// `VarnodeContext` exposes (`isConstant`, `getSize`, `getOffset`, `getText`). Since none of
/// `VarnodeContext`'s own behavior is ever actually inherited or reachable (the `null` base is
/// never touched, because there is nothing left un-overridden to touch it), this port does not
/// compose over [`VarnodeContext`](super::varnode_context::VarnodeContext) at all (unlike, e.g.,
/// [`VarDefContext`](super::var_def_context::VarDefContext), which composes over a *real* wrapped
/// `VarnodeContext` because it only overrides two of the four methods). It is instead a
/// free-standing struct with its own inherent methods mirroring the four Java overrides.
#[derive(Clone, Debug)]
pub struct SymbolVarnodeContext {
    context: String,
    size: i32,
}

impl SymbolVarnodeContext {
    /// Java: `SymbolVarnodeContext(Address context)`.
    pub fn new(context: &Address) -> Self {
        Self { context: context.to_string(), size: context.space().pointer_size() }
    }

    /// Java: `SymbolVarnodeContext(String name, Address context)`, which delegates to the
    /// single-`Address` constructor (computing [`Self::get_size`] from `context`'s pointer size)
    /// and then overwrites the display text with `name`.
    pub fn with_name(name: impl Into<String>, context: &Address) -> Self {
        let mut ctx = Self::new(context);
        ctx.context = name.into();
        ctx
    }

    /// Java: the overridden `isConstant()`, always `false`.
    pub fn is_constant(&self) -> bool {
        false
    }

    /// Java: the overridden `getSize()`: the pointer size of the address space `context` was
    /// constructed from.
    pub fn get_size(&self) -> i32 {
        self.size
    }

    /// Java: the overridden `getOffset()`, always `0`.
    pub fn get_offset(&self) -> i64 {
        0
    }

    /// Java: the overridden `getText()`.
    pub fn get_text(&self) -> &str {
        &self.context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_space() -> std::sync::Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    #[test]
    fn is_constant_is_always_false() {
        let addr = Address::new(ram_space(), 0x1000);
        let ctx = SymbolVarnodeContext::new(&addr);
        assert!(!ctx.is_constant());
    }

    #[test]
    fn offset_is_always_zero() {
        let addr = Address::new(ram_space(), 0x1000);
        let ctx = SymbolVarnodeContext::new(&addr);
        assert_eq!(ctx.get_offset(), 0);
    }

    #[test]
    fn size_is_the_address_spaces_pointer_size() {
        let addr = Address::new(ram_space(), 0x1000);
        let expected = addr.space().pointer_size();
        let ctx = SymbolVarnodeContext::new(&addr);
        assert_eq!(ctx.get_size(), expected);
    }

    #[test]
    fn get_text_renders_the_address_by_default() {
        let addr = Address::new(ram_space(), 0x1000);
        let ctx = SymbolVarnodeContext::new(&addr);
        assert_eq!(ctx.get_text(), addr.to_string());
    }

    #[test]
    fn with_name_overrides_the_display_text_but_keeps_the_addresss_size() {
        let addr = Address::new(ram_space(), 0x2000);
        let expected_size = addr.space().pointer_size();
        let ctx = SymbolVarnodeContext::with_name("my_symbol", &addr);

        assert_eq!(ctx.get_text(), "my_symbol");
        assert_eq!(ctx.get_size(), expected_size);
        assert_eq!(ctx.get_offset(), 0);
        assert!(!ctx.is_constant());
    }
}
