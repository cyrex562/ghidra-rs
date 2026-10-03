use crate::program::model::address::Address;

/// Maps addresses between different address spaces.
///
/// Ported from `ghidra.app.plugin.core.debug.client.tracermi.MemoryMapper`.
/// This trait defines the contract for mapping addresses, supporting both forward
/// and reverse mapping operations as well as address generation from space and offset.
pub trait MemoryMapper: Send + Sync {
    /// Maps an address from one space to another.
    fn map(&self, address: &Address) -> Address;

    /// Maps an address back from one space to another (reverse mapping).
    fn map_back(&self, address: &Address) -> Address;

    /// Generates an address from a space name and offset.
    fn gen_addr(&self, space: &str, offset: i64) -> Address;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct IdentityMapper;

    impl MemoryMapper for IdentityMapper {
        fn map(&self, address: &Address) -> Address {
            address.clone()
        }

        fn map_back(&self, address: &Address) -> Address {
            address.clone()
        }

        fn gen_addr(&self, _space: &str, _offset: i64) -> Address {
            panic!("gen_addr not implemented in test");
        }
    }

    #[test]
    fn trait_is_implementable() {
        let _: &dyn MemoryMapper = &IdentityMapper;
    }
}
