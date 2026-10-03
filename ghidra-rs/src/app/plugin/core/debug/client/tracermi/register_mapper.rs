use crate::program::model::lang::register_value::RegisterValue;

/// Maps register names and values between two naming/encoding conventions (e.g. a target's
/// native register set and Ghidra's).
///
/// Port of `ghidra.app.plugin.core.debug.client.tracermi.RegisterMapper`.
pub trait RegisterMapper: Send + Sync {
    /// Maps a register name forward, mirroring `mapName(String)`.
    fn map_name(&self, name: &str) -> String;

    /// Maps a register name back, mirroring `mapNameBack(String)`.
    fn map_name_back(&self, name: &str) -> String;

    /// Maps a register value forward, mirroring `mapValue(String, RegisterValue)`.
    fn map_value(&self, name: &str, rv: &RegisterValue) -> RegisterValue;

    /// Maps a register value back, mirroring `mapValueBack(String, RegisterValue)`.
    fn map_value_back(&self, name: &str, rv: &RegisterValue) -> RegisterValue;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::{Register, RegisterRef};
    fn register_ref(name: &str) -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let address = Address::new(space, 0);
        Register::new(name, "", address, 4, false, 0)
    }

    /// Identity-prefixing mapper: prepends/strips an `"r_"` prefix on names, and hands values
    /// through unchanged (aside from constructing a fresh boxed copy), enough to prove the trait
    /// shape and object-safety.
    struct PrefixMapper;

    impl RegisterMapper for PrefixMapper {
        fn map_name(&self, name: &str) -> String {
            format!("r_{name}")
        }

        fn map_name_back(&self, name: &str) -> String {
            name.strip_prefix("r_").unwrap_or(name).to_string()
        }

        fn map_value(&self, name: &str, _rv: &RegisterValue) -> RegisterValue {
            RegisterValue::with_value(register_ref(&self.map_name(name)), 0)
        }

        fn map_value_back(&self, name: &str, _rv: &RegisterValue) -> RegisterValue {
            RegisterValue::with_value(register_ref(&self.map_name_back(name)), 0)
        }
    }

    #[test]
    fn map_name_adds_prefix() {
        assert_eq!(PrefixMapper.map_name("eax"), "r_eax");
    }

    #[test]
    fn map_name_back_strips_prefix() {
        assert_eq!(PrefixMapper.map_name_back("r_eax"), "eax");
    }

    #[test]
    fn map_name_and_map_name_back_round_trip() {
        let mapper = PrefixMapper;
        let mapped = mapper.map_name("rax");
        assert_eq!(mapper.map_name_back(&mapped), "rax");
    }

    #[test]
    fn map_value_uses_mapped_name() {
        let mapper = PrefixMapper;
        let rv = RegisterValue::with_value(register_ref("eax"), 0);
        let mapped = mapper.map_value("eax", &rv);
        assert_eq!(mapped.register().name(), "r_eax");
    }

    #[test]
    fn map_value_back_uses_unmapped_name() {
        let mapper = PrefixMapper;
        let rv = RegisterValue::with_value(register_ref("r_eax"), 0);
        let mapped = mapper.map_value_back("r_eax", &rv);
        assert_eq!(mapped.register().name(), "eax");
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mapper: Box<dyn RegisterMapper> = Box::new(PrefixMapper);
        assert_eq!(mapper.map_name("x"), "r_x");
    }
}
