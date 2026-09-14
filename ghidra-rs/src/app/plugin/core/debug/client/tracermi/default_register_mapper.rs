//! Port of `ghidra.app.plugin.core.debug.client.tracermi.DefaultRegisterMapper`.

use crate::app::plugin::core::debug::client::tracermi::register_mapper::RegisterMapper;
use crate::program::model::lang::register_value::RegisterValue as ConcreteRegisterValue;
use crate::program::model::lang::LanguageID;
use crate::program::seam_stubs::RegisterValue;

/// A no-op [`RegisterMapper`]: names and values pass through unchanged.
///
/// Port of `ghidra.app.plugin.core.debug.client.tracermi.DefaultRegisterMapper`. The Java
/// constructor accepts a `LanguageID` but never uses it (`// Nothing so far`); faithfully
/// preserved here as an accepted-but-unused constructor parameter.
pub struct DefaultRegisterMapper;

impl DefaultRegisterMapper {
    /// Port of `DefaultRegisterMapper(LanguageID id)`.
    pub fn new(_id: LanguageID) -> Self {
        DefaultRegisterMapper
    }
}

impl RegisterMapper for DefaultRegisterMapper {
    /// Port of `mapName(String)`, which returns `name` unchanged.
    fn map_name(&self, name: &str) -> String {
        name.to_string()
    }

    /// Port of `mapNameBack(String)`, which returns `name` unchanged.
    fn map_name_back(&self, name: &str) -> String {
        name.to_string()
    }

    /// Port of `mapValue(String, RegisterValue)`, which returns `rv` unchanged.
    ///
    /// The trait signature takes `rv` by shared reference and must hand back an owned
    /// `Box<dyn RegisterValue>`, so returning the *exact same* Java object reference isn't
    /// representable directly. [`ConcreteRegisterValue::from_trait_object`] is this crate's
    /// established way to materialize an owned, behaviorally-equivalent `RegisterValue` from an
    /// arbitrary `&dyn RegisterValue` (see that method's own docs for the two cases it
    /// reconstructs exactly); using it here reproduces "return rv unchanged" as closely as the
    /// trait boundary allows.
    fn map_value(&self, _name: &str, rv: &dyn RegisterValue) -> Box<dyn RegisterValue> {
        Box::new(ConcreteRegisterValue::from_trait_object(rv))
    }

    /// Port of `mapValueBack(String, RegisterValue)`, which returns `rv` unchanged. See
    /// [`map_value`](Self::map_value) for why this goes through
    /// [`ConcreteRegisterValue::from_trait_object`].
    fn map_value_back(&self, _name: &str, rv: &dyn RegisterValue) -> Box<dyn RegisterValue> {
        Box::new(ConcreteRegisterValue::from_trait_object(rv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{Address, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::register::{Register, RegisterRef};

    fn language_id() -> LanguageID {
        LanguageID::new("mock:LE:32:default").unwrap()
    }

    fn register(name: &str) -> RegisterRef {
        let space = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0);
        let address = Address::new(space, 0);
        Register::new(name, "", address, 4, false, 0)
    }

    #[test]
    fn map_name_returns_the_name_unchanged() {
        let mapper = DefaultRegisterMapper::new(language_id());
        assert_eq!(mapper.map_name("eax"), "eax");
    }

    #[test]
    fn map_name_back_returns_the_name_unchanged() {
        let mapper = DefaultRegisterMapper::new(language_id());
        assert_eq!(mapper.map_name_back("eax"), "eax");
    }

    #[test]
    fn map_value_returns_an_equivalent_value() {
        let mapper = DefaultRegisterMapper::new(language_id());
        let reg = register("eax");
        let rv = ConcreteRegisterValue::with_value(reg, 0x1234);

        let mapped = mapper.map_value("eax", &rv);

        assert_eq!(mapped.get_register().borrow().name(), "eax");
        assert!(mapped.has_value());
        assert_eq!(mapped.get_unsigned_value_ignore_mask(), 0x1234);
    }

    #[test]
    fn map_value_back_returns_an_equivalent_value() {
        let mapper = DefaultRegisterMapper::new(language_id());
        let reg = register("ebx");
        let rv = ConcreteRegisterValue::with_value(reg, 0xabcd);

        let mapped = mapper.map_value_back("ebx", &rv);

        assert_eq!(mapped.get_register().borrow().name(), "ebx");
        assert!(mapped.has_value());
        assert_eq!(mapped.get_unsigned_value_ignore_mask(), 0xabcd);
    }

    #[test]
    fn map_value_of_an_unset_register_stays_unset() {
        let mapper = DefaultRegisterMapper::new(language_id());
        let reg = register("ecx");
        let rv = ConcreteRegisterValue::new(reg);

        let mapped = mapper.map_value("ecx", &rv);

        assert!(!mapped.has_value());
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let mapper: Box<dyn RegisterMapper> = Box::new(DefaultRegisterMapper::new(language_id()));
        assert_eq!(mapper.map_name("x"), "x");
    }
}
