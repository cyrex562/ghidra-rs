use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::rc::Rc;

use crate::program::model::address::{Address, AddressSet, AddressSetView, AddressSpaceType};

use super::register::{Register, RegisterRef};

/// Key used by [`RegisterManager`]'s address+size lookup table.
///
/// Mirrors the private `RegisterManager.RegisterSizeKey` inner class. Its Java `equals()` is
/// ported faithfully below (address normalized via `getGlobalAddress`, negative sizes clamped
/// to zero). Its Java `hashCode()` is NOT reproduced bit-for-bit: `address.hashCode() << 8 +
/// size` is a real operator-precedence bug in the original (`+` binds tighter than `<<` in
/// Java, so this actually computes `address.hashCode() << (8 + size)`, not `(address.hashCode()
/// << 8) + size`). That hash value is never observable outside the private `HashMap` it keys,
/// so reproducing the buggy arithmetic would add nothing but risk (e.g. `8 + size` shifting by
/// more than 31 bits is technically UB-adjacent in Java too); we use a standard derived `Hash`
/// that is consistent with the ported `equals()` semantics instead.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RegisterSizeKey {
    address: Address,
    size: i32,
}

impl RegisterSizeKey {
    fn new(address: Address, size: i32) -> Self {
        RegisterSizeKey {
            address: RegisterManager::get_global_address(&address),
            size: size.max(0),
        }
    }
}

/// Owns the full set of registers defined by a language, providing lookup by name, address,
/// and address+size, plus register-to-context-field and vector-register queries.
///
/// Port of `ghidra.program.model.lang.RegisterManager`. Instances are produced exclusively by
/// [`super::RegisterBuilder::register_manager`], mirroring the Java class's package-private
/// constructor.
pub struct RegisterManager {
    registers: Vec<RegisterRef>,
    /// Includes aliases and case-variations, same as the Java field.
    register_name_map: HashMap<String, RegisterRef>,
    /// Alphabetically sorted; excludes aliases.
    register_names: Vec<String>,
    context_registers: Vec<RegisterRef>,
    context_base_register: RegisterRef,
    size_map: HashMap<RegisterSizeKey, RegisterRef>,
    register_address_map: HashMap<Address, Vec<RegisterRef>>,
    register_addresses: AddressSet,
    /// Lazily computed and cached on first call to [`Self::get_sorted_vector_registers`],
    /// mirroring the Java field of the same name that's populated on first access.
    sorted_vector_registers: RefCell<Option<Vec<RegisterRef>>>,
}

impl RegisterManager {
    /// Constructs a `RegisterManager` from a fully-wired register collection (parent/child
    /// relationships already established by `RegisterBuilder`) and a complete name-to-register
    /// map including aliases and case-variations.
    pub(crate) fn new(
        registers: Vec<RegisterRef>,
        register_name_map: HashMap<String, RegisterRef>,
    ) -> Self {
        let mut manager = RegisterManager {
            registers,
            register_name_map,
            register_names: Vec::new(),
            context_registers: Vec::new(),
            // Placeholder; always overwritten by `initialize()` below (forced to
            // `Register::NO_CONTEXT` when no context register is defined -- see the doc
            // comment on `get_context_base_register`).
            context_base_register: Register::no_context(),
            size_map: HashMap::new(),
            register_address_map: HashMap::new(),
            register_addresses: AddressSet::new(),
            sorted_vector_registers: RefCell::new(None),
        };
        manager.initialize();
        manager
    }

    fn initialize(&mut self) {
        let mut register_name_list: Vec<String> = Vec::with_capacity(self.registers.len());
        let mut context_register_list: Vec<RegisterRef> = Vec::new();
        let mut context_base_register: Option<RegisterRef> = None;

        // Copy for sorting, descending by bit length. `sort_by` is stable, matching Java's
        // `Collections.sort`, so registers of equal bit length keep their original
        // (construction) order.
        let mut sorted_by_size: Vec<RegisterRef> = self.registers.clone();
        sorted_by_size.sort_by(|a, b| b.borrow().bit_length().cmp(&a.borrow().bit_length()));

        for reg in &sorted_by_size {
            let (reg_name, is_context, is_base, addr, is_big_endian) = {
                let r = reg.borrow();
                (
                    r.name().to_string(),
                    r.is_processor_context(),
                    r.is_base_register(),
                    r.address().clone(),
                    r.is_big_endian(),
                )
            };
            register_name_list.push(reg_name);

            if is_context {
                context_register_list.push(Rc::clone(reg));
                if is_base {
                    context_base_register = Some(Rc::clone(reg));
                }
            }

            self.register_address_map
                .entry(addr)
                .or_default()
                .push(Rc::clone(reg));
            self.add_register_addresses(reg);

            if is_context {
                continue;
            }

            if is_big_endian {
                self.populate_size_map_big_endian(reg);
            } else {
                self.populate_size_map_little_endian(reg);
            }
        }

        // If there is no context register, force a default one. NOTE: this means
        // `context_base_register` is unconditionally `Some` after this point, matching the
        // real (if oddly documented) Java behavior -- see `get_context_base_register`.
        self.context_base_register = context_base_register.unwrap_or_else(Register::no_context);

        // Handle the register size-0 case ("largest register at this address"): process
        // ascending by bit length so that, for registers sharing an address, later (larger)
        // puts win over earlier (smaller) ones. This intentionally includes context registers,
        // unlike the non-zero-size population above.
        for reg in sorted_by_size.iter().rev() {
            let addr = reg.borrow().address().clone();
            let key = RegisterSizeKey::new(addr, 0);
            self.size_map.insert(key, Rc::clone(reg));
        }

        self.context_registers = context_register_list;
        register_name_list.sort();
        self.register_names = register_name_list;
    }

    fn add_register_addresses(&mut self, reg: &RegisterRef) {
        let (min, num_bytes) = {
            let r = reg.borrow();
            (r.address().clone(), r.num_bytes())
        };
        let max = min
            .add((num_bytes - 1) as i64)
            .expect("register address range overflow");
        self.register_addresses.add_range(&min, &max);
    }

    fn populate_size_map_big_endian(&mut self, reg: &RegisterRef) {
        let (address, reg_size) = {
            let r = reg.borrow();
            (r.address().clone(), r.minimum_byte_size())
        };
        for i in 1..=reg_size {
            let key_addr = address
                .add((reg_size - i) as i64)
                .expect("register address range overflow");
            let key = RegisterSizeKey::new(key_addr, i);
            self.size_map.insert(key, Rc::clone(reg));
        }
    }

    fn populate_size_map_little_endian(&mut self, reg: &RegisterRef) {
        let (address, reg_size) = {
            let r = reg.borrow();
            (r.address().clone(), r.minimum_byte_size())
        };
        for i in 1..=reg_size {
            let key = RegisterSizeKey::new(address.clone(), i);
            self.size_map.insert(key, Rc::clone(reg));
        }
    }

    /// Mirrors `RegisterManager.getGlobalAddress`, which downcasts to
    /// `OldGenericNamespaceAddress` and unwraps its underlying global address. In this port,
    /// [`Address`](crate::program::model::address::Address) is a single concrete struct rather
    /// than an interface implemented by multiple address kinds --
    /// [`OldGenericNamespaceAddress`](crate::program::model::address::OldGenericNamespaceAddress)
    /// is a distinct type that a plain `Address` can never actually be, so the downcast this
    /// mirrors can never succeed here and this is always the identity function.
    fn get_global_address(addr: &Address) -> Address {
        addr.clone()
    }

    /// Mirrors `space.isRegisterSpace() || space.hasMappedRegisters()`. No concrete address
    /// space in this port currently overrides `hasMappedRegisters()` away from its `false`
    /// default (see
    /// [`AbstractAddressSpace::has_mapped_registers`](crate::program::model::address::AbstractAddressSpace::has_mapped_registers)),
    /// so the check simplifies to just the register-space test.
    fn is_register_addressable(addr: &Address) -> bool {
        addr.space().space_type() == AddressSpaceType::Register
    }

    /// Get context base-register.
    ///
    /// NOTE: the Java javadoc says this returns "null if one has not been defined by the
    /// language", but `initialize()` unconditionally forces a default
    /// (`Register.NO_CONTEXT`/[`Register::no_context`]) when no context register is found, so
    /// in practice this method never actually returns null/`None` -- the javadoc is stale. We
    /// preserve the real (non-`Option`) behavior here rather than the documented-but-untrue
    /// one.
    pub fn get_context_base_register(&self) -> RegisterRef {
        Rc::clone(&self.context_base_register)
    }

    /// Get an unsorted list of all processor context registers (includes the base context
    /// register and its children).
    pub fn get_context_registers(&self) -> Vec<RegisterRef> {
        self.context_registers.clone()
    }

    /// Get an alphabetically sorted list of original register names (including context
    /// registers). Names correspond to the original register name, not aliases.
    pub fn get_register_names(&self) -> Vec<String> {
        self.register_names.clone()
    }

    /// Returns the largest register located at the specified address, or `None` if not found.
    pub fn get_register(&self, addr: &Address) -> Option<RegisterRef> {
        if !Self::is_register_addressable(addr) {
            return None;
        }
        let key = RegisterSizeKey::new(addr.clone(), 0);
        self.size_map.get(&key).cloned()
    }

    /// Returns all registers located at the specified address (may be empty).
    pub fn get_registers_at(&self, addr: &Address) -> Vec<RegisterRef> {
        if !Self::is_register_addressable(addr) {
            return Vec::new();
        }
        let key = Self::get_global_address(addr);
        self.register_address_map
            .get(&key)
            .cloned()
            .unwrap_or_default()
    }

    /// Get register by address and size. A `size` of 0 returns the largest register at the
    /// specified address.
    pub fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
        if !Self::is_register_addressable(addr) {
            return None;
        }
        let key = RegisterSizeKey::new(addr.clone(), size);
        self.size_map.get(&key).cloned()
    }

    /// Get register by name. A semi-case-insensitive lookup is performed: `name` must match
    /// either the case-sensitive name or be entirely lowercase or uppercase.
    pub fn get_register_by_name(&self, name: &str) -> Option<RegisterRef> {
        self.register_name_map.get(name).cloned()
    }

    /// Get all registers as an unsorted list.
    pub fn get_registers(&self) -> Vec<RegisterRef> {
        self.registers.clone()
    }

    /// Get all vector registers identified by the processor specification, sorted first by
    /// size (descending) and then by offset (ascending).
    pub fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
        if let Some(cached) = self.sorted_vector_registers.borrow().as_ref() {
            return cached.clone();
        }
        let mut list: Vec<RegisterRef> = self
            .registers
            .iter()
            .filter(|reg| reg.borrow().is_vector_register())
            .cloned()
            .collect();
        list.sort_by(Self::compare_vector_registers);
        *self.sorted_vector_registers.borrow_mut() = Some(list.clone());
        list
    }

    /// Get the set of addresses contained in registers.
    pub fn get_register_addresses(&self) -> Box<dyn AddressSetView> {
        Box::new(self.register_addresses.clone())
    }

    /// Compares two vector registers, first by size (descending) and then by offset
    /// (ascending).
    ///
    /// NOTE: Java's `compareVectorRegisters` throws `IllegalArgumentException` if either
    /// argument is not a vector register. It is only ever invoked (via
    /// `get_sorted_vector_registers`) on registers already filtered to
    /// `is_vector_register()`, so that branch can never fire in practice. `sort_by`'s
    /// comparator must be infallible, so the check is preserved as a `debug_assert!` rather
    /// than a `Result`-returning guard.
    fn compare_vector_registers(reg1: &RegisterRef, reg2: &RegisterRef) -> Ordering {
        debug_assert!(
            reg1.borrow().is_vector_register() && reg2.borrow().is_vector_register(),
            "compareVectorRegisters can only be applied to vector registers!"
        );
        let (bit_len1, offset1) = {
            let r = reg1.borrow();
            (r.bit_length(), r.offset())
        };
        let (bit_len2, offset2) = {
            let r = reg2.borrow();
            (r.bit_length(), r.offset())
        };
        // Descending order of size.
        bit_len2.cmp(&bit_len1).then_with(|| offset1.cmp(&offset2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::lang::register_builder::RegisterBuilder;
    use std::sync::Arc;

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn addr(offset: i64) -> Address {
        register_space().address(offset)
    }

    fn other_space_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        space.address(offset)
    }

    /// Ports `RegisterManagerTest.testLittle`: a little-endian 8-byte register split into 4-
    /// and 2-byte sub-registers, verifying `getRegister(Address, int)` resolves to the
    /// smallest enclosing register for every offset/size combination in the Java fixture.
    #[test]
    fn get_register_at_matches_java_little_endian_fixture() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("L_0_8", "", addr(0), 8, false, 0);
        builder.add_register("L_0_4", "", addr(0), 4, false, 0);
        builder.add_register("L_4_4", "", addr(4), 4, false, 0);
        builder.add_register("L_0_2", "", addr(0), 2, false, 0);
        builder.add_register("L_2_2", "", addr(2), 2, false, 0);

        let rm = builder.register_manager();
        let name_at = |offset: i64, size: i32| {
            rm.get_register_at(&addr(offset), size)
                .map(|r| r.borrow().name().to_string())
        };

        for size in [8, 7, 6, 5] {
            assert_eq!(name_at(0, size), Some("L_0_8".to_string()));
        }
        for size in [4, 3] {
            assert_eq!(name_at(0, size), Some("L_0_4".to_string()));
        }
        for size in [2, 1] {
            assert_eq!(name_at(0, size), Some("L_0_2".to_string()));
        }
        assert_eq!(name_at(0, 0), Some("L_0_8".to_string()));

        for size in [8, 7, 6, 5, 4, 3, 2, 1, 0] {
            assert_eq!(name_at(1, size), None);
        }

        for size in [8, 7, 6, 5, 4, 3] {
            assert_eq!(name_at(2, size), None);
        }
        for size in [2, 1, 0] {
            assert_eq!(name_at(2, size), Some("L_2_2".to_string()));
        }

        for size in [8, 7, 6, 5, 4, 3, 2, 1, 0] {
            assert_eq!(name_at(3, size), None);
        }

        for size in [8, 7, 6, 5] {
            assert_eq!(name_at(4, size), None);
        }
        for size in [4, 3, 2, 1, 0] {
            assert_eq!(name_at(4, size), Some("L_4_4".to_string()));
        }
    }

    /// Ports `RegisterManagerTest.testBig`: same shape, but big-endian, which flips which
    /// starting offset resolves to which register (MSB at the lowest address).
    #[test]
    fn get_register_at_matches_java_big_endian_fixture() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("B_0_8", "", addr(0), 8, true, 0);
        builder.add_register("B_0_4", "", addr(0), 4, true, 0);
        builder.add_register("B_4_4", "", addr(4), 4, true, 0);
        builder.add_register("B_6_2", "", addr(6), 2, true, 0);
        builder.add_register("B_2_2", "", addr(2), 2, true, 0);

        let rm = builder.register_manager();
        let name_at = |offset: i64, size: i32| {
            rm.get_register_at(&addr(offset), size)
                .map(|r| r.borrow().name().to_string())
        };

        assert_eq!(name_at(0, 8), Some("B_0_8".to_string()));
        for size in [7, 6, 5] {
            assert_eq!(name_at(0, size), None);
        }
        assert_eq!(name_at(0, 4), Some("B_0_4".to_string()));
        for size in [3, 2, 1] {
            assert_eq!(name_at(0, size), None);
        }
        assert_eq!(name_at(0, 0), Some("B_0_8".to_string()));

        assert_eq!(name_at(1, 8), None);
        assert_eq!(name_at(1, 7), Some("B_0_8".to_string()));
        for size in [6, 5, 4] {
            assert_eq!(name_at(1, size), None);
        }
        assert_eq!(name_at(1, 3), Some("B_0_4".to_string()));
        for size in [2, 1, 0] {
            assert_eq!(name_at(1, size), None);
        }

        for size in [8, 7] {
            assert_eq!(name_at(2, size), None);
        }
        assert_eq!(name_at(2, 6), Some("B_0_8".to_string()));
        for size in [5, 4, 3] {
            assert_eq!(name_at(2, size), None);
        }
        assert_eq!(name_at(2, 2), Some("B_2_2".to_string()));
        assert_eq!(name_at(2, 1), None);
        assert_eq!(name_at(2, 0), Some("B_2_2".to_string()));

        for size in [8, 7, 6] {
            assert_eq!(name_at(3, size), None);
        }
        assert_eq!(name_at(3, 5), Some("B_0_8".to_string()));
        for size in [4, 3, 2] {
            assert_eq!(name_at(3, size), None);
        }
        assert_eq!(name_at(3, 1), Some("B_2_2".to_string()));
        assert_eq!(name_at(3, 0), None);

        for size in [8, 7, 6, 5] {
            assert_eq!(name_at(4, size), None);
        }
        assert_eq!(name_at(4, 4), Some("B_4_4".to_string()));
        for size in [3, 2, 1] {
            assert_eq!(name_at(4, size), None);
        }
        assert_eq!(name_at(4, 0), Some("B_4_4".to_string()));

        for size in [8, 7, 6, 5, 4] {
            assert_eq!(name_at(5, size), None);
        }
        assert_eq!(name_at(5, 3), Some("B_4_4".to_string()));
        for size in [2, 1, 0] {
            assert_eq!(name_at(5, size), None);
        }

        for size in [8, 7, 6, 5, 4, 3] {
            assert_eq!(name_at(6, size), None);
        }
        assert_eq!(name_at(6, 2), Some("B_6_2".to_string()));
        assert_eq!(name_at(6, 1), None);
        assert_eq!(name_at(6, 0), Some("B_6_2".to_string()));

        for size in [8, 7, 6, 5, 4, 3, 2] {
            assert_eq!(name_at(7, size), None);
        }
        assert_eq!(name_at(7, 1), Some("B_6_2".to_string()));
        assert_eq!(name_at(7, 0), None);
    }

    /// Ports `RegisterManagerTest.testRenameAndAlias`: renaming registers and adding aliases
    /// through the builder, verifying all name-forms of a register resolve to the exact same
    /// shared `Register` instance once wrapped in a `RegisterManager`.
    #[test]
    fn rename_and_alias_all_resolve_to_same_register_instance() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("A", "", addr(0), 8, false, 0);
        builder.add_register("B", "", addr(0), 4, false, 0);
        builder.add_register("C", "", addr(4), 4, false, 0);
        builder.add_register("D", "", addr(0), 2, false, 0);
        builder.add_register("E", "", addr(2), 2, false, 0);

        builder.rename_register("A", "L_0_8");
        builder.rename_register("B", "L_0_4");
        builder.rename_register("C", "L_4_4");
        builder.rename_register("D", "L_0_2");
        builder.rename_register("E", "L_2_2");

        builder.add_alias("L_0_8", "L08");
        builder.add_alias("L_0_4", "L04");
        builder.add_alias("L_4_4", "L44");
        builder.add_alias("L_0_2", "L02");
        builder.add_alias("L_2_2", "L22");

        let rm = builder.register_manager();

        for (name, alias) in [
            ("L_0_8", "L08"),
            ("L_0_4", "L04"),
            ("L_4_4", "L44"),
            ("L_0_2", "L02"),
            ("L_2_2", "L22"),
        ] {
            let r = rm.get_register_by_name(name).expect("register present");
            assert_eq!(r.borrow().name(), name);
            let aliases: Vec<String> = r.borrow().aliases().cloned().collect();
            assert_eq!(aliases, vec![alias.to_string()]);

            assert!(Rc::ptr_eq(
                &r,
                &rm.get_register_by_name(&name.to_lowercase()).unwrap()
            ));
            assert!(Rc::ptr_eq(&r, &rm.get_register_by_name(alias).unwrap()));
            assert!(Rc::ptr_eq(
                &r,
                &rm.get_register_by_name(&alias.to_lowercase()).unwrap()
            ));
        }
    }

    #[test]
    fn get_register_returns_largest_register_at_address_only_in_register_space() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("EAX", "", addr(0), 4, false, 0);
        builder.add_register("AX", "", addr(0), 2, false, 0);
        let rm = builder.register_manager();

        let largest = rm.get_register(&addr(0)).unwrap();
        assert_eq!(largest.borrow().name(), "EAX");

        // A non-register address space always yields `None`, matching
        // `space.isRegisterSpace()` gating the Java lookup.
        assert!(rm.get_register(&other_space_addr(0)).is_none());
        assert!(rm.get_registers_at(&other_space_addr(0)).is_empty());
        assert!(rm.get_register_at(&other_space_addr(0), 4).is_none());
    }

    #[test]
    fn get_registers_at_returns_every_register_sharing_an_address() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("EAX", "", addr(0), 4, false, 0);
        builder.add_register("AX", "", addr(0), 2, false, 0);
        builder.add_register("EBX", "", addr(4), 4, false, 0);
        let rm = builder.register_manager();

        let mut names: Vec<String> = rm
            .get_registers_at(&addr(0))
            .into_iter()
            .map(|r| r.borrow().name().to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["AX".to_string(), "EAX".to_string()]);

        assert_eq!(rm.get_registers_at(&addr(4)).len(), 1);
        assert!(rm.get_registers_at(&addr(99)).is_empty());
    }

    #[test]
    fn context_base_register_falls_back_to_no_context_sentinel() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("R0", "", addr(0), 4, false, 0);
        let rm = builder.register_manager();

        // NOTE: per the Java quirk documented on `get_context_base_register`, this is never
        // `None` -- it's forced to the NO_CONTEXT sentinel when no context register exists.
        let base = rm.get_context_base_register();
        assert_eq!(base.borrow().name(), "NO_CONTEXT");
        assert!(rm.get_context_registers().is_empty());
    }

    #[test]
    fn context_base_register_is_the_processor_context_base() {
        let mut builder = RegisterBuilder::new();
        let ctx = Register::with_bit_range(
            "contextreg",
            "",
            addr(0),
            4,
            0,
            32,
            false,
            Register::TYPE_CONTEXT,
        );
        builder.add_register_ref(ctx);
        builder.add_register_with_bit_range(
            "field_a",
            "",
            addr(0),
            4,
            0,
            8,
            false,
            Register::TYPE_CONTEXT,
        );

        let rm = builder.register_manager();
        let base = rm.get_context_base_register();
        assert_eq!(base.borrow().name(), "contextreg");
        assert!(base.borrow().is_base_register());
        // Base register plus its context field child.
        assert_eq!(rm.get_context_registers().len(), 2);
    }

    #[test]
    fn register_names_are_alphabetically_sorted_and_exclude_aliases() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("Zeta", "", addr(0), 4, false, 0);
        builder.add_register("Alpha", "", addr(4), 4, false, 0);
        builder.add_alias("Zeta", "ZetaAlias");

        let rm = builder.register_manager();
        assert_eq!(
            rm.get_register_names(),
            vec!["Alpha".to_string(), "Zeta".to_string()]
        );
    }

    #[test]
    fn sorted_vector_registers_ordered_by_descending_size_then_ascending_offset() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("V_SMALL_HI", "", addr(16), 8, false, Register::TYPE_VECTOR);
        builder.add_register("V_BIG", "", addr(0), 16, false, Register::TYPE_VECTOR);
        builder.add_register("V_SMALL_LO", "", addr(8), 8, false, Register::TYPE_VECTOR);
        builder.add_register("NOT_VECTOR", "", addr(32), 4, false, 0);

        let rm = builder.register_manager();
        let names: Vec<String> = rm
            .get_sorted_vector_registers()
            .into_iter()
            .map(|r| r.borrow().name().to_string())
            .collect();
        assert_eq!(
            names,
            vec![
                "V_BIG".to_string(),
                "V_SMALL_LO".to_string(),
                "V_SMALL_HI".to_string(),
            ]
        );

        // Cached: calling again returns the same (recomputed-from-cache) ordering.
        let names_again: Vec<String> = rm
            .get_sorted_vector_registers()
            .into_iter()
            .map(|r| r.borrow().name().to_string())
            .collect();
        assert_eq!(names, names_again);
    }

    #[test]
    fn register_addresses_cover_every_register_byte_range() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("R0", "", addr(0), 4, false, 0);
        builder.add_register("R1", "", addr(8), 2, false, 0);

        let rm = builder.register_manager();
        let view = rm.get_register_addresses();
        assert!(view.contains(&addr(0)));
        assert!(view.contains(&addr(3)));
        assert!(!view.contains(&addr(4)));
        assert!(view.contains(&addr(8)));
        assert!(view.contains(&addr(9)));
        assert!(!view.contains(&addr(10)));
    }

    #[test]
    fn get_registers_returns_every_top_level_register_unsorted_by_name() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("R0", "", addr(0), 4, false, 0);
        builder.add_register("R1", "", addr(4), 4, false, 0);

        let rm = builder.register_manager();
        assert_eq!(rm.get_registers().len(), 2);
    }
}
