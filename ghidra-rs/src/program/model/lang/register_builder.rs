use std::collections::HashMap;
use std::rc::Rc;

use crate::program::model::address::Address;
use crate::util::msg::Msg;

use super::register::{Register, RegisterRef};
use super::register_manager::RegisterManager;

/// Builder/factory for constructing the full set of [`Register`]s for a language.
///
/// Port of `ghidra.program.model.lang.RegisterBuilder`. Registers are typically added while
/// parsing a processor-spec's `<context_data>`/register definitions; once all registers have
/// been added, [`RegisterBuilder::register_manager`] wires up the base-register/sub-register
/// parent-child tree and produces the immutable [`RegisterManager`] that a `Language`
/// ultimately owns.
pub struct RegisterBuilder {
    register_list: Vec<RegisterRef>,
    /// Includes aliases and case-variations, same as the Java field.
    register_map: HashMap<String, RegisterRef>,
    context_address: Option<Address>,
}

impl Default for RegisterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RegisterBuilder {
    pub fn new() -> Self {
        RegisterBuilder {
            register_list: Vec::new(),
            register_map: HashMap::new(),
            context_address: None,
        }
    }

    /// Convenience constructor: whole-register add, byte-aligned (`leastSignificantBit = 0`,
    /// `bitLength = numBytes * 8`). Mirrors the 6-argument Java `addRegister` overload.
    pub fn add_register(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        big_endian: bool,
        type_flags: i32,
    ) {
        self.add_register_with_bit_range(
            name,
            description,
            address,
            num_bytes,
            0,
            num_bytes * 8,
            big_endian,
            type_flags,
        );
    }

    /// Convenience constructor for a register covering a specific bit range within its byte
    /// span. Mirrors the 8-argument Java `addRegister` overload.
    #[allow(clippy::too_many_arguments)]
    pub fn add_register_with_bit_range(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        least_significant_bit: i32,
        bit_length: i32,
        big_endian: bool,
        type_flags: i32,
    ) {
        let register = Register::with_bit_range(
            name,
            description,
            address,
            num_bytes,
            least_significant_bit,
            bit_length,
            big_endian,
            type_flags,
        );
        self.add_register_ref(register);
    }

    /// Adds an already-constructed [`Register`]. Mirrors the single-argument Java
    /// `addRegister(Register)` overload, which is where all the real logic lives.
    ///
    /// If a previously-added register already occupies the exact same address, least
    /// significant bit and bit length, `register` is *not* added as a new top-level register.
    /// Instead its name is folded into the existing register as an alias -- this is how
    /// context-field registers declared under different names (e.g. by the base language vs.
    /// a processor variant) end up resolving to the same underlying [`Register`].
    pub fn add_register_ref(&mut self, register: RegisterRef) {
        let name = register.borrow().name().to_string();
        if self.register_map.contains_key(&name) {
            // TODO: should we throw exception here - hopefully sleigh will prevent this
            // condition (kept as a faithful port of the Java comment).
            Msg::error("RegisterBuilder", &format!("Duplicate register name: {name}"));
        }

        // Use of register alias handles case where context field is defined with different
        // names.
        for existing in &self.register_list {
            let matches = {
                let existing_ref = existing.borrow();
                let new_ref = register.borrow();
                existing_ref.address() == new_ref.address()
                    && existing_ref.least_significant_bit() == new_ref.least_significant_bit()
                    && existing_ref.bit_length() == new_ref.bit_length()
            };
            if matches {
                existing.borrow_mut().add_alias(name.clone());
                self.add_register_to_name_map(&name, Rc::clone(existing));
                return;
            }
        }

        if self.context_address.is_none() && register.borrow().is_processor_context() {
            self.context_address = Some(register.borrow().address().clone());
        }
        self.register_list.push(Rc::clone(&register));
        self.add_register_to_name_map(&name, register);
    }

    fn add_register_to_name_map(&mut self, name: &str, register: RegisterRef) {
        self.register_map.insert(name.to_string(), Rc::clone(&register));
        self.register_map.insert(name.to_lowercase(), Rc::clone(&register));
        self.register_map.insert(name.to_uppercase(), register);
    }

    fn remove_register_from_name_map(&mut self, name: &str) {
        self.register_map.remove(name);
        self.register_map.remove(&name.to_lowercase());
        self.register_map.remove(&name.to_uppercase());
    }

    /// Returns the processor context address of the first context register added to this
    /// builder.
    pub fn process_context_address(&self) -> Option<&Address> {
        self.context_address.as_ref()
    }

    /// Computes the current register collection and instantiates a [`RegisterManager`].
    pub fn register_manager(&self) -> RegisterManager {
        RegisterManager::new(self.compute_registers(), self.register_map.clone())
    }

    /// Wires up base-register/sub-register (parent/child) relationships across all top-level
    /// registers added to this builder.
    ///
    /// NOTE (faithful port of a real Java quirk): the Java method builds a second list
    /// (`regList`), sorted by ascending `bitLength`, purely to drive the child-register
    /// computation below as a side effect (each register's `setChildRegisters` is called on
    /// the shared `Register` object, so the mutation is visible regardless of which list holds
    /// the reference). At the very end it returns `registerList` -- the original,
    /// unsorted-by-size, insertion-order list -- rather than the `regList` it just built. See
    /// `RegisterBuilder.java` lines 100-123: `return registerList;`, not `return regList;`. We
    /// reproduce that here: `reg_list`/`unprocessed` only exist to wire up parent/child links,
    /// and the return value is `self.register_list.clone()`.
    fn compute_registers(&self) -> Vec<RegisterRef> {
        let mut reg_list: Vec<RegisterRef> = Vec::new();
        let mut unprocessed: Vec<RegisterRef> = self.register_list.clone();

        let mut bit_size = 1;
        while !unprocessed.is_empty() {
            let mut next_larger_size = i32::MAX;
            let mut i = 0;
            while i < unprocessed.len() {
                let bl = unprocessed[i].borrow().bit_length();
                if bl == bit_size {
                    let register = unprocessed.remove(i);
                    let children = Self::get_children(&register, &mut reg_list);
                    register.borrow_mut().set_child_registers(children);
                    reg_list.push(register);
                    // Element at `i` was removed, so the next element has shifted into `i`;
                    // do not advance.
                } else {
                    next_larger_size = next_larger_size.min(bl);
                    i += 1;
                }
            }
            bit_size = next_larger_size;
        }

        self.register_list.clone()
    }

    /// Removes and returns every register in `reg_list` that `parent` contains, in `reg_list`
    /// order. Because `compute_registers` processes registers in ascending bit-length order,
    /// `reg_list` only ever holds registers smaller than `parent` that have not already been
    /// claimed as a child of some other (smaller) register -- so the first sufficiently-small
    /// enclosing register in the list "wins" a given descendant, correctly forming a tree
    /// instead of a flat set of all enclosing ancestors.
    fn get_children(parent: &RegisterRef, reg_list: &mut Vec<RegisterRef>) -> Vec<RegisterRef> {
        let mut children = Vec::new();
        let mut i = 0;
        while i < reg_list.len() {
            let contains = Self::contains(&parent.borrow(), &reg_list[i].borrow());
            if contains {
                children.push(reg_list.remove(i));
            } else {
                i += 1;
            }
        }
        children
    }

    /// Determines whether `child`'s byte range is fully contained within `parent`'s byte
    /// range, restricted to whole-byte-aligned parents (bit registers/context fields can never
    /// be a `parent` here). Method does not work for bit registers as a `parent`.
    fn contains(parent: &Register, child: &Register) -> bool {
        if parent.address_space() != child.address_space() {
            return false;
        }

        let parent_offset = parent.offset();
        let child_offset = child.offset();
        if child_offset < parent_offset
            || child_offset + child.minimum_byte_size() > parent_offset + parent.minimum_byte_size()
        {
            return false;
        }

        if parent.least_significant_bit() != 0 {
            return false;
        }
        if parent.bit_length() != parent.minimum_byte_size() * 8 {
            return false;
        }
        true
    }

    /// Returns the register with the given name, or `None` if not found.
    pub fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.register_map.get(name).cloned()
    }

    /// Rename a register. This allows generic register names declared within the language
    /// specification (`*.slaspec`) to be renamed for a processor variant specification
    /// (`*.pspec`).
    ///
    /// Returns `true` if the rename was successful, else `false`.
    ///
    /// NOTE (faithful port of a real Java quirk): `old_name` is looked up through the full
    /// name map, which includes aliases and case-variations, not just a register's canonical
    /// name. If `old_name` is actually an alias (or a case-variation) rather than the
    /// register's canonical name, only that one name-map entry is removed and replaced --
    /// the register's *original* canonical name keeps mapping to the (now differently-named)
    /// register too, since `register.rename()` changes the underlying `Register`'s name but
    /// this method never removes the old canonical name from the map unless it was the exact
    /// string passed in.
    pub fn rename_register(&mut self, old_name: &str, new_name: &str) -> bool {
        if self.register_map.contains_key(new_name) {
            return false;
        }
        let register = match self.register_map.get(old_name) {
            Some(register) => Rc::clone(register),
            None => return false,
        };
        register.borrow_mut().rename(new_name.to_string());
        self.remove_register_from_name_map(old_name);
        self.add_register_to_name_map(new_name, register);
        true
    }

    /// Add an alias to a previously defined register.
    ///
    /// Returns `true` if the alias addition was successful, else `false`.
    pub fn add_alias(&mut self, register_name: &str, alias: &str) -> bool {
        let register = match self.register_map.get(register_name) {
            Some(register) => Rc::clone(register),
            None => return false,
        };
        if self.register_map.contains_key(alias) {
            return false;
        }
        register.borrow_mut().add_alias(alias.to_string());
        self.add_register_to_name_map(alias, register);
        true
    }

    /// Set the group name for the specified register.
    ///
    /// Returns `true` if the register was found, else `false`.
    pub fn set_group(&mut self, register_name: &str, group_name: &str) -> bool {
        let register = match self.register_map.get(register_name) {
            Some(register) => Rc::clone(register),
            None => return false,
        };
        register.borrow_mut().set_group(group_name.to_string());
        true
    }

    /// Set a register flag for the specified register.
    ///
    /// Returns `true` if the register was found, else `false`.
    pub fn set_flag(&mut self, register_name: &str, register_flag: i32) -> bool {
        let register = match self.register_map.get(register_name) {
            Some(register) => Rc::clone(register),
            None => return false,
        };
        register.borrow_mut().set_flag(register_flag);
        true
    }

    /// Add a vector lane size to the specified register.
    ///
    /// Returns `Ok(false)` if no such register was found, `Ok(true)` on success, and `Err`
    /// (standing in for Java's `UnsupportedOperationException`/`IllegalArgumentException`) if
    /// the register cannot support the definition of lanes or `lane_size_in_bytes` is invalid.
    pub fn add_lane_size(&mut self, register_name: &str, lane_size_in_bytes: i32) -> Result<bool, String> {
        let register = match self.register_map.get(register_name) {
            Some(register) => Rc::clone(register),
            None => return Ok(false),
        };
        register.borrow_mut().add_lane_size(lane_size_in_bytes)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use std::sync::Arc;

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn addr(offset: i64) -> Address {
        register_space().address(offset)
    }

    #[test]
    fn duplicate_register_at_same_bit_range_becomes_an_alias() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("EAX", "", addr(0), 4, false, 0);
        // Same address, LSB, and bit length as EAX -- should fold into an alias, not a new
        // top-level register.
        builder.add_register("R0", "", addr(0), 4, false, 0);

        let manager = builder.register_manager();
        assert_eq!(manager.get_registers().len(), 1);

        let eax = manager.get_register_by_name("EAX").unwrap();
        assert!(eax.borrow().aliases().any(|a| a == "R0"));

        let r0 = manager.get_register_by_name("R0").unwrap();
        assert!(Rc::ptr_eq(&eax, &r0));
    }

    #[test]
    fn process_context_address_captures_first_context_register() {
        let mut builder = RegisterBuilder::new();
        assert!(builder.process_context_address().is_none());

        builder.add_register("R0", "", addr(0), 4, false, 0);
        assert!(builder.process_context_address().is_none());

        builder.add_register("CTX", "", addr(4), 4, false, Register::TYPE_CONTEXT);
        assert_eq!(builder.process_context_address(), Some(&addr(4)));

        // A second context register must not move the captured address.
        builder.add_register("CTX2", "", addr(8), 4, false, Register::TYPE_CONTEXT);
        assert_eq!(builder.process_context_address(), Some(&addr(4)));
    }

    #[test]
    fn rename_then_add_alias_round_trips_through_register_manager() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("A", "", addr(0), 8, false, 0);
        assert!(builder.rename_register("A", "L_0_8"));
        assert!(builder.add_alias("L_0_8", "L08"));

        // Renaming to a name that's already taken fails.
        builder.add_register("B", "", addr(8), 4, false, 0);
        assert!(!builder.rename_register("B", "L_0_8"));
        // Renaming something that doesn't exist fails.
        assert!(!builder.rename_register("NOPE", "WHATEVER"));

        let manager = builder.register_manager();
        let reg = manager.get_register_by_name("L_0_8").unwrap();
        assert_eq!(reg.borrow().name(), "L_0_8");
        let via_alias = manager.get_register_by_name("L08").unwrap();
        assert!(Rc::ptr_eq(&reg, &via_alias));
        let via_lowercase = manager.get_register_by_name("l_0_8").unwrap();
        assert!(Rc::ptr_eq(&reg, &via_lowercase));
    }

    #[test]
    fn rename_register_java_quirk_leaves_stale_canonical_name_mapped() {
        // Faithful port of the documented Java quirk: renaming via an alias/case-variation
        // key leaves the ORIGINAL canonical name still mapped to the (now renamed) register.
        let mut builder = RegisterBuilder::new();
        builder.add_register("Foo", "", addr(0), 4, false, 0);
        // "foo" (lowercase) is a case-variation key, not the canonical "Foo".
        assert!(builder.rename_register("foo", "Bar"));

        let renamed = builder.get_register("Bar").unwrap();
        assert_eq!(renamed.borrow().name(), "Bar");

        // The original canonical name "Foo" is still present in the map (bug preserved),
        // pointing at the same underlying (now differently-named) Register object.
        let stale = builder.get_register("Foo").unwrap();
        assert!(Rc::ptr_eq(&renamed, &stale));
        assert_eq!(stale.borrow().name(), "Bar");
    }

    #[test]
    fn set_group_flag_and_lane_size_mutate_shared_register() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("V0", "", addr(0), 8, false, 0);

        assert!(builder.set_group("V0", "vector"));
        assert!(builder.set_flag("V0", Register::TYPE_VECTOR));
        assert_eq!(builder.add_lane_size("V0", 4), Ok(true));

        assert!(!builder.set_group("NOPE", "x"));
        assert!(!builder.set_flag("NOPE", 0));
        assert_eq!(builder.add_lane_size("NOPE", 4), Ok(false));

        let manager = builder.register_manager();
        let v0 = manager.get_register_by_name("V0").unwrap();
        assert_eq!(v0.borrow().group(), Some("vector"));
        assert!(v0.borrow().is_vector_register());
        assert!(v0.borrow().is_valid_lane_size(4));
    }

    #[test]
    fn add_lane_size_propagates_register_validation_errors() {
        let mut builder = RegisterBuilder::new();
        builder.add_register("R0", "", addr(0), 4, false, 0);
        // Not a lane-eligible register configuration (non-vector, size 4 doesn't divide by 3).
        assert!(builder.add_lane_size("R0", 3).is_err());
    }

    #[test]
    fn compute_registers_wires_up_parent_child_tree_for_byte_sub_registers() {
        let mut builder = RegisterBuilder::new();
        // 8-byte, then two 4-byte halves, matching the parent-child nesting the Java test
        // vectors rely on.
        builder.add_register("L_0_8", "", addr(0), 8, false, 0);
        builder.add_register("L_0_4", "", addr(0), 4, false, 0);
        builder.add_register("L_4_4", "", addr(4), 4, false, 0);

        let manager = builder.register_manager();
        let parent = manager.get_register_by_name("L_0_8").unwrap();
        assert!(parent.borrow().has_children());
        assert_eq!(parent.borrow().child_registers().len(), 2);

        let child = manager.get_register_by_name("L_0_4").unwrap();
        let child_parent = child.borrow().parent_register().unwrap();
        assert!(Rc::ptr_eq(&parent, &child_parent));
    }
}
