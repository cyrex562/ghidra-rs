use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use crate::program::model::address::{Address, AddressSpace, SpecialAddress};

/// Shared, mutable reference to a [`Register`].
///
/// Mirrors the Java class's shared-object-graph semantics: a register's parent, base register,
/// and children are set up once (by a not-yet-ported `RegisterBuilder`/`Language`) and then
/// treated as read-only for the remainder of the program's life.
pub type RegisterRef = Rc<RefCell<Register>>;

/// Non-owning reference to a [`Register`], used for parent back-links so the tree doesn't leak.
pub type WeakRegisterRef = Weak<RefCell<Register>>;

/// A processor register.
///
/// To sort of handle bit registers, a special addressing convention is used. First the upper
/// bit is set. Second, the next 3 bits are used to specify what bit position within a byte that
/// this register bit exists at. Finally, the rest of the address is the address of the byte
/// where the register bit lives.
pub struct Register {
    self_ref: WeakRegisterRef,
    name: String,
    description: String,
    address: Address,
    num_bytes: i32,
    least_sig_bit: i32,
    bit_length: i32,
    type_flags: i32,
    big_endian: bool,
    child_registers: Vec<RegisterRef>,
    aliases: HashSet<String>,
    base_mask: RefCell<Option<Vec<u8>>>,
    least_sig_bit_in_base_register: i32,
    parent: Option<WeakRegisterRef>,
    base_register: Option<RegisterRef>,
    group: Option<String>,
    /// Bit vector of valid lane sizes.
    lane_sizes: u64,
}

impl Register {
    /// Nothing special.
    pub const TYPE_NONE: i32 = 0;
    /// Frame pointer.
    pub const TYPE_FP: i32 = 1;
    /// Stack pointer.
    pub const TYPE_SP: i32 = 2;
    /// Program counter.
    pub const TYPE_PC: i32 = 4;
    /// Processor state.
    pub const TYPE_CONTEXT: i32 = 8;
    /// Register is always zero.
    pub const TYPE_ZERO: i32 = 16;
    /// Register should not be exposed to users.
    pub const TYPE_HIDDEN: i32 = 32;
    /// Register value should NOT follow disassembly flow.
    pub const TYPE_DOES_NOT_FOLLOW_FLOW: i32 = 64;
    /// Register can be used in SIMD operations.
    pub const TYPE_VECTOR: i32 = 128;

    /// Constructs a new `Register`.
    ///
    /// * `big_endian` - true if the most significant bytes are associated with the lowest
    ///   register addresses, and false if the least significant bytes are associated with the
    ///   lowest register addresses.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        big_endian: bool,
        type_flags: i32,
    ) -> RegisterRef {
        Self::with_bit_range(
            name,
            description,
            address,
            num_bytes,
            0,
            num_bytes * 8,
            big_endian,
            type_flags,
        )
    }

    /// Creates a detached copy of `register`'s base fields (name, description, address, size,
    /// bit range, endianness, and type flags).
    ///
    /// Mirrors Java's copy constructor: the parent/child links, aliases, group, and lane sizes
    /// are not copied.
    pub fn from_register(register: &Register) -> RegisterRef {
        Self::with_bit_range(
            register.name.clone(),
            register.description.clone(),
            register.address.clone(),
            register.num_bytes,
            register.least_sig_bit,
            register.bit_length,
            register.big_endian,
            register.type_flags,
        )
    }

    /// Constructs a new `Register` covering a specific bit range within its byte span.
    pub fn with_bit_range(
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        least_significant_bit: i32,
        bit_length: i32,
        big_endian: bool,
        type_flags: i32,
    ) -> RegisterRef {
        let name = name.into();
        let description = description.into();

        let mut address = address;
        let mut num_bytes = num_bytes;
        let mut least_sig_bit = least_significant_bit;

        let least_sig_byte = least_significant_bit / 8;
        let most_sig_byte = (least_significant_bit + bit_length - 1) / 8;
        let extra_lower_bytes = least_sig_byte;
        let extra_high_bytes = num_bytes - most_sig_byte - 1;

        if big_endian {
            if extra_lower_bytes > 0 {
                num_bytes -= extra_lower_bytes;
                least_sig_bit -= extra_lower_bytes * 8;
            }
            if extra_high_bytes > 0 {
                address = address
                    .add(extra_high_bytes as i64)
                    .expect("register address space overflow");
                num_bytes -= extra_high_bytes;
            }
        } else {
            if extra_lower_bytes > 0 {
                address = address
                    .add(extra_lower_bytes as i64)
                    .expect("register address space overflow");
                num_bytes -= extra_lower_bytes;
                least_sig_bit -= extra_lower_bytes * 8;
            }
            if extra_high_bytes > 0 {
                num_bytes -= extra_high_bytes;
            }
        }

        Rc::new_cyclic(|weak| {
            RefCell::new(Register {
                self_ref: weak.clone(),
                name,
                description,
                address,
                num_bytes,
                least_sig_bit,
                bit_length,
                type_flags,
                big_endian,
                child_registers: Vec::new(),
                aliases: HashSet::new(),
                base_mask: RefCell::new(None),
                least_sig_bit_in_base_register: 0,
                parent: None,
                base_register: None,
                group: None,
                lane_sizes: 0,
            })
        })
    }

    /// Register used to denote no defined context for a language.
    pub fn no_context() -> RegisterRef {
        Register::new(
            "NO_CONTEXT",
            "NO_CONTEXT",
            SpecialAddress::no_address(),
            4,
            true,
            Register::TYPE_NONE,
        )
    }

    /// Adds a register alias.
    pub(crate) fn add_alias(&mut self, alias: impl Into<String>) {
        let alias = alias.into();
        if self.name == alias {
            return;
        }
        self.aliases.insert(alias);
    }

    /// Removes a register alias.
    pub(crate) fn remove_alias(&mut self, alias: &str) {
        self.aliases.remove(alias);
    }

    /// Returns register aliases. NOTE: This is generally only supported for context register
    /// fields.
    pub fn aliases(&self) -> impl Iterator<Item = &String> {
        self.aliases.iter()
    }

    /// Gets the name of this Register.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Gets the description of the Register.
    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Gets the total number of bits for this Register.
    pub fn bit_length(&self) -> i32 {
        self.bit_length
    }

    /// Returns the minimum number of bytes required to store a value for this Register.
    pub fn minimum_byte_size(&self) -> i32 {
        (self.bit_length + 7) / 8
    }

    /// Returns the number of bytes spanned by this Register.
    ///
    /// Compare to [`Self::minimum_byte_size`]: Suppose a 5-bit register spans 2 bytes: 1 bit in
    /// the first byte, and the remaining 4 in the following byte. Its value can still be stored
    /// in 1 byte, which is what `minimum_byte_size` returns; however, its storage still spans 2
    /// bytes of the base register, which is what this method returns.
    pub fn num_bytes(&self) -> i32 {
        self.num_bytes
    }

    /// Returns the offset into the register space for this register.
    pub fn offset(&self) -> i32 {
        self.address.offset() as i32
    }

    /// Returns the bit offset from the register address for this register.
    pub fn least_significant_bit(&self) -> i32 {
        self.least_sig_bit
    }

    /// Returns true if this is the default frame pointer register.
    pub fn is_default_frame_pointer(&self) -> bool {
        (self.type_flags & Self::TYPE_FP) != 0
    }

    /// Returns true for a register whose context value should follow the disassembly flow.
    pub fn follows_flow(&self) -> bool {
        (self.type_flags & Self::TYPE_DOES_NOT_FOLLOW_FLOW) == 0
    }

    /// Returns true if this is a hidden register.
    pub fn is_hidden(&self) -> bool {
        (self.type_flags & Self::TYPE_HIDDEN) != 0
    }

    /// Returns true if this is the program counter register.
    pub fn is_program_counter(&self) -> bool {
        (self.type_flags & Self::TYPE_PC) != 0
    }

    /// Returns true if this is a processor state register.
    pub fn is_processor_context(&self) -> bool {
        (self.type_flags & Self::TYPE_CONTEXT) != 0
    }

    /// Returns true for a register that is always zero.
    pub fn is_zero(&self) -> bool {
        (self.type_flags & Self::TYPE_ZERO) != 0
    }

    /// Returns the register address space.
    pub fn address_space(&self) -> Arc<AddressSpace> {
        self.address.space().clone()
    }

    /// Returns the address of the register.
    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn parent_register(&self) -> Option<RegisterRef> {
        self.parent.as_ref().and_then(Weak::upgrade)
    }

    /// Returns list of children registers sorted by least-significant bit-offset within this
    /// register.
    pub fn child_registers(&self) -> Vec<RegisterRef> {
        self.child_registers.clone()
    }

    /// Returns the base register: `self` if this register has no base register of its own.
    pub fn get_base_register(&self) -> RegisterRef {
        if let Some(base) = &self.base_register {
            return Rc::clone(base);
        }
        self.self_ref
            .upgrade()
            .expect("register dropped while still in use")
    }

    pub fn least_significant_bit_in_base_register(&self) -> i32 {
        self.least_sig_bit_in_base_register
    }

    pub fn type_flags(&self) -> i32 {
        self.type_flags
    }

    /// Returns the mask that indicates which bits in the base register apply to this register.
    pub fn base_mask(&self) -> Vec<u8> {
        if let Some(mask) = self.base_mask.borrow().as_ref() {
            return mask.clone();
        }
        let base = self.get_base_register();
        let byte_length = ((base.borrow().bit_length + 7) / 8) as usize;
        let mut mask = vec![0u8; byte_length];
        let end_bit = self.least_sig_bit_in_base_register + self.bit_length - 1;
        for bit in self.least_sig_bit_in_base_register..=end_bit {
            Self::set_bit(&mut mask, bit);
        }
        *self.base_mask.borrow_mut() = Some(mask.clone());
        mask
    }

    fn set_bit(mask: &mut [u8], bit: i32) {
        let byte_num = mask.len() as i32 - (bit / 8) - 1;
        let bit_num = bit % 8;
        mask[byte_num as usize] |= 1 << bit_num;
    }

    pub(crate) fn set_flag(&mut self, flag: i32) {
        self.type_flags |= flag;
    }

    pub fn has_children(&self) -> bool {
        !self.child_registers.is_empty()
    }

    pub(crate) fn set_group(&mut self, group: impl Into<String>) {
        self.group = Some(group.into());
    }

    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    pub fn is_base_register(&self) -> bool {
        self.base_register.is_none()
    }

    /// Determines if `reg` is contained within this register. Method does not work for bit
    /// registers (e.g., context-bits).
    ///
    /// Returns true if `reg` equals this register or is contained within it.
    pub fn contains(&self, reg: &Register) -> bool {
        if self == reg {
            return true;
        }
        self.child_registers.iter().any(|child| child.borrow().contains(reg))
    }

    pub(crate) fn rename(&mut self, new_name: impl Into<String>) {
        let new_name = new_name.into();
        self.aliases.remove(&new_name);
        self.name = new_name;
    }

    /// Returns true if this is a vector register.
    pub fn is_vector_register(&self) -> bool {
        (self.type_flags & Self::TYPE_VECTOR) != 0
    }

    /// Determines whether `lane_size_in_bytes` is a valid lane size for this register.
    pub fn is_valid_lane_size(&self, lane_size_in_bytes: i32) -> bool {
        if !self.is_vector_register() {
            return false;
        }
        if !(1..=64).contains(&lane_size_in_bytes) {
            return false;
        }
        ((1u64 << (lane_size_in_bytes - 1)) & self.lane_sizes) != 0
    }

    /// Returns the sorted lane sizes for this register, measured in bytes, or `None` if this is
    /// not a vector register or no lane sizes have been set.
    pub fn lane_sizes(&self) -> Option<Vec<i32>> {
        if self.lane_sizes == 0 {
            return None;
        }
        let mut sizes = Vec::with_capacity(self.lane_sizes.count_ones() as usize);
        let mut size = 1i32;
        let mut remaining = self.lane_sizes;
        while remaining != 0 {
            if (remaining & 1) != 0 {
                sizes.push(size);
            }
            remaining >>= 1;
            size += 1;
        }
        Some(sizes)
    }

    /// Adds a lane size.
    ///
    /// Returns `Err` if this register is unable to support the definition of lanes, or if
    /// `lane_size_in_bytes` is invalid.
    pub(crate) fn add_lane_size(&mut self, lane_size_in_bytes: i32) -> Result<(), String> {
        if (8 * self.num_bytes) != self.bit_length {
            return Err(format!("Register {} does not support lanes", self.name));
        }
        if lane_size_in_bytes <= 0
            || lane_size_in_bytes >= self.num_bytes
            || lane_size_in_bytes > 64
            || (self.num_bytes % lane_size_in_bytes) != 0
        {
            return Err(format!(
                "Invalid lane size: {} for register {}",
                lane_size_in_bytes, self.name
            ));
        }
        self.type_flags |= Self::TYPE_VECTOR;
        self.lane_sizes |= 1u64 << (lane_size_in_bytes - 1);
        Ok(())
    }

    /// Attaches `children` to this register, sorted by least-significant bit-offset.
    pub(crate) fn set_child_registers(&mut self, mut children: Vec<RegisterRef>) {
        let (base, base_offset, base_num_bytes) = match &self.base_register {
            Some(base) => {
                let (offset, num_bytes) = {
                    let base_ref = base.borrow();
                    (base_ref.offset(), base_ref.num_bytes)
                };
                (Rc::clone(base), offset, num_bytes)
            }
            None => (
                self.self_ref
                    .upgrade()
                    .expect("register dropped while still in use"),
                self.offset(),
                self.num_bytes,
            ),
        };

        let parent_weak = self.self_ref.clone();
        for child in &children {
            if child.borrow().is_processor_context() {
                self.type_flags |= Self::TYPE_CONTEXT;
            }
            child.borrow_mut().attach_to_parent(
                parent_weak.clone(),
                Rc::clone(&base),
                base_offset,
                base_num_bytes,
            );
        }

        children.sort_by(|a, b| a.borrow().cmp(&b.borrow()));
        self.child_registers = children;
    }

    fn attach_to_parent(
        &mut self,
        parent: WeakRegisterRef,
        base: RegisterRef,
        base_offset: i32,
        base_num_bytes: i32,
    ) {
        self.parent = Some(parent);
        self.set_base_register_info(base, base_offset, base_num_bytes);
    }

    fn set_base_register_info(&mut self, base: RegisterRef, base_offset: i32, base_num_bytes: i32) {
        *self.base_mask.get_mut() = None;

        let base_end_addr = base_offset + base_num_bytes;
        let my_start_addr = self.offset();
        let my_end_addr = my_start_addr + self.num_bytes;

        if self.big_endian {
            let bytes_after_me = base_end_addr - my_end_addr;
            self.least_sig_bit_in_base_register = self.least_sig_bit + bytes_after_me * 8;
        } else {
            let bytes_before_me = my_start_addr - base_offset;
            self.least_sig_bit_in_base_register = self.least_sig_bit + bytes_before_me * 8;
        }

        self.base_register = Some(Rc::clone(&base));

        for child in &self.child_registers {
            child
                .borrow_mut()
                .set_base_register_info(Rc::clone(&base), base_offset, base_num_bytes);
        }
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl fmt::Debug for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Register")
            .field("name", &self.name)
            .field("address", &self.address)
            .field("bit_length", &self.bit_length)
            .field("type_flags", &self.type_flags)
            .finish()
    }
}

impl PartialEq for Register {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.bit_length == other.bit_length
            && self.address == other.address
            && self.least_sig_bit == other.least_sig_bit
    }
}

impl Eq for Register {}

impl std::hash::Hash for Register {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.address.offset() as i32).hash(state);
    }
}

impl PartialOrd for Register {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Register {
    fn cmp(&self, other: &Self) -> Ordering {
        let my_base = self.get_base_register();
        let other_base = other.get_base_register();
        // Fast path: when both registers share the very same base register object
        // (e.g. while sorting the children of a register whose RefCell is currently
        // mutably borrowed), avoid borrowing the base cells at all — they are identical
        // by construction, which would otherwise panic with "already mutably borrowed".
        let same_base =
            Rc::ptr_eq(&my_base, &other_base) || *my_base.borrow() == *other_base.borrow();
        let mut ordering = if same_base {
            self.least_sig_bit_in_base_register
                .cmp(&other.least_sig_bit_in_base_register)
        } else {
            self.address.cmp(&other.address)
        };
        if ordering == Ordering::Equal {
            ordering = self.bit_length.cmp(&other.bit_length);
        }
        ordering
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    #[test]
    fn simple_construction_reports_basic_fields() {
        let space = register_space();
        let reg = Register::new(
            "R0",
            "general purpose register 0",
            space.address(0x100),
            4,
            false,
            Register::TYPE_NONE,
        );
        let reg = reg.borrow();
        assert_eq!(reg.name(), "R0");
        assert_eq!(reg.description(), "general purpose register 0");
        assert_eq!(reg.num_bytes(), 4);
        assert_eq!(reg.bit_length(), 32);
        assert_eq!(reg.minimum_byte_size(), 4);
        assert_eq!(reg.offset(), 0x100);
        assert!(!reg.is_big_endian());
        assert!(reg.is_base_register());
        assert!(!reg.has_children());
    }

    #[test]
    fn type_flags_are_readable_via_accessors() {
        let space = register_space();
        let pc = Register::new(
            "PC",
            "program counter",
            space.address(0x200),
            4,
            false,
            Register::TYPE_PC | Register::TYPE_DOES_NOT_FOLLOW_FLOW,
        );
        let pc = pc.borrow();
        assert!(pc.is_program_counter());
        assert!(!pc.follows_flow());
        assert!(!pc.is_hidden());
        assert!(!pc.is_zero());
        assert!(!pc.is_default_frame_pointer());
    }

    #[test]
    fn little_endian_bit_range_normalizes_address_and_size() {
        let space = register_space();
        // A 1-byte field starting at bit 8 of a 4-byte register.
        let reg = Register::with_bit_range(
            "AH",
            "",
            space.address(0x0),
            4,
            8,
            8,
            false,
            Register::TYPE_NONE,
        );
        let reg = reg.borrow();
        assert_eq!(reg.num_bytes(), 1);
        assert_eq!(reg.offset(), 1);
        assert_eq!(reg.least_significant_bit(), 0);
    }

    #[test]
    fn big_endian_bit_range_normalizes_from_opposite_end() {
        let space = register_space();
        let reg = Register::with_bit_range(
            "AH",
            "",
            space.address(0x0),
            4,
            8,
            8,
            true,
            Register::TYPE_NONE,
        );
        let reg = reg.borrow();
        assert_eq!(reg.num_bytes(), 1);
        assert_eq!(reg.offset(), 2);
        assert_eq!(reg.least_significant_bit(), 0);
    }

    #[test]
    fn no_context_sentinel_matches_java_defaults() {
        let no_context = Register::no_context();
        let no_context = no_context.borrow();
        assert_eq!(no_context.name(), "NO_CONTEXT");
        assert!(no_context.is_big_endian());
        assert_eq!(no_context.type_flags(), Register::TYPE_NONE);
        assert_eq!(no_context.address().to_string(), "NO ADDRESS");
    }

    #[test]
    fn equals_and_hash_depend_only_on_identity_fields() {
        let space = register_space();
        let a = Register::new("R0", "one", space.address(0x10), 4, false, Register::TYPE_NONE);
        let b = Register::new("R0", "two", space.address(0x10), 4, false, Register::TYPE_ZERO);
        assert_eq!(*a.borrow(), *b.borrow());

        let c = Register::new("R1", "one", space.address(0x10), 4, false, Register::TYPE_NONE);
        assert_ne!(*a.borrow(), *c.borrow());
    }

    #[test]
    fn from_register_copies_base_fields_but_not_graph_state() {
        let space = register_space();
        let base = Register::new("R0", "base", space.address(0x10), 4, false, Register::TYPE_NONE);
        let child = Register::new("R0L", "low", space.address(0x10), 2, false, Register::TYPE_NONE);
        base.borrow_mut().set_child_registers(vec![Rc::clone(&child)]);
        base.borrow_mut().add_alias("R0_ALIAS");

        let copy = Register::from_register(&base.borrow());
        let copy = copy.borrow();
        assert_eq!(copy.name(), "R0");
        assert!(copy.is_base_register());
        assert!(!copy.has_children());
        assert_eq!(copy.aliases().count(), 0);
    }

    #[test]
    fn set_child_registers_wires_parent_and_base_register() {
        let space = register_space();
        let base = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let low_half =
            Register::new("AX", "", space.address(0x0), 2, false, Register::TYPE_NONE);

        base.borrow_mut().set_child_registers(vec![Rc::clone(&low_half)]);

        assert!(base.borrow().has_children());
        assert!(base.borrow().is_base_register());
        assert!(!low_half.borrow().is_base_register());

        let parent = low_half.borrow().parent_register().expect("parent set");
        assert_eq!(*parent.borrow(), *base.borrow());

        let resolved_base = low_half.borrow().get_base_register();
        assert_eq!(*resolved_base.borrow(), *base.borrow());

        assert!(base.borrow().contains(&low_half.borrow()));
        assert!(!low_half.borrow().contains(&base.borrow()));
    }

    #[test]
    fn set_child_registers_propagates_context_flag_to_parent() {
        let space = register_space();
        let base = Register::new("CTX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        let field = Register::new(
            "CTX_F",
            "",
            space.address(0x0),
            4,
            false,
            Register::TYPE_CONTEXT,
        );

        base.borrow_mut().set_child_registers(vec![field]);

        assert!(base.borrow().is_processor_context());
    }

    #[test]
    fn child_registers_are_sorted_by_least_significant_bit_in_base_register() {
        let space = register_space();
        let base = Register::new("EAX", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        // Little-endian: byte 0 is the low byte (least-significant), byte 1 is next.
        let low_byte =
            Register::with_bit_range("AL", "", space.address(0x0), 1, 0, 8, false, Register::TYPE_NONE);
        let high_byte =
            Register::with_bit_range("AH", "", space.address(0x1), 1, 0, 8, false, Register::TYPE_NONE);

        base.borrow_mut()
            .set_child_registers(vec![Rc::clone(&high_byte), Rc::clone(&low_byte)]);

        let children = base.borrow().child_registers();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].borrow().name(), "AL");
        assert_eq!(children[1].borrow().name(), "AH");
    }

    #[test]
    fn base_mask_reflects_bit_position_within_base_register() {
        let space = register_space();
        let base = Register::new("AX", "", space.address(0x0), 2, false, Register::TYPE_NONE);
        let low_byte =
            Register::with_bit_range("AL", "", space.address(0x0), 1, 0, 8, false, Register::TYPE_NONE);

        base.borrow_mut().set_child_registers(vec![Rc::clone(&low_byte)]);

        assert_eq!(low_byte.borrow().base_mask(), vec![0x00, 0xFF]);
    }

    #[test]
    fn aliases_can_be_added_and_removed_but_not_the_own_name() {
        let space = register_space();
        let reg = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);

        reg.borrow_mut().add_alias("R0");
        assert_eq!(reg.borrow().aliases().count(), 0);

        reg.borrow_mut().add_alias("ZERO");
        assert!(reg.borrow().aliases().any(|a| a == "ZERO"));

        reg.borrow_mut().remove_alias("ZERO");
        assert_eq!(reg.borrow().aliases().count(), 0);
    }

    #[test]
    fn rename_updates_name_and_drops_matching_alias() {
        let space = register_space();
        let reg = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        reg.borrow_mut().add_alias("R0_NEW");

        reg.borrow_mut().rename("R0_NEW");

        assert_eq!(reg.borrow().name(), "R0_NEW");
        assert_eq!(reg.borrow().aliases().count(), 0);
    }

    #[test]
    fn group_can_be_set_and_read() {
        let space = register_space();
        let reg = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        assert_eq!(reg.borrow().group(), None);

        reg.borrow_mut().set_group("general");
        assert_eq!(reg.borrow().group(), Some("general"));
    }

    #[test]
    fn lane_sizes_default_to_none_until_added() {
        let space = register_space();
        let reg = Register::new("V0", "", space.address(0x0), 8, false, Register::TYPE_NONE);
        assert!(!reg.borrow().is_vector_register());
        assert_eq!(reg.borrow().lane_sizes(), None);
        assert!(!reg.borrow().is_valid_lane_size(4));
    }

    #[test]
    fn add_lane_size_marks_register_as_vector_and_records_size() {
        let space = register_space();
        let reg = Register::new("V0", "", space.address(0x0), 8, false, Register::TYPE_NONE);

        reg.borrow_mut().add_lane_size(4).unwrap();

        assert!(reg.borrow().is_vector_register());
        assert!(reg.borrow().is_valid_lane_size(4));
        assert!(!reg.borrow().is_valid_lane_size(8));
        assert_eq!(reg.borrow().lane_sizes(), Some(vec![4]));
    }

    #[test]
    fn add_lane_size_rejects_registers_with_partial_byte_bit_length() {
        let space = register_space();
        let reg = Register::with_bit_range(
            "CTX_F",
            "",
            space.address(0x0),
            4,
            0,
            5,
            false,
            Register::TYPE_NONE,
        );

        let result = reg.borrow_mut().add_lane_size(1);
        assert!(result.is_err());
    }

    #[test]
    fn add_lane_size_rejects_sizes_that_do_not_divide_evenly() {
        let space = register_space();
        let reg = Register::new("V0", "", space.address(0x0), 8, false, Register::TYPE_NONE);

        let result = reg.borrow_mut().add_lane_size(3);
        assert!(result.is_err());
    }

    #[test]
    fn display_shows_register_name() {
        let space = register_space();
        let reg = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        assert_eq!(reg.borrow().to_string(), "R0");
    }
}
