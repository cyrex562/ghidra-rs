//! Port of `ghidra.program.model.lang.Register`, stored in an arena.
//!
//! # Ownership model
//! Java's `Register` objects form a graph: a register points at its parent, its base register
//! and its children, and every register of a language is shared by the language, its compiler
//! specs, program contexts, p-code executors and so on. Following convention 1 of
//! `OWNERSHIP_MIGRATION.md` ("arena + typed ID", decided for `Register` on 2026-09-24), this
//! module splits that object into:
//!
//! * [`RegisterStore`] -- the arena. One store holds every register of a language (it is
//!   built by [`RegisterBuilder`](super::RegisterBuilder) and owned by the language's
//!   [`RegisterManager`](super::RegisterManager)). It is immutable once shared.
//! * [`RegisterId`] -- a `Copy` index into a store. Parent, child and base-register links are
//!   `RegisterId`s, never references.
//! * [`RegisterData`] -- the per-register record (name, address, bit range, flags, links).
//!   Graph queries that need other records ([`RegisterStore::base_register_of`],
//!   [`RegisterStore::contains`], [`RegisterStore::base_mask`], ...) are methods on the store
//!   taking `RegisterId`s.
//! * [`Register`] -- a resolved handle: the store (`Arc<RegisterStore>`) plus an id. It stands
//!   in for a Java `Register` reference in APIs that hand a register to code that does not
//!   otherwise hold the language (variable storage, register values, program contexts). It
//!   dereferences to its [`RegisterData`], exposes the graph queries as handle-returning
//!   methods, and is `Clone + Send + Sync`. Two handles to the same store and id are the same
//!   register ([`Register::same`]); handles compare with `==` by Java's `equals` (name, bit
//!   length, address, least significant bit).
//!
//! A register built outside a language ([`Register::new`] and friends, as used by tests and
//! by synthesized registers such as `UnknownRegister`) lives alone in a one-entry store.
//!
//! [`RegisterRef`] is the handle's former name (it used to be `Rc<RefCell<Register>>`); it is
//! kept as an alias while callers migrate.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;
use std::sync::{Arc, OnceLock};

use crate::program::model::address::{Address, AddressSpace, SpecialAddress};

/// Former name of [`Register`] (the handle), kept while callers migrate.
pub type RegisterRef = Register;

/// Typed index of a register within its [`RegisterStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegisterId(u32);

impl RegisterId {
    /// The position of this register in its store.
    pub fn index(self) -> usize {
        self.0 as usize
    }

    /// Resolves this id against `store`.
    pub fn data(self, store: &RegisterStore) -> &RegisterData {
        store.get(self)
    }
}

/// The record of one processor register, held by a [`RegisterStore`].
///
/// To sort of handle bit registers, a special addressing convention is used. First the upper
/// bit is set. Second, the next 3 bits are used to specify what bit position within a byte that
/// this register bit exists at. Finally, the rest of the address is the address of the byte
/// where the register bit lives.
#[derive(Clone)]
pub struct RegisterData {
    id: RegisterId,
    name: String,
    description: String,
    address: Address,
    num_bytes: i32,
    least_sig_bit: i32,
    bit_length: i32,
    type_flags: i32,
    big_endian: bool,
    child_registers: Vec<RegisterId>,
    aliases: HashSet<String>,
    least_sig_bit_in_base_register: i32,
    parent: Option<RegisterId>,
    base_register: Option<RegisterId>,
    group: Option<String>,
    /// Bit vector of valid lane sizes.
    lane_sizes: u64,
    /// Computed when the store is shared ([`RegisterStore::into_shared`]); Java computes it
    /// lazily and caches it.
    base_mask: Vec<u8>,
}

impl RegisterData {
    /// Builds a detached record, normalizing the byte span to the bytes the bit range covers
    /// (the Java constructor's logic).
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: String,
        description: String,
        address: Address,
        num_bytes: i32,
        least_significant_bit: i32,
        bit_length: i32,
        big_endian: bool,
        type_flags: i32,
    ) -> Self {
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

        RegisterData {
            id: RegisterId(0),
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
            least_sig_bit_in_base_register: 0,
            parent: None,
            base_register: None,
            group: None,
            lane_sizes: 0,
            base_mask: Vec::new(),
        }
    }

    /// A detached copy of the base fields (Java's copy constructor): name, description,
    /// address, size, bit range, endianness and type flags. Links, aliases, group and lane
    /// sizes are not copied.
    fn copy_base_fields(&self) -> Self {
        RegisterData::new(
            self.name.clone(),
            self.description.clone(),
            self.address.clone(),
            self.num_bytes,
            self.least_sig_bit,
            self.bit_length,
            self.big_endian,
            self.type_flags,
        )
    }

    /// This register's id within its store.
    pub fn id(&self) -> RegisterId {
        self.id
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

    /// Returns true if the most significant bytes are associated with the lowest register
    /// addresses.
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
        (self.type_flags & Register::TYPE_FP) != 0
    }

    /// Returns true for a register whose context value should follow the disassembly flow.
    pub fn follows_flow(&self) -> bool {
        (self.type_flags & Register::TYPE_DOES_NOT_FOLLOW_FLOW) == 0
    }

    /// Returns true if this is a hidden register.
    pub fn is_hidden(&self) -> bool {
        (self.type_flags & Register::TYPE_HIDDEN) != 0
    }

    /// Returns true if this is the program counter register.
    pub fn is_program_counter(&self) -> bool {
        (self.type_flags & Register::TYPE_PC) != 0
    }

    /// Returns true if this is a processor state register.
    pub fn is_processor_context(&self) -> bool {
        (self.type_flags & Register::TYPE_CONTEXT) != 0
    }

    /// Returns true for a register that is always zero.
    pub fn is_zero(&self) -> bool {
        (self.type_flags & Register::TYPE_ZERO) != 0
    }

    /// Returns the register address space.
    pub fn address_space(&self) -> Arc<AddressSpace> {
        self.address.space().clone()
    }

    /// Returns the address of the register.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// The parent register's id, if this register has been attached to one.
    pub fn parent_id(&self) -> Option<RegisterId> {
        self.parent
    }

    /// Ids of the child registers, sorted by least-significant bit-offset within this register.
    pub fn child_ids(&self) -> &[RegisterId] {
        &self.child_registers
    }

    /// The base register's id: this register's own id if it has no base register of its own.
    pub fn base_register_id(&self) -> RegisterId {
        self.base_register.unwrap_or(self.id)
    }

    pub fn least_significant_bit_in_base_register(&self) -> i32 {
        self.least_sig_bit_in_base_register
    }

    pub fn type_flags(&self) -> i32 {
        self.type_flags
    }

    pub fn has_children(&self) -> bool {
        !self.child_registers.is_empty()
    }

    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    pub fn is_base_register(&self) -> bool {
        self.base_register.is_none()
    }

    /// Returns true if this is a vector register.
    pub fn is_vector_register(&self) -> bool {
        (self.type_flags & Register::TYPE_VECTOR) != 0
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

    /// Adds a register alias (ignored when it equals the register's own name).
    fn add_alias(&mut self, alias: String) {
        if self.name == alias {
            return;
        }
        self.aliases.insert(alias);
    }

    fn rename(&mut self, new_name: String) {
        self.aliases.remove(&new_name);
        self.name = new_name;
    }

    fn add_lane_size(&mut self, lane_size_in_bytes: i32) -> Result<(), String> {
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
        self.type_flags |= Register::TYPE_VECTOR;
        self.lane_sizes |= 1u64 << (lane_size_in_bytes - 1);
        Ok(())
    }
}

impl fmt::Debug for RegisterData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Register")
            .field("name", &self.name)
            .field("address", &self.address)
            .field("bit_length", &self.bit_length)
            .field("type_flags", &self.type_flags)
            .finish()
    }
}

impl fmt::Display for RegisterData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Java's `Register.equals`: name, bit length, address and least significant bit.
impl PartialEq for RegisterData {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.bit_length == other.bit_length
            && self.address == other.address
            && self.least_sig_bit == other.least_sig_bit
    }
}

impl Eq for RegisterData {}

/// The arena owning every register of a language.
///
/// Mutated only while being built (by [`RegisterBuilder`](super::RegisterBuilder) or the
/// one-register constructors); shared immutably through `Arc` afterwards
/// ([`Self::into_shared`]), which is when base masks are computed.
#[derive(Clone, Debug, Default)]
pub struct RegisterStore {
    registers: Vec<RegisterData>,
}

impl RegisterStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of registers in this store.
    pub fn len(&self) -> usize {
        self.registers.len()
    }

    /// Whether the store holds no registers.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    /// Resolves `id`. Panics if `id` came from a different, smaller store.
    pub fn get(&self, id: RegisterId) -> &RegisterData {
        &self.registers[id.index()]
    }

    fn get_mut(&mut self, id: RegisterId) -> &mut RegisterData {
        &mut self.registers[id.index()]
    }

    /// Every register id in insertion order.
    pub fn ids(&self) -> impl Iterator<Item = RegisterId> + '_ {
        (0..self.registers.len() as u32).map(RegisterId)
    }

    /// Adds a register covering `bit_length` bits starting at `least_significant_bit` of its
    /// `num_bytes`-byte span (the Java constructor), returning its id.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add(
        &mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        least_significant_bit: i32,
        bit_length: i32,
        big_endian: bool,
        type_flags: i32,
    ) -> RegisterId {
        self.push(RegisterData::new(
            name.into(),
            description.into(),
            address,
            num_bytes,
            least_significant_bit,
            bit_length,
            big_endian,
            type_flags,
        ))
    }

    /// Adds a detached copy of `register`'s base fields (Java's copy constructor).
    pub(crate) fn add_copy(&mut self, register: &RegisterData) -> RegisterId {
        self.push(register.copy_base_fields())
    }

    fn push(&mut self, mut data: RegisterData) -> RegisterId {
        let id = RegisterId(u32::try_from(self.registers.len()).expect("too many registers"));
        data.id = id;
        self.registers.push(data);
        id
    }

    pub(crate) fn add_alias(&mut self, id: RegisterId, alias: impl Into<String>) {
        self.get_mut(id).add_alias(alias.into());
    }

    pub(crate) fn remove_alias(&mut self, id: RegisterId, alias: &str) {
        self.get_mut(id).aliases.remove(alias);
    }

    pub(crate) fn rename(&mut self, id: RegisterId, new_name: impl Into<String>) {
        self.get_mut(id).rename(new_name.into());
    }

    pub(crate) fn set_flag(&mut self, id: RegisterId, flag: i32) {
        self.get_mut(id).type_flags |= flag;
    }

    pub(crate) fn set_group(&mut self, id: RegisterId, group: impl Into<String>) {
        self.get_mut(id).group = Some(group.into());
    }

    /// Adds a lane size. `Err` if the register cannot support lanes or the size is invalid.
    pub(crate) fn add_lane_size(&mut self, id: RegisterId, lane_size_in_bytes: i32) -> Result<(), String> {
        self.get_mut(id).add_lane_size(lane_size_in_bytes)
    }

    /// Port of `Register.setChildRegisters`: attaches `children` to `parent` (updating their
    /// base-register info, recursively), marks `parent` as context if any child is, and stores
    /// the children sorted by `Register.compareTo`.
    pub(crate) fn set_child_registers(&mut self, parent: RegisterId, mut children: Vec<RegisterId>) {
        for &child in &children {
            if self.get(child).is_processor_context() {
                self.get_mut(parent).type_flags |= Register::TYPE_CONTEXT;
            }
            self.get_mut(child).parent = Some(parent);
            self.update_base_register_info(child);
        }
        children.sort_by(|&a, &b| self.compare(a, self, b));
        self.get_mut(parent).child_registers = children;
    }

    /// Port of `Register.updateBaseRegisterInfo` (which `setParent` triggers): the base register
    /// is the parent's base register, and the bit offset within it follows from the byte
    /// offsets. Recurses into the children.
    fn update_base_register_info(&mut self, id: RegisterId) {
        let parent = self.get(id).parent.expect("only attached registers have a base register");
        let base = self.get(parent).base_register_id();
        let (base_start, base_num_bytes) = {
            let b = self.get(base);
            (b.offset(), b.num_bytes)
        };
        let base_end = base_start + base_num_bytes;
        let reg = self.get_mut(id);
        let my_start = reg.offset();
        let my_end = my_start + reg.num_bytes;
        reg.least_sig_bit_in_base_register = if reg.big_endian {
            reg.least_sig_bit + (base_end - my_end) * 8
        } else {
            reg.least_sig_bit + (my_start - base_start) * 8
        };
        reg.base_register = Some(base);
        for child in reg.child_registers.clone() {
            self.update_base_register_info(child);
        }
    }

    /// Freezes this store for sharing, computing every register's base mask.
    pub fn into_shared(mut self) -> Arc<Self> {
        for i in 0..self.registers.len() {
            let mask = self.compute_base_mask(RegisterId(i as u32));
            self.registers[i].base_mask = mask;
        }
        Arc::new(self)
    }

    fn compute_base_mask(&self, id: RegisterId) -> Vec<u8> {
        let reg = self.get(id);
        let base = self.get(reg.base_register_id());
        let byte_length = ((base.bit_length + 7) / 8) as usize;
        let mut mask = vec![0u8; byte_length];
        let end_bit = reg.least_sig_bit_in_base_register + reg.bit_length - 1;
        for bit in reg.least_sig_bit_in_base_register..=end_bit {
            let byte_num = mask.len() as i32 - (bit / 8) - 1;
            mask[byte_num as usize] |= 1 << (bit % 8);
        }
        mask
    }

    /// The parent of `id`, if any.
    pub fn parent_of(&self, id: RegisterId) -> Option<RegisterId> {
        self.get(id).parent
    }

    /// The base register of `id` (`id` itself for a base register).
    pub fn base_register_of(&self, id: RegisterId) -> RegisterId {
        self.get(id).base_register_id()
    }

    /// Returns the mask that indicates which bits in the base register apply to `id`.
    pub fn base_mask(&self, id: RegisterId) -> &[u8] {
        &self.get(id).base_mask
    }

    /// Port of `Register.contains`: true if `reg` (resolved against `reg_store`) equals `id` or
    /// is contained within it. Does not work for bit registers (e.g., context-bits).
    pub fn contains(&self, id: RegisterId, reg_store: &RegisterStore, reg: RegisterId) -> bool {
        if self.get(id) == reg_store.get(reg) {
            return true;
        }
        self.get(id)
            .child_registers
            .iter()
            .any(|&child| self.contains(child, reg_store, reg))
    }

    /// Port of `Register.compareTo`: registers sharing an equal base register order by bit
    /// offset within it, others by address; ties break on bit length.
    pub fn compare(&self, id: RegisterId, other_store: &RegisterStore, other: RegisterId) -> Ordering {
        let me = self.get(id);
        let them = other_store.get(other);
        let my_base = self.get(me.base_register_id());
        let other_base = other_store.get(them.base_register_id());
        let ordering = if my_base == other_base {
            me.least_sig_bit_in_base_register
                .cmp(&them.least_sig_bit_in_base_register)
        } else {
            me.address.cmp(&them.address)
        };
        ordering.then_with(|| me.bit_length.cmp(&them.bit_length))
    }
}

/// A processor register: a resolved handle to one register of a [`RegisterStore`].
///
/// See the module docs. Dereferences to the register's [`RegisterData`].
#[derive(Clone)]
pub struct Register {
    store: Arc<RegisterStore>,
    id: RegisterId,
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

    /// Constructs a stand-alone register (in its own one-entry store).
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
    ) -> Register {
        Self::with_bit_range(name, description, address, num_bytes, 0, num_bytes * 8, big_endian, type_flags)
    }

    /// Creates a detached stand-alone copy of `register`'s base fields (name, description,
    /// address, size, bit range, endianness, and type flags).
    ///
    /// Mirrors Java's copy constructor: the parent/child links, aliases, group, and lane sizes
    /// are not copied.
    pub fn from_register(register: &RegisterData) -> Register {
        let mut store = RegisterStore::new();
        let id = store.add_copy(register);
        Register::from_store(&store.into_shared(), id)
    }

    /// Constructs a stand-alone register covering a specific bit range within its byte span.
    #[allow(clippy::too_many_arguments)]
    pub fn with_bit_range(
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: i32,
        least_significant_bit: i32,
        bit_length: i32,
        big_endian: bool,
        type_flags: i32,
    ) -> Register {
        let mut store = RegisterStore::new();
        let id = store.add(
            name,
            description,
            address,
            num_bytes,
            least_significant_bit,
            bit_length,
            big_endian,
            type_flags,
        );
        Register::from_store(&store.into_shared(), id)
    }

    /// Register used to denote no defined context for a language (Java's `NO_CONTEXT`
    /// singleton; every call returns the same register).
    pub fn no_context() -> Register {
        static NO_CONTEXT: OnceLock<Register> = OnceLock::new();
        NO_CONTEXT
            .get_or_init(|| {
                Register::new(
                    "NO_CONTEXT",
                    "NO_CONTEXT",
                    SpecialAddress::no_address(),
                    4,
                    true,
                    Register::TYPE_NONE,
                )
            })
            .clone()
    }

    /// The handle for `id` in `store`.
    pub fn from_store(store: &Arc<RegisterStore>, id: RegisterId) -> Register {
        assert!(id.index() < store.len(), "register id out of range for its store");
        Register { store: Arc::clone(store), id }
    }

    /// This register's id within [`Self::store`].
    pub fn id(&self) -> RegisterId {
        self.id
    }

    /// The store this register lives in.
    pub fn store(&self) -> &Arc<RegisterStore> {
        &self.store
    }

    /// This register's record.
    pub fn data(&self) -> &RegisterData {
        self.store.get(self.id)
    }

    /// Identity: true if both handles denote the same register of the same store (Java's `==`
    /// on `Register` objects). Compare with `==` for Java's `equals`.
    pub fn same(a: &Register, b: &Register) -> bool {
        a.id == b.id && Arc::ptr_eq(&a.store, &b.store)
    }

    fn handle(&self, id: RegisterId) -> Register {
        Register { store: Arc::clone(&self.store), id }
    }

    pub fn parent_register(&self) -> Option<Register> {
        self.store.parent_of(self.id).map(|id| self.handle(id))
    }

    /// Returns list of children registers sorted by least-significant bit-offset within this
    /// register.
    pub fn child_registers(&self) -> Vec<Register> {
        self.data().child_ids().iter().map(|&id| self.handle(id)).collect()
    }

    /// Returns the base register: `self` if this register has no base register of its own.
    pub fn get_base_register(&self) -> Register {
        self.handle(self.store.base_register_of(self.id))
    }

    /// Returns the mask that indicates which bits in the base register apply to this register.
    pub fn base_mask(&self) -> Vec<u8> {
        self.store.base_mask(self.id).to_vec()
    }

    /// Determines if `reg` is contained within this register. Method does not work for bit
    /// registers (e.g., context-bits).
    ///
    /// Returns true if `reg` equals this register or is contained within it.
    pub fn contains(&self, reg: &Register) -> bool {
        self.store.contains(self.id, &reg.store, reg.id)
    }
}

impl Deref for Register {
    type Target = RegisterData;

    fn deref(&self) -> &RegisterData {
        self.data()
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.data(), f)
    }
}

impl fmt::Debug for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.data(), f)
    }
}

/// Java's `Register.equals` (see [`RegisterData`]'s `PartialEq`).
impl PartialEq for Register {
    fn eq(&self, other: &Self) -> bool {
        self.data() == other.data()
    }
}

impl Eq for Register {}

/// Java's `Register.hashCode`: the register's offset.
impl std::hash::Hash for Register {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.offset().hash(state);
    }
}

impl PartialOrd for Register {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Java's `Register.compareTo` (see [`RegisterStore::compare`]).
impl Ord for Register {
    fn cmp(&self, other: &Self) -> Ordering {
        self.store.compare(self.id, &other.store, other.id)
    }
}

/// Helpers for tests that assemble small register graphs out of stand-alone registers.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    fn detached(register: &Register) -> RegisterData {
        let mut data = register.data().clone();
        data.child_registers.clear();
        data.parent = None;
        data.base_register = None;
        data.least_sig_bit_in_base_register = 0;
        data
    }

    /// Copies `registers` (every field except their links) into one new store, applies
    /// `links` (`(parent index, child indices)`, in order, as `Register.setChildRegisters`
    /// would be called) and returns the new handles in `registers` order.
    pub(crate) fn linked(registers: &[&Register], links: &[(usize, &[usize])]) -> Vec<Register> {
        let mut store = RegisterStore::new();
        let ids: Vec<RegisterId> = registers.iter().map(|r| store.push(detached(r))).collect();
        for &(parent, children) in links {
            store.set_child_registers(ids[parent], children.iter().map(|&c| ids[c]).collect());
        }
        let store = store.into_shared();
        ids.iter().map(|&id| Register::from_store(&store, id)).collect()
    }

    /// A stand-alone copy of `register` modified by `edit` (aliases, group, flags, lanes).
    pub(crate) fn edited(register: &Register, edit: impl FnOnce(&mut RegisterStore, RegisterId)) -> Register {
        let mut store = RegisterStore::new();
        let id = store.push(detached(register));
        edit(&mut store, id);
        Register::from_store(&store.into_shared(), id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpaceType;

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    /// Builds a shared store from `(name, offset, num_bytes, lsb, bit_length, flags)` rows and
    /// `(parent, children)` links, returning a handle per row.
    fn build(
        rows: &[(&str, i64, i32, i32, i32, i32)],
        links: &[(usize, &[usize])],
    ) -> Vec<Register> {
        let space = register_space();
        let mut store = RegisterStore::new();
        let ids: Vec<RegisterId> = rows
            .iter()
            .map(|&(name, offset, num_bytes, lsb, bits, flags)| {
                store.add(name, "", space.address(offset), num_bytes, lsb, bits, false, flags)
            })
            .collect();
        for &(parent, children) in links {
            store.set_child_registers(ids[parent], children.iter().map(|&c| ids[c]).collect());
        }
        let store = store.into_shared();
        ids.iter().map(|&id| Register::from_store(&store, id)).collect()
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
        let reg = Register::with_bit_range("AH", "", space.address(0x0), 4, 8, 8, false, Register::TYPE_NONE);
        assert_eq!(reg.num_bytes(), 1);
        assert_eq!(reg.offset(), 1);
        assert_eq!(reg.least_significant_bit(), 0);
    }

    #[test]
    fn big_endian_bit_range_normalizes_from_opposite_end() {
        let space = register_space();
        let reg = Register::with_bit_range("AH", "", space.address(0x0), 4, 8, 8, true, Register::TYPE_NONE);
        assert_eq!(reg.num_bytes(), 1);
        assert_eq!(reg.offset(), 2);
        assert_eq!(reg.least_significant_bit(), 0);
    }

    #[test]
    fn no_context_sentinel_matches_java_defaults() {
        let no_context = Register::no_context();
        assert_eq!(no_context.name(), "NO_CONTEXT");
        assert!(no_context.is_big_endian());
        assert_eq!(no_context.type_flags(), Register::TYPE_NONE);
        assert_eq!(no_context.address().to_string(), "NO ADDRESS");
        // Java's NO_CONTEXT is a singleton.
        assert!(Register::same(&no_context, &Register::no_context()));
    }

    #[test]
    fn equals_and_hash_depend_only_on_identity_fields() {
        let space = register_space();
        let a = Register::new("R0", "one", space.address(0x10), 4, false, Register::TYPE_NONE);
        let b = Register::new("R0", "two", space.address(0x10), 4, false, Register::TYPE_ZERO);
        assert_eq!(a, b);
        assert!(!Register::same(&a, &b));

        let c = Register::new("R1", "one", space.address(0x10), 4, false, Register::TYPE_NONE);
        assert_ne!(a, c);
    }

    #[test]
    fn from_register_copies_base_fields_but_not_graph_state() {
        let regs = build(&[("R0", 0x10, 4, 0, 32, 0), ("R0L", 0x10, 2, 0, 16, 0)], &[(0, &[1])]);
        let copy = Register::from_register(&regs[0]);
        assert_eq!(copy.name(), "R0");
        assert!(copy.is_base_register());
        assert!(!copy.has_children());
        assert_eq!(copy.aliases().count(), 0);
    }

    #[test]
    fn set_child_registers_wires_parent_and_base_register() {
        let regs = build(&[("EAX", 0, 4, 0, 32, 0), ("AX", 0, 2, 0, 16, 0)], &[(0, &[1])]);
        let (base, low_half) = (&regs[0], &regs[1]);

        assert!(base.has_children());
        assert!(base.is_base_register());
        assert!(!low_half.is_base_register());

        let parent = low_half.parent_register().expect("parent set");
        assert!(Register::same(&parent, base));
        assert_eq!(low_half.parent_id(), Some(base.id()));

        let resolved_base = low_half.get_base_register();
        assert!(Register::same(&resolved_base, base));
        assert!(Register::same(&base.get_base_register(), base));

        assert!(base.contains(low_half));
        assert!(!low_half.contains(base));
    }

    #[test]
    fn grandchildren_resolve_to_the_top_base_register() {
        // Built bottom-up, as RegisterBuilder does: AX adopts AL, then EAX adopts AX.
        let regs = build(
            &[("EAX", 0, 4, 0, 32, 0), ("AX", 0, 2, 0, 16, 0), ("AH", 1, 1, 0, 8, 0)],
            &[(1, &[2]), (0, &[1])],
        );
        let ah = &regs[2];
        assert!(Register::same(&ah.get_base_register(), &regs[0]));
        assert!(Register::same(&ah.parent_register().unwrap(), &regs[1]));
        assert_eq!(ah.least_significant_bit_in_base_register(), 8);
        assert_eq!(ah.base_mask(), vec![0x00, 0x00, 0xFF, 0x00]);
    }

    #[test]
    fn set_child_registers_propagates_context_flag_to_parent() {
        let regs = build(
            &[("CTX", 0, 4, 0, 32, 0), ("CTX_F", 0, 4, 0, 32, Register::TYPE_CONTEXT)],
            &[(0, &[1])],
        );
        assert!(regs[0].is_processor_context());
    }

    #[test]
    fn context_bit_field_mask_and_offset_within_base() {
        // A 3-bit little-endian context field at bits 4..7 of a 4-byte context register.
        let regs = build(
            &[
                ("contextreg", 0x40, 4, 0, 32, Register::TYPE_CONTEXT),
                ("TMode", 0x40, 4, 4, 3, Register::TYPE_CONTEXT),
            ],
            &[(0, &[1])],
        );
        let field = &regs[1];
        assert_eq!(field.num_bytes(), 1);
        assert_eq!(field.least_significant_bit_in_base_register(), 4);
        assert_eq!(field.base_mask(), vec![0x00, 0x00, 0x00, 0x70]);
        assert_eq!(regs[0].base_mask(), vec![0xFF; 4]);
    }

    #[test]
    fn child_registers_are_sorted_by_least_significant_bit_in_base_register() {
        let regs = build(
            &[("EAX", 0, 4, 0, 32, 0), ("AH", 1, 1, 0, 8, 0), ("AL", 0, 1, 0, 8, 0)],
            &[(0, &[1, 2])],
        );
        let children = regs[0].child_registers();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].name(), "AL");
        assert_eq!(children[1].name(), "AH");
        assert!(children[0] < children[1]);
    }

    #[test]
    fn base_mask_reflects_bit_position_within_base_register() {
        let regs = build(&[("AX", 0, 2, 0, 16, 0), ("AL", 0, 1, 0, 8, 0)], &[(0, &[1])]);
        assert_eq!(regs[1].base_mask(), vec![0x00, 0xFF]);
    }

    #[test]
    fn aliases_can_be_added_and_removed_but_not_the_own_name() {
        let space = register_space();
        let mut store = RegisterStore::new();
        let r0 = store.add("R0", "", space.address(0), 4, 0, 32, false, 0);

        store.add_alias(r0, "R0");
        assert_eq!(store.get(r0).aliases().count(), 0);

        store.add_alias(r0, "ZERO");
        assert!(store.get(r0).aliases().any(|a| a == "ZERO"));

        store.remove_alias(r0, "ZERO");
        assert_eq!(store.get(r0).aliases().count(), 0);
    }

    #[test]
    fn rename_updates_name_and_drops_matching_alias() {
        let space = register_space();
        let mut store = RegisterStore::new();
        let r0 = store.add("R0", "", space.address(0), 4, 0, 32, false, 0);
        store.add_alias(r0, "R0_NEW");

        store.rename(r0, "R0_NEW");

        assert_eq!(store.get(r0).name(), "R0_NEW");
        assert_eq!(store.get(r0).aliases().count(), 0);
    }

    #[test]
    fn group_can_be_set_and_read() {
        let space = register_space();
        let mut store = RegisterStore::new();
        let r0 = store.add("R0", "", space.address(0), 4, 0, 32, false, 0);
        assert_eq!(store.get(r0).group(), None);

        store.set_group(r0, "general");
        assert_eq!(store.get(r0).group(), Some("general"));
    }

    #[test]
    fn lane_sizes_default_to_none_until_added() {
        let space = register_space();
        let reg = Register::new("V0", "", space.address(0x0), 8, false, Register::TYPE_NONE);
        assert!(!reg.is_vector_register());
        assert_eq!(reg.lane_sizes(), None);
        assert!(!reg.is_valid_lane_size(4));
    }

    #[test]
    fn add_lane_size_marks_register_as_vector_and_records_size() {
        let space = register_space();
        let mut store = RegisterStore::new();
        let v0 = store.add("V0", "", space.address(0), 8, 0, 64, false, 0);

        store.add_lane_size(v0, 4).unwrap();

        let reg = store.get(v0);
        assert!(reg.is_vector_register());
        assert!(reg.is_valid_lane_size(4));
        assert!(!reg.is_valid_lane_size(8));
        assert_eq!(reg.lane_sizes(), Some(vec![4]));
    }

    #[test]
    fn add_lane_size_rejects_registers_with_partial_byte_bit_length() {
        let space = register_space();
        let mut store = RegisterStore::new();
        let field = store.add("CTX_F", "", space.address(0), 4, 0, 5, false, 0);
        assert!(store.add_lane_size(field, 1).is_err());
    }

    #[test]
    fn add_lane_size_rejects_sizes_that_do_not_divide_evenly() {
        let space = register_space();
        let mut store = RegisterStore::new();
        let v0 = store.add("V0", "", space.address(0), 8, 0, 64, false, 0);
        assert!(store.add_lane_size(v0, 3).is_err());
    }

    #[test]
    fn display_shows_register_name() {
        let space = register_space();
        let reg = Register::new("R0", "", space.address(0x0), 4, false, Register::TYPE_NONE);
        assert_eq!(reg.to_string(), "R0");
    }

    #[test]
    fn register_handles_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Register>();
        assert_send_sync::<RegisterStore>();
        assert_send_sync::<RegisterId>();
    }
}
