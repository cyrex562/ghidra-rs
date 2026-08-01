//! Port of `ghidra.program.model.listing.VariableStorage`, promoted from a minimal placeholder
//! trait (see `STUBS.tsv`) to its real port because it was selected as a dependency-cycle
//! cut-point.
//!
//! The Java class is concrete (not an interface), so this port follows the same shape used
//! elsewhere in this crate for cut-point classes that carry a real algorithm
//! ([`VariableImpl`](crate::program::model::listing::variable_impl::VariableImpl),
//! [`ParameterDefinitionImpl`](crate::program::model::data::parameter_definition_impl::ParameterDefinitionImpl)):
//! the public query API becomes the object-safe [`VariableStorage`] trait (covering both the
//! original placeholder's methods, kept as a compiling superset, and the rest of the Java class's
//! public instance API), while [`check_varnodes`] ports the private validation algorithm as a free
//! function and [`VariableStorageImpl`] is a concrete, fully-validated implementor built from it
//! (mirroring the public `VariableStorage(ProgramArchitecture, ...)` constructor family).
//!
//! Two aspects of the Java class have no faithful Rust equivalent yet and are approximated the
//! same way [`variable_impl`](crate::program::model::listing::variable_impl) already documents
//! this tradeoff for its own storage handling:
//! - `Address.isHashAddress()` has no analogue on the ported
//!   [`Address`](crate::program::model::address::Address) (no `Hash` variant on
//!   [`AddressSpaceType`](crate::program::model::address::AddressSpaceType)), so
//!   [`check_varnodes`] only recognizes memory/register/stack/unique/constant addresses; a
//!   hash-space address (not producible by any code that calls into this port yet) is rejected
//!   the same way an unrecognized space is. [`VariableStorage::is_hash_storage`] therefore stays
//!   defaulted to `false`, matching the pre-existing placeholder default; storage that needs to
//!   report itself as hash-addressed (e.g.
//!   [`HashVariableStorage`](crate::program::seam_stubs::HashVariableStorage)) overrides it
//!   directly instead of deriving it from an address.
//! - `instanceof UnknownRegister` has no runtime-type-based analogue: the ported
//!   [`Language::get_register_at`](crate::program::model::lang::Language::get_register_at)
//!   returns a plain `RegisterRef` with no marker distinguishing
//!   [`UnknownRegister`](crate::program::model::lang::unknown_register::UnknownRegister)-backed
//!   registers from ordinary ones, so [`check_varnodes`] treats any register `Language` resolves
//!   as a real storage register (the Java `!(reg instanceof UnknownRegister)` guard is dropped).
//!
//! The `equals(Object)`/`intersects(VariableStorage)` methods were previously stubbed out to
//! always return `false` (a safe, if imprecise, default while no real class existed to compare
//! against). This port gives them their real algorithm as the trait's default body -- see
//! [`VariableStorage::storage_equals`] and [`VariableStorage::intersects`] -- since every existing
//! implementor already has the varnode-list/flag accessors those algorithms are built from.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::generic::algorithms::crc64::CRC64;
use crate::program::model::address::{Address, AddressFactory, AddressSetView};
use crate::program::model::lang::{ProgramArchitecture, Register, RegisterRef};
use crate::program::model::listing::AutoParameterType;
use crate::program::model::pcode::Varnode;
use crate::program::seam_stubs::VarnodeListStorage;
use crate::program::util::language_translator::LanguageTranslator;
use crate::util::exception::InvalidInputException;

const BAD: &str = "<BAD>";
const UNASSIGNED: &str = "<UNASSIGNED>";
const VOID: &str = "<VOID>";

/// Port of the instance contract of `ghidra.program.model.listing.VariableStorage`.
///
/// Grown from the placeholder stub that predated this port (all pre-existing methods are kept
/// with their original defaults so existing `impl VariableStorage for Foo {}` blocks keep
/// compiling unmodified), then extended to cover the rest of the Java class's public query API.
pub trait VariableStorage {
    /// Stands in for `VariableStorage.isHashStorage()`. See the module docs for why this cannot
    /// be derived from an address the way [`is_unique_storage`](Self::is_unique_storage)/
    /// [`is_constant_storage`](Self::is_constant_storage)/[`is_register_storage`](Self::is_register_storage)
    /// are.
    fn is_hash_storage(&self) -> bool {
        false
    }

    /// Port of `VariableStorage.isMemoryStorage()`.
    fn is_memory_storage(&self) -> bool {
        matches!(self.get_varnodes().as_slice(), [vn] if vn.get_address().is_memory_address())
            && self.get_register().is_none()
    }

    /// Port of `VariableStorage.getFirstVarnode()`.
    fn get_first_varnode(&self) -> Option<Varnode> {
        None
    }

    /// Port of `VariableStorage.intersects(VariableStorage)`: `true` if any storage varnode of
    /// `self` intersects any storage varnode of `other`.
    fn intersects(&self, other: &dyn VariableStorage) -> bool {
        let mine = self.get_varnodes();
        let theirs = other.get_varnodes();
        if mine.is_empty() || theirs.is_empty() {
            return false;
        }
        mine.iter().any(|a| theirs.iter().any(|b| a.intersects(b)))
    }

    /// Port of `VariableStorage.equals(Object)`: two storages are considered equal if they carry
    /// the same auto/forced-indirect/bad/unassigned/void flags and the same ordered varnode list
    /// (per [`compare_to`](Self::compare_to)).
    fn storage_equals(&self, other: &dyn VariableStorage) -> bool {
        if self.is_auto_storage() != other.is_auto_storage() {
            return false;
        }
        if self.is_forced_indirect() != other.is_forced_indirect() {
            return false;
        }
        if self.is_bad_storage() != other.is_bad_storage() {
            return false;
        }
        if self.is_unassigned_storage() != other.is_unassigned_storage() {
            return false;
        }
        if self.is_void_storage() != other.is_void_storage() {
            return false;
        }
        self.compare_to(other) == Ordering::Equal
    }

    /// Port of `VariableStorage.getVarnodes()`. Defaults to the single varnode reported by
    /// [`get_first_varnode`](Self::get_first_varnode) (if any), so pre-existing single-varnode
    /// implementors report a consistent answer without needing to override this.
    fn get_varnodes(&self) -> Vec<Varnode> {
        self.get_first_varnode().into_iter().collect()
    }

    /// Port of `VariableStorage.isValid()`. Kept at its original placeholder default ("has at
    /// least one varnode") for backward compatibility with existing callers (e.g.
    /// `VariableUtilities.checkStorage`, which relies on this to let `BAD`/`UNASSIGNED`-style
    /// empty placeholders pass through unchanged) rather than switching to the Java class's exact
    /// `!isUnassignedStorage() && !isBadStorage()` (which treats `VOID_STORAGE`, despite its
    /// empty varnode list, as valid). [`VariableStorageImpl`] and the `BAD`/`UNASSIGNED`/`VOID`
    /// marker types override this directly with the exact Java semantics for themselves.
    fn is_valid(&self) -> bool {
        !self.get_varnodes().is_empty()
    }

    /// Port of `VariableStorage.size()`: the total byte length across all storage varnodes.
    fn size(&self) -> i32 {
        self.get_varnodes().iter().map(Varnode::get_size).sum()
    }

    /// Port of `VariableStorage.isUniqueStorage()`: `true` if this is a single varnode located
    /// in the unique (temporary) address space.
    fn is_unique_storage(&self) -> bool {
        matches!(self.get_varnodes().as_slice(), [vn] if vn.is_unique())
    }

    /// Port of `VariableStorage.isConstantStorage()`: `true` if this is a single varnode located
    /// in the constant address space.
    fn is_constant_storage(&self) -> bool {
        matches!(self.get_varnodes().as_slice(), [vn] if vn.is_constant())
    }

    /// Port of `VariableStorage.isRegisterStorage()`: `true` if this is a single varnode located
    /// in the register address space.
    fn is_register_storage(&self) -> bool {
        matches!(self.get_varnodes().as_slice(), [vn] if vn.is_register())
    }

    /// Port of `VariableStorage.getRegister()`: the first storage register, if any.
    fn get_register(&self) -> Option<RegisterRef> {
        None
    }

    /// Port of `VariableStorage.getRegisters()`: all storage registers associated with this
    /// register or compound storage. Defaults to a single-element list wrapping
    /// [`get_register`](Self::get_register), which is exact for the common single-register case.
    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        self.get_register().map(|r| vec![r])
    }

    /// Port of `VariableStorage.getAutoParameterType()`. Defaults to `None` (not an
    /// auto-parameter).
    fn get_auto_parameter_type(&self) -> Option<AutoParameterType> {
        None
    }

    /// Port of `VariableStorage.isForcedIndirect()`. Defaults to `false`.
    fn is_forced_indirect(&self) -> bool {
        false
    }

    /// Port of `VariableStorage.isAutoStorage()`. Defaults to `false`.
    fn is_auto_storage(&self) -> bool {
        false
    }

    /// Port of `VariableStorage.isStackStorage()`: `true` if this is a single varnode located in
    /// the stack address space.
    fn is_stack_storage(&self) -> bool {
        matches!(self.get_varnodes().as_slice(), [vn] if vn.get_address().is_stack_address())
    }

    /// Port of `VariableStorage.hasStackStorage()`: `true` if the first or last varnode of
    /// simple or compound storage is a stack varnode.
    fn has_stack_storage(&self) -> bool {
        let varnodes = self.get_varnodes();
        match varnodes.as_slice() {
            [] => false,
            [only] => only.get_address().is_stack_address(),
            [first, .., last] => {
                first.get_address().is_stack_address() || last.get_address().is_stack_address()
            }
        }
    }

    /// Port of `VariableStorage.getStackOffset()`: the raw offset of the first storage varnode's
    /// address. Only meaningful when [`is_stack_storage`](Self::is_stack_storage) is `true`.
    fn get_stack_offset(&self) -> i32 {
        self.get_first_varnode().map(|vn| vn.get_offset() as i32).unwrap_or(0)
    }

    /// Stands in for the `new VariableStorage(ProgramArchitecture, Varnode...)` family of
    /// constructors used throughout `VariableUtilities` to build resized/derived storage.
    /// Defaults to a fresh [`VarnodeListStorage`] backed by `varnodes`, which is enough for
    /// query-only callers; storage backed by a real database record should override this to
    /// persist the new varnode list instead.
    fn with_varnodes(&self, varnodes: Vec<Varnode>) -> Box<dyn VariableStorage> {
        Box::new(VarnodeListStorage(varnodes))
    }

    /// Port of `VariableStorage.getProgramArchitecture()`.
    fn get_program_architecture(&self) -> Option<Arc<dyn ProgramArchitecture>> {
        None
    }

    /// Port of `VariableStorage.getVarnodeCount()`.
    fn get_varnode_count(&self) -> i32 {
        self.get_varnodes().len() as i32
    }

    /// Port of `VariableStorage.getLastVarnode()`.
    fn get_last_varnode(&self) -> Option<Varnode> {
        self.get_varnodes().last().cloned()
    }

    /// Port of `VariableStorage.isCompoundStorage()`: `true` if storage consists of two or more
    /// storage varnodes.
    fn is_compound_storage(&self) -> bool {
        self.get_varnodes().len() > 1
    }

    /// Port of `VariableStorage.isBadStorage()`: identifies storage which is no longer valid
    /// (analogous to `this == BAD_STORAGE` in Java, which has no direct Rust equivalent).
    /// Defaults to `false`; overridden by the [`BadStorage`] marker type.
    fn is_bad_storage(&self) -> bool {
        false
    }

    /// Port of `VariableStorage.isUnassignedStorage()`: identifies storage which has not been
    /// assigned. Defaults to `false`; overridden by the [`UnassignedStorage`] marker type.
    fn is_unassigned_storage(&self) -> bool {
        false
    }

    /// Port of `VariableStorage.isVoidStorage()`: identifies storage which corresponds to the
    /// `VOID_STORAGE` singleton. Defaults to `false`; overridden by the [`VoidStorage`] marker
    /// type.
    fn is_void_storage(&self) -> bool {
        false
    }

    /// Port of `VariableStorage.getMinAddress()`: the minimum address corresponding to the first
    /// varnode of this storage, or `None` for special empty storage.
    fn get_min_address(&self) -> Option<Address> {
        self.get_first_varnode().map(|vn| vn.get_address().clone())
    }

    /// Port of `VariableStorage.contains(Address)`.
    fn contains_address(&self, address: &Address) -> bool {
        self.get_varnodes().iter().any(|vn| vn.contains(address))
    }

    /// Port of `VariableStorage.intersects(AddressSetView)`.
    fn intersects_address_set(&self, set: &dyn AddressSetView) -> bool {
        if set.is_empty() {
            return false;
        }
        self.get_varnodes().iter().any(|vn| {
            let start = vn.get_address();
            let end = start.add(vn.get_size() as i64 - 1).unwrap_or_else(|_| start.clone());
            set.intersects_range(start, &end)
        })
    }

    /// Port of `VariableStorage.intersects(Register)`.
    fn intersects_register(&self, reg: &Register) -> bool {
        let reg_varnode = Varnode::new(reg.address().clone(), reg.minimum_byte_size());
        self.get_varnodes().iter().any(|vn| vn.intersects(&reg_varnode))
    }

    /// Port of `VariableStorage.getSerializationString()`.
    fn get_serialization_string(&self) -> String {
        if self.is_bad_storage() {
            BAD.to_string()
        } else if self.is_unassigned_storage() {
            UNASSIGNED.to_string()
        } else if self.is_void_storage() {
            VOID.to_string()
        } else {
            serialization_string(&self.get_varnodes())
        }
    }

    /// Port of `VariableStorage.getLongHash()`.
    fn get_long_hash(&self) -> i64 {
        let mut crc = CRC64::new();
        crc.update(self.get_serialization_string().as_bytes());
        crc.finish() as i64
    }

    /// Port of `VariableStorage.compareTo(VariableStorage)`.
    fn compare_to(&self, other: &dyn VariableStorage) -> Ordering {
        let my_precedence = precedence(self);
        let other_precedence = precedence(other);
        let diff = my_precedence.cmp(&other_precedence);
        if diff != Ordering::Equal || my_precedence != PRECEDENCE_MAPPED {
            return diff;
        }
        let mine = self.get_varnodes();
        let theirs = other.get_varnodes();
        let n = mine.len().min(theirs.len());
        for i in 0..n {
            let addr_cmp = mine[i].get_address().cmp(theirs[i].get_address());
            if addr_cmp != Ordering::Equal {
                return addr_cmp;
            }
            let size_cmp = mine[i].get_size().cmp(&theirs[i].get_size());
            if size_cmp != Ordering::Equal {
                return size_cmp;
            }
        }
        mine.len().cmp(&theirs.len())
    }
}

const PRECEDENCE_MAPPED: i32 = 1;
const PRECEDENCE_UNMAPPED: i32 = 2;
const PRECEDENCE_BAD: i32 = 3;

/// Port of the private static `VariableStorage.getPrecedence(VariableStorage)`.
fn precedence<S: VariableStorage + ?Sized>(storage: &S) -> i32 {
    if storage.is_unassigned_storage() {
        return PRECEDENCE_UNMAPPED;
    }
    if !storage.get_varnodes().is_empty() {
        return PRECEDENCE_MAPPED;
    }
    PRECEDENCE_BAD
}

/// Port of the static `VariableStorage.getSerializationString(Varnode...)`.
pub fn serialization_string(varnodes: &[Varnode]) -> String {
    varnodes
        .iter()
        .map(|v| format!("{}:{}", v.get_address().format(true, 1), v.get_size()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Port of the static `VariableStorage.getVarnodes(AddressFactory, String)`: parse a storage
/// serialization string (see [`serialization_string`]) into a varnode list. Returns `Ok(None)`
/// where the Java method returns `null` (invalid/`BAD` serialization recognized without error).
pub fn parse_varnode_list(
    addr_factory: &dyn AddressFactory,
    serialization: &str,
) -> Result<Option<Vec<Varnode>>, InvalidInputException> {
    if serialization == BAD {
        return Ok(None);
    }
    let mut list = Vec::new();
    for piece in serialization.split(',') {
        let index = piece.rfind(':');
        let Some(index) = index.filter(|&i| i > 0) else {
            return Err(InvalidInputException::with_message(format!(
                "Invalid varnode serialization: '{serialization}'"
            )));
        };
        let addr_str = &piece[..index];
        let size_str = &piece[index + 1..];
        let Some(addr) = addr_factory.get_address(addr_str) else {
            return Err(InvalidInputException::with_message(format!(
                "Invalid varnode serialization: '{serialization}'"
            )));
        };
        let size: i32 = size_str.parse().map_err(|_| {
            InvalidInputException::with_message(format!(
                "Invalid varnode serialization: '{serialization}'"
            ))
        })?;
        list.push(Varnode::new(addr, size));
    }
    Ok(Some(list))
}

/// Port of the static `VariableStorage.deserialize(ProgramArchitecture, String)`.
pub fn deserialize(
    program_arch: Arc<dyn ProgramArchitecture>,
    serialization: Option<&str>,
) -> Result<Box<dyn VariableStorage>, InvalidInputException> {
    let Some(serialization) = serialization else {
        return Ok(Box::new(UnassignedStorage));
    };
    if serialization == UNASSIGNED {
        return Ok(Box::new(UnassignedStorage));
    }
    if serialization == VOID {
        return Ok(Box::new(VoidStorage));
    }
    if serialization == BAD {
        return Ok(Box::new(BadStorage));
    }
    match parse_varnode_list(program_arch.get_address_factory().as_ref(), serialization) {
        Ok(Some(varnodes)) => match VariableStorageImpl::new(program_arch, varnodes) {
            Ok(storage) => Ok(Box::new(storage)),
            Err(_) => Ok(Box::new(BadStorage)),
        },
        Ok(None) | Err(_) => Ok(Box::new(BadStorage)),
    }
}

/// Port of the static `VariableStorage.translateSerialization(LanguageTranslator, String)`.
/// Register-space offsets are remapped via the translator; other spaces (and stack/special
/// encodings) are passed through unchanged, mirroring the Java method's "leave it alone" fallback
/// for anything that is not a plain register-space varnode.
pub fn translate_serialization(
    translator: &dyn LanguageTranslator,
    serialization: Option<&str>,
) -> Result<Option<String>, InvalidInputException> {
    let Some(serialization) = serialization else {
        return Ok(None);
    };
    if serialization == UNASSIGNED {
        return Ok(None);
    }
    if serialization == VOID {
        return Ok(Some(VOID.to_string()));
    }
    if serialization == BAD {
        return Ok(Some(BAD.to_string()));
    }

    let mut pieces = Vec::new();
    for piece in serialization.split(',') {
        let index = piece.rfind(':');
        let Some(index) = index.filter(|&i| i > 0) else {
            return Err(InvalidInputException::with_message(format!(
                "Invalid varnode serialization: '{serialization}'"
            )));
        };
        let addr_str = &piece[..index];
        let size_str = &piece[index + 1..];

        if let Some(space_index) = addr_str.find(':') {
            let space_name = &addr_str[..space_index];
            let offset_str = &addr_str[space_index + 1..];
            if let Some(new_space) = translator.get_new_address_space(space_name) {
                let mut offset_str = offset_str.to_string();
                if new_space.space_type() == crate::program::model::address::AddressSpaceType::Register {
                    if let (Ok(offset), Ok(size)) =
                        (u64::from_str_radix(offset_str.trim_start_matches("0x"), 16), size_str.parse::<i32>())
                    {
                        let old_reg_addr = translator.get_old_language().get_address_factory().get_register_space();
                        if let Some(old_reg_space) = old_reg_addr {
                            let old_addr = old_reg_space.address(offset as i64);
                            if let Some(new_offset) =
                                translate_register_varnode_offset(&old_addr, size, translator)
                            {
                                offset_str = new_offset;
                            }
                        }
                    }
                }
                pieces.push(format!("{}:{}:{}", new_space.name(), offset_str, size_str));
                continue;
            }
        }
        // Space not found (overlay) or no space prefix (Stack/special encoding): leave unchanged.
        pieces.push(piece.to_string());
    }

    Ok(Some(pieces.join(",")))
}

/// Port of the private static `VariableStorage.translateRegisterVarnodeOffset`. Returns the new
/// register offset (as a hex string, matching `Long.toHexString`) within the same space as
/// `old_reg_addr`, or `None` if translation failed.
///
/// See the module docs: the `instanceof UnknownRegister` guard the Java method also applies has
/// no analogue here and is dropped.
fn translate_register_varnode_offset(
    old_reg_addr: &Address,
    varnode_size: i32,
    translator: &dyn LanguageTranslator,
) -> Option<String> {
    let offset = old_reg_addr.offset();
    let old_reg = translator
        .get_old_register(old_reg_addr, varnode_size)
        .or_else(|| translator.get_old_register_containing(old_reg_addr))?;
    let new_reg = translator.get_new_register(&old_reg)?;
    let old_reg = old_reg.borrow();
    let new_reg_borrow = new_reg.borrow();
    let orig_byte_shift = offset - old_reg.offset() as i64;
    let mut new_offset = new_reg_borrow.offset() as i64 + orig_byte_shift;
    if new_reg_borrow.is_big_endian() {
        let reg_size_diff = new_reg_borrow.minimum_byte_size() - old_reg.minimum_byte_size();
        new_offset += reg_size_diff as i64;
        if new_offset < new_reg_borrow.offset() as i64 {
            return None;
        }
    } else if (orig_byte_shift + varnode_size as i64) > new_reg_borrow.minimum_byte_size() as i64 {
        return None;
    }
    Some(format!("{new_offset:x}"))
}

/// Port of the private `VariableStorage.checkVarnodes()`, extracted as a free function since it
/// is also reused to back each public `VariableStorage(ProgramArchitecture, ...)` constructor
/// overload via [`VariableStorageImpl::new`]. Returns the register cache and total size Java
/// computes as a side effect of validation.
pub fn check_varnodes(
    program_arch: &dyn ProgramArchitecture,
    varnodes: &[Varnode],
) -> Result<(Vec<RegisterRef>, i32), InvalidInputException> {
    if varnodes.is_empty() {
        return Err(InvalidInputException::with_message(
            "A minimum of one varnode must be specified".to_string(),
        ));
    }

    let addr_factory = program_arch.get_address_factory();
    let language = program_arch.get_language();
    let big_endian = language.is_big_endian();

    let mut size = 0i32;
    let mut registers = Vec::new();

    for (i, varnode) in varnodes.iter().enumerate() {
        if varnode.get_size() <= 0 {
            return Err(InvalidInputException::with_message(format!(
                "Unsupported varnode size: {}",
                varnode.get_size()
            )));
        }

        let mut is_register = false;
        let storage_addr = varnode.get_address();
        if storage_addr.is_unique_address() || storage_addr.is_constant_address() {
            if varnodes.len() != 1 {
                return Err(InvalidInputException::with_message(
                    "Unique and Constant storage may only use a single varnode".to_string(),
                ));
            }
        } else {
            let space = addr_factory.get_address_space_by_id(varnode.get_space_id());
            if space.as_deref() != Some(storage_addr.space().as_ref()) {
                return Err(InvalidInputException::with_message(format!(
                    "Invalid varnode address for specified program: {}",
                    storage_addr.format(true, 1)
                )));
            }
        }

        if !storage_addr.is_stack_address() {
            if let Some(reg) = language.get_register_at(storage_addr, varnode.get_size()) {
                is_register = true;
                registers.push(reg);
            }
        } else {
            let stack_offset = storage_addr.offset();
            if stack_offset < 0 && -stack_offset < varnode.get_size() as i64 {
                return Err(InvalidInputException::with_message(format!(
                    "Stack varnode violates stack frame constraints (stack offset={}, size={})",
                    stack_offset,
                    varnode.get_size()
                )));
            }
        }

        if big_endian {
            if i < varnodes.len() - 1 && !is_register {
                return Err(InvalidInputException::with_message(
                    "Compound storage must use registers except for last BE varnode".to_string(),
                ));
            }
        } else if i > 0 && !is_register {
            return Err(InvalidInputException::with_message(
                "Compound storage must use registers except for first LE varnode".to_string(),
            ));
        }

        size += varnode.get_size();
    }

    for i in 0..varnodes.len() {
        for j in (i + 1)..varnodes.len() {
            if varnodes[i].intersects(&varnodes[j]) {
                return Err(InvalidInputException::with_message(
                    "One or more conflicting storage varnodes".to_string(),
                ));
            }
        }
    }

    Ok((registers, size))
}

/// Concrete, fully-validated [`VariableStorage`] implementor. Port of the public,
/// non-placeholder instance state of `ghidra.program.model.listing.VariableStorage` (the
/// `varnodes`/`programArch`/`registers`/`size` fields), constructed through
/// [`check_varnodes`]-backed factory methods mirroring the Java constructor family.
#[derive(Clone)]
pub struct VariableStorageImpl {
    program_arch: Arc<dyn ProgramArchitecture>,
    varnodes: Vec<Varnode>,
    registers: Vec<RegisterRef>,
    size: i32,
}

impl std::fmt::Debug for VariableStorageImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VariableStorageImpl")
            .field("varnodes", &self.varnodes)
            .field("register_count", &self.registers.len())
            .field("size", &self.size)
            .finish()
    }
}

impl VariableStorageImpl {
    /// Port of `VariableStorage(ProgramArchitecture, Varnode...)`.
    pub fn new(
        program_arch: Arc<dyn ProgramArchitecture>,
        varnodes: Vec<Varnode>,
    ) -> Result<Self, InvalidInputException> {
        let (registers, size) = check_varnodes(program_arch.as_ref(), &varnodes)?;
        Ok(VariableStorageImpl { program_arch, varnodes, registers, size })
    }

    /// Port of `VariableStorage(ProgramArchitecture, Register...)`.
    pub fn from_registers(
        program_arch: Arc<dyn ProgramArchitecture>,
        registers: &[RegisterRef],
    ) -> Result<Self, InvalidInputException> {
        let varnodes = registers
            .iter()
            .map(|r| {
                let reg = r.borrow();
                Varnode::new(reg.address().clone(), reg.minimum_byte_size())
            })
            .collect();
        Self::new(program_arch, varnodes)
    }

    /// Port of `VariableStorage(ProgramArchitecture, int stackOffset, int size)`.
    pub fn from_stack(
        program_arch: Arc<dyn ProgramArchitecture>,
        stack_offset: i32,
        size: i32,
    ) -> Result<Self, InvalidInputException> {
        let stack_space = program_arch.get_address_factory().get_stack_space().ok_or_else(|| {
            InvalidInputException::with_message(
                "program architecture has no stack address space".to_string(),
            )
        })?;
        let addr = stack_space.address(stack_offset as i64);
        Self::new(program_arch, vec![Varnode::new(addr, size)])
    }

    /// Port of `VariableStorage(ProgramArchitecture, Address, int)`.
    pub fn from_address(
        program_arch: Arc<dyn ProgramArchitecture>,
        address: Address,
        size: i32,
    ) -> Result<Self, InvalidInputException> {
        Self::new(program_arch, vec![Varnode::new(address, size)])
    }

    /// Port of `VariableStorage.clone(ProgramArchitecture)`.
    pub fn clone_for_architecture(
        &self,
        new_program_arch: Arc<dyn ProgramArchitecture>,
    ) -> Result<Self, InvalidInputException> {
        Self::new(new_program_arch, self.varnodes.clone())
    }
}

impl VariableStorage for VariableStorageImpl {
    fn get_first_varnode(&self) -> Option<Varnode> {
        self.varnodes.first().cloned()
    }

    fn get_varnodes(&self) -> Vec<Varnode> {
        self.varnodes.clone()
    }

    fn size(&self) -> i32 {
        self.size
    }

    fn is_register_storage(&self) -> bool {
        self.varnodes.len() == 1 && !self.registers.is_empty()
    }

    fn get_register(&self) -> Option<RegisterRef> {
        self.registers.first().cloned()
    }

    fn get_registers(&self) -> Option<Vec<RegisterRef>> {
        if self.registers.is_empty() {
            None
        } else {
            Some(self.registers.clone())
        }
    }

    fn get_program_architecture(&self) -> Option<Arc<dyn ProgramArchitecture>> {
        Some(self.program_arch.clone())
    }

    fn with_varnodes(&self, varnodes: Vec<Varnode>) -> Box<dyn VariableStorage> {
        match VariableStorageImpl::new(self.program_arch.clone(), varnodes.clone()) {
            Ok(storage) => Box::new(storage),
            Err(_) => Box::new(VarnodeListStorage(varnodes)),
        }
    }
}

/// Port of the `VariableStorage.BAD_STORAGE` singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BadStorage;

impl VariableStorage for BadStorage {
    fn is_bad_storage(&self) -> bool {
        true
    }

    fn is_valid(&self) -> bool {
        false
    }
}

/// Port of the `VariableStorage.UNASSIGNED_STORAGE` singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnassignedStorage;

impl VariableStorage for UnassignedStorage {
    fn is_unassigned_storage(&self) -> bool {
        true
    }

    fn is_valid(&self) -> bool {
        false
    }
}

/// Port of the `VariableStorage.VOID_STORAGE` singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VoidStorage;

impl VariableStorage for VoidStorage {
    fn is_void_storage(&self) -> bool {
        true
    }

    fn is_valid(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSet, AddressSpace, AddressSpaceType};
    use crate::program::model::lang::compiler_spec::CompilerSpec;
    use crate::program::model::lang::language::Language;
    use crate::program::model::lang::register::Register;
    use std::collections::HashSet;

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn register_space() -> Arc<AddressSpace> {
        AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 0)
    }

    fn stack_space() -> Arc<AddressSpace> {
        AddressSpace::new("stack", 32, 1, AddressSpaceType::Stack, 0)
    }

    struct MockLanguage {
        register_space: Arc<AddressSpace>,
    }

    impl Language for MockLanguage {
        fn get_language_id(&self) -> crate::program::model::lang::language_id::LanguageID {
            crate::program::model::lang::language_id::LanguageID::new("x86:LE:32:default").unwrap()
        }
        fn get_language_description(
            &self,
        ) -> Box<dyn crate::program::model::lang::language_description::LanguageDescription> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_parallel_instruction_helper(
            &self,
        ) -> Option<Box<dyn crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper>>
        {
            None
        }
        fn get_processor(&self) -> Box<dyn crate::program::seam_stubs::Processor> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_version(&self) -> i32 {
            1
        }
        fn get_minor_version(&self) -> i32 {
            0
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn get_default_data_space(&self) -> Arc<AddressSpace> {
            ram_space()
        }
        fn is_big_endian(&self) -> bool {
            false
        }
        fn get_instruction_alignment(&self) -> i32 {
            1
        }
        fn supports_pcode(&self) -> bool {
            true
        }
        fn is_volatile(&self, _addr: &Address) -> bool {
            false
        }
        fn parse(
            &self,
            _buf: &dyn crate::program::seam_stubs::MemBuffer,
            _context: &mut dyn crate::program::model::lang::processor_context::ProcessorContext,
            _in_delay_slot: bool,
        ) -> Result<
            Box<dyn crate::program::model::lang::instruction_prototype::InstructionPrototype>,
            crate::program::model::lang::language::ParseError,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_number_of_user_defined_op_names(&self) -> i32 {
            0
        }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> {
            None
        }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_in_space(
            &self,
            _addrspc: &Arc<AddressSpace>,
            _offset: i64,
            _size: i32,
        ) -> Option<RegisterRef> {
            None
        }
        fn get_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_names(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> {
            None
        }
        fn get_register_at(&self, addr: &Address, size: i32) -> Option<RegisterRef> {
            if addr.space().as_ref() != self.register_space.as_ref() {
                return None;
            }
            Some(Register::new("r0", "mock register", addr.clone(), size, false, 0))
        }
        fn get_program_counter(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            None
        }
        fn get_context_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_default_memory_blocks(
            &self,
        ) -> Vec<Box<dyn crate::app::plugin::processors::generic::MemoryBlockDefinition>> {
            Vec::new()
        }
        fn get_default_symbols(&self) -> Vec<Box<dyn crate::program::seam_stubs::AddressLabelInfo>> {
            Vec::new()
        }
        fn get_segmented_space(&self) -> String {
            String::new()
        }
        fn get_volatile_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn apply_context_settings(
            &self,
            _ctx: &mut dyn crate::program::model::listing::default_program_context::DefaultProgramContext,
        ) {
        }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> {
            Ok(())
        }
        fn get_compatible_compiler_spec_descriptions(
            &self,
        ) -> Vec<Box<dyn crate::program::model::lang::compiler_spec_description::CompilerSpecDescription>>
        {
            Vec::new()
        }
        fn get_compiler_spec_by_id(
            &self,
            _compiler_spec_id: &crate::program::model::lang::compiler_spec_id::CompilerSpecID,
        ) -> Result<
            Box<dyn CompilerSpec>,
            crate::program::model::lang::compiler_spec_not_found_exception::CompilerSpecNotFoundException,
        > {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
        fn has_property(&self, _key: &str) -> bool {
            false
        }
        fn get_property_as_int(&self, _key: &str, default_int: i32) -> i32 {
            default_int
        }
        fn get_property_as_boolean(&self, _key: &str, default_boolean: bool) -> bool {
            default_boolean
        }
        fn get_property_or(&self, _key: &str, default_string: &str) -> String {
            default_string.to_string()
        }
        fn get_property(&self, _key: &str) -> Option<String> {
            None
        }
        fn get_property_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn has_manual(&self) -> bool {
            false
        }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> {
            None
        }
        fn get_manual_instruction_mnemonic_keys(&self) -> HashSet<String> {
            HashSet::new()
        }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> {
            None
        }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> {
            Vec::new()
        }
        fn get_register_addresses(&self) -> Box<dyn crate::program::model::address::AddressSetView> {
            unimplemented!("not exercised by this smoke test")
        }
        fn get_maximum_instruction_length(&self) -> Option<i32> {
            None
        }
    }

    struct MockAddressFactory {
        ram_space: Arc<AddressSpace>,
        register_space: Arc<AddressSpace>,
        stack_space: Arc<AddressSpace>,
    }

    impl AddressFactory for MockAddressFactory {
        fn get_address(&self, addr_string: &str) -> Option<Address> {
            let (space_name, offset_str) = addr_string.split_once(':')?;
            let offset = i64::from_str_radix(offset_str, 16).ok()?;
            let space = self.get_address_space_by_name(space_name)?;
            Some(space.address(offset))
        }
        fn get_all_addresses_case(&self, _addr_string: &str, _case_sensitive: bool) -> Vec<Address> {
            Vec::new()
        }
        fn get_default_address_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.ram_space.clone())
        }
        fn get_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            vec![self.ram_space.clone(), self.register_space.clone(), self.stack_space.clone()]
        }
        fn get_address_space_by_name(&self, name: &str) -> Option<Arc<AddressSpace>> {
            self.get_address_spaces().into_iter().find(|s| s.name() == name)
        }
        fn get_address_space_by_id(&self, id: i32) -> Option<Arc<AddressSpace>> {
            self.get_address_spaces().into_iter().find(|s| s.space_id() == id)
        }
        fn get_all_address_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }
        fn get_num_address_spaces(&self) -> usize {
            3
        }
        fn is_valid_address(&self, _address: &Address) -> bool {
            true
        }
        fn get_index(&self, _address: &Address) -> i64 {
            0
        }
        fn get_physical_space(&self, space: &Arc<AddressSpace>) -> Arc<AddressSpace> {
            space.clone()
        }
        fn get_physical_spaces(&self) -> Vec<Arc<AddressSpace>> {
            self.get_address_spaces()
        }
        fn address(&self, _space_id: i32, _offset: i64) -> Option<Address> {
            None
        }
        fn get_stack_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.stack_space.clone())
        }
        fn get_constant_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_unique_space(&self) -> Option<Arc<AddressSpace>> {
            None
        }
        fn get_register_space(&self) -> Option<Arc<AddressSpace>> {
            Some(self.register_space.clone())
        }
        fn get_constant_address(&self, _offset: i64) -> Option<Address> {
            None
        }
        fn get_address_set_range(&self, _min: &Address, _max: &Address) -> AddressSet {
            AddressSet::new()
        }
        fn get_address_set(&self) -> AddressSet {
            AddressSet::new()
        }
        fn old_get_address_from_long(&self, _value: i64) -> Option<Address> {
            None
        }
        fn has_multiple_memory_spaces(&self) -> bool {
            true
        }
    }

    struct MockProgramArchitecture {
        address_factory: Arc<MockAddressFactoryHandle>,
    }

    struct MockAddressFactoryHandle(MockAddressFactory);

    impl ProgramArchitecture for MockProgramArchitecture {
        fn get_language(&self) -> Box<dyn Language> {
            Box::new(MockLanguage { register_space: self.address_factory.0.register_space.clone() })
        }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> {
            Box::new(MockAddressFactory {
                ram_space: self.address_factory.0.ram_space.clone(),
                register_space: self.address_factory.0.register_space.clone(),
                stack_space: self.address_factory.0.stack_space.clone(),
            })
        }
        fn get_compiler_spec(&self) -> Box<dyn CompilerSpec> {
            unimplemented!("not exercised by this smoke test")
        }
    }

    fn mock_program_arch() -> Arc<dyn ProgramArchitecture> {
        Arc::new(MockProgramArchitecture {
            address_factory: Arc::new(MockAddressFactoryHandle(MockAddressFactory {
                ram_space: ram_space(),
                register_space: register_space(),
                stack_space: stack_space(),
            })),
        })
    }

    #[test]
    fn new_validates_register_varnode_and_reports_register_storage() {
        let arch = mock_program_arch();
        let varnode = Varnode::new(register_space().address(0x10), 4);
        let storage = VariableStorageImpl::new(arch, vec![varnode]).expect("valid register varnode");
        assert!(storage.is_register_storage());
        assert!(storage.get_register().is_some());
        assert_eq!(storage.size(), 4);
        assert!(storage.is_valid());
    }

    #[test]
    fn new_rejects_zero_size_varnode() {
        let arch = mock_program_arch();
        let varnode = Varnode::new(ram_space().address(0x10), 0);
        let err = VariableStorageImpl::new(arch, vec![varnode]).unwrap_err();
        assert!(err.0.contains("Unsupported varnode size"));
    }

    #[test]
    fn new_rejects_le_compound_storage_without_leading_register() {
        let arch = mock_program_arch();
        // Little-endian: only the *first* varnode of compound storage may be non-register.
        let varnodes =
            vec![Varnode::new(ram_space().address(0x10), 4), Varnode::new(ram_space().address(0x20), 4)];
        let err = VariableStorageImpl::new(arch, varnodes).unwrap_err();
        assert!(err.0.contains("Compound storage must use registers"));
    }

    #[test]
    fn with_varnodes_round_trips_through_check_varnodes() {
        let arch = mock_program_arch();
        let storage =
            VariableStorageImpl::new(arch, vec![Varnode::new(register_space().address(0x10), 4)]).unwrap();
        let resized = storage.with_varnodes(vec![Varnode::new(register_space().address(0x10), 2)]);
        assert_eq!(resized.size(), 2);
        assert!(resized.is_register_storage());
    }

    #[test]
    fn compare_to_orders_by_precedence_then_varnodes() {
        let arch = mock_program_arch();
        let a = VariableStorageImpl::new(arch.clone(), vec![Varnode::new(ram_space().address(0x10), 4)])
            .unwrap();
        let b = VariableStorageImpl::new(arch, vec![Varnode::new(ram_space().address(0x20), 4)]).unwrap();
        assert_eq!(a.compare_to(&b), Ordering::Less);
        assert_eq!(b.compare_to(&a), Ordering::Greater);
        assert_eq!(a.compare_to(&a), Ordering::Equal);

        let unassigned = UnassignedStorage;
        assert_eq!(a.compare_to(&unassigned), Ordering::Less);
        assert_eq!(unassigned.compare_to(&a), Ordering::Greater);
    }

    #[test]
    fn storage_equals_matches_compare_to_and_flags() {
        let arch = mock_program_arch();
        let a = VariableStorageImpl::new(arch.clone(), vec![Varnode::new(ram_space().address(0x10), 4)])
            .unwrap();
        let b = VariableStorageImpl::new(arch.clone(), vec![Varnode::new(ram_space().address(0x10), 4)])
            .unwrap();
        let c = VariableStorageImpl::new(arch, vec![Varnode::new(ram_space().address(0x20), 4)]).unwrap();
        assert!(a.storage_equals(&b));
        assert!(!a.storage_equals(&c));
    }

    #[test]
    fn intersects_detects_overlapping_varnodes() {
        let arch = mock_program_arch();
        let a = VariableStorageImpl::new(arch.clone(), vec![Varnode::new(ram_space().address(0x10), 4)])
            .unwrap();
        let overlapping =
            VariableStorageImpl::new(arch.clone(), vec![Varnode::new(ram_space().address(0x12), 4)])
                .unwrap();
        let disjoint =
            VariableStorageImpl::new(arch, vec![Varnode::new(ram_space().address(0x100), 4)]).unwrap();
        assert!(a.intersects(&overlapping));
        assert!(!a.intersects(&disjoint));
    }

    #[test]
    fn serialization_round_trips_through_free_functions() {
        let arch = mock_program_arch();
        let storage = VariableStorageImpl::new(arch.clone(), vec![Varnode::new(ram_space().address(0x10), 4)])
            .unwrap();
        let serialized = storage.get_serialization_string();
        let factory = arch.get_address_factory();
        let parsed = parse_varnode_list(factory.as_ref(), &serialized).unwrap().unwrap();
        assert_eq!(parsed, storage.get_varnodes());

        let round_tripped = deserialize(arch, Some(&serialized)).unwrap();
        assert!(round_tripped.storage_equals(&storage));
    }

    #[test]
    fn bad_unassigned_void_singletons_have_expected_flags() {
        assert!(BadStorage.is_bad_storage());
        assert!(!BadStorage.is_valid());
        assert!(UnassignedStorage.is_unassigned_storage());
        assert!(!UnassignedStorage.is_valid());
        assert!(VoidStorage.is_void_storage());
        assert!(VoidStorage.is_valid());
        assert_eq!(BadStorage.get_serialization_string(), BAD);
        assert_eq!(UnassignedStorage.get_serialization_string(), UNASSIGNED);
        assert_eq!(VoidStorage.get_serialization_string(), VOID);
    }

    #[test]
    fn trait_object_usage_is_object_safe() {
        let arch = mock_program_arch();
        let storage: Box<dyn VariableStorage> =
            Box::new(VariableStorageImpl::new(arch, vec![Varnode::new(ram_space().address(0x10), 4)]).unwrap());
        assert!(storage.is_valid());
        assert!(!storage.is_stack_storage());
        assert_eq!(storage.get_varnode_count(), 1);
    }
}
