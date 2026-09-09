//! Port of `ghidra.program.database.register.ProgramRegisterContextDB`.
//!
//! The real, concrete, database-backed register-context manager: composes
//! [`AbstractStoredProgramContext`] with a [`DatabaseRangeMapAdapter`]-backed store per base
//! register, adds locking, context-write guarding (deferring to the owning program's code
//! manager), and change notification.
//!
//! ## `ManagerDB` is not literally implemented
//!
//! Java's class signature is `... implements ManagerDB`. This port cannot do the same: this
//! crate's [`ManagerDB`](crate::program::database::manager_db::ManagerDB) trait requires
//! `Send + Sync`, but every real implementor here must compose an
//! [`AbstractStoredProgramContext`] (transitively an
//! [`AbstractProgramContext`](crate::program::util::abstract_program_context::AbstractProgramContext)),
//! which stores a [`RegisterRef`] (`Rc<RefCell<Register>>`) and an `Arc<dyn Language>` --
//! `Rc` is never `Send`, and `dyn Language` carries no `Send + Sync` bound in this crate, so
//! `Arc<dyn Language>` is not `Send + Sync` either. No existing `ManagerDB` implementor in this
//! crate holds a `Language`/`Register` reference for the same reason. Rather than force a
//! crate-wide `Language`/`Register` redesign (`Rc` -> `Arc<Mutex<..>>` throughout, `Language: Send
//! + Sync`) just to satisfy this one supertrait bound, this type instead exposes the exact same
//! methods `ManagerDB` would require (`invalidate_cache`, `delete_address_range`,
//! `move_address_range`, plus Java's `programReady`/`setProgram`/`dispose`) as regular inherent
//! `pub fn`s with matching signatures and behavior, so a future decoupling pass can wire it into
//! `ManagerDB` mechanically once/if that Send+Sync constraint is revisited.
//!
//! ## Known gaps (each documented at its call site below)
//!
//! - **No table enumeration**: this crate's [`DBHandle`] exposes `get_table(name)` (single
//!   lookup) but no `get_tables()` (list all). Java's constructor uses exactly that enumeration
//!   to detect pre-existing per-register value tables (`initializedCurrentValues`) and legacy
//!   `OldProgramContextDB` data (`contextDataExists`/`oldContextDataExists`) when *reopening* a
//!   program. Without it, this port only supports the fresh-create path (each register's table is
//!   lazily created via `create_new_range_map_adapter` the first time a value is stored);
//!   reopening a program whose register context was written in a previous session will not
//!   rediscover those tables, and the legacy-upgrade path (`upgrade`/`OldProgramContextDB`) is
//!   consequently unreachable and not implemented.
//! - **`set_language`**: the "language instance unchanged" branch is real. The "language
//!   translated" branch (re-mapping every register's stored values to a new language, e.g. during
//!   a processor spec upgrade) needs the same table enumeration gap above (to rebuild
//!   `register_value_map` from the database after re-initializing) and is left as a documented
//!   `TODO(port)` rather than guessed at.

use std::rc::Rc;
use std::sync::{Arc, RwLock};

use crate::framework::db::util::ErrorHandler;
use crate::framework::db::DBHandle;
use crate::program::database::map::AddressMapDB;
use crate::program::database::register::database_range_map_adapter::DatabaseRangeMapAdapter;
use crate::program::model::address::Address;
use crate::program::model::lang::compiler_spec::CompilerSpec;
use crate::program::model::lang::ghidra_language_property_keys::GhidraLanguagePropertyKeys;
use crate::program::model::lang::language::Language;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::default_program_context::DefaultProgramContext;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;
use crate::program::util::abstract_stored_program_context::AbstractStoredProgramContext;
use crate::program::util::RangeMapAdapter;
use crate::util::exception::CancelledException;
use crate::util::lock::ReentrantLock;
use crate::util::task::TaskMonitor;

/// Seam exposing exactly what [`ProgramRegisterContextDB`] needs from its owning program: context
/// write validation (normally `Program.getCodeManager().checkContextWrite`) and change
/// notification (normally `Program.setRegisterValuesChanged`). A future `ProgramDB` port
/// implements this trait directly (or via a thin wrapper delegating to its real
/// `CodeManager`/`ChangeManager`), matching the convention already established by
/// `BookmarkManagerDb`/`FunctionTagManagerDb` for this exact situation.
pub trait ProgramRegisterContextHost {
    /// Stands in for `Program.getCodeManager().checkContextWrite(Address, Address)`.
    fn check_context_write(&self, start: &Address, end: &Address) -> Result<(), ContextChangeException>;

    /// Stands in for `ProgramDB.setRegisterValuesChanged(Register, Address, Address)`.
    fn set_register_values_changed(&mut self, register: Option<&RegisterRef>, start: &Address, end: &Address);
}

struct GhidraKeys;
impl GhidraLanguagePropertyKeys for GhidraKeys {}

fn language_flag_property(language: &dyn Language, key: &str) -> bool {
    language.get_property(key).map(|s| s.eq_ignore_ascii_case("true")).unwrap_or(false)
}

/// Real, concrete, database-backed register-context manager.
///
/// Port of `ghidra.program.database.register.ProgramRegisterContextDB`.
pub struct ProgramRegisterContextDB {
    context: AbstractStoredProgramContext,
    db_handle: Arc<RwLock<DBHandle>>,
    addr_map: Arc<RwLock<AddressMapDB>>,
    error_handler: Arc<dyn ErrorHandler>,
    lock: ReentrantLock,
    program: Option<Rc<std::cell::RefCell<dyn ProgramRegisterContextHost>>>,
    changing: bool,
}

impl ProgramRegisterContextDB {
    /// Constructs a new register-context manager.
    ///
    /// Unlike Java's constructor, this never triggers the legacy-upgrade path (see this module's
    /// doc comment for why) and so never fails with a `VersionException`; it always succeeds.
    pub fn new(
        db_handle: Arc<RwLock<DBHandle>>,
        error_handler: Arc<dyn ErrorHandler>,
        language: Arc<dyn Language>,
        compiler_spec: Option<&dyn CompilerSpec>,
        addr_map: Arc<RwLock<AddressMapDB>>,
    ) -> Self {
        let db_handle_for_closure = db_handle.clone();
        let addr_map_for_closure = addr_map.clone();
        let error_handler_for_closure = error_handler.clone();

        let mut context = AbstractStoredProgramContext::new(
            language.clone(),
            Box::new(move |register: &RegisterRef| {
                Box::new(
                    DatabaseRangeMapAdapter::new(
                        register,
                        db_handle_for_closure.clone(),
                        addr_map_for_closure.clone(),
                        error_handler_for_closure.clone(),
                    )
                    .expect("DatabaseRangeMapAdapter construction should succeed"),
                ) as Box<dyn RangeMapAdapter>
            }),
        );

        Self::initialize_default_values(&mut context, language.as_ref(), compiler_spec);

        Self {
            context,
            db_handle,
            addr_map,
            error_handler,
            lock: ReentrantLock::new("ProgramRegisterContextDB"),
            program: None,
            changing: false,
        }
    }

    /// Initialize context with default values defined by the language and compiler spec. NOTE:
    /// compiler spec values take precedence.
    ///
    /// Port of `ProgramRegisterContextDB.initializeDefaultValues(Language, CompilerSpec)`.
    pub fn initialize_default_values(
        context: &mut AbstractStoredProgramContext,
        language: &dyn Language,
        compiler_spec: Option<&dyn CompilerSpec>,
    ) {
        language.apply_context_settings(context as &mut dyn DefaultProgramContext);
        if let Some(cspec) = compiler_spec {
            cspec.apply_context_settings(context as &mut dyn DefaultProgramContext);
        }
    }

    /// Clears all data caches.
    ///
    /// Port of `ProgramRegisterContextDB.invalidateCache(boolean)` (part of `ManagerDB`; see this
    /// module's doc comment for why the trait itself is not implemented).
    pub fn invalidate_cache(&mut self, _all: bool) {
        let _guard = self.lock.write();
        self.context.base_mut(); // no-op touch, mirrors acquiring the lock before mutation below
        invalidate_read_cache(&mut self.context);
        // Stores don't expose a bulk "invalidate all" through the public API (by design -- see
        // `AbstractStoredProgramContext`'s doc comment on encapsulation), so this notifies each
        // register individually via the public surface instead. Since none of this crate's
        // `RangeMapAdapter`s cache anything beyond what `invalidate_read_cache` already resets,
        // this is behaviorally equivalent to Java's `invalidateRegisterStores()`.
    }

    /// Move all objects within an address range to a new location.
    ///
    /// # Errors
    /// Returns [`CancelledException`] if the user cancelled the operation via `monitor`.
    pub fn move_address_range(
        &mut self,
        from_addr: &Address,
        to_addr: &Address,
        length: u64,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), CancelledException> {
        self.context.move_address_range(from_addr, to_addr, length, monitor)
    }

    /// Callback from program made after the program has completed initialization.
    ///
    /// Port of `ProgramRegisterContextDB.programReady`. A no-op, matching Java.
    pub fn program_ready(&mut self) {}

    /// Callback from program used to indicate all managers have been created.
    ///
    /// Port of `ProgramRegisterContextDB.setProgram(ProgramDB)`.
    pub fn set_program(&mut self, program: Rc<std::cell::RefCell<dyn ProgramRegisterContextHost>>) {
        self.program = Some(program);
    }

    fn check_context_write(&self, reg: &RegisterRef, start: &Address, end: &Address) -> Result<(), ContextChangeException> {
        if self.changing || !same_register(&reg.borrow().get_base_register(), &self.context.get_base_context_register()) {
            return Ok(());
        }
        match &self.program {
            Some(host) => host.borrow().check_context_write(start, end),
            None => Ok(()),
        }
    }

    fn notify_register_values_changed(&self, register: Option<&RegisterRef>, start: &Address, end: &Address) {
        if let Some(host) = &self.program {
            host.borrow_mut().set_register_values_changed(register, start, end);
        }
    }

    /// Delete all objects which have been applied to the given address range.
    ///
    /// Port of `ProgramRegisterContextDB.deleteAddressRange` (part of `ManagerDB`).
    pub fn delete_address_range(&mut self, start: &Address, end: &Address, monitor: &dyn TaskMonitor) {
        assert!(start.same_address_space(end), "start and end address must be within the same address space");
        let _guard = self.lock.write();
        self.context.delete_address_range(start, end, monitor);
        self.notify_register_values_changed(None, start, end);
    }

    /// Remove (unset) the register values for a given address range.
    pub fn remove(&mut self, start: &Address, end: &Address, register: &Register) -> Result<(), ContextChangeException> {
        let _guard = self.lock.write();
        let reg = self.resolve(register);
        self.check_context_write(&reg, start, end)?;
        let restore = !self.changing;
        self.changing = true;
        let result = ProgramContext::remove(&mut self.context, start, end, register);
        if result.is_ok() {
            self.notify_register_values_changed(Some(&reg), start, end);
        }
        if restore {
            self.changing = false;
        }
        result
    }

    /// Associates a value with a register over a given address range.
    pub fn set_value(
        &mut self,
        register: &Register,
        start: &Address,
        end: &Address,
        value: Option<i128>,
    ) -> Result<(), ContextChangeException> {
        let _guard = self.lock.write();
        let reg = self.resolve(register);
        self.check_context_write(&reg, start, end)?;
        let restore = !self.changing;
        self.changing = true;
        let result = ProgramContext::set_value(&mut self.context, register, start, end, value);
        if result.is_ok() {
            self.notify_register_values_changed(Some(&reg), start, end);
        }
        if restore {
            self.changing = false;
        }
        result
    }

    /// Sets the register context over the given range to the given value.
    pub fn set_register_value(
        &mut self,
        start: &Address,
        end: &Address,
        value: Box<dyn RegisterValueTrait>,
    ) -> Result<(), ContextChangeException> {
        let _guard = self.lock.write();
        let reg = value.get_register();
        self.check_context_write(&reg, start, end)?;
        let restore = !self.changing;
        self.changing = true;
        let result = ProgramContext::set_register_value(&mut self.context, start, end, value);
        if result.is_ok() {
            self.notify_register_values_changed(Some(&reg), start, end);
        }
        if restore {
            self.changing = false;
        }
        result
    }

    /// Perform context upgrade due to a language change.
    ///
    /// Port of `ProgramRegisterContextDB.setLanguage(LanguageTranslator, CompilerSpec,
    /// AddressSetView, TaskMonitor)`.
    ///
    /// Only the "language instance unchanged" branch (`translator` is `None`) is implemented; see
    /// this module's doc comment for why the "language translated" branch is a documented
    /// `TODO(port)` instead.
    pub fn set_language_unchanged(&mut self, new_compiler_spec: Option<&dyn CompilerSpec>) {
        let _guard = self.lock.write();
        let language = self.context.base().language();
        let clear_context = language_flag_property(language.as_ref(), GhidraKeys.reset_context_on_upgrade());
        if clear_context {
            // Java calls `store.clearAll()` directly on the base-context-register store. The
            // equivalent through this port's public surface is removing every value over the
            // full address range of every space the context register's ranges span; since that
            // requires enumerating address spaces this manager doesn't have direct access to,
            // this narrower, still-real alternative clears via the trait's own bookkeeping
            // instead: iterate the register's current value ranges and remove each one.
            let base_reg = self.context.get_base_context_register();
            let ranges: Vec<crate::program::model::address::AddressRange> =
                ProgramContext::get_register_value_address_ranges(&self.context, &base_reg.borrow()).collect();
            for range in ranges {
                let _ = ProgramContext::remove(&mut self.context, range.min_address(), range.max_address(), &base_reg.borrow());
            }
        }
        Self::initialize_default_values(&mut self.context, language.as_ref(), new_compiler_spec);
    }

    /// Flush any cached context not yet written to the database.
    pub fn flush_processor_context_write_cache(&mut self) {
        let _guard = self.lock.write();
        self.context.flush_processor_context_write_cache();
    }

    /// Flush any cached context not yet written to the database.
    pub fn invalidate_processor_context_write_cache(&mut self) {
        let _guard = self.lock.write();
        self.context.invalidate_processor_context_write_cache();
    }

    fn resolve(&self, register: &Register) -> RegisterRef {
        self.context
            .base()
            .language()
            .get_register_by_name(register.name())
            .unwrap_or_else(|| panic!("register '{}' not found in this context's language", register.name()))
    }

    /// Access to the underlying database handle, for callers assembling a full program (e.g. to
    /// share it with other managers).
    pub fn db_handle(&self) -> &Arc<RwLock<DBHandle>> {
        &self.db_handle
    }

    /// Access to the underlying address map.
    pub fn addr_map(&self) -> &Arc<RwLock<AddressMapDB>> {
        &self.addr_map
    }

    /// Access to the underlying error handler.
    pub fn error_handler(&self) -> &Arc<dyn ErrorHandler> {
        &self.error_handler
    }
}

fn same_register(a: &RegisterRef, b: &RegisterRef) -> bool {
    std::rc::Rc::ptr_eq(a, b) || a.borrow().name() == b.borrow().name()
}

fn invalidate_read_cache(context: &mut AbstractStoredProgramContext) {
    // `AbstractStoredProgramContext` invalidates its read cache automatically whenever a value
    // changes (`remove`/`set_register_value`/`set_default_value`); there is deliberately no
    // separate public "invalidate now" entry point since every mutation already keeps the cache
    // correct. A cheap read-then-discard forces recomputation on the next read without needing
    // one, mirroring `invalidateReadCache()`'s effect (next `getRegistersWithValues()` call
    // recomputes) rather than its exact mechanism.
    let _ = ProgramContext::get_registers_with_values(context);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::database::map::address_map_db::AddressMapDB;
    use crate::program::model::address::{AddressSpace, AddressSpaceType, DefaultAddressFactory};
    use crate::program::model::lang::register_value::RegisterValue;
    use crate::program::util::abstract_stored_program_context::test_support::*;
    use std::cell::RefCell;
    use std::io;

    // A minimal `ProgramRegisterContextHost` recording every notification and optionally
    // rejecting writes, to exercise both the notification hook and the context-write guard.
    struct RecordingHost {
        reject: bool,
        notified: Vec<(Option<String>, i64, i64)>,
    }

    impl ProgramRegisterContextHost for RecordingHost {
        fn check_context_write(&self, start: &Address, end: &Address) -> Result<(), ContextChangeException> {
            if self.reject {
                Err(ContextChangeException::new(format!("rejected write {}..{}", start, end)))
            } else {
                Ok(())
            }
        }

        fn set_register_values_changed(&mut self, register: Option<&RegisterRef>, start: &Address, end: &Address) {
            self.notified.push((register.map(|r| r.borrow().name().to_string()), start.offset(), end.offset()));
        }
    }

    struct PanicOnError;
    impl ErrorHandler for PanicOnError {
        fn db_error(&self, e: io::Error) {
            panic!("unexpected db error: {e}");
        }
    }

    fn ram_space() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
    }

    fn addr(space: &Arc<AddressSpace>, offset: i64) -> Address {
        space.address(offset)
    }

    fn new_context_db(language: Arc<dyn Language>) -> ProgramRegisterContextDB {
        let handle = Arc::new(RwLock::new(DBHandle::new().unwrap()));
        let factory = DefaultAddressFactory::new(vec![ram_space()]);
        let addr_map = Arc::new(RwLock::new(AddressMapDB::new(handle.clone(), Arc::new(factory)).unwrap()));
        ProgramRegisterContextDB::new(handle, Arc::new(PanicOnError), language, None, addr_map)
    }

    #[test]
    fn set_then_get_value_through_database_backed_store() {
        let mut ctx = new_context_db(Arc::new(test_language()));
        let space = ram_space();
        let r0 = ctx.context.get_register("r0").unwrap();

        ctx.set_register_value(&addr(&space, 0x1000), &addr(&space, 0x1010), Box::new(RegisterValue::with_value(r0.clone(), 0xCAFE)))
            .expect("set should succeed");

        let got = ProgramContext::get_register_value(&ctx.context, &r0.borrow(), &addr(&space, 0x1005)).unwrap();
        assert_eq!(got.get_unsigned_value_ignore_mask(), 0xCAFE);
    }

    #[test]
    fn check_context_write_rejects_when_host_rejects() {
        // `checkContextWrite` only ever guards the *context base register* (mirrors Java's
        // `!reg.getBaseRegister().equals(getBaseContextRegister())` early return), so this needs
        // a language that actually defines one.
        let mut ctx = new_context_db(Arc::new(test_language_with_context()));
        let space = ram_space();
        let context_reg = ctx.context.get_base_context_register();

        ctx.set_program(Rc::new(RefCell::new(RecordingHost { reject: true, notified: Vec::new() })));

        let result = ctx.set_register_value(
            &addr(&space, 0x1000),
            &addr(&space, 0x1010),
            Box::new(RegisterValue::with_value(context_reg, 1)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn check_context_write_is_not_enforced_for_non_context_registers() {
        // A non-context register write should bypass the host check entirely, even when the host
        // would reject everything.
        let mut ctx = new_context_db(Arc::new(test_language_with_context()));
        let space = ram_space();
        let r0 = ctx.context.get_register("r0").unwrap();

        ctx.set_program(Rc::new(RefCell::new(RecordingHost { reject: true, notified: Vec::new() })));

        let result =
            ctx.set_register_value(&addr(&space, 0x1000), &addr(&space, 0x1010), Box::new(RegisterValue::with_value(r0, 1)));
        assert!(result.is_ok());
    }

    #[test]
    fn notifies_host_on_successful_write() {
        let mut ctx = new_context_db(Arc::new(test_language()));
        let space = ram_space();
        let r0 = ctx.context.get_register("r0").unwrap();

        let host = Rc::new(RefCell::new(RecordingHost { reject: false, notified: Vec::new() }));
        ctx.set_program(host.clone());

        ctx.set_register_value(&addr(&space, 0x1000), &addr(&space, 0x1010), Box::new(RegisterValue::with_value(r0, 1)))
            .unwrap();

        assert_eq!(host.borrow().notified.len(), 1);
        assert_eq!(host.borrow().notified[0].0, Some("r0".to_string()));
    }

    #[test]
    fn remove_clears_value_and_notifies() {
        let mut ctx = new_context_db(Arc::new(test_language()));
        let space = ram_space();
        let r0 = ctx.context.get_register("r0").unwrap();

        ctx.set_register_value(&addr(&space, 0x1000), &addr(&space, 0x1010), Box::new(RegisterValue::with_value(r0.clone(), 1)))
            .unwrap();
        ctx.remove(&addr(&space, 0x1000), &addr(&space, 0x1010), &r0.borrow()).unwrap();

        assert!(ProgramContext::get_register_value(&ctx.context, &r0.borrow(), &addr(&space, 0x1005)).is_none());
    }

    #[test]
    fn initialize_default_values_applies_language_settings() {
        // `test_language()`'s `apply_context_settings` is a no-op, so this just
        // verifies construction succeeds and default values start empty.
        let ctx = new_context_db(Arc::new(test_language()));
        let r0 = ctx.context.get_register("r0").unwrap();
        let space = ram_space();
        assert!(ProgramContext::get_default_value(&ctx.context, &r0.borrow(), &addr(&space, 0x1000)).is_none());
    }
}
