//! Port of `ghidra.app.plugin.core.disassembler.DisassemblerPlugin`.
//!
//! `DisassemblerPlugin` provides functionality for dynamic disassembly and static disassembly.
//!
//! In dynamic disassembly, disassembling begins from the selected addresses or, if there is no
//! selection, at the address of the current cursor location, and attempts to continue disassembling
//! through fallthroughs and along all flows from a disassembled instruction. For instance, if a
//! jump instruction is disassembled then the address being jumped to will be disassembled. The
//! dynamic disassembly will also follow data pointers to addresses containing undefined data, which
//! is then disassembled.
//!
//! In static disassembly a range or set of ranges is given and disassembly is attempted on each
//! range. Any defined code in the ranges before the static disassembly are first removed.
//!
//! # Shape
//!
//! Java's `DisassemblerPlugin` is a concrete class (nothing extends it), so it becomes a plain
//! `struct` (rule R14a-concrete-leaf). It extends `Plugin`, which is ported as a trait, so the
//! methods it `@Override`s there are implemented through
//! [`Plugin`](crate::framework::plugintool::Plugin) (and its
//! [`ServiceListener`]/[`PluginEventListener`]/[`ExtensionPoint`] supertraits). The state Java
//! inherits from the `Plugin` base class -- the provided-service registry, the consumed-event set
//! and the disposed flag -- has no base struct to live in, so this struct holds it, exactly as
//! [`DecompilePlugin`](crate::app::plugin::core::decompile::DecompilePlugin) does.
//!
//! # Seams
//!
//! Two dependency cycles run back into this type, and both are broken by handing the plugin
//! already-built collaborators instead of having it construct them:
//!
//! * **Actions.** Java's `createActions()` builds sixteen actions, each with a back-reference to
//!   the plugin (`new DisassembleAction(this, GROUP_NAME)`), and every one of those classes calls
//!   back into the callbacks below. None is ported. The plugin therefore takes them as
//!   [`DisassemblerActions`] -- one field per Java field, typed at their shared Java base through
//!   the [`ListingContextAction`] stub -- and [`create_actions`](DisassemblerPlugin::create_actions)
//!   performs the rest of Java's body (installing them in the tool, in Java's order).
//! * **Commands.** Each callback ends in `new SomeDisassembleCommand(...)`, and none of those six
//!   classes is ported either. The arguments Java passes are computed here and handed to the caller
//!   as a [`DisassembleRequest`]; the callbacks take a factory that turns one into a command, in
//!   the same spirit as `DecompilePlugin`'s provider factory. A callback that decides not to
//!   disassemble at all (Java's `MemoryAccessException` branch) never calls its factory, and
//!   returns `None`.
//!
//! Two further seams shape the signatures below:
//!
//! * **Listing access.** This crate's [`Program::get_listing`] takes `&mut self`, and an action
//!   context only ever yields a shared `Arc<dyn Program>`. The one method that needs the listing,
//!   [`check_disassembly_enabled`](DisassemblerPlugin::check_disassembly_enabled), takes it as a
//!   parameter rather than reaching for it through the context, so the whole recursive
//!   pointer-following algorithm stays portable.
//! * **Events.** This crate models `PluginEvent` as one concrete struct with no subclass payload
//!   and no downcasting seam, so `processEvent`'s single `instanceof` branch becomes the typed
//!   [`process_program_activated_event`](DisassemblerPlugin::process_program_activated_event), and
//!   [`Plugin::process_event`] can only document that.

use std::any::{Any, TypeId};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::app::events::ProgramActivatedPluginEvent;
use crate::app::plugin::plugin_category_names::PluginCategoryNames;
use crate::app::seam_stubs::{
    CorePluginPackage, DisassembleCommand, ListingActionContext, ListingContextAction,
    ProcessorStateDialog, ProgramSelection,
};
use crate::framework::plugintool::util::{
    PluginDescription, PluginEventListener, PluginStatus, ServiceListener,
};
use crate::framework::plugintool::{Plugin, PluginEvent};
use crate::framework::seam_stubs::{PluginPackageLike, PluginTool};
use crate::program::disassemble::{
    MARK_BAD_INSTRUCTION_PROPERTY, MARK_UNIMPL_PCODE_PROPERTY,
    RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY,
};
use crate::program::model::address::{Address, AddressSet};
use crate::program::model::lang::Register;
use crate::program::model::listing::code_unit::CodeUnit;
use crate::program::model::listing::{Listing, Program, DISASSEMBLER_PROPERTIES};
use crate::util::classfinder::ExtensionPoint;

/// The action group every action this plugin installs belongs to.
///
/// Mirrors the package-private `DisassemblerPlugin.GROUP_NAME`, which Java passes to each action's
/// constructor; the actions are built outside this type here (see the module docs), so it is public
/// for their builders to use.
pub const GROUP_NAME: &str = "Disassembly";

/// Fully-qualified name of the single event `@PluginInfo(eventsConsumed = ...)` lists.
const PROGRAM_ACTIVATED_EVENT_CLASS: &str = "ghidra.app.events.ProgramActivatedPluginEvent";

/// The same event by [`PluginEvent::event_name`], which is how [`Plugin::process_last_events`]
/// matches an event against the consumed set in this crate.
const PROGRAM_ACTIVATED_EVENT_NAME: &str = "Program Activated";

/// The status message shown when the cursor sits on uninitialized memory.
const UNINITIALIZED_MEMORY_MESSAGE: &str = "Can't disassemble uninitialized memory!";

/// Where a disassembly command should start: Java's two `DisassembleCommand` constructor
/// overloads, `(ProgramSelection, ...)` and `(Address, ...)`.
#[derive(Clone)]
pub enum DisassembleSeed {
    /// Java's `new DisassembleCommand(currentSelection, ...)`: disassemble the whole selection.
    Selection(Arc<dyn ProgramSelection>),
    /// Java's `new DisassembleCommand(addr, ...)`: disassemble outwards from a single address.
    Address(Address),
}

/// The `restrictedSet` argument Java passes alongside the seed.
#[derive(Clone)]
pub enum DisassembleRestriction {
    /// Java's `null` restricted set: disassembly follows flow wherever it leads.
    Unrestricted,
    /// Java passes the current selection itself as the restricted set, confining disassembly to it.
    Selection(Arc<dyn ProgramSelection>),
    /// Java passes an explicit set; for a cursor-seeded restricted or static disassembly that set
    /// is `new AddressSet(addr, addr)`, the single address under the cursor.
    Set(AddressSet),
}

/// One command's worth of constructor arguments, as computed by the callbacks below.
///
/// Stands in for the `new SomeDisassembleCommand(seed, restrictedSet, flag)` call this plugin can't
/// make yet (see the module docs). `flag` is the commands' shared third argument: `followFlow` for
/// [`DisassembleCommand`], and the mode selector for each architecture-specific subclass
/// (`thumbMode`, `xgMode`, `mips16`, `vle`, `size32Mode`).
#[derive(Clone)]
pub struct DisassembleRequest {
    /// Where disassembly starts.
    pub seed: DisassembleSeed,
    /// What, if anything, confines it.
    pub restriction: DisassembleRestriction,
    /// The command's third constructor argument.
    pub flag: bool,
}

/// The sixteen actions Java's `createActions()` builds, one field per Java field.
///
/// Java constructs each with a back-reference to the plugin, which is the cycle this type breaks;
/// see the module docs. The two `ArmDisassembleAction`/`Hcs12DisassembleAction`/
/// `MipsDisassembleAction`/`PowerPCDisassembleAction`/`X86_64DisassembleAction` fields differ only
/// in the boolean their builder passes, exactly as in Java.
pub struct DisassemblerActions {
    /// `new RestrictedDisassembleAction(this, GROUP_NAME)`.
    pub disassemble_restricted_action: Arc<dyn ListingContextAction>,
    /// `new DisassembleAction(this, GROUP_NAME)`.
    pub disassemble_action: Arc<dyn ListingContextAction>,
    /// `new StaticDisassembleAction(this, GROUP_NAME)`.
    pub disassemble_static_action: Arc<dyn ListingContextAction>,
    /// `new ContextAction(this, GROUP_NAME)`.
    pub context_action: Arc<dyn ListingContextAction>,
    /// `new ArmDisassembleAction(this, GROUP_NAME, false)`.
    pub arm_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new ArmDisassembleAction(this, GROUP_NAME, true)`.
    pub arm_thumb_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new Hcs12DisassembleAction(this, GROUP_NAME, false)`.
    pub hcs12_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new Hcs12DisassembleAction(this, GROUP_NAME, true)`.
    pub xgate_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new MipsDisassembleAction(this, GROUP_NAME, false)`.
    pub mips_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new MipsDisassembleAction(this, GROUP_NAME, true)`.
    pub mips16_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new PowerPCDisassembleAction(this, GROUP_NAME, false)`.
    pub ppc_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new PowerPCDisassembleAction(this, GROUP_NAME, true)`.
    pub ppc_vle_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new X86_64DisassembleAction(this, GROUP_NAME, false)`.
    pub x86_64_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new X86_64DisassembleAction(this, GROUP_NAME, true)`.
    pub x86_32_disassemble_action: Arc<dyn ListingContextAction>,
    /// `new SetFlowOverrideAction(this, GROUP_NAME)`.
    pub set_flow_override_action: Arc<dyn ListingContextAction>,
    /// `new SetLengthOverrideAction(this, GROUP_NAME)`.
    pub set_length_override_action: Arc<dyn ListingContextAction>,
}

/// Provides functionality for dynamic disassembly and static disassembly.
///
/// Port of `ghidra.app.plugin.core.disassembler.DisassemblerPlugin`.
pub struct DisassemblerPlugin {
    tool: Arc<dyn PluginTool + Send + Sync>,

    actions: DisassemblerActions,

    // State Java inherits from the `Plugin` base class; see the module docs.
    services_provided: Mutex<HashMap<String, Vec<Arc<dyn Any + Send + Sync>>>>,
    events_consumed: Mutex<HashSet<String>>,
    disposed: AtomicBool,
    description: DisassemblerPluginDescription,
}

impl DisassemblerPlugin {
    /// Port of the static `getDescription()`.
    pub fn get_description() -> &'static str {
        "Provides disassembler services for all supplied machine language modules."
    }

    /// Port of the static `getDescriptiveName()`.
    pub fn get_descriptive_name() -> &'static str {
        "Disassembler"
    }

    /// Port of the static `getCategory()`.
    pub fn get_category() -> &'static str {
        "Disassemblers"
    }

    /// Port of `DisassemblerPlugin(PluginTool)`.
    ///
    /// Java's constructor also builds the sixteen actions before installing them; they are passed
    /// in instead (see the module docs). Installing them -- the rest of `createActions()` -- still
    /// happens here, as in Java.
    pub fn new(tool: Arc<dyn PluginTool + Send + Sync>, actions: DisassemblerActions) -> Self {
        let plugin = Self {
            tool,
            actions,
            services_provided: Mutex::new(HashMap::new()),
            events_consumed: Mutex::new(HashSet::new()),
            disposed: AtomicBool::new(false),
            description: DisassemblerPluginDescription,
        };
        plugin.create_actions();
        plugin
    }

    /// The actions this plugin installed.
    pub fn actions(&self) -> &DisassemblerActions {
        &self.actions
    }

    /// Port of the private `createActions()`, less the construction of the actions themselves.
    ///
    /// The install order is Java's, which is not the order the fields are assigned in: `contextAction`
    /// goes in fourteenth, after the architecture-specific actions.
    fn create_actions(&self) {
        let actions = &self.actions;
        for action in [
            &actions.disassemble_action,
            &actions.disassemble_restricted_action,
            &actions.disassemble_static_action,
            &actions.arm_disassemble_action,
            &actions.arm_thumb_disassemble_action,
            &actions.hcs12_disassemble_action,
            &actions.xgate_disassemble_action,
            &actions.mips_disassemble_action,
            &actions.mips16_disassemble_action,
            &actions.ppc_disassemble_action,
            &actions.ppc_vle_disassemble_action,
            &actions.x86_64_disassemble_action,
            &actions.x86_32_disassemble_action,
            &actions.context_action,
            &actions.set_flow_override_action,
            &actions.set_length_override_action,
        ] {
            self.tool.add_action(action.clone().as_any_arc());
        }
    }

    /// Port of `processEvent`'s `ProgramActivatedPluginEvent` branch, which delegates to
    /// `programActivated(Program)`.
    ///
    /// A closed program whose handle has already been dropped matches Java's null program and is
    /// ignored, as `programActivated` does.
    pub fn process_program_activated_event(&self, event: &ProgramActivatedPluginEvent) {
        if let Some(program) = event.get_active_program() {
            self.program_activated(program.as_ref());
        }
    }

    /// Port of the protected `programActivated(Program)`, which registers the disassembler's three
    /// per-program options.
    pub fn program_activated(&self, program: &dyn Program) {
        let mut options = program.get_options(DISASSEMBLER_PROPERTIES);
        options.register_option(
            MARK_BAD_INSTRUCTION_PROPERTY,
            Box::new(true),
            None,
            "Place ERROR Bookmark at locations where disassembly could not be perfomed.",
        );
        options.register_option(
            MARK_UNIMPL_PCODE_PROPERTY,
            Box::new(true),
            None,
            "Place WARNING Bookmark at locations where a disassembled instruction has unimplemented pcode.",
        );
        options.register_option(
            RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY,
            Box::new(false),
            None,
            "Restrict disassembly to executable memory blocks.",
        );
    }

    /// Port of the package-private `disassembleRestrictedCallback(ListingActionContext)`.
    ///
    /// Disassembly is confined to the selection, or to the single address under the cursor.
    pub fn disassemble_restricted_callback(
        &self,
        context: &dyn ListingActionContext,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        let request = match self.non_empty_selection(context) {
            Some(selection) => DisassembleRequest {
                seed: DisassembleSeed::Selection(selection.clone()),
                restriction: DisassembleRestriction::Selection(selection),
                flag: true,
            },
            None => {
                let addr = context.get_location()?.get_address();
                DisassembleRequest {
                    seed: DisassembleSeed::Address(addr.clone()),
                    restriction: DisassembleRestriction::Set(AddressSet::from_start_end(
                        addr.clone(),
                        addr,
                    )),
                    flag: true,
                }
            }
        };
        self.execute(context, new_command(&request))
    }

    /// Port of the package-private `disassembleStaticCallback(ListingActionContext)`.
    ///
    /// Identical to [`disassemble_restricted_callback`](Self::disassemble_restricted_callback)
    /// except that the command does not follow flow.
    pub fn disassemble_static_callback(
        &self,
        context: &dyn ListingActionContext,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        let request = match self.non_empty_selection(context) {
            Some(selection) => DisassembleRequest {
                seed: DisassembleSeed::Selection(selection.clone()),
                restriction: DisassembleRestriction::Selection(selection),
                flag: false,
            },
            None => {
                let addr = context.get_location()?.get_address();
                DisassembleRequest {
                    seed: DisassembleSeed::Address(addr.clone()),
                    restriction: DisassembleRestriction::Set(AddressSet::from_start_end(
                        addr.clone(),
                        addr,
                    )),
                    flag: false,
                }
            }
        };
        self.execute(context, new_command(&request))
    }

    /// Port of the package-private `disassembleCallback(ListingActionContext)`.
    ///
    /// Unrestricted disassembly following flow. With no selection, the address under the cursor
    /// must be readable: Java reports `MemoryAccessException` on the status line and builds no
    /// command, which is the `None` return here. Follow-on code analysis is enabled unless the
    /// action came from a dynamic (debugger) listing.
    pub fn disassemble_callback(
        &self,
        context: &dyn ListingActionContext,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        let request = match self.non_empty_selection(context) {
            Some(selection) => Some(DisassembleRequest {
                seed: DisassembleSeed::Selection(selection),
                restriction: DisassembleRestriction::Unrestricted,
                flag: true,
            }),
            None => self.address_seeded_request(context, true)?,
        };
        let request = request?;
        let cmd = new_command(&request);
        // do not analyze debugger listing
        let is_dynamic = context
            .get_navigatable()
            .is_some_and(|navigatable| navigatable.is_dynamic());
        cmd.enable_code_analysis(!is_dynamic);
        self.execute(context, cmd)
    }

    /// Port of `checkDisassemblyEnabled(ListingActionContext, Address, boolean)`.
    ///
    /// Java reads the listing off `context.getProgram()`; it is passed in here instead (see the
    /// module docs).
    pub fn check_disassembly_enabled(
        &self,
        context: &dyn ListingActionContext,
        listing: &dyn Listing,
        address: &Address,
        follow_ptr: bool,
    ) -> bool {
        // Debugger now has its own Disassemble actions
        if context
            .get_navigatable()
            .is_some_and(|navigatable| navigatable.is_dynamic())
        {
            return false;
        }
        if self.non_empty_selection(context).is_some() {
            return true;
        }

        if listing.get_instruction_containing(address).is_some() {
            return false;
        }
        if let Some(data) = listing.get_defined_data_containing(address) {
            if follow_ptr && data.is_pointer() {
                if let Some(ptr_addr) = CodeUnit::get_address(data.as_ref(), 0) {
                    return self.check_disassembly_enabled(context, listing, &ptr_addr, false);
                }
            }
            return false;
        }
        context
            .get_program()
            .and_then(|program| program.get_memory())
            .is_some_and(|memory| memory.contains(address))
    }

    /// Port of `setDefaultContext(ListingActionContext)`.
    ///
    /// Java builds `new ProcessorStateDialog(contextProgram.getProgramContext())` inline; that class
    /// is not ported (and this crate's [`Program::get_program_context`] needs `&mut Program`, which
    /// a context cannot hand out), so the dialog is supplied by a factory that is only invoked when
    /// Java would have constructed one. Returns whether the dialog was shown.
    pub fn set_default_context(
        &self,
        context: &dyn ListingActionContext,
        new_dialog: &mut dyn FnMut() -> Arc<dyn ProcessorStateDialog>,
    ) -> bool {
        let Some(context_program) = context.get_program() else {
            return false;
        };
        if !self.has_context_registers(context_program.as_ref()) {
            return false;
        }
        self.tool.show_dialog(
            new_dialog().as_any_arc(),
            context.get_component_provider(),
        );
        true
    }

    /// Port of `hasContextRegisters(Program)`.
    ///
    /// Java compares the base register against the `Register.NO_CONTEXT` singleton by identity;
    /// [`Register::no_context`] builds a fresh instance per call here, so the comparison goes
    /// through [`Register`]'s value equality instead. A program with no language has no context
    /// registers.
    pub fn has_context_registers(&self, current_program: &dyn Program) -> bool {
        let Some(language) = current_program.get_language() else {
            return false;
        };
        let Some(base_context_reg) = language.get_context_base_register() else {
            return false;
        };
        let base_context_reg = base_context_reg.borrow();
        *base_context_reg != *Register::no_context().borrow() && base_context_reg.has_children()
    }

    /// Port of `disassembleArmCallback(ListingActionContext, boolean)`.
    pub fn disassemble_arm_callback(
        &self,
        context: &dyn ListingActionContext,
        thumb_mode: bool,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        self.disassemble_unrestricted_callback(context, thumb_mode, new_command)
    }

    /// Port of `disassembleHcs12Callback(ListingActionContext, boolean)`.
    pub fn disassemble_hcs12_callback(
        &self,
        context: &dyn ListingActionContext,
        xg_mode: bool,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        self.disassemble_unrestricted_callback(context, xg_mode, new_command)
    }

    /// Port of `disassembleMipsCallback(ListingActionContext, boolean)`.
    pub fn disassemble_mips_callback(
        &self,
        context: &dyn ListingActionContext,
        mips16: bool,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        self.disassemble_unrestricted_callback(context, mips16, new_command)
    }

    /// Port of `disassemblePPCCallback(ListingActionContext, boolean)`.
    pub fn disassemble_ppc_callback(
        &self,
        context: &dyn ListingActionContext,
        vle: bool,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        self.disassemble_unrestricted_callback(context, vle, new_command)
    }

    /// Port of `disassembleX86_64Callback(ListingActionContext, boolean)`.
    ///
    /// Java's body differs from its four siblings only in returning early from the
    /// `MemoryAccessException` branch instead of falling through a null check -- the same
    /// behaviour -- so it shares their implementation here.
    pub fn disassemble_x86_64_callback(
        &self,
        context: &dyn ListingActionContext,
        size32_mode: bool,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        self.disassemble_unrestricted_callback(context, size32_mode, new_command)
    }

    /// The body the five architecture-specific callbacks share verbatim in Java: seed from the
    /// selection if there is one, otherwise from the cursor address provided it is readable, and
    /// never restrict the range.
    fn disassemble_unrestricted_callback(
        &self,
        context: &dyn ListingActionContext,
        flag: bool,
        new_command: &mut dyn FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        let request = match self.non_empty_selection(context) {
            Some(selection) => Some(DisassembleRequest {
                seed: DisassembleSeed::Selection(selection),
                restriction: DisassembleRestriction::Unrestricted,
                flag,
            }),
            None => self.address_seeded_request(context, flag)?,
        }?;
        self.execute(context, new_command(&request))
    }

    /// Java's `else` branch, shared by every callback that seeds from the cursor and does not
    /// restrict the range: read a byte at the cursor to prove the memory is initialized, and report
    /// on the status line if it is not.
    ///
    /// The outer `Option` is `None` when the context yields no location or program at all (nothing
    /// to act on); the inner one is `None` for Java's `MemoryAccessException` branch.
    fn address_seeded_request(
        &self,
        context: &dyn ListingActionContext,
        flag: bool,
    ) -> Option<Option<DisassembleRequest>> {
        let addr = context.get_location()?.get_address();
        let memory = context.get_program()?.get_memory()?;
        if memory.get_byte(&addr).is_err() {
            self.tool.set_status_info(UNINITIALIZED_MEMORY_MESSAGE, true);
            return Some(None);
        }
        Some(Some(DisassembleRequest {
            seed: DisassembleSeed::Address(addr),
            restriction: DisassembleRestriction::Unrestricted,
            flag,
        }))
    }

    /// Java's `(currentSelection != null) && (!currentSelection.isEmpty())` guard, which every
    /// callback opens with.
    fn non_empty_selection(
        &self,
        context: &dyn ListingActionContext,
    ) -> Option<Arc<dyn ProgramSelection>> {
        context
            .get_selection()
            .filter(|selection| !selection.is_empty())
    }

    /// Java's closing `tool.executeBackgroundCommand(cmd, currentProgram)`. A context with no
    /// program has nothing to run the command against, so the command is dropped.
    fn execute(
        &self,
        context: &dyn ListingActionContext,
        cmd: Arc<dyn DisassembleCommand>,
    ) -> Option<Arc<dyn DisassembleCommand>> {
        let current_program = context.get_program()?;
        self.tool
            .execute_background_command(cmd.clone().as_any_arc(), current_program);
        Some(cmd)
    }
}

impl ExtensionPoint for DisassemblerPlugin {}

impl PluginEventListener for DisassemblerPlugin {
    fn event_sent(&self, event: &PluginEvent) {
        self.handle_plugin_event(event);
    }
}

impl ServiceListener for DisassemblerPlugin {
    /// Java's `DisassemblerPlugin` overrides neither `serviceAdded` nor `serviceRemoved`; the
    /// `Plugin` base class's bodies are empty.
    fn service_added(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}

    fn service_removed(&self, _interface_class: TypeId, _service: Arc<dyn Any + Send + Sync>) {}
}

impl Plugin for DisassemblerPlugin {
    fn name(&self) -> String {
        "DisassemblerPlugin".to_string()
    }

    fn tool(&self) -> Arc<dyn PluginTool> {
        self.tool.clone()
    }

    fn plugin_description(&self) -> &dyn PluginDescription {
        &self.description
    }

    fn is_disposed(&self) -> bool {
        self.disposed.load(Ordering::SeqCst)
    }

    fn events_consumed(&self) -> Vec<String> {
        let mut names = vec![PROGRAM_ACTIVATED_EVENT_NAME.to_string()];
        for name in self.events_consumed.lock().unwrap().iter() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }

    fn service_classes(&self) -> Vec<String> {
        self.services_provided
            .lock()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    fn service_provider_instances(&self, interface_class: &str) -> Vec<Arc<dyn Any + Send + Sync>> {
        self.services_provided
            .lock()
            .unwrap()
            .get(interface_class)
            .cloned()
            .unwrap_or_default()
    }

    fn register_service_provided(
        &self,
        interface_class: &str,
        service: Arc<dyn Any + Send + Sync>,
    ) {
        self.services_provided
            .lock()
            .unwrap()
            .entry(interface_class.to_string())
            .or_default()
            .push(service);
    }

    fn deregister_service(&self, interface_class: &str, service: &Arc<dyn Any + Send + Sync>) {
        let mut services = self.services_provided.lock().unwrap();
        if let Some(instances) = services.get_mut(interface_class) {
            instances.retain(|registered| !Arc::ptr_eq(registered, service));
            if instances.is_empty() {
                services.remove(interface_class);
            }
        }
    }

    fn internal_register_event_consumed(&self, event_class: &str) {
        self.events_consumed
            .lock()
            .unwrap()
            .insert(event_class.to_string());
    }

    fn cleanup(&self) {
        self.dispose();
        self.disposed.store(true, Ordering::SeqCst);
    }

    /// Port of `processEvent(PluginEvent)`.
    ///
    /// Java tests the event's concrete subclass and reads the activated program off it. A
    /// [`PluginEvent`] here carries no such payload and cannot be downcast, so the one branch lives
    /// in [`process_program_activated_event`](DisassemblerPlugin::process_program_activated_event),
    /// which the tool's event plumbing should call once it can hand out the concrete event. This
    /// override recognizes nothing on its own -- as Java's does for every other event.
    fn process_event(&self, _event: &PluginEvent) {}
}

/// The `@PluginInfo` metadata declared on `DisassemblerPlugin`, as a [`PluginDescription`].
///
/// Java derives this from the annotation by reflection at registration time; with no annotations to
/// read, the values are stated directly here.
struct DisassemblerPluginDescription;

impl PluginCategoryNames for DisassemblerPluginDescription {}

impl PluginDescription for DisassemblerPluginDescription {
    fn plugin_class_name(&self) -> String {
        "ghidra.app.plugin.core.disassembler.DisassemblerPlugin".to_string()
    }

    fn name(&self) -> String {
        "DisassemblerPlugin".to_string()
    }

    fn short_description(&self) -> String {
        "Disassembler".to_string()
    }

    fn description(&self) -> String {
        "This plugin provides functionality for dynamic disassembly, static disassembly. In \
         dynamic disassembly, disassembling begins from the selected addresses or if there is no \
         selection then at the address of the current cursor location and attempts to continue \
         disassembling through fallthroughs and along all flows from a disassembled instruction. \
         For instance, if a jump instruction is disassembled then the address being jumped to will \
         be disassembled. The dynamic disassembly will also follow data pointers to addresses \
         containing undefined data, which is then disassembled.  In static disassembly a range or \
         set of ranges is given and disassembly is attempted on each range. Any defined code in \
         the ranges before the static disassembly are first removed."
            .to_string()
    }

    fn category(&self) -> String {
        Self::ANALYSIS.to_string()
    }

    fn status(&self) -> PluginStatus {
        PluginStatus::Released
    }

    fn plugin_package(&self) -> Box<dyn PluginPackageLike> {
        Box::new(CorePluginPackage)
    }

    fn is_slow_installation(&self) -> bool {
        false
    }

    fn services_required(&self) -> Vec<String> {
        // The annotation declares none.
        Vec::new()
    }

    fn services_provided(&self) -> Vec<String> {
        // The annotation declares none, even though the class doc calls the plugin's functions a
        // service another plugin may use.
        Vec::new()
    }

    fn events_consumed(&self) -> Vec<String> {
        vec![PROGRAM_ACTIVATED_EVENT_CLASS.to_string()]
    }

    fn events_produced(&self) -> Vec<String> {
        Vec::new()
    }

    fn source_location(&self) -> String {
        String::new()
    }

    fn module_name(&self) -> String {
        "Base".to_string()
    }

    fn is_in_extension(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet as StdHashSet;
    use std::rc::Rc;
    use std::sync::atomic::AtomicUsize;

    use crate::app::seam_stubs::Navigatable;
    use crate::docking::settings::settings::Settings;
    use crate::framework::model::DomainObject;
    use crate::framework::options::Options;
    use crate::framework::seam_stubs::HelpLocation;
    use crate::program::model::address::{
        AddressFactory, AddressSetView, AddressSpace, AddressSpaceType,
    };
    use crate::program::model::data::data_type::DataType;
    use crate::program::model::data::data_type_display_options::DataTypeDisplayOptions;
    use crate::program::model::lang::instruction_prototype::InstructionPrototype;
    use crate::program::model::lang::register::RegisterRef;
    use crate::app::plugin::processors::generic::MemoryBlockDefinition;
    use crate::program::model::lang::{
        CompilerSpec, CompilerSpecDescription, CompilerSpecID, CompilerSpecNotFoundException,
        Language, LanguageDescription, LanguageID, ParseError, ProcessorContext,
        ProcessorContextView,
    };
    use crate::program::model::listing::{ContextChangeException, DefaultProgramContext};
    use crate::program::seam_stubs::{
        AddressLabelInfo, Processor, RefType as DataRefType, Reference as DataReference,
        RegisterValue,
    };
    use crate::program::model::lang::parallel_instruction_language_helper::ParallelInstructionLanguageHelper;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::data::Data;
    use crate::program::model::listing::instruction::{Instruction, OperandValue};
    use crate::program::model::listing::stub_listing::StubListing;
    use crate::program::model::listing::CommentType;
    use crate::program::model::mem::{MemBuffer, Memory, MemoryAccessException};
    use crate::program::model::pcode::PcodeOp;
    use crate::program::model::scalar::Scalar;
    use crate::program::model::symbol::{
        ExternalReference, RefType, Reference, ReferenceIterator, SourceType, Symbol,
    };
    use crate::program::model::util::PropertySet;
    use crate::program::seam_stubs::{FlowOverride, InstructionContext};
    use crate::program::util::{CodeUnitInsertionException, ProgramLocation};

    fn ram() -> Arc<AddressSpace> {
        AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 0)
    }

    fn addr(offset: i64) -> Address {
        Address::new(ram(), offset)
    }

    // --- program -----------------------------------------------------------------------------

    /// Which context base register the mock program's language reports. Held as a recipe rather
    /// than a [`RegisterRef`] because `Register` is `Rc`-backed (so not `Send`), while `Program`
    /// is `Send + Sync`; the register is built inside `get_language()`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ContextBase {
        /// The program has no language at all.
        NoLanguage,
        /// `Language.getContextBaseRegister()` answers `Register.NO_CONTEXT`.
        NoContext,
        /// A context register with no children -- nothing for the dialog to edit.
        Childless,
        /// A context register with one child field.
        WithChildren,
    }

    /// A program whose memory is initialized over `readable`, and whose language reports the
    /// context base register described by `context_base`.
    struct MockProgram {
        readable: Option<(i64, i64)>,
        context_base: ContextBase,
        /// Every `"name=default"` / description pair `programActivated` registered.
        registered: Arc<Mutex<Vec<(String, String)>>>,
        /// Every options list `programActivated` asked for.
        options_asked: Arc<Mutex<Vec<String>>>,
    }

    impl MockProgram {
        fn new() -> Self {
            Self {
                readable: Some((0, 0xffff)),
                context_base: ContextBase::NoLanguage,
                registered: Arc::default(),
                options_asked: Arc::default(),
            }
        }

        fn unreadable() -> Self {
            Self {
                readable: None,
                ..Self::new()
            }
        }

        fn with_context_base(context_base: ContextBase) -> Self {
            Self {
                context_base,
                ..Self::new()
            }
        }

        fn arc(self) -> Arc<dyn Program> {
            Arc::new(self)
        }
    }

    impl DomainObject for MockProgram {
        fn get_options(&self, property_list_name: &str) -> Box<dyn Options> {
            self.options_asked
                .lock()
                .unwrap()
                .push(property_list_name.to_string());
            Box::new(RecordingOptions {
                registered: self.registered.clone(),
            })
        }
    }

    impl Program for MockProgram {
        fn get_name(&self) -> String {
            "mock".to_string()
        }

        fn get_language_id(&self) -> String {
            "mock:LE:32:default".to_string()
        }

        fn get_language(&self) -> Option<Arc<dyn Language>> {
            let base = match self.context_base {
                ContextBase::NoLanguage => return None,
                ContextBase::NoContext => Register::no_context(),
                ContextBase::Childless => {
                    Register::new("contextreg", "context", addr(0), 4, true, Register::TYPE_NONE)
                }
                ContextBase::WithChildren => {
                    let base = Register::new(
                        "contextreg",
                        "context",
                        addr(0),
                        4,
                        true,
                        Register::TYPE_NONE,
                    );
                    let child = Register::with_bit_range(
                        "TMode",
                        "thumb mode",
                        addr(0),
                        4,
                        0,
                        1,
                        true,
                        Register::TYPE_NONE,
                    );
                    base.borrow_mut().set_child_registers(vec![Rc::clone(&child)]);
                    base
                }
            };
            Some(Arc::new(MockLanguage(base)))
        }

        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(Arc::new(MockMemory {
                readable: self.readable,
            }))
        }
    }

    struct MockMemory {
        readable: Option<(i64, i64)>,
    }

    impl MockMemory {
        fn holds(&self, address: &Address) -> bool {
            matches!(self.readable, Some((from, to))
                if address.offset() >= from && address.offset() <= to)
        }
    }

    impl Memory for MockMemory {
        fn is_big_endian(&self) -> bool {
            false
        }

        fn get_byte(&self, addr: &Address) -> Result<u8, MemoryAccessException> {
            if self.holds(addr) {
                Ok(0)
            } else {
                Err(MemoryAccessException::new("uninitialized memory"))
            }
        }

        fn get_bytes(&self, _addr: &Address, _dest: &mut [u8]) -> usize {
            unimplemented!()
        }

        fn set_bytes(&mut self, _addr: &Address, _source: &[u8]) -> Result<(), MemoryAccessException> {
            unimplemented!()
        }

        fn contains(&self, addr: &Address) -> bool {
            self.holds(addr)
        }
    }

    /// The [`Options`] `programActivated` registers into; records every registration. Every other
    /// member keeps the trait's default body.
    struct RecordingOptions {
        registered: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl Options for RecordingOptions {
        fn get_name(&self) -> String {
            DISASSEMBLER_PROPERTIES.to_string()
        }

        fn register_option(
            &mut self,
            option_name: &str,
            default_value: Box<dyn Any>,
            help: Option<Box<dyn HelpLocation>>,
            description: &str,
        ) {
            assert!(help.is_none(), "Java passes a null help location");
            let default = *default_value
                .downcast::<bool>()
                .expect("the disassembler registers only boolean options");
            self.registered
                .lock()
                .unwrap()
                .push((format!("{option_name}={default}"), description.to_string()));
        }
    }

    // --- language ----------------------------------------------------------------------------

    /// A [`Language`] answering only `getContextBaseRegister()`; every other member panics, which
    /// is all `hasContextRegisters` needs.
    struct MockLanguage(RegisterRef);

    impl Language for MockLanguage {
        fn get_context_base_register(&self) -> Option<RegisterRef> {
            Some(self.0.clone())
        }

        fn get_language_id(&self) -> LanguageID { unimplemented!() }
        fn get_language_description(&self) -> Box<dyn LanguageDescription> { unimplemented!() }
        fn get_parallel_instruction_helper(&self) -> Option<Box<dyn ParallelInstructionLanguageHelper>> { unimplemented!() }
        fn get_processor(&self) -> Box<dyn Processor> { unimplemented!() }
        fn get_version(&self) -> i32 { unimplemented!() }
        fn get_minor_version(&self) -> i32 { unimplemented!() }
        fn get_address_factory(&self) -> Box<dyn AddressFactory> { unimplemented!() }
        fn get_default_space(&self) -> Arc<AddressSpace> { unimplemented!() }
        fn get_default_data_space(&self) -> Arc<AddressSpace> { unimplemented!() }
        fn is_big_endian(&self) -> bool { unimplemented!() }
        fn get_instruction_alignment(&self) -> i32 { unimplemented!() }
        fn supports_pcode(&self) -> bool { unimplemented!() }
        fn is_volatile(&self, _addr: &Address) -> bool { unimplemented!() }
        fn parse(&self, _buf: &dyn MemBuffer, _context: &mut dyn ProcessorContext, _in_delay_slot: bool) -> Result<Box<dyn InstructionPrototype>, ParseError> { unimplemented!() }
        fn get_number_of_user_defined_op_names(&self) -> i32 { unimplemented!() }
        fn get_user_defined_op_name(&self, _index: i32) -> Option<String> { unimplemented!() }
        fn get_registers_at(&self, _address: &Address) -> Vec<RegisterRef> { unimplemented!() }
        fn get_register_in_space(&self, _addrspc: &Arc<AddressSpace>, _offset: i64, _size: i32) -> Option<RegisterRef> { unimplemented!() }
        fn get_registers(&self) -> Vec<RegisterRef> { unimplemented!() }
        fn get_register_names(&self) -> Vec<String> { unimplemented!() }
        fn get_register_by_name(&self, _name: &str) -> Option<RegisterRef> { unimplemented!() }
        fn get_register_at(&self, _addr: &Address, _size: i32) -> Option<RegisterRef> { unimplemented!() }
        fn get_program_counter(&self) -> Option<RegisterRef> { unimplemented!() }
        fn get_context_registers(&self) -> Vec<RegisterRef> { unimplemented!() }
        fn get_default_memory_blocks(&self) -> Vec<Box<dyn MemoryBlockDefinition>> { unimplemented!() }
        fn get_default_symbols(&self) -> Vec<Box<dyn AddressLabelInfo>> { unimplemented!() }
        fn get_segmented_space(&self) -> String { unimplemented!() }
        fn get_volatile_addresses(&self) -> Box<dyn AddressSetView> { unimplemented!() }
        fn apply_context_settings(&self, _ctx: &mut dyn DefaultProgramContext) { unimplemented!() }
        fn reload_language(&self, _task_monitor: &dyn crate::util::task::TaskMonitor) -> std::io::Result<()> { unimplemented!() }
        fn get_compatible_compiler_spec_descriptions(&self) -> Vec<Box<dyn CompilerSpecDescription>> { unimplemented!() }
        fn get_compiler_spec_by_id(&self, _compiler_spec_id: &CompilerSpecID) -> Result<Box<dyn CompilerSpec>, CompilerSpecNotFoundException> { unimplemented!() }
        fn get_default_compiler_spec(&self) -> Box<dyn CompilerSpec> { unimplemented!() }
        fn has_property(&self, _key: &str) -> bool { unimplemented!() }
        fn get_property_as_int(&self, _key: &str, _default_int: i32) -> i32 { unimplemented!() }
        fn get_property_as_boolean(&self, _key: &str, _default_boolean: bool) -> bool { unimplemented!() }
        fn get_property_or(&self, _key: &str, _default_string: &str) -> String { unimplemented!() }
        fn get_property(&self, _key: &str) -> Option<String> { unimplemented!() }
        fn get_property_keys(&self) -> StdHashSet<String> { unimplemented!() }
        fn has_manual(&self) -> bool { unimplemented!() }
        fn get_manual_entry(&self, _instruction_mnemonic: &str) -> Option<crate::util::manual_entry::ManualEntry> { unimplemented!() }
        fn get_manual_instruction_mnemonic_keys(&self) -> StdHashSet<String> { unimplemented!() }
        fn get_manual_exception(&self) -> Option<Box<dyn std::error::Error + Send + Sync + 'static>> { unimplemented!() }
        fn get_sorted_vector_registers(&self) -> Vec<RegisterRef> { unimplemented!() }
        fn get_register_addresses(&self) -> Box<dyn AddressSetView> { unimplemented!() }
        fn get_maximum_instruction_length(&self) -> Option<i32> { unimplemented!() }
    }

    // --- action context ----------------------------------------------------------------------

    struct MockSelection {
        empty: bool,
    }

    impl ProgramSelection for MockSelection {
        fn is_empty(&self) -> bool {
            self.empty
        }
    }

    struct MockLocation(Address);

    impl ProgramLocation for MockLocation {
        fn get_program(&self) -> Arc<dyn Program> {
            MockProgram::new().arc()
        }

        fn get_address(&self) -> Address {
            self.0.clone()
        }

        fn get_byte_address(&self) -> Address {
            self.0.clone()
        }
    }

    struct MockNavigatable {
        dynamic: bool,
    }

    impl Navigatable for MockNavigatable {
        fn is_connected(&self) -> bool {
            true
        }

        fn get_program(&self) -> Box<dyn Program> {
            Box::new(MockProgram::new())
        }

        fn is_dynamic(&self) -> bool {
            self.dynamic
        }
    }

    struct MockContext {
        program: Arc<dyn Program>,
        location: Option<Address>,
        /// `Some(empty)` models a selection whose `isEmpty()` answers `empty`.
        selection: Option<bool>,
        dynamic: bool,
    }

    impl MockContext {
        /// A static listing over a readable program, cursor at `0x1000`, no selection.
        fn at_cursor() -> Self {
            Self {
                program: MockProgram::new().arc(),
                location: Some(addr(0x1000)),
                selection: None,
                dynamic: false,
            }
        }

        fn with_program(program: Arc<dyn Program>) -> Self {
            Self {
                program,
                ..Self::at_cursor()
            }
        }

        fn with_selection(empty: bool) -> Self {
            Self {
                selection: Some(empty),
                ..Self::at_cursor()
            }
        }

        fn dynamic() -> Self {
            Self {
                dynamic: true,
                ..Self::at_cursor()
            }
        }
    }

    impl ListingActionContext for MockContext {
        fn get_program(&self) -> Option<Arc<dyn Program>> {
            Some(self.program.clone())
        }

        fn get_location(&self) -> Option<Arc<dyn ProgramLocation + Send + Sync>> {
            self.location
                .clone()
                .map(|a| Arc::new(MockLocation(a)) as Arc<dyn ProgramLocation + Send + Sync>)
        }

        fn get_selection(&self) -> Option<Arc<dyn ProgramSelection>> {
            self.selection
                .map(|empty| Arc::new(MockSelection { empty }) as Arc<dyn ProgramSelection>)
        }

        fn get_navigatable(&self) -> Option<Arc<dyn Navigatable + Send + Sync>> {
            Some(Arc::new(MockNavigatable {
                dynamic: self.dynamic,
            }))
        }

        fn get_component_provider(&self) -> Option<Arc<dyn Any + Send + Sync>> {
            Some(Arc::new("listing provider"))
        }
    }

    // --- listing -----------------------------------------------------------------------------

    /// A listing reporting an instruction over `instruction_at` and defined data over `data_at`,
    /// the latter optionally a pointer aiming at `pointer_target`.
    #[derive(Default)]
    struct MockListing {
        instruction_at: Option<i64>,
        data_at: Option<i64>,
        pointer_target: Option<i64>,
    }

    impl StubListing for MockListing {
        fn get_instruction_containing(&self, addr: &Address) -> Option<Arc<dyn Instruction>> {
            (self.instruction_at == Some(addr.offset()))
                .then(|| Arc::new(MockCodeUnit::default()) as Arc<dyn Instruction>)
        }

        fn get_defined_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>> {
            (self.data_at == Some(addr.offset())).then(|| {
                Arc::new(MockCodeUnit {
                    pointer_target: self.pointer_target,
                }) as Arc<dyn Data>
            })
        }
    }

    /// Stands in for both a defined `Data` and an `Instruction`. The plugin calls `isPointer()`
    /// and `getAddress(0)` on the former and nothing at all on the latter, so everything else
    /// panics.
    #[derive(Default)]
    struct MockCodeUnit {
        pointer_target: Option<i64>,
    }

    impl Settings for MockCodeUnit {}
    impl PropertySet for MockCodeUnit {}

    impl MemBuffer for MockCodeUnit {
        fn get_address(&self) -> Address { unimplemented!() }
        fn get_byte(&self, _offset: i32) -> Result<u8, MemoryAccessException> { unimplemented!() }
        fn get_bytes(&self, _buf: &mut [u8], _offset: i32) -> usize { unimplemented!() }
        fn is_big_endian(&self) -> bool { unimplemented!() }
    }

    impl CodeUnit for MockCodeUnit {
        /// The one member the plugin calls: Java's `data.getAddress(0)`.
        fn get_address(&self, op_index: i32) -> Option<Address> {
            assert_eq!(op_index, 0, "Java follows only operand 0");
            self.pointer_target.map(addr)
        }

        fn get_address_string(&self, _show_block_name: bool, _pad: bool) -> String { unimplemented!() }
        fn get_label(&self) -> Option<String> { unimplemented!() }
        fn get_symbols(&self) -> Vec<Arc<dyn Symbol>> { unimplemented!() }
        fn get_primary_symbol(&self) -> Option<Arc<dyn Symbol>> { unimplemented!() }
        fn get_min_address(&self) -> Address { unimplemented!() }
        fn get_max_address(&self) -> Address { unimplemented!() }
        fn get_mnemonic_string(&self) -> String { unimplemented!() }
        fn get_comment(&self, _comment_type: CommentType) -> Option<String> { unimplemented!() }
        fn get_comment_as_array(&self, _comment_type: CommentType) -> Vec<String> { unimplemented!() }
        fn set_comment(&mut self, _comment_type: CommentType, _comment: Option<String>) { unimplemented!() }
        fn set_comment_as_array(&mut self, _comment_type: CommentType, _comment: &[String]) { unimplemented!() }
        fn get_length(&self) -> i32 { unimplemented!() }
        fn get_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> { unimplemented!() }
        fn get_bytes_in_code_unit(&self, _buffer: &mut [u8], _buffer_offset: i32) -> Result<(), MemoryAccessException> { unimplemented!() }
        fn contains(&self, _test_addr: &Address) -> bool { unimplemented!() }
        fn compare_to(&self, _addr: &Address) -> i32 { unimplemented!() }
        fn add_mnemonic_reference(&mut self, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) { unimplemented!() }
        fn remove_mnemonic_reference(&mut self, _ref_addr: &Address) { unimplemented!() }
        fn get_mnemonic_references(&self) -> Vec<Arc<dyn Reference>> { unimplemented!() }
        fn get_operand_references(&self, _index: i32) -> Vec<Arc<dyn Reference>> { unimplemented!() }
        fn get_primary_reference(&self, _index: i32) -> Option<Arc<dyn Reference>> { unimplemented!() }
        fn add_operand_reference(&mut self, _index: i32, _ref_addr: Address, _ref_type: RefType, _source_type: SourceType) { unimplemented!() }
        fn remove_operand_reference(&mut self, _index: i32, _ref_addr: &Address) { unimplemented!() }
        fn get_references_from(&self) -> Vec<Arc<dyn Reference>> { unimplemented!() }
        fn get_reference_iterator_to(&self) -> Box<dyn ReferenceIterator> { unimplemented!() }
        fn get_program(&self) -> Arc<dyn Program> { unimplemented!() }
        fn get_external_reference(&self, _op_index: i32) -> Option<Arc<dyn ExternalReference>> { unimplemented!() }
        fn remove_external_reference(&mut self, _op_index: i32) { unimplemented!() }
        fn set_primary_memory_reference(&mut self, _reference: Arc<dyn Reference>) { unimplemented!() }
        fn set_stack_reference(&mut self, _op_index: i32, _offset: i32, _source_type: SourceType, _ref_type: RefType) { unimplemented!() }
        fn set_register_reference(&mut self, _op_index: i32, _reg: &Register, _source_type: SourceType, _ref_type: RefType) { unimplemented!() }
        fn get_num_operands(&self) -> i32 { unimplemented!() }
        fn get_scalar(&self, _op_index: i32) -> Option<Scalar> { unimplemented!() }
    }

    impl Data for MockCodeUnit {
        /// The other member the plugin calls: Java's `data.isPointer()`.
        fn is_pointer(&self) -> bool {
            self.pointer_target.is_some()
        }

        fn get_value(&self) -> Option<Box<dyn Any>> { unimplemented!() }
        fn get_value_class(&self) -> Option<TypeId> { unimplemented!() }
        fn has_string_value(&self) -> bool { unimplemented!() }
        fn is_constant(&self) -> bool { unimplemented!() }
        fn is_writable(&self) -> bool { unimplemented!() }
        fn is_volatile(&self) -> bool { unimplemented!() }
        fn is_defined(&self) -> bool { unimplemented!() }
        fn get_data_type(&self) -> Box<dyn DataType> { unimplemented!() }
        fn get_base_data_type(&self) -> Box<dyn DataType> { unimplemented!() }
        fn get_value_references(&self) -> Vec<Box<dyn DataReference>> { unimplemented!() }
        fn add_value_reference(&mut self, _ref_addr: Address, _ref_type: Box<dyn DataRefType>) { unimplemented!() }
        fn remove_value_reference(&mut self, _ref_addr: Address) { unimplemented!() }
        fn get_field_name(&self) -> Option<String> { unimplemented!() }
        fn get_path_name(&self) -> String { unimplemented!() }
        fn get_component_path_name(&self) -> String { unimplemented!() }
        fn is_union(&self) -> bool { unimplemented!() }
        fn is_structure(&self) -> bool { unimplemented!() }
        fn is_array(&self) -> bool { unimplemented!() }
        fn is_dynamic(&self) -> bool { unimplemented!() }
        fn get_parent(&self) -> Option<Box<dyn Data>> { unimplemented!() }
        fn get_root(&self) -> Box<dyn Data> { unimplemented!() }
        fn get_root_offset(&self) -> i32 { unimplemented!() }
        fn get_parent_offset(&self) -> i32 { unimplemented!() }
        fn get_component(&self, _index: i32) -> Option<Box<dyn Data>> { unimplemented!() }
        fn get_component_by_path(&self, _component_path: &[i32]) -> Option<Box<dyn Data>> { unimplemented!() }
        fn get_component_path(&self) -> Vec<i32> { unimplemented!() }
        fn get_num_components(&self) -> i32 { unimplemented!() }
        fn get_component_at(&self, _offset: i32) -> Option<Box<dyn Data>> { unimplemented!() }
        fn get_component_containing(&self, _offset: i32) -> Option<Box<dyn Data>> { unimplemented!() }
        fn get_components_containing(&self, _offset: i32) -> Option<Vec<Box<dyn Data>>> { unimplemented!() }
        fn get_primitive_at(&self, _offset: i32) -> Option<Box<dyn Data>> { unimplemented!() }
        fn get_component_index(&self) -> i32 { unimplemented!() }
        fn get_component_level(&self) -> i32 { unimplemented!() }
        fn get_default_value_representation(&self) -> String { unimplemented!() }
        fn get_default_label_prefix(&self, _options: &dyn DataTypeDisplayOptions) -> Option<String> { unimplemented!() }
    }

    impl ProcessorContextView for MockCodeUnit {
        fn get_base_context_register(&self) -> Option<RegisterRef> { unimplemented!() }
        fn get_registers(&self) -> Vec<RegisterRef> { unimplemented!() }
        fn get_register(&self, _name: &str) -> Option<RegisterRef> { unimplemented!() }
        fn get_value(&self, _register: &Register, _signed: bool) -> Option<i128> { unimplemented!() }
        fn get_register_value(&self, _register: &Register) -> Option<Box<dyn RegisterValue>> { unimplemented!() }
        fn has_value(&self, _register: &Register) -> bool { unimplemented!() }
    }

    impl ProcessorContext for MockCodeUnit {
        fn set_value(&mut self, _register: &Register, _value: i128) -> Result<(), ContextChangeException> { unimplemented!() }
        fn set_register_value(&mut self, _value: Box<dyn RegisterValue>) -> Result<(), ContextChangeException> { unimplemented!() }
        fn clear_register(&mut self, _register: &Register) -> Result<(), ContextChangeException> { unimplemented!() }
    }

    impl Instruction for MockCodeUnit {
        fn get_prototype(&self) -> Arc<dyn InstructionPrototype> { unimplemented!() }
        fn get_register(&self, _operand_index: i32) -> Option<RegisterRef> { unimplemented!() }
        fn get_op_objects(&self, _operand_index: i32) -> Vec<OperandValue> { unimplemented!() }
        fn get_input_objects(&self) -> Vec<OperandValue> { unimplemented!() }
        fn get_result_objects(&self) -> Vec<OperandValue> { unimplemented!() }
        fn get_default_operand_representation(&self, _operand_index: i32) -> String { unimplemented!() }
        fn get_default_operand_representation_list(&self, _operand_index: i32) -> Option<Vec<OperandValue>> { unimplemented!() }
        fn get_separator(&self, _operand_index: i32) -> Option<String> { unimplemented!() }
        fn get_operand_type(&self, _operand_index: i32) -> i32 { unimplemented!() }
        fn get_operand_ref_type(&self, _operand_index: i32) -> RefType { unimplemented!() }
        fn get_default_fall_through_offset(&self) -> i32 { unimplemented!() }
        fn get_default_fall_through(&self) -> Option<Address> { unimplemented!() }
        fn get_fall_through(&self) -> Option<Address> { unimplemented!() }
        fn get_fall_from(&self) -> Option<Address> { unimplemented!() }
        fn get_flows(&self) -> Option<Vec<Address>> { unimplemented!() }
        fn get_default_flows(&self) -> Option<Vec<Address>> { unimplemented!() }
        fn get_flow_type(&self) -> RefType { unimplemented!() }
        fn is_fallthrough(&self) -> bool { unimplemented!() }
        fn has_fallthrough(&self) -> bool { unimplemented!() }
        fn get_flow_override(&self) -> FlowOverride { unimplemented!() }
        fn set_flow_override(&mut self, _flow_override: FlowOverride) { unimplemented!() }
        fn set_length_override(&mut self, _length: i32) -> Result<(), CodeUnitInsertionException> { unimplemented!() }
        fn is_length_overridden(&self) -> bool { unimplemented!() }
        fn get_parsed_length(&self) -> i32 { unimplemented!() }
        fn get_parsed_bytes(&self) -> Result<Vec<u8>, MemoryAccessException> { unimplemented!() }
        fn get_pcode(&self) -> Vec<PcodeOp> { unimplemented!() }
        fn get_pcode_with_overrides(&self, _include_overrides: bool) -> Vec<PcodeOp> { unimplemented!() }
        fn get_pcode_for_operand(&self, _operand_index: i32) -> Vec<PcodeOp> { unimplemented!() }
        fn get_delay_slot_depth(&self) -> i32 { unimplemented!() }
        fn is_in_delay_slot(&self) -> bool { unimplemented!() }
        fn get_next(&self) -> Option<Arc<dyn Instruction>> { unimplemented!() }
        fn get_previous(&self) -> Option<Arc<dyn Instruction>> { unimplemented!() }
        fn set_fall_through(&mut self, _addr: Option<Address>) { unimplemented!() }
        fn clear_fall_through_override(&mut self) { unimplemented!() }
        fn is_fall_through_overridden(&self) -> bool { unimplemented!() }
        fn get_instruction_context(&self) -> Arc<dyn InstructionContext> { unimplemented!() }
    }

    // --- tool --------------------------------------------------------------------------------

    #[derive(Default)]
    struct MockTool {
        actions_added: AtomicUsize,
        status_info: Mutex<Vec<(String, bool)>>,
        commands_run: AtomicUsize,
        /// Whether each shown dialog was centered on a component provider.
        dialogs_shown: Mutex<Vec<bool>>,
    }

    impl PluginTool for MockTool {
        fn add_action(&self, _action: Arc<dyn Any + Send + Sync>) {
            self.actions_added.fetch_add(1, Ordering::SeqCst);
        }

        fn execute_background_command(
            &self,
            _cmd: Arc<dyn Any + Send + Sync>,
            _obj: Arc<dyn Program>,
        ) {
            self.commands_run.fetch_add(1, Ordering::SeqCst);
        }

        fn set_status_info(&self, text: &str, beep: bool) {
            self.status_info
                .lock()
                .unwrap()
                .push((text.to_string(), beep));
        }

        fn show_dialog(
            &self,
            _dialog_component: Arc<dyn Any + Send + Sync>,
            centered_on_provider: Option<Arc<dyn Any + Send + Sync>>,
        ) {
            self.dialogs_shown
                .lock()
                .unwrap()
                .push(centered_on_provider.is_some());
        }
    }

    // --- actions, commands, dialog -----------------------------------------------------------

    /// An action the plugin only ever installs.
    struct MockAction;

    impl ListingContextAction for MockAction {
        fn action_performed(&self, _context: &dyn ListingActionContext) {}

        fn is_enabled_for_context(&self, _context: &dyn ListingActionContext) -> bool {
            true
        }

        fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    fn mock_actions() -> DisassemblerActions {
        fn action() -> Arc<dyn ListingContextAction> {
            Arc::new(MockAction)
        }
        DisassemblerActions {
            disassemble_restricted_action: action(),
            disassemble_action: action(),
            disassemble_static_action: action(),
            context_action: action(),
            arm_disassemble_action: action(),
            arm_thumb_disassemble_action: action(),
            hcs12_disassemble_action: action(),
            xgate_disassemble_action: action(),
            mips_disassemble_action: action(),
            mips16_disassemble_action: action(),
            ppc_disassemble_action: action(),
            ppc_vle_disassemble_action: action(),
            x86_64_disassemble_action: action(),
            x86_32_disassemble_action: action(),
            set_flow_override_action: action(),
            set_length_override_action: action(),
        }
    }

    #[derive(Default)]
    struct MockCommand {
        code_analysis: Mutex<Vec<bool>>,
    }

    impl DisassembleCommand for MockCommand {
        fn enable_code_analysis(&self, enable: bool) {
            self.code_analysis.lock().unwrap().push(enable);
        }

        fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    struct MockDialog;

    impl ProcessorStateDialog for MockDialog {
        fn ok_callback(&self) {}

        fn as_any_arc(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    /// Records the request the plugin builds, and hands back a fresh command.
    fn recording_factory(
        seen: Arc<Mutex<Vec<DisassembleRequest>>>,
    ) -> impl FnMut(&DisassembleRequest) -> Arc<dyn DisassembleCommand> {
        move |request| {
            seen.lock().unwrap().push(request.clone());
            Arc::new(MockCommand::default())
        }
    }

    fn plugin_with(tool: Arc<MockTool>) -> DisassemblerPlugin {
        DisassemblerPlugin::new(tool, mock_actions())
    }

    /// `seed/restriction/flag`, i.e. the three arguments Java passes to a command constructor.
    fn describe(request: &DisassembleRequest) -> String {
        let seed = match &request.seed {
            DisassembleSeed::Selection(_) => "selection".to_string(),
            DisassembleSeed::Address(a) => format!("addr:{:x}", a.offset()),
        };
        let restriction = match &request.restriction {
            DisassembleRestriction::Unrestricted => "none".to_string(),
            DisassembleRestriction::Selection(_) => "selection".to_string(),
            DisassembleRestriction::Set(set) => format!(
                "set:{:x}..{:x}",
                set.min_address().unwrap().offset(),
                set.max_address().unwrap().offset()
            ),
        };
        format!("{seed}/{restriction}/{}", request.flag)
    }

    // --- tests -------------------------------------------------------------------------------

    #[test]
    fn static_metadata_matches_java() {
        assert_eq!(
            DisassemblerPlugin::get_description(),
            "Provides disassembler services for all supplied machine language modules."
        );
        assert_eq!(DisassemblerPlugin::get_descriptive_name(), "Disassembler");
        assert_eq!(DisassemblerPlugin::get_category(), "Disassemblers");
        assert_eq!(GROUP_NAME, "Disassembly");
    }

    #[test]
    fn description_mirrors_the_plugin_info_annotation() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let description = plugin.plugin_description();

        assert_eq!(description.name(), "DisassemblerPlugin");
        assert_eq!(description.short_description(), "Disassembler");
        assert_eq!(description.category(), "Analysis");
        assert_eq!(description.status(), PluginStatus::Released);
        assert_eq!(description.plugin_package().name(), "Ghidra Core");
        assert!(description.services_required().is_empty());
        assert!(description.services_provided().is_empty());
        assert_eq!(
            description.events_consumed(),
            vec!["ghidra.app.events.ProgramActivatedPluginEvent"]
        );
        assert!(description.events_produced().is_empty());
        assert!(description
            .description()
            .starts_with("This plugin provides functionality for dynamic disassembly"));
    }

    #[test]
    fn construction_installs_all_sixteen_actions() {
        let tool = Arc::new(MockTool::default());
        let _plugin = plugin_with(tool.clone());

        assert_eq!(tool.actions_added.load(Ordering::SeqCst), 16);
    }

    #[test]
    fn program_activated_registers_the_three_disassembler_options() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let program = MockProgram::new();
        let registered = program.registered.clone();
        let options_asked = program.options_asked.clone();

        plugin.program_activated(&program);

        assert_eq!(*options_asked.lock().unwrap(), vec!["Disassembler"]);
        let registered = registered.lock().unwrap();
        let names: Vec<&str> = registered.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "Mark Bad Disassembly=true",
                "Mark Unimplemented Pcode=true",
                "Restrict Disassembly to Executable Memory=false",
            ]
        );
        assert_eq!(
            registered[0].1,
            "Place ERROR Bookmark at locations where disassembly could not be perfomed."
        );
    }

    #[test]
    fn a_null_activated_program_registers_nothing() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let program = MockProgram::new();
        let registered = program.registered.clone();

        // `ProgramActivatedPluginEvent` holds the program weakly, so dropping the only strong
        // handle makes `getActiveProgram()` answer Java's null.
        let handle = program.arc();
        let event = ProgramActivatedPluginEvent::new("Test", handle.clone());
        drop(handle);
        plugin.process_program_activated_event(&event);

        assert!(registered.lock().unwrap().is_empty());
    }

    #[test]
    fn a_selection_seeds_a_restricted_command_confined_to_that_selection() {
        let tool = Arc::new(MockTool::default());
        let plugin = plugin_with(tool.clone());
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let mut factory = recording_factory(seen.clone());

        let cmd = plugin
            .disassemble_restricted_callback(&MockContext::with_selection(false), &mut factory);

        assert!(cmd.is_some());
        assert_eq!(
            describe(&seen.lock().unwrap()[0]),
            "selection/selection/true"
        );
        assert_eq!(tool.commands_run.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_empty_selection_falls_back_to_the_cursor_address() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let mut factory = recording_factory(seen.clone());

        // Java's guard is `selection != null && !selection.isEmpty()`, so an empty selection takes
        // the same branch as no selection at all: `new AddressSet(addr, addr)`.
        plugin.disassemble_restricted_callback(&MockContext::with_selection(true), &mut factory);

        assert_eq!(
            describe(&seen.lock().unwrap()[0]),
            "addr:1000/set:1000..1000/true"
        );
    }

    #[test]
    fn static_disassembly_does_not_follow_flow() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let mut factory = recording_factory(seen.clone());

        plugin.disassemble_static_callback(&MockContext::with_selection(false), &mut factory);
        plugin.disassemble_static_callback(&MockContext::at_cursor(), &mut factory);

        let seen = seen.lock().unwrap();
        assert_eq!(describe(&seen[0]), "selection/selection/false");
        assert_eq!(describe(&seen[1]), "addr:1000/set:1000..1000/false");
    }

    #[test]
    fn plain_disassembly_is_unrestricted_and_enables_code_analysis() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let command = Arc::new(MockCommand::default());
        let mut factory = {
            let seen = seen.clone();
            let command = command.clone();
            move |request: &DisassembleRequest| {
                seen.lock().unwrap().push(request.clone());
                command.clone() as Arc<dyn DisassembleCommand>
            }
        };

        plugin.disassemble_callback(&MockContext::at_cursor(), &mut factory);

        assert_eq!(describe(&seen.lock().unwrap()[0]), "addr:1000/none/true");
        // The listing is static, so follow-on analysis is enabled.
        assert_eq!(*command.code_analysis.lock().unwrap(), vec![true]);
    }

    #[test]
    fn plain_disassembly_over_a_dynamic_listing_disables_code_analysis() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let command = Arc::new(MockCommand::default());
        let mut factory = {
            let command = command.clone();
            move |_request: &DisassembleRequest| command.clone() as Arc<dyn DisassembleCommand>
        };

        plugin.disassemble_callback(&MockContext::dynamic(), &mut factory);

        assert_eq!(*command.code_analysis.lock().unwrap(), vec![false]);
    }

    #[test]
    fn uninitialized_memory_under_the_cursor_builds_no_command_and_reports_it() {
        let tool = Arc::new(MockTool::default());
        let plugin = plugin_with(tool.clone());
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let mut factory = recording_factory(seen.clone());

        let context = MockContext::with_program(MockProgram::unreadable().arc());
        let cmd = plugin.disassemble_callback(&context, &mut factory);

        assert!(cmd.is_none());
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(tool.commands_run.load(Ordering::SeqCst), 0);
        assert_eq!(
            *tool.status_info.lock().unwrap(),
            vec![("Can't disassemble uninitialized memory!".to_string(), true)]
        );
    }

    #[test]
    fn each_architecture_callback_passes_its_mode_through_unrestricted() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let mut factory = recording_factory(seen.clone());
        let context = MockContext::at_cursor();

        plugin.disassemble_arm_callback(&context, true, &mut factory);
        plugin.disassemble_hcs12_callback(&context, true, &mut factory);
        plugin.disassemble_mips_callback(&context, false, &mut factory);
        plugin.disassemble_ppc_callback(&context, true, &mut factory);
        plugin.disassemble_x86_64_callback(&context, false, &mut factory);

        let seen = seen.lock().unwrap();
        let described: Vec<String> = seen.iter().map(describe).collect();
        assert_eq!(
            described,
            vec![
                "addr:1000/none/true",
                "addr:1000/none/true",
                "addr:1000/none/false",
                "addr:1000/none/true",
                "addr:1000/none/false",
            ]
        );
    }

    #[test]
    fn an_architecture_callback_seeds_from_a_selection_without_restricting_it() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let seen: Arc<Mutex<Vec<DisassembleRequest>>> = Arc::default();
        let mut factory = recording_factory(seen.clone());

        plugin.disassemble_arm_callback(&MockContext::with_selection(false), true, &mut factory);

        assert_eq!(describe(&seen.lock().unwrap()[0]), "selection/none/true");
    }

    #[test]
    fn disassembly_is_disabled_over_a_dynamic_listing() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let listing = MockListing::default();

        assert!(!plugin.check_disassembly_enabled(
            &MockContext::dynamic(),
            &listing,
            &addr(0x1000),
            true
        ));
    }

    #[test]
    fn disassembly_is_enabled_wherever_there_is_a_non_empty_selection() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        // An instruction already covers the address, which on its own disables the action...
        let listing = MockListing {
            instruction_at: Some(0x1000),
            ..MockListing::default()
        };

        assert!(plugin.check_disassembly_enabled(
            &MockContext::with_selection(false),
            &listing,
            &addr(0x1000),
            true
        ));
        // ...as it does with no selection.
        assert!(!plugin.check_disassembly_enabled(
            &MockContext::at_cursor(),
            &listing,
            &addr(0x1000),
            true
        ));
    }

    #[test]
    fn disassembly_of_undefined_bytes_is_enabled_only_where_memory_exists() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let listing = MockListing::default();

        assert!(plugin.check_disassembly_enabled(
            &MockContext::at_cursor(),
            &listing,
            &addr(0x1000),
            true
        ));
        // 0x1_0000 is past the end of the mock program's memory.
        assert!(!plugin.check_disassembly_enabled(
            &MockContext::at_cursor(),
            &listing,
            &addr(0x1_0000),
            true
        ));
    }

    #[test]
    fn defined_data_disables_disassembly_unless_a_pointer_leads_somewhere_disassemblable() {
        let plugin = plugin_with(Arc::new(MockTool::default()));
        let context = MockContext::at_cursor();

        // Non-pointer data: disabled outright.
        let plain_data = MockListing {
            data_at: Some(0x1000),
            ..MockListing::default()
        };
        assert!(!plugin.check_disassembly_enabled(&context, &plain_data, &addr(0x1000), true));

        // A pointer into undefined-but-mapped memory: enabled, one level down.
        let pointer = MockListing {
            data_at: Some(0x1000),
            pointer_target: Some(0x2000),
            ..MockListing::default()
        };
        assert!(plugin.check_disassembly_enabled(&context, &pointer, &addr(0x1000), true));

        // The same pointer with followPtr off: Java never dereferences it.
        assert!(!plugin.check_disassembly_enabled(&context, &pointer, &addr(0x1000), false));

        // A pointer aiming at an instruction: disabled.
        let pointer_to_code = MockListing {
            data_at: Some(0x1000),
            pointer_target: Some(0x2000),
            instruction_at: Some(0x2000),
        };
        assert!(!plugin.check_disassembly_enabled(&context, &pointer_to_code, &addr(0x1000), true));
    }

    #[test]
    fn a_program_only_has_context_registers_when_the_base_register_has_children() {
        let plugin = plugin_with(Arc::new(MockTool::default()));

        for (base, expected) in [
            (ContextBase::NoLanguage, false),
            (ContextBase::NoContext, false),
            (ContextBase::Childless, false),
            (ContextBase::WithChildren, true),
        ] {
            let program = MockProgram::with_context_base(base);
            assert_eq!(
                plugin.has_context_registers(&program),
                expected,
                "context base {}",
                base as i32
            );
        }
    }

    #[test]
    fn the_processor_state_dialog_is_shown_only_for_a_language_with_context_registers() {
        let tool = Arc::new(MockTool::default());
        let plugin = plugin_with(tool.clone());
        let mut new_dialog = || Arc::new(MockDialog) as Arc<dyn ProcessorStateDialog>;

        for base in [
            ContextBase::NoLanguage,
            ContextBase::NoContext,
            ContextBase::Childless,
        ] {
            let context = MockContext::with_program(MockProgram::with_context_base(base).arc());
            assert!(!plugin.set_default_context(&context, &mut new_dialog));
        }
        assert!(tool.dialogs_shown.lock().unwrap().is_empty());

        let context = MockContext::with_program(
            MockProgram::with_context_base(ContextBase::WithChildren).arc(),
        );
        assert!(plugin.set_default_context(&context, &mut new_dialog));

        // Java centers the dialog on `context.getComponentProvider()`.
        assert_eq!(*tool.dialogs_shown.lock().unwrap(), vec![true]);
    }

    #[test]
    fn events_consumed_lists_the_program_activated_event() {
        let plugin = plugin_with(Arc::new(MockTool::default()));

        assert_eq!(plugin.events_consumed(), vec!["Program Activated"]);
    }
}
