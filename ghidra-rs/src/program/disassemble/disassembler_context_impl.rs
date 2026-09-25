//! Port of `ghidra.program.disassemble.DisassemblerContextImpl`.
//!
//! Maintains processor state during disassembly and analysis: the register state of the
//! current instruction flow (a contiguous range of instructions), and the state recorded for
//! future flow addresses, which is picked up when the flow later starts at, or continues to,
//! one of those addresses.
//!
//! # Shape
//!
//! A concrete Java class, so a struct. Java holds the `ProgramContext` it reads defaults and
//! stored context from, and writes non-context register state back to; the disassembler hands it
//! a proxy it keeps talking to directly. Here the context *owns* that program context, generic
//! as `P`, and lends it out through [`DisassemblerContextImpl::program_context`] /
//! [`DisassemblerContextImpl::program_context_mut`], so the disassembler reaches its proxy
//! through the context rather than through a second reference.
//!
//! # `Address.NO_ADDRESS`
//!
//! Java keys flows whose origin does not matter by the `Address.NO_ADDRESS` sentinel. Here a
//! flow-from address is an `Option<&Address>`, `None` being `NO_ADDRESS`; the methods Java
//! overloads without a `fromAddr` are the plain names, and the ones taking it end in `_from`.
//! One Java quirk is kept: [`DisassemblerContextImpl::get_register_value_from`] with no flow-from
//! address looks for future state in the per-origin maps under `NO_ADDRESS`, where none is ever
//! stored, so it never sees values saved without an origin and falls back to the program context
//! (Java's `futureFlowRegisterStateMaps.get(destAddr).get(NO_ADDRESS)`).
//!
//! # Values
//!
//! Java passes `RegisterValue`s by reference and uses `null` for "no value"; here they are the
//! concrete [`RegisterValue`], with `None` for `null`. The [`ProgramContext`] trait speaks
//! `Box<dyn RegisterValue>`; values cross it exactly (see
//! [`RegisterValue::from_trait_object`]).

use std::collections::HashMap;

use crate::program::model::address::Address;
use crate::program::model::lang::disassembler_context::DisassemblerContext;
use crate::program::model::lang::processor_context::ProcessorContext;
use crate::program::model::lang::processor_context_view::ProcessorContextView;
use crate::program::model::lang::register::{Register, RegisterRef};
use crate::program::model::lang::register_value::RegisterValue;
use crate::program::model::listing::context_change_exception::ContextChangeException;
use crate::program::model::listing::program_context::ProgramContext;
use crate::program::seam_stubs::RegisterValue as RegisterValueTrait;

/// Register state keyed by base register.
type RegisterStateMap = HashMap<Register, RegisterValue>;

/// Converts a value that crossed the [`ProgramContext`] trait boundary back to the concrete type.
fn concrete(value: Box<dyn RegisterValueTrait>) -> RegisterValue {
    RegisterValue::from_trait_object(value.as_ref())
}

/// Port of the private `combineRegisterValues`: combines two values; if `new_value_precedence`,
/// the new value wins for active bits, else the current value does. `None` if both are `None`.
/// A value without any active bits counts as `None`.
fn combine_register_values(
    current_value: Option<RegisterValue>,
    new_value: Option<RegisterValue>,
    new_value_precedence: bool,
) -> Option<RegisterValue> {
    let Some(current_value) = current_value.filter(RegisterValue::has_any_value) else {
        return new_value;
    };
    let Some(new_value) = new_value.filter(RegisterValue::has_any_value) else {
        return Some(current_value);
    };
    if new_value_precedence {
        Some(current_value.combine_values(&new_value))
    } else {
        Some(new_value.combine_values(&current_value))
    }
}

/// Maintains processor state information during disassembly and analysis; see the module docs.
///
/// Port of `ghidra.program.disassemble.DisassemblerContextImpl`.
pub struct DisassemblerContextImpl<P> {
    program_context: P,
    start_addr: Option<Address>,
    context_change_point: Option<Address>,
    current_address: Option<Address>,
    context_register: RegisterRef,
    /// Active context register state for the current flow location.
    context_register_value: Option<RegisterValue>,
    /// Delayed context register state for the current flow location. Set only if the context
    /// value changed for the current flow location.
    delayed_context_register_value: Option<RegisterValue>,
    /// Non-flowing context-register value which repeats until the next context change point.
    repeated_noflow_value: Option<RegisterValue>,
    /// Active register values (never the context register, never language defaults) for the
    /// current flow location.
    register_state_map: RegisterStateMap,
    /// Future register state for flow starts whose origin does not matter (`NO_ADDRESS`), by
    /// destination.
    no_address_future_register_state_map: HashMap<Address, RegisterStateMap>,
    /// Future register state by destination, then by the address the flow comes from.
    future_flow_register_state_maps: HashMap<Address, HashMap<Address, RegisterStateMap>>,
}

impl<P: ProgramContext> DisassemblerContextImpl<P> {
    /// Port of `DisassemblerContextImpl(ProgramContext)`.
    ///
    /// # Arguments
    /// * `program_context` - the values for registers at specific addresses stored in the program
    pub fn new(program_context: P) -> Self {
        let context_register = program_context.get_base_context_register();
        DisassemblerContextImpl {
            context_register_value: Some(RegisterValue::new(context_register.clone())),
            program_context,
            start_addr: None,
            context_change_point: None,
            current_address: None,
            context_register,
            delayed_context_register_value: None,
            repeated_noflow_value: None,
            register_state_map: HashMap::new(),
            no_address_future_register_state_map: HashMap::new(),
            future_flow_register_state_maps: HashMap::new(),
        }
    }

    /// The program context this context reads and writes. Port of `getProgramContext()`.
    pub fn program_context(&self) -> &P {
        &self.program_context
    }

    /// The program context, for writing.
    pub fn program_context_mut(&mut self) -> &mut P {
        &mut self.program_context
    }

    /// The processor context base register (Java's `Register.NO_CONTEXT` for a language without
    /// one). Port of `getBaseContextRegister()`.
    pub fn base_context_register(&self) -> &RegisterRef {
        &self.context_register
    }

    fn flow_value(&self, value: Option<&RegisterValue>) -> Option<RegisterValue> {
        value.map(|v| concrete(self.program_context.get_flow_value(Box::new(v.clone()))))
    }

    fn non_flow_value(&self, value: Option<RegisterValue>) -> Option<RegisterValue> {
        value.and_then(|v| self.program_context.get_non_flow_value(Box::new(v)).map(concrete))
    }

    fn default_context_value(&self, address: &Address) -> Option<RegisterValue> {
        self.program_context.get_default_value(&self.context_register, address).map(concrete)
    }

    /// Saves the current processor state for when this context flows to `address`, whatever it
    /// flows from. Port of `copyToFutureFlowState(Address)`.
    ///
    /// Returns the context register value which was copied.
    pub fn copy_to_future_flow_state(&mut self, address: &Address) -> Option<RegisterValue> {
        self.copy_to_future_flow_state_from(None, address)
    }

    /// Saves the current processor state flowing from `from_addr`, for when this context flows to
    /// `dest_addr`. Port of `copyToFutureFlowState(Address, Address)`.
    ///
    /// Returns the context register value which was copied.
    pub fn copy_to_future_flow_state_from(
        &mut self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
    ) -> Option<RegisterValue> {
        if self.current_address.as_ref() == Some(dest_addr) {
            return self.context_register_value.clone();
        }
        // give precedence to any future context set explicitly during instruction parse
        let flow_value = self.flow_value(
            self.delayed_context_register_value.as_ref().or(self.context_register_value.as_ref()),
        );
        self.set_future_register_value_internal(from_addr, dest_addr, flow_value.clone(), false);

        let values: Vec<RegisterValue> = self.register_state_map.values().cloned().collect();
        for value in values {
            self.set_future_register_value_internal(from_addr, dest_addr, Some(value), false);
        }
        flow_value
    }

    /// Saves the current processor state for when this context is later used at `address`,
    /// whatever it flows from, returning the values that collided with ones already saved there.
    /// Port of `mergeToFutureFlowState(Address)`.
    pub fn merge_to_future_flow_state(&mut self, address: &Address) -> Vec<RegisterValue> {
        self.merge_to_future_flow_state_from(None, address)
    }

    /// Saves the current processor state flowing from `from_addr` to `dest_addr`, returning the
    /// values that collided with ones already saved there. Port of
    /// `mergeToFutureFlowState(Address, Address)`.
    pub fn merge_to_future_flow_state_from(
        &mut self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
    ) -> Vec<RegisterValue> {
        let mut collision_list = Vec::new();
        if self.current_address.as_ref() == Some(dest_addr) {
            return collision_list;
        }
        let flow_value = self.flow_value(self.context_register_value.as_ref());
        self.set_future_register_value_internal(from_addr, dest_addr, flow_value, false);

        let entries: Vec<(Register, RegisterValue)> =
            self.register_state_map.iter().map(|(r, v)| (r.clone(), v.clone())).collect();
        for (reg, value) in entries {
            let cur_value = self.get_register_value_from(&reg, from_addr, dest_addr);
            // check if there already is a value
            if let Some(cur_value) = cur_value {
                if value != cur_value {
                    collision_list.push(value.clone());
                }
            }
            self.set_future_register_value_internal(from_addr, dest_addr, Some(value), false);
        }
        collision_list
    }

    /// Terminates the active flow while preserving any accumulated future context. Port of
    /// `flowAbort()`.
    ///
    /// # Panics
    /// If no flow is active (Java's `IllegalStateException`).
    pub fn flow_abort(&mut self) {
        if !self.is_flow_active() {
            panic!("Attempted to abort a flow that was not started.");
        }
        self.start_addr = None;
        self.current_address = None;
    }

    /// Starts a new flow at `address`, whatever it flows from, initializing the current state of
    /// all registers from any future flow state saved for it. Port of `flowStart(Address)`.
    ///
    /// # Panics
    /// If a previous flow was not ended (Java's `IllegalStateException`).
    pub fn flow_start(&mut self, address: &Address) {
        self.flow_start_from(None, address);
    }

    /// Starts a new flow from `from_addr` to `to_addr`, initializing the current state of all
    /// registers from any future flow state saved for that flow. Port of
    /// `flowStart(Address, Address)`.
    ///
    /// # Panics
    /// If a previous flow was not ended (Java's `IllegalStateException`).
    pub fn flow_start_from(&mut self, from_addr: Option<&Address>, to_addr: &Address) {
        if self.is_flow_active() {
            panic!("Previous flow was not ended.");
        }
        self.start_addr = Some(to_addr.clone());
        self.current_address = Some(to_addr.clone());
        self.register_state_map.clear();
        self.context_register_value = None;
        self.delayed_context_register_value = None;
        self.context_change_point = Some(to_addr.clone());

        // get next context value within flow, combining current, future, previously stored and
        // default context values. Java makes the future state map the register state map before
        // taking the context register out of it, so the register state never holds the context
        // register.
        let mut future_state_map = self.take_future_register_state_map(from_addr, to_addr);
        let next = self.get_next_context_in_flow(to_addr, future_state_map.as_mut(), true);
        self.register_state_map = future_state_map.unwrap_or_default();
        self.context_register_value = Some(next);

        self.set_next_context_change_point(to_addr);
    }

    /// The flowed context value at an arbitrary destination, whatever it flows from, without
    /// affecting state. Port of `getFlowContextValue(Address, boolean)`.
    pub fn get_flow_context_value(&self, dest_addr: &Address, is_fall_through: bool) -> RegisterValue {
        self.get_flow_context_value_from(None, dest_addr, is_fall_through)
    }

    /// The flowed context value at a destination that has been flowed to from `from_addr`,
    /// without affecting state. Port of `getFlowContextValue(Address, Address, boolean)`.
    pub fn get_flow_context_value_from(
        &self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
        is_fall_through: bool,
    ) -> RegisterValue {
        if self.is_flow_active() && self.current_address.as_ref() == Some(dest_addr) {
            return self.context_register_value.clone().expect("an active flow has a context value");
        }

        // strip non-flowing context
        let mut next_context_register_value = self.flow_value(self.context_register_value.as_ref());

        // combine in any context register value from the future flow state
        if let Some(future_state_map) = self.peek_future_register_state_map(from_addr, dest_addr) {
            let future_context_register_value = future_state_map.get(&self.context_register).cloned();
            next_context_register_value = combine_register_values(
                next_context_register_value,
                future_context_register_value,
                true,
            );
        }

        // combine any previously stored context with future state value
        let mut pre_existing_context_register_value =
            Some(concrete(self.program_context.get_disassembly_context(dest_addr)));
        if is_fall_through {
            pre_existing_context_register_value =
                self.non_flow_value(pre_existing_context_register_value);
        }
        next_context_register_value = combine_register_values(
            pre_existing_context_register_value,
            next_context_register_value,
            true,
        );

        // combine default context
        let default_value = self.default_context_value(dest_addr);
        next_context_register_value =
            combine_register_values(default_value, next_context_register_value, true);

        next_context_register_value.unwrap_or_else(|| RegisterValue::new(self.context_register.clone()))
    }

    /// Continues the current flow at `address`, whatever it flows from. If any registers have
    /// saved future state there, the current state of all registers is written to the program
    /// context up to `address` (exclusive), and the future state becomes current. Port of
    /// `flowToAddress(Address)`.
    ///
    /// # Panics
    /// If no flow was started, or `address` precedes the current address.
    pub fn flow_to_address(&mut self, address: &Address) {
        self.flow_to_address_from(None, address);
    }

    /// Continues the current flow from `from_addr` to `dest_addr`; see
    /// [`DisassemblerContextImpl::flow_to_address`]. Port of `flowToAddress(Address, Address)`.
    ///
    /// # Panics
    /// If no flow was started (Java's `IllegalStateException`), or `dest_addr` precedes the
    /// current address (Java's `IllegalArgumentException`).
    pub fn flow_to_address_from(&mut self, from_addr: Option<&Address>, dest_addr: &Address) {
        if !self.is_flow_active() {
            panic!("Attempted to continue a flow that was not started.");
        }
        let current = self.current_address.clone().expect("an active flow has a current address");
        if current > *dest_addr {
            panic!("address must not be less than current address");
        }
        if current == *dest_addr {
            return;
        }

        self.current_address = Some(dest_addr.clone());

        if let Some(delayed) = self.delayed_context_register_value.clone() {
            if Some(&delayed) != self.context_register_value.as_ref() {
                // flush current range due to delayed context change
                self.flush_current_range();
                self.context_register_value = Some(delayed);
                self.start_addr = Some(dest_addr.clone());
            }
        }

        // get next context value within flow, combining current, future, previously stored and
        // default context values
        let mut future_state_map = self.take_future_register_state_map(from_addr, dest_addr);
        let next_context_register_value =
            self.get_next_context_in_flow(dest_addr, future_state_map.as_mut(), false);
        self.delayed_context_register_value = None;

        // continue flowing context if no change
        if future_state_map.is_none()
            && Some(&next_context_register_value) == self.context_register_value.as_ref()
        {
            return;
        }

        // store context to program over previous range
        self.flush_current_range();

        // start new range using modified context
        self.start_addr = Some(dest_addr.clone());
        self.context_register_value = Some(next_context_register_value);

        // update all other registers values in current state
        if let Some(future_state_map) = future_state_map {
            for (register, future_value) in future_state_map {
                let future_value = match self.register_state_map.get(&register) {
                    Some(current_value) => current_value.combine_values(&future_value),
                    None => future_value,
                };
                self.register_state_map.insert(register, future_value);
            }
        }
    }

    /// Java's `if (!startAddr.equals(currentAddress)) saveProgramContext(startAddr,
    /// currentAddress.previous())`.
    fn flush_current_range(&mut self) {
        let start = self.start_addr.clone().expect("an active flow has a start address");
        let current = self.current_address.clone().expect("an active flow has a current address");
        if start != current {
            self.save_program_context(&start, current.previous().ok().as_ref());
        }
    }

    /// Port of the private `getFutureRegisterStateMap(fromAddr, destAddr, true)`: removes and
    /// returns the future state saved for the flow.
    fn take_future_register_state_map(
        &mut self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
    ) -> Option<RegisterStateMap> {
        // if we don't know the fromAddr for this flow, then just use the simple map, which is
        // always indexed on destAddr
        let Some(from_addr) = from_addr else {
            return self.no_address_future_register_state_map.remove(dest_addr);
        };

        // if we have a fromAddr for this flow, then look up the destAddr, then look in a sub-map
        // to find the address we flowed from
        let future_register_state_map = self.future_flow_register_state_maps.get_mut(dest_addr)?;
        let future_state_map = future_register_state_map.remove(from_addr);
        // Java drops the destination's entry only when the removed map itself is empty.
        if future_state_map.as_ref().is_some_and(HashMap::is_empty) {
            self.future_flow_register_state_maps.remove(dest_addr);
        }
        future_state_map
    }

    /// Port of the private `getFutureRegisterStateMap(fromAddr, destAddr, false)`.
    fn peek_future_register_state_map(
        &self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
    ) -> Option<&RegisterStateMap> {
        match from_addr {
            None => self.no_address_future_register_state_map.get(dest_addr),
            Some(from_addr) => self.future_flow_register_state_maps.get(dest_addr)?.get(from_addr),
        }
    }

    /// Port of the private `findFutureFlowStateMap`: the future flow state for the flow,
    /// created if absent.
    fn find_future_flow_state_map(
        &mut self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
    ) -> &mut RegisterStateMap {
        match from_addr {
            // for NO_ADDRESS flow from, always look up by the destAddr
            None => self.no_address_future_register_state_map.entry(dest_addr.clone()).or_default(),
            // for flows where the flowFrom addr is known, look up by destAddr first, then
            // flowFrom addr
            Some(from_addr) => self
                .future_flow_register_state_maps
                .entry(dest_addr.clone())
                .or_default()
                .entry(from_addr.clone())
                .or_default(),
        }
    }

    /// Port of the private `getNextContextInFlow`: the next (i.e., fall-through) context register
    /// value in the active flow. Internal state may be updated to track the next future context
    /// change point. The context register's future value, if any, is taken out of
    /// `future_state_map`.
    fn get_next_context_in_flow(
        &mut self,
        address: &Address,
        future_state_map: Option<&mut RegisterStateMap>,
        start_of_flow: bool,
    ) -> RegisterValue {
        let mut context_value = self.context_register_value.clone();
        if self.delayed_context_register_value.is_some() {
            context_value = combine_register_values(
                context_value,
                self.delayed_context_register_value.clone(),
                true,
            );
        }
        // strip non-flowing context
        let mut next_context_register_value = self.flow_value(context_value.as_ref());

        // combine in any context register value from the future flow state
        if let Some(future_state_map) = future_state_map {
            let future_context_register_value = future_state_map.remove(&self.context_register);
            next_context_register_value = combine_register_values(
                next_context_register_value,
                future_context_register_value,
                true,
            );
        }

        // combine any previously stored context with future state value
        let reached_change_point =
            self.context_change_point.as_ref().is_some_and(|point| address >= point);
        if reached_change_point {
            let mut pre_existing_context_register_value =
                Some(concrete(self.program_context.get_disassembly_context(address)));
            self.repeated_noflow_value = self.non_flow_value(pre_existing_context_register_value.clone());
            if !start_of_flow {
                pre_existing_context_register_value = self.repeated_noflow_value.clone();
            }
            next_context_register_value = combine_register_values(
                pre_existing_context_register_value,
                next_context_register_value,
                true,
            );
            self.set_next_context_change_point(address);
        } else if let Some(repeated) =
            self.repeated_noflow_value.clone().filter(RegisterValue::has_any_value)
        {
            // combine any repeated noflow context
            next_context_register_value =
                combine_register_values(Some(repeated), next_context_register_value, true);
        }

        // combine default context
        let default_value = self.default_context_value(address);
        next_context_register_value =
            combine_register_values(default_value, next_context_register_value, true);

        next_context_register_value.unwrap_or_else(|| RegisterValue::new(self.context_register.clone()))
    }

    fn set_next_context_change_point(&mut self, current_address: &Address) {
        let range = self
            .program_context
            .get_register_value_range_containing(&self.context_register, current_address);
        // `None` at the end of the space
        self.context_change_point = range.max_address().add_no_wrap(1).ok();
    }

    /// Ends the current flow. Unsaved register values are saved up to and including
    /// `max_address`. If `max_address` is `None`, or the flow start has already advanced beyond
    /// it, no save is performed. Port of `flowEnd(Address)`.
    ///
    /// # Panics
    /// If a flow has not been started (Java's `IllegalStateException`).
    pub fn flow_end(&mut self, max_address: Option<&Address>) {
        if !self.is_flow_active() {
            panic!("Attempted to end a flow that was not started.");
        }
        let start = self.start_addr.clone().expect("an active flow has a start address");
        if let Some(max_address) = max_address {
            if *max_address >= start {
                self.save_program_context(&start, Some(max_address));
            }
        }
        self.start_addr = None;
        self.current_address = None;
    }

    /// The value of `register` at the current flow location. Port of
    /// `getRegisterValue(Register)`.
    ///
    /// Outside a flow, Java asks the program context about the `null` current address; here
    /// there is no program value to combine then.
    pub fn get_register_value(&self, register: &Register) -> Option<RegisterValue> {
        if register.is_processor_context() {
            return self.context_register_value.as_ref().map(|v| v.get_register_value(register));
        }

        let base_register = register.get_base_register();

        // if we have a current value and it specifies all the required bits then return it
        let value = self
            .register_state_map
            .get(&base_register)
            .map(|v| v.get_register_value(register));
        if value.as_ref().is_some_and(RegisterValue::has_value) {
            return value;
        }

        // otherwise get the value stored in the program and combine with any current bits
        let program_value = self
            .current_address
            .as_ref()
            .and_then(|current| self.program_context.get_register_value(&base_register, current))
            .map(concrete);
        let Some(program_value) = program_value else {
            return value;
        };
        let program_value = program_value.get_register_value(register);
        Some(match value {
            Some(value) => program_value.combine_values(&value),
            None => program_value,
        })
    }

    /// Port of `getValue(Register, boolean)`: the value of `register` at the current flow
    /// location, if it is fully known.
    pub fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        let value = self.get_register_value(register)?;
        if signed {
            value.signed_value()
        } else {
            value.unsigned_value().map(|v| v as i128)
        }
    }

    /// Sets the value of `register` to be used when the flow advances to `address` using either
    /// the flow-to or flow-start methods, whatever it flows from. The new value has precedence
    /// over any existing value. Port of `setValue(Register, Address, BigInteger)`.
    pub fn set_value_at(&mut self, register: &Register, address: &Address, new_value: u128) {
        self.set_future_register_value_internal(
            None,
            address,
            Some(RegisterValue::with_value(register.clone(), new_value)),
            true,
        );
    }

    /// Sets the value of `register` to be used when the flow from `from_addr` advances to
    /// `to_addr`. The new value has precedence over any existing value. Port of
    /// `setValue(Register, Address, Address, BigInteger)`.
    pub fn set_value_from(
        &mut self,
        register: &Register,
        from_addr: Option<&Address>,
        to_addr: &Address,
        new_value: u128,
    ) {
        self.set_future_register_value_internal(
            from_addr,
            to_addr,
            Some(RegisterValue::with_value(register.clone(), new_value)),
            true,
        );
    }

    /// Port of `setFutureRegisterValue(Address, RegisterValue)` in the concrete value domain.
    pub fn set_future_register_value_at(&mut self, address: &Address, value: Option<RegisterValue>) {
        self.set_future_register_value_internal(None, address, value, true);
    }

    /// Port of `setFutureRegisterValue(Address, Address, RegisterValue)` in the concrete value
    /// domain.
    pub fn set_future_register_value_from(
        &mut self,
        from_addr: Option<&Address>,
        to_addr: &Address,
        value: Option<RegisterValue>,
    ) {
        self.set_future_register_value_internal(from_addr, to_addr, value, true);
    }

    /// Port of the private `setRegisterValue(Address, Address, RegisterValue, boolean)`: stores
    /// `new_value` as future state for the flow; with `new_value_precedence` the new value
    /// overrides the current one. A value for the current flow location is applied to the
    /// current state instead.
    fn set_future_register_value_internal(
        &mut self,
        from_addr: Option<&Address>,
        dest_addr: &Address,
        new_value: Option<RegisterValue>,
        mut new_value_precedence: bool,
    ) {
        let Some(new_value) = new_value else {
            return;
        };
        if self.is_flow_active() && self.current_address.as_ref() == Some(dest_addr) {
            self.set_register_value_now(new_value);
            return;
        }
        let base_register = new_value.register().get_base_register();

        // merge the new value with any existing future value, or a value from the program if the
        // future value was not previously set
        let mut value = self
            .find_future_flow_state_map(from_addr, dest_addr)
            .get(&base_register)
            .cloned();
        if value.is_none() {
            // if there is no previously saved future value, always give precedence to the new
            // value
            value = self
                .program_context
                .get_non_default_value(&base_register, dest_addr)
                .map(concrete);
            new_value_precedence = true;
        }
        let value = combine_register_values(value, Some(new_value), new_value_precedence)
            .expect("combining with a value yields a value");

        self.find_future_flow_state_map(from_addr, dest_addr).insert(base_register, value);
    }

    /// The current flow address, or `None` outside a flow. Port of `getAddress()`.
    pub fn get_address(&self) -> Option<&Address> {
        self.current_address.as_ref()
    }

    /// Port of the private `saveProgramContext`: saves the non-context register state from
    /// `start` to `end` (both inclusive) back to the program's stored context.
    ///
    /// # Panics
    /// If `end` is `None` or precedes `start` (Java's `IllegalArgumentException`).
    fn save_program_context(&mut self, start: &Address, end: Option<&Address>) {
        let end = match end {
            Some(end) if start <= end => end,
            _ => panic!("Invalid context range: ({start},{})", end.map_or("null".to_string(), ToString::to_string)),
        };
        for (reg, value) in &self.register_state_map {
            if reg.is_processor_context() {
                continue;
            }
            // we should never be writing the context register, so a ContextChangeException is
            // not expected
            let _ = self.program_context.set_register_value(start, end, Box::new(value.clone()));
        }
    }

    /// Port of `setValue(Register, BigInteger)`: sets `register` at the current flow location.
    ///
    /// # Panics
    /// If no flow is active.
    pub fn set_value_now(&mut self, register: &Register, value: u128) {
        self.set_register_value_now(RegisterValue::with_value(register.clone(), value));
    }

    /// Port of `clearRegister(Register)`.
    ///
    /// # Panics
    /// If no flow is active (Java's `IllegalStateException`).
    pub fn clear_register_now(&mut self, register: &Register) {
        if !self.is_flow_active() {
            panic!("Context flow has not be started");
        }
        let start = self.start_addr.clone().expect("an active flow has a start address");
        let current = self.current_address.clone().expect("an active flow has a current address");
        if start != current {
            self.save_program_context(&start, current.previous().ok().as_ref());
            self.start_addr = Some(current);
        }
        if register.is_processor_context() {
            if let Some(context) = &self.context_register_value {
                self.context_register_value = Some(context.clear_bit_values(&register.base_mask()));
            }
        } else {
            let base_register = register.get_base_register();
            let current_value = self.register_state_map.remove(&base_register);
            if let Some(current_value) = current_value {
                if !register.is_base_register() {
                    let current_value = current_value.clear_bit_values(&register.base_mask());
                    if current_value.has_any_value() {
                        self.register_state_map.insert(base_register, current_value);
                    }
                }
            }
        }
    }

    /// Modifies the context register value at `address`, whatever it flows from: the current
    /// context if `address` is the current flow address, else the future flow state. Unlike
    /// [`DisassemblerContextImpl::set_value_at`], it can affect the current state at the current
    /// address in a non-delayed fashion. Port of `setContextRegisterValue(RegisterValue,
    /// Address)`.
    pub fn set_context_register_value(&mut self, value: Option<RegisterValue>, address: &Address) {
        self.set_context_register_value_from(value, None, address);
    }

    /// Modifies the context register value for the flow from `from_addr` to `to_addr`; see
    /// [`DisassemblerContextImpl::set_context_register_value`]. Port of
    /// `setContextRegisterValue(RegisterValue, Address, Address)`.
    ///
    /// # Panics
    /// If `value` is not a value of this context's context register (Java's
    /// `IllegalArgumentException`).
    pub fn set_context_register_value_from(
        &mut self,
        value: Option<RegisterValue>,
        from_addr: Option<&Address>,
        to_addr: &Address,
    ) {
        let Some(value) = value else {
            return;
        };
        let base_reg = value.register().get_base_register();
        if !base_reg.is_processor_context() || base_reg != self.context_register {
            panic!("Invalid processor context register value");
        }
        if self.is_flow_active() && self.current_address.as_ref() == Some(to_addr) {
            let context = self.context_register_value.as_ref().expect("an active flow has a context value");
            self.context_register_value = Some(context.combine_values(&value));
            return;
        }
        self.set_future_register_value_internal(from_addr, to_addr, Some(value), true);
    }

    /// Port of `setRegisterValue(RegisterValue)`: sets a value at the current flow location. A
    /// context register value takes effect at the next flow address (delayed context).
    ///
    /// # Panics
    /// If no flow is active (Java's `IllegalStateException`).
    pub fn set_register_value_now(&mut self, value: RegisterValue) {
        if !self.is_flow_active() {
            panic!("Context flow has not been started");
        }

        let register = value.register();
        if register.is_processor_context() {
            // flow is already active - assume delayed flow context
            if self.delayed_context_register_value.is_none() {
                self.delayed_context_register_value = self.context_register_value.clone();
            }
            self.delayed_context_register_value = combine_register_values(
                self.delayed_context_register_value.take(),
                Some(value),
                true,
            );
            return; // delay saving of range context
        }

        let start = self.start_addr.clone().expect("an active flow has a start address");
        let current = self.current_address.clone().expect("an active flow has a current address");
        if start != current {
            self.save_program_context(&start, current.previous().ok().as_ref());
            self.start_addr = Some(current);
        }

        let base_register = register.get_base_register();
        let current_value = self.register_state_map.remove(&base_register);
        let new_value = combine_register_values(current_value, Some(value), true)
            .expect("combining with a value yields a value");
        self.register_state_map.insert(base_register, new_value);
    }

    /// The future value of `register` at `address`, whatever it flows from, or the value stored
    /// in the program; `None` unless the value is fully established. Port of
    /// `getValue(Register, Address, boolean)`.
    pub fn get_value_at(&self, register: &Register, address: &Address, signed: bool) -> Option<i128> {
        self.get_value_from(register, None, address, signed)
    }

    /// The future value of `register` at `to_addr` for the flow from `from_addr`, or the value
    /// stored in the program. Port of `getValue(Register, Address, Address, boolean)`.
    pub fn get_value_from(
        &self,
        register: &Register,
        from_addr: Option<&Address>,
        to_addr: &Address,
        signed: bool,
    ) -> Option<i128> {
        let value = self.get_register_value_from(register, from_addr, to_addr)?;
        if signed {
            value.signed_value()
        } else {
            value.unsigned_value().map(|v| v as i128)
        }
    }

    /// The future value of `register` at `address`, or the value stored in the program. It may
    /// not have a complete value for the register. Port of `getRegisterValue(Register,
    /// Address)`; see the module docs for why it never sees future state saved without a flow
    /// origin.
    pub fn get_register_value_at(&self, register: &Register, address: &Address) -> Option<RegisterValue> {
        self.get_register_value_from(register, None, address)
    }

    /// The future value of `register` at `dest_addr` for the flow from `from_addr`, or the value
    /// stored in the program. Within the active flow's range, the current value. Port of
    /// `getRegisterValue(Register, Address, Address)`.
    pub fn get_register_value_from(
        &self,
        register: &Register,
        from_addr: Option<&Address>,
        dest_addr: &Address,
    ) -> Option<RegisterValue> {
        if let (Some(start), Some(current)) = (&self.start_addr, &self.current_address) {
            if dest_addr >= start && dest_addr <= current {
                return self.get_register_value(register);
            }
        }

        // Java looks up `futureFlowRegisterStateMaps.get(destAddr).get(fromAddr)`; a flow-from of
        // NO_ADDRESS finds nothing there (see the module docs).
        let map = from_addr.and_then(|from_addr| {
            self.future_flow_register_state_maps.get(dest_addr).and_then(|m| m.get(from_addr))
        });
        if let Some(value) = map.and_then(|map| map.get(&register.get_base_register())) {
            return Some(value.get_register_value(register));
        }
        self.program_context.get_register_value(register, dest_addr).map(concrete)
    }

    /// The addresses whose flows carry state to `to_addr`; `None` stands for
    /// `Address.NO_ADDRESS` (state saved whatever the origin) and comes last. Port of
    /// `getKnownFlowToAddresses(Address)`.
    pub fn get_known_flow_to_addresses(&self, to_addr: &Address) -> Vec<Option<Address>> {
        let has_no_address_flow = self.no_address_future_register_state_map.contains_key(to_addr);
        let mut flows_to: Vec<Option<Address>> = self
            .future_flow_register_state_maps
            .get(to_addr)
            .map(|m| m.keys().cloned().map(Some).collect())
            .unwrap_or_default();
        if has_no_address_flow {
            flows_to.push(None);
        }
        flows_to
    }

    /// True if a flow has been started and not yet ended. Port of `isFlowActive()`.
    pub fn is_flow_active(&self) -> bool {
        self.start_addr.is_some()
    }
}

impl<P: ProgramContext> ProcessorContextView for DisassemblerContextImpl<P> {
    /// Java returns `Register.NO_CONTEXT` for a language without a context register; this
    /// crate's view renders that as `None`.
    fn get_base_context_register(&self) -> Option<RegisterRef> {
        self.context_register.is_processor_context().then(|| self.context_register.clone())
    }

    fn get_registers(&self) -> Vec<RegisterRef> {
        self.program_context.get_registers()
    }

    fn get_register(&self, name: &str) -> Option<RegisterRef> {
        self.program_context.get_register(name)
    }

    fn get_value(&self, register: &Register, signed: bool) -> Option<i128> {
        DisassemblerContextImpl::get_value(self, register, signed)
    }

    fn get_register_value(&self, register: &Register) -> Option<Box<dyn RegisterValueTrait>> {
        DisassemblerContextImpl::get_register_value(self, register)
            .map(|v| Box::new(v) as Box<dyn RegisterValueTrait>)
    }

    /// Port of `hasValue(Register)`: whether the value is fully known.
    fn has_value(&self, register: &Register) -> bool {
        DisassemblerContextImpl::get_value(self, register, true).is_some()
    }
}

impl<P: ProgramContext> ProcessorContext for DisassemblerContextImpl<P> {
    fn set_value(&mut self, register: &Register, value: i128) -> Result<(), ContextChangeException> {
        self.set_value_now(register, value as u128);
        Ok(())
    }

    fn set_register_value(&mut self, value: Box<dyn RegisterValueTrait>) -> Result<(), ContextChangeException> {
        self.set_register_value_now(concrete(value));
        Ok(())
    }

    fn clear_register(&mut self, register: &Register) -> Result<(), ContextChangeException> {
        self.clear_register_now(register);
        Ok(())
    }
}

impl<P: ProgramContext> DisassemblerContext for DisassemblerContextImpl<P> {
    fn set_future_register_value(&mut self, address: Address, value: Box<dyn RegisterValueTrait>) {
        self.set_future_register_value_at(&address, Some(concrete(value)));
    }

    fn set_future_register_value_for_flow(
        &mut self,
        from_addr: Address,
        to_addr: Address,
        value: Box<dyn RegisterValueTrait>,
    ) {
        self.set_future_register_value_from(Some(&from_addr), &to_addr, Some(concrete(value)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::AddressSpace;
    use crate::program::model::listing::default_program_context::DefaultProgramContext;
    use crate::program::util::abstract_stored_program_context::test_support::{
        ram_space, test_language, test_language_with_context_fields,
    };
    use crate::program::util::program_context_impl::ProgramContextImpl;
    use std::sync::Arc;

    struct Fixture {
        ctx: DisassemblerContextImpl<ProgramContextImpl>,
        ram: Arc<AddressSpace>,
        mode: Register,
        phase: Register,
        eax: Register,
    }

    impl Fixture {
        fn new() -> Self {
            let program_context = ProgramContextImpl::new(Arc::new(test_language_with_context_fields()));
            let reg = |name: &str| ProgramContext::get_register(&program_context, name).unwrap();
            let (mode, phase, eax) = (reg("mode"), reg("phase"), reg("eax"));
            Fixture { ctx: DisassemblerContextImpl::new(program_context), ram: ram_space(), mode, phase, eax }
        }

        fn at(&self, offset: i64) -> Address {
            self.ram.address(offset)
        }
    }

    #[test]
    fn the_context_register_comes_from_the_program_context() {
        let f = Fixture::new();
        assert_eq!(f.ctx.base_context_register().name(), "contextreg");
        assert_eq!(ProcessorContextView::get_base_context_register(&f.ctx).unwrap().name(), "contextreg");
        assert!(!f.ctx.is_flow_active());

        // A language without one gets Java's NO_CONTEXT, which the view reports as none.
        let ctx = DisassemblerContextImpl::new(ProgramContextImpl::new(Arc::new(test_language())));
        assert_eq!(ctx.base_context_register().name(), "NO_CONTEXT");
        assert!(ProcessorContextView::get_base_context_register(&ctx).is_none());
    }

    /// A context change made while parsing takes effect at the next instruction (delayed
    /// context), flows along the fall-through, and is copied to a branch target -- without its
    /// non-flowing bits.
    #[test]
    fn context_flows_across_a_branch_without_its_non_flowing_bits() {
        let mut f = Fixture::new();
        let (a1000, a1002, a2000) = (f.at(0x1000), f.at(0x1002), f.at(0x2000));

        f.ctx.flow_start(&a1000);
        assert!(f.ctx.is_flow_active());
        assert_eq!(f.ctx.get_address(), Some(&a1000));
        assert_eq!(f.ctx.get_value(&f.mode, false), None, "no context established yet");

        // Parsing the instruction at 0x1000 sets context: delayed until the flow moves on.
        f.ctx.set_register_value_now(RegisterValue::with_value(f.mode.clone(), 5));
        f.ctx.set_register_value_now(RegisterValue::with_value(f.phase.clone(), 3));
        assert_eq!(f.ctx.get_value(&f.mode, false), None);

        // Fall through to 0x1002: the new context is now current -- its flowing part only, as
        // Java strips non-flowing bits from the delayed value too.
        f.ctx.flow_to_address(&a1002);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(5));
        assert_eq!(f.ctx.get_value(&f.phase, false), None);
        assert!(ProcessorContextView::has_value(&f.ctx, &f.mode));

        // The instruction at 0x1002 branches to 0x2000: its flowing context goes with it.
        let copied = f.ctx.copy_to_future_flow_state(&a2000).unwrap();
        assert_eq!(copied.get_register_value(&f.mode).unsigned_value(), Some(5));
        assert!(!copied.get_register_value(&f.phase).has_any_value(), "phase does not follow flow");
        let flowed = f.ctx.get_flow_context_value(&a2000, false);
        assert_eq!(flowed.get_register_value(&f.mode).unsigned_value(), Some(5));
        f.ctx.flow_end(Some(&f.at(0x1003)));
        assert!(!f.ctx.is_flow_active());

        f.ctx.flow_start(&a2000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(5));
        assert_eq!(f.ctx.get_value(&f.phase, false), None);
        f.ctx.flow_end(None);
    }

    /// Non-flowing context stored in the program repeats along a flow until the next point where
    /// the stored context changes, but is not carried into a branch target.
    #[test]
    fn stored_non_flowing_context_repeats_until_the_next_change_point() {
        let mut f = Fixture::new();
        let (a1000, a1002, a10ff, a1100) = (f.at(0x1000), f.at(0x1002), f.at(0x10ff), f.at(0x1100));
        let stored = RegisterValue::with_value(f.mode.clone(), 2)
            .combine_values(&RegisterValue::with_value(f.phase.clone(), 3));
        ProgramContext::set_register_value(f.ctx.program_context_mut(), &a1000, &a10ff, Box::new(stored))
            .unwrap();

        f.ctx.flow_start(&a1000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(2));
        assert_eq!(f.ctx.get_value(&f.phase, false), Some(3));
        f.ctx.flow_to_address(&a1002);
        assert_eq!(f.ctx.get_value(&f.phase, false), Some(3), "repeats within the stored range");
        // Past the stored range the program has nothing, and the non-flowing value stops.
        f.ctx.flow_to_address(&a1100);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(2), "flowing context carries on");
        assert_eq!(f.ctx.get_value(&f.phase, false), None);
        f.ctx.flow_end(None);

        // A branch into the middle of the stored range sees only the non-flowing part stored there
        // when it is a fall-through...
        let flowed = f.ctx.get_flow_context_value(&a1002, true);
        assert_eq!(flowed.get_register_value(&f.phase).unsigned_value(), Some(3));
        // ...and the whole stored value otherwise.
        let flowed = f.ctx.get_flow_context_value(&a1002, false);
        assert_eq!(flowed.get_register_value(&f.mode).unsigned_value(), Some(2));
    }

    #[test]
    fn future_state_is_kept_per_flow_origin() {
        let mut f = Fixture::new();
        let (a1000, a3000) = (f.at(0x1000), f.at(0x3000));
        f.ctx.set_value_from(&f.mode.clone(), Some(&a1000), &a3000, 2);
        f.ctx.set_value_at(&f.mode.clone(), &a3000, 7);
        assert_eq!(f.ctx.get_known_flow_to_addresses(&a3000), vec![Some(a1000.clone()), None]);
        assert_eq!(f.ctx.get_value_from(&f.mode, Some(&a1000), &a3000, false), Some(2));
        // Java quirk: without an origin, the per-origin maps are searched under NO_ADDRESS, where
        // nothing is ever saved, so the lookup falls through to the (empty) program context...
        assert_eq!(f.ctx.get_value_at(&f.mode, &a3000, false), None);
        // ...while the flow itself does see the origin-less state.
        let flowed = f.ctx.get_flow_context_value(&a3000, false);
        assert_eq!(flowed.get_register_value(&f.mode).unsigned_value(), Some(7));

        f.ctx.flow_start_from(Some(&a1000), &a3000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(2));
        f.ctx.flow_end(None);
        // Taking the origin's state leaves the destination's (now empty) per-origin map behind;
        // Java only drops it when the taken map itself was empty.
        assert_eq!(f.ctx.get_known_flow_to_addresses(&a3000), vec![None]);

        f.ctx.flow_start(&a3000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(7));
        assert!(f.ctx.get_known_flow_to_addresses(&a3000).is_empty());
    }

    #[test]
    fn language_default_context_seeds_a_flow_and_an_explicit_value_overrides_it() {
        let mut f = Fixture::new();
        let (start, end) = (f.at(0), f.at(0xffff));
        f.ctx
            .program_context_mut()
            .set_default_value(Box::new(RegisterValue::with_value(f.mode.clone(), 1)), &start, &end);

        let a5000 = f.at(0x5000);
        f.ctx.flow_start(&a5000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(1));
        f.ctx.flow_end(None);

        f.ctx.set_context_register_value(Some(RegisterValue::with_value(f.mode.clone(), 9)), &a5000);
        f.ctx.flow_start(&a5000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(9));
        // At the current address the change is immediate, not delayed.
        f.ctx.set_context_register_value(Some(RegisterValue::with_value(f.mode.clone(), 4)), &a5000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(4));
        f.ctx.clear_register_now(&f.mode.clone());
        assert_eq!(f.ctx.get_value(&f.mode, false), None);
        f.ctx.flow_abort();
        assert!(!f.ctx.is_flow_active());
    }

    #[test]
    fn non_context_registers_are_written_to_the_program_when_a_flow_ends() {
        let mut f = Fixture::new();
        let (a1000, a1004) = (f.at(0x1000), f.at(0x1004));
        f.ctx.flow_start(&a1000);
        f.ctx.set_value_now(&f.eax.clone(), 0x1234);
        assert_eq!(f.ctx.get_value(&f.eax, false), Some(0x1234));
        f.ctx.flow_to_address(&a1004);
        assert_eq!(f.ctx.get_value(&f.eax, false), Some(0x1234), "the value carries along the flow");
        assert_eq!(ProgramContext::get_value(f.ctx.program_context(), &f.eax, &a1000, false), None);

        f.ctx.flow_end(Some(&f.at(0x1007)));
        for offset in [0x1000, 0x1004, 0x1007] {
            assert_eq!(
                ProgramContext::get_value(f.ctx.program_context(), &f.eax, &f.at(offset), false),
                Some(0x1234)
            );
        }
        assert_eq!(ProgramContext::get_value(f.ctx.program_context(), &f.eax, &f.at(0x1008), false), None);
        // A stored program value is what the context reads outside the flow.
        assert_eq!(f.ctx.get_value_at(&f.eax, &f.at(0x1002), false), Some(0x1234));
    }

    #[test]
    fn merging_reports_values_that_collide_with_saved_future_state() {
        let mut f = Fixture::new();
        let (a1000, a2000) = (f.at(0x1000), f.at(0x2000));
        f.ctx.set_value_from(&f.eax.clone(), Some(&a1000), &a2000, 2);

        f.ctx.flow_start(&a1000);
        f.ctx.set_value_now(&f.eax.clone(), 1);
        let collisions = f.ctx.merge_to_future_flow_state_from(Some(&a1000), &a2000);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].unsigned_value(), Some(1));
        // Merging never overrides what was saved first.
        assert_eq!(f.ctx.get_value_from(&f.eax, Some(&a1000), &a2000, false), Some(2));
        // Nothing collides with the destination the flow is at.
        assert!(f.ctx.merge_to_future_flow_state(&a1000).is_empty());
        f.ctx.flow_end(None);

        f.ctx.flow_start_from(Some(&a1000), &a2000);
        assert_eq!(f.ctx.get_value(&f.eax, false), Some(2));
    }

    #[test]
    fn the_trait_views_share_the_concrete_state() {
        let mut f = Fixture::new();
        let a1000 = f.at(0x1000);
        f.ctx.flow_start(&a1000);
        ProcessorContext::set_value(&mut f.ctx, &f.eax.clone(), 0x55).unwrap();
        assert_eq!(ProcessorContextView::get_value(&f.ctx, &f.eax, false), Some(0x55));
        let boxed = ProcessorContextView::get_register_value(&f.ctx, &f.eax).unwrap();
        assert_eq!(boxed.get_unsigned_value_ignore_mask(), 0x55);
        ProcessorContext::clear_register(&mut f.ctx, &f.eax.clone()).unwrap();
        assert!(!ProcessorContextView::has_value(&f.ctx, &f.eax));
        f.ctx.flow_end(None);

        let a2000 = f.at(0x2000);
        DisassemblerContext::set_future_register_value(
            &mut f.ctx,
            a2000.clone(),
            Box::new(RegisterValue::with_value(f.mode.clone(), 6)),
        );
        f.ctx.flow_start(&a2000);
        assert_eq!(f.ctx.get_value(&f.mode, false), Some(6));
        assert_eq!(ProcessorContextView::get_registers(&f.ctx).len(), 7);
        assert_eq!(ProcessorContextView::get_register(&f.ctx, "phase").unwrap(), f.phase);
    }

    #[test]
    #[should_panic(expected = "Attempted to continue a flow that was not started.")]
    fn flowing_without_a_flow_panics() {
        let mut f = Fixture::new();
        let a = f.at(0x1000);
        f.ctx.flow_to_address(&a);
    }

    #[test]
    #[should_panic(expected = "Previous flow was not ended.")]
    fn starting_a_flow_twice_panics() {
        let mut f = Fixture::new();
        let a = f.at(0x1000);
        f.ctx.flow_start(&a);
        f.ctx.flow_start(&a);
    }

    #[test]
    #[should_panic(expected = "address must not be less than current address")]
    fn flowing_backwards_panics() {
        let mut f = Fixture::new();
        let (a, b) = (f.at(0x1000), f.at(0xfff));
        f.ctx.flow_start(&a);
        f.ctx.flow_to_address(&b);
    }
}
