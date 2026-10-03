//! Port of `ghidra.program.model.lang.InstructionBlockFlow`.
//!
//! A small value type describing a single control-flow edge leaving an [`InstructionBlock`]
//! (crate::program::model::lang::instruction_block::InstructionBlock) -- a branch, call,
//! call-fallthrough, or forced "priority" start -- pointing at the address the flow lands on.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::program::model::address::Address;

/// The kind of flow a given [`InstructionBlockFlow`] represents.
///
/// Port of the nested enum `InstructionBlockFlow.Type`. Ordered (by declaration, matching Java's
/// enum ordinal order) by disassembly priority: `Priority` is the highest-priority flow start,
/// `Branch` is a normal within-set block branch, `CallFallthrough` is fall-through flow from a
/// CALL instruction that must be deferred until all branch flows are processed, and `Call` always
/// starts a new `InstructionSet`.
///
/// Note: despite this declared priority ordering, [`InstructionBlockFlow`]'s own [`Ord`] impl
/// (mirroring `InstructionBlockFlow.compareTo`) does **not** consult this type at all -- see that
/// impl's doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InstructionBlockFlowType {
    /// `PRIORITY` is the highest priority flow start.
    Priority,
    /// `BRANCH` is a normal block branch flow within an `InstructionSet`.
    Branch,
    /// `CALL_FALLTHROUGH` is fall-through flow from a CALL instruction which must be deferred
    /// until all branch flows are processed.
    CallFallthrough,
    /// `CALL` is a call flow which always starts a new `InstructionSet`.
    Call,
}

impl fmt::Display for InstructionBlockFlowType {
    /// Mirrors Java's default `Enum.toString()`, which returns the constant's declared name.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            InstructionBlockFlowType::Priority => "PRIORITY",
            InstructionBlockFlowType::Branch => "BRANCH",
            InstructionBlockFlowType::CallFallthrough => "CALL_FALLTHROUGH",
            InstructionBlockFlowType::Call => "CALL",
        };
        f.write_str(name)
    }
}

/// Describes a single control-flow edge from one [`InstructionBlock`]
/// (crate::program::model::lang::instruction_block::InstructionBlock) to a destination address.
///
/// Port of `ghidra.program.model.lang.InstructionBlockFlow`.
///
/// The `flowFrom` field is documented in Java as nullable ("may be null"); `address` (the flow
/// destination) is not null-checked by the constructor either, but every real Java call site
/// always supplies one (the class's own `hashCode()` has a defensive `address != null ? ... : 0`
/// that is dead in practice), so this port models it as a required `Address` rather than
/// `Option<Address>`.
#[derive(Debug, Clone)]
pub struct InstructionBlockFlow {
    address: Address,
    flow_from: Option<Address>,
    flow_type: InstructionBlockFlowType,
}

impl InstructionBlockFlow {
    /// Construct a new flow edge landing at `address`, having flowed from `flow_from` (`None` if
    /// unknown), of the given `flow_type`.
    pub fn new(address: Address, flow_from: Option<Address>, flow_type: InstructionBlockFlowType) -> Self {
        InstructionBlockFlow { address, flow_from, flow_type }
    }

    /// Get the flow destination address.
    pub fn get_destination_address(&self) -> Address {
        self.address.clone()
    }

    /// Get the flow from address (may be `None`).
    pub fn get_flow_from_address(&self) -> Option<Address> {
        self.flow_from.clone()
    }

    /// The flow type.
    pub fn get_type(&self) -> InstructionBlockFlowType {
        self.flow_type
    }
}

impl PartialEq for InstructionBlockFlow {
    /// Port of `InstructionBlockFlow.equals`: full structural equality across `type`, `address`,
    /// and `flowFrom`. Note this is intentionally a *stricter* comparison than [`Ord::cmp`] below
    /// (which only looks at `address`) -- see that impl's doc comment for why the two are not
    /// consistent, exactly mirroring the Java source.
    fn eq(&self, other: &Self) -> bool {
        self.flow_type == other.flow_type
            && self.address == other.address
            && self.flow_from == other.flow_from
    }
}

impl Eq for InstructionBlockFlow {}

impl Hash for InstructionBlockFlow {
    /// Port of `InstructionBlockFlow.hashCode`: hashes only `address`, ignoring `type` and
    /// `flowFrom`. This remains a valid (if weak) hash given [`PartialEq`] above: equal objects
    /// necessarily share the same `address` and therefore the same hash, even though the converse
    /// does not hold.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.address.hash(state);
    }
}

impl PartialOrd for InstructionBlockFlow {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InstructionBlockFlow {
    /// Port of `InstructionBlockFlow.compareTo`.
    ///
    /// Java quirk faithfully reproduced: despite [`InstructionBlockFlowType`]'s doc comment
    /// describing the type variants as "ordered by disassembly priority", `compareTo` only ever
    /// compares `address` -- `type` and `flowFrom` play no part. This means two flows with the
    /// same destination address but different `type` and/or `flowFrom` compare as
    /// [`Ordering::Equal`] here even though [`PartialEq`]/[`Eq`] above report them as unequal --
    /// `compareTo` is inconsistent with `equals`, exactly as in the original Java class. See
    /// `flows_with_same_address_compare_equal_but_are_not_equal` below for a test proving this.
    fn cmp(&self, other: &Self) -> Ordering {
        self.address.cmp(&other.address)
    }
}

impl fmt::Display for InstructionBlockFlow {
    /// Port of `InstructionBlockFlow.toString()`: `<TYPE> <flowFrom>-><address>`, printing the
    /// Java literal `"null"` when `flowFrom` is absent (mirroring `"" + null` in Java string
    /// concatenation).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flow_from_str = match &self.flow_from {
            Some(addr) => addr.to_string(),
            None => "null".to_string(),
        };
        write!(f, "{} {}->{}", self.flow_type, flow_from_str, self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};

    fn ram_addr(offset: i64) -> Address {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        Address::new(space, offset)
    }

    #[test]
    fn getters_report_constructed_fields() {
        let flow = InstructionBlockFlow::new(
            ram_addr(0x2000),
            Some(ram_addr(0x1000)),
            InstructionBlockFlowType::Branch,
        );
        assert_eq!(flow.get_destination_address(), ram_addr(0x2000));
        assert_eq!(flow.get_flow_from_address(), Some(ram_addr(0x1000)));
        assert_eq!(flow.get_type(), InstructionBlockFlowType::Branch);
    }

    #[test]
    fn flow_from_may_be_absent() {
        let flow = InstructionBlockFlow::new(ram_addr(0x2000), None, InstructionBlockFlowType::Priority);
        assert_eq!(flow.get_flow_from_address(), None);
    }

    #[test]
    fn equals_requires_matching_type_address_and_flow_from() {
        let a = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1000)), InstructionBlockFlowType::Branch);
        let b = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1000)), InstructionBlockFlowType::Branch);
        let different_type = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1000)), InstructionBlockFlowType::Call);
        let different_flow_from = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1004)), InstructionBlockFlowType::Branch);
        let different_address = InstructionBlockFlow::new(ram_addr(0x2004), Some(ram_addr(0x1000)), InstructionBlockFlowType::Branch);

        assert_eq!(a, b);
        assert_ne!(a, different_type);
        assert_ne!(a, different_flow_from);
        assert_ne!(a, different_address);
    }

    #[test]
    fn hash_depends_only_on_address() {
        use std::collections::hash_map::DefaultHasher;

        let a = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1000)), InstructionBlockFlowType::Branch);
        let b = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1004)), InstructionBlockFlowType::Call);

        let hash_of = |flow: &InstructionBlockFlow| {
            let mut hasher = DefaultHasher::new();
            flow.hash(&mut hasher);
            hasher.finish()
        };

        // `a` and `b` differ in type and flow-from (so are unequal per `equals`), yet still hash
        // the same because Java's hashCode ignores everything but `address`.
        assert_ne!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[test]
    fn compare_to_orders_purely_by_address() {
        let low = InstructionBlockFlow::new(ram_addr(0x1000), None, InstructionBlockFlowType::Call);
        let high = InstructionBlockFlow::new(ram_addr(0x2000), None, InstructionBlockFlowType::Priority);
        assert_eq!(low.cmp(&high), Ordering::Less);
        assert_eq!(high.cmp(&low), Ordering::Greater);
    }

    /// Faithfully reproduces the Java quirk documented on the `Ord` impl: `compareTo` only
    /// compares `address`, so two flows sharing an address but differing in every other field
    /// compare as `Equal` even though `equals()` reports them as unequal. `compareTo` is thus
    /// inconsistent with `equals`, mirroring the original Java class exactly.
    #[test]
    fn flows_with_same_address_compare_equal_but_are_not_equal() {
        let a = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x1000)), InstructionBlockFlowType::Branch);
        let b = InstructionBlockFlow::new(ram_addr(0x2000), Some(ram_addr(0x9000)), InstructionBlockFlowType::Call);

        assert_eq!(a.cmp(&b), Ordering::Equal);
        assert_ne!(a, b);
    }

    #[test]
    fn display_matches_java_tostring_including_null_flow_from() {
        let with_flow_from = InstructionBlockFlow::new(
            ram_addr(0x2000),
            Some(ram_addr(0x1000)),
            InstructionBlockFlowType::CallFallthrough,
        );
        assert_eq!(
            with_flow_from.to_string(),
            format!("CALL_FALLTHROUGH {}->{}", ram_addr(0x1000), ram_addr(0x2000))
        );

        let without_flow_from = InstructionBlockFlow::new(ram_addr(0x2000), None, InstructionBlockFlowType::Priority);
        assert_eq!(
            without_flow_from.to_string(),
            format!("PRIORITY null->{}", ram_addr(0x2000))
        );
    }

    #[test]
    fn type_display_matches_java_enum_names() {
        assert_eq!(InstructionBlockFlowType::Priority.to_string(), "PRIORITY");
        assert_eq!(InstructionBlockFlowType::Branch.to_string(), "BRANCH");
        assert_eq!(InstructionBlockFlowType::CallFallthrough.to_string(), "CALL_FALLTHROUGH");
        assert_eq!(InstructionBlockFlowType::Call.to_string(), "CALL");
    }
}
