use std::sync::Arc;

use super::*;
use crate::program::model::address::{AddressSpace, AddressSpaceType};

fn ram() -> Arc<AddressSpace> {
    AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1)
}

fn a(space: &Arc<AddressSpace>, offset: i64) -> Address {
    Address::new(space.clone(), offset)
}

#[test]
fn the_first_reference_on_each_operand_is_primary() {
    let s = ram();
    let mut store = ReferenceStore::new();
    let r1 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap();
    let r2 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x300), RefType::Read, SourceType::Default, 0).unwrap();
    let r3 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x400), RefType::UnconditionalCall, SourceType::Default, -1).unwrap();
    assert!(r1.is_primary());
    assert!(!r2.is_primary());
    assert!(r3.is_primary(), "first mnemonic reference");
    assert_eq!(store.primary_reference_from(&a(&s, 0x100), 0).map(|r| r.id()), Some(r1.id()));
    assert_eq!(store.primary_reference_from(&a(&s, 0x100), -1).map(|r| r.id()), Some(r3.id()));
    assert_eq!(store.primary_reference_from(&a(&s, 0x100), 1), None);
    assert_eq!(store.len(), 3);
}

#[test]
fn queries_answer_from_to_and_per_operand_in_insertion_order() {
    let s = ram();
    let mut store = ReferenceStore::new();
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x300), RefType::Data, SourceType::Default, 1).unwrap();
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::ConditionalJump, SourceType::Default, 0).unwrap();
    store.add_memory_reference(a(&s, 0x110), a(&s, 0x200), RefType::Read, SourceType::UserDefined, 1).unwrap();

    let from: Vec<i64> = store.references_from(&a(&s, 0x100)).iter().map(|r| r.to_address().offset()).collect();
    assert_eq!(from, vec![0x300, 0x200]);
    let op1: Vec<i64> = store.references_from_operand(&a(&s, 0x100), 1).iter().map(|r| r.to_address().offset()).collect();
    assert_eq!(op1, vec![0x300]);
    let flows = store.flow_references_from(&a(&s, 0x100));
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].reference_type(), RefType::ConditionalJump);

    let to: Vec<(i64, i32)> =
        store.references_to(&a(&s, 0x200)).iter().map(|r| (r.from_address().offset(), r.operand_index())).collect();
    assert_eq!(to, vec![(0x100, 0), (0x110, 1)]);
    assert_eq!(store.reference_count_to(&a(&s, 0x200)), 2);
    assert_eq!(store.reference_count_from(&a(&s, 0x100)), 2);
    assert!(store.has_references_to(&a(&s, 0x300)));
    assert!(!store.has_references_to(&a(&s, 0x100)));
    assert!(store.has_references_from(&a(&s, 0x110)));
    let r = store.reference(&a(&s, 0x110), &a(&s, 0x200), 1).unwrap();
    assert_eq!((r.source(), r.reference_type()), (SourceType::UserDefined, RefType::Read));
    assert!(store.reference(&a(&s, 0x110), &a(&s, 0x200), 0).is_none());

    let sources: Vec<i64> = store.source_addresses(&a(&s, 0), &a(&s, 0xfff)).map(Address::offset).collect();
    assert_eq!(sources, vec![0x100, 0x110]);
    let dests: Vec<i64> = store.destination_addresses(&a(&s, 0), &a(&s, 0xfff)).map(Address::offset).collect();
    assert_eq!(dests, vec![0x200, 0x300]);
}

#[test]
fn adding_on_top_of_an_existing_reference_combines_types_and_keeps_primary() {
    let s = ram();
    let mut store = ReferenceStore::new();
    let first = store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Read, SourceType::Default, 0).unwrap();
    // same type: the existing reference comes back unchanged
    let same = store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Read, SourceType::UserDefined, 0).unwrap();
    assert_eq!(same, first);
    // read + write combine to read/write, keeping the primary flag
    let combined = store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Write, SourceType::UserDefined, 0).unwrap();
    assert_eq!(combined.reference_type(), RefType::ReadWrite);
    assert!(combined.is_primary());
    assert_eq!(combined.source(), SourceType::UserDefined);
    assert_ne!(combined.id(), first.id());
    assert!(store.get(first.id()).is_none());
    assert_eq!(store.len(), 1);
    // a data reference never replaces a flow reference
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x300), RefType::UnconditionalJump, SourceType::Default, -1).unwrap();
    let kept = store.add_memory_reference(a(&s, 0x100), a(&s, 0x300), RefType::Data, SourceType::Default, -1).unwrap();
    assert_eq!(kept.reference_type(), RefType::UnconditionalJump);
}

#[test]
fn combine_reference_type_follows_java() {
    use RefType::*;
    assert_eq!(combine_reference_type(Data, Read), Read);
    assert_eq!(combine_reference_type(Read, Data), Read);
    assert_eq!(combine_reference_type(DataInd, ReadInd), ReadInd);
    assert_eq!(combine_reference_type(ReadInd, WriteInd), ReadWriteInd);
    assert_eq!(combine_reference_type(WriteInd, ReadInd), ReadWriteInd);
    assert_eq!(combine_reference_type(Read, ReadWrite), ReadWrite);
    assert_eq!(combine_reference_type(ConditionalCall, Data), ConditionalCall);
    assert_eq!(combine_reference_type(Data, ComputedCall), ComputedCall);
    assert_eq!(combine_reference_type(Write, Data), Write);
}

#[test]
fn set_primary_moves_the_primary_flag_within_an_operand() {
    let s = ram();
    let mut store = ReferenceStore::new();
    let r1 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap();
    let r2 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x300), RefType::Data, SourceType::Default, 0).unwrap();
    assert!(store.set_primary(r2.id(), true));
    assert!(!store.get(r1.id()).unwrap().is_primary());
    assert!(store.get(r2.id()).unwrap().is_primary());
    assert!(!store.set_primary(r2.id(), true), "no change");
    assert!(store.set_primary(r2.id(), false));
    assert_eq!(store.primary_reference_from(&a(&s, 0x100), 0), None);
}

#[test]
fn deleting_a_primary_reference_promotes_nothing() {
    let s = ram();
    let mut store = ReferenceStore::new();
    let r1 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap();
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x300), RefType::Data, SourceType::Default, 0).unwrap();
    assert_eq!(store.delete(r1.id()).map(|r| r.id()), Some(r1.id()));
    assert_eq!(store.primary_reference_from(&a(&s, 0x100), 0), None);
    assert!(!store.has_references_to(&a(&s, 0x200)));
    // the next reference on the operand is not primary either: the operand still has one
    let r3 = store.add_memory_reference(a(&s, 0x100), a(&s, 0x400), RefType::Data, SourceType::Default, 0).unwrap();
    assert!(!r3.is_primary());
    assert!(store.remove_reference(&a(&s, 0x100), &a(&s, 0x400), 0).is_some());
    assert!(store.remove_reference(&a(&s, 0x100), &a(&s, 0x400), 0).is_none());
}

#[test]
fn removing_all_references_from_a_range_clears_both_indexes() {
    let s = ram();
    let mut store = ReferenceStore::new();
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap();
    store.add_memory_reference(a(&s, 0x104), a(&s, 0x200), RefType::Read, SourceType::UserDefined, 1).unwrap();
    store.add_memory_reference(a(&s, 0x108), a(&s, 0x200), RefType::Read, SourceType::Default, 1).unwrap();
    store.remove_all_references_from_range(&a(&s, 0x100), &a(&s, 0x104));
    assert_eq!(store.len(), 1);
    let to: Vec<i64> = store.references_to(&a(&s, 0x200)).iter().map(|r| r.from_address().offset()).collect();
    assert_eq!(to, vec![0x108]);
    store.remove_all_references_from(&a(&s, 0x108));
    assert!(store.is_empty());
    assert!(!store.has_references_to(&a(&s, 0x200)));
}

#[test]
fn a_register_destination_replaces_the_operands_references_and_is_not_indexed_by_to() {
    let s = ram();
    let regs = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
    let mut store = ReferenceStore::new();
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap();
    let reg = store.add_memory_reference(a(&s, 0x100), a(&regs, 0x8), RefType::Write, SourceType::UserDefined, 0).unwrap();
    assert!(reg.is_register_reference());
    assert!(reg.is_primary());
    assert_eq!(store.references_from(&a(&s, 0x100)).len(), 1);
    assert!(!store.has_references_to(&a(&s, 0x200)));
    assert!(!store.has_references_to(&a(&regs, 0x8)));
    // and a memory destination replaces the operand's register reference
    store.add_memory_reference(a(&s, 0x100), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap();
    assert_eq!(store.references_from(&a(&s, 0x100)).iter().map(|r| r.to_address().offset()).collect::<Vec<_>>(), vec![0x200]);
}

#[test]
fn invalid_from_addresses_and_operands_are_rejected() {
    let s = ram();
    let regs = AddressSpace::new("register", 32, 1, AddressSpaceType::Register, 2);
    let mut store = ReferenceStore::new();
    assert_eq!(
        store.add_memory_reference(a(&regs, 0), a(&s, 0x200), RefType::Data, SourceType::Default, 0).unwrap_err().to_string(),
        "From address must be memory addresses"
    );
    assert_eq!(
        store.add_memory_reference(a(&s, 0), a(&s, 0x200), RefType::Data, SourceType::Default, -2).unwrap_err().to_string(),
        "Invalid opIndex specified: -2"
    );
    assert!(store.is_empty());
}
