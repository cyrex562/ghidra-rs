//! Port of `ghidra.app.util.bin.format.dwarf.DWARFDataInstanceHelper`.

use std::any::TypeId;

use crate::program::model::address::Address;
use crate::program::model::data::array::Array;
use crate::program::model::data::char_data_type::CharDataType;
use crate::program::model::data::data_type::DataType;
use crate::program::model::data::data_utilities::DataUtilities;
use crate::program::model::data::enum_::Enum;
use crate::program::model::data::pointer::Pointer;
use crate::program::model::data::signed_char_data_type::SignedCharDataType;
use crate::program::model::data::string_data_type::StringDataType;
use crate::program::model::data::structure::Structure;
use crate::program::model::data::undefined::is_undefined;
use crate::program::model::data::unsigned_char_data_type::UnsignedCharDataType;
use crate::program::model::data::wide_char16_data_type::WideChar16DataType;
use crate::program::model::data::wide_char32_data_type::WideChar32DataType;
use crate::program::model::data::wide_char_data_type::WideCharDataType;
use crate::program::model::listing::{Data, Program};

/// `DataUtilities`' statics are trait default methods in this port.
struct Utilities;
impl DataUtilities for Utilities {}

/// `instanceof CharDataType`: `CharDataType` or one of its Java subclasses
/// (`SignedCharDataType`, `UnsignedCharDataType`).
fn is_char_data_type(dt: &dyn DataType) -> bool {
    matches!(dt.runtime_class(), Some(c) if c == TypeId::of::<CharDataType>()
        || c == TypeId::of::<SignedCharDataType>()
        || c == TypeId::of::<UnsignedCharDataType>())
}

/// `instanceof StringDataType` (a class with no subclasses).
fn is_string_data_type(dt: &dyn DataType) -> bool {
    dt.runtime_class() == Some(TypeId::of::<StringDataType>())
}

/// `instanceof WideCharDataType || instanceof WideChar16DataType || instanceof
/// WideChar32DataType`.
fn is_wide_char_data_type(dt: &dyn DataType) -> bool {
    matches!(dt.runtime_class(), Some(c) if c == TypeId::of::<WideCharDataType>()
        || c == TypeId::of::<WideChar16DataType>()
        || c == TypeId::of::<WideChar32DataType>())
}

/// `simpleDT.getClass().isInstance(existingDT)` for the simple (integer, float, string, wide
/// char) data types: the same class, or -- the only subclassing among those built-ins --
/// `existing` is a subclass of `CharDataType` when `simple` is a `CharDataType`.
fn is_instance_of_class_of(simple: &dyn DataType, existing: &dyn DataType) -> bool {
    match (simple.runtime_class(), existing.runtime_class()) {
        (Some(s), Some(e)) if s == e => true,
        (Some(s), Some(_)) if s == TypeId::of::<CharDataType>() => is_char_data_type(existing),
        _ => false,
    }
}

/// Logic to test if a `Data` instance is replaceable with a data type.
///
/// Port of `ghidra.app.util.bin.format.dwarf.DWARFDataInstanceHelper`. The helper borrows the
/// program and reaches its listing through the `&self` `Program` accessors at call time (Java
/// caches `program.getListing()` in a field).
pub struct DWARFDataInstanceHelper<'a> {
    program: &'a dyn Program,
    allow_truncating: bool,
}

impl<'a> DWARFDataInstanceHelper<'a> {
    /// `DWARFDataInstanceHelper(Program)`: truncation is allowed by default.
    pub fn new(program: &'a dyn Program) -> Self {
        DWARFDataInstanceHelper { program, allow_truncating: true }
    }

    /// `setAllowTruncating(boolean)`.
    pub fn set_allow_truncating(mut self, b: bool) -> Self {
        self.allow_truncating = b;
        self
    }

    /// The defined-or-undefined data at `address`, as Java's `listing.getDataAt(address)`.
    fn data_at(&self, address: &Address) -> Option<std::sync::Arc<dyn Data>> {
        self.program.get_listing().and_then(|l| l.get_data_at(address))
    }

    /// `isArrayDataTypeCompatibleWithExistingData(Array, Data)`.
    fn is_array_data_type_compatible_with_existing_data(&self, array_dt: &dyn Array, existing_data: &dyn Data) -> bool {
        let existing_data_dt = existing_data.get_base_data_type();
        if existing_data_dt.is_equivalent(array_dt) {
            return true;
        }

        let mut element_dt = array_dt.get_data_type();
        if let Some(typedef) = element_dt.as_typedef() {
            element_dt = typedef.get_base_data_type();
        }

        let existing_is_string = is_string_data_type(existing_data_dt.as_ref());
        let mut existing_element_dt: Option<Box<dyn DataType>> =
            existing_data_dt.as_array().map(|a| a.get_data_type());
        let char_over_string = is_char_data_type(element_dt.as_ref()) && existing_is_string;
        if let Some(typedef) = existing_element_dt.as_deref().and_then(|dt| dt.as_typedef()) {
            existing_element_dt = Some(typedef.get_base_data_type());
        }

        if existing_data_dt.as_array().is_some() || existing_is_string {
            // hack to allow a char array to overwrite a string in memory: the string's
            // "element" is taken to be the proposed char element itself
            let elements_equivalent = if char_over_string {
                true
            } else {
                // Java dereferences a null element type here (a non-char array over a
                // string) and throws; that is treated as incompatible.
                existing_element_dt.is_some_and(|e| e.is_equivalent(element_dt.as_ref()))
            };
            if !elements_equivalent {
                return false;
            }

            if array_dt.get_length() == existing_data.get_length() {
                return true;
            }
            if array_dt.get_length() < existing_data.get_length() {
                // if proposed array is smaller than in-memory array
                return self.allow_truncating;
            }

            // if proposed array is longer than in-memory array, check if there is only
            // undefined data following the in-memory array
            return self.has_trailing_undefined(existing_data, array_dt);
        }

        // existing data wasn't an array, test each location the proposed array would overwrite
        let address = existing_data.get_min_address();
        for i in 0..array_dt.get_num_elements() {
            let Ok(element_address) = address.add(array_dt.get_element_length() as i64 * i as i64) else {
                return false;
            };
            if let Some(data) = self.data_at(&element_address) {
                if !self.is_data_type_compatible_with_existing_data(element_dt.as_ref(), data.as_ref()) {
                    return false;
                }
            }
        }
        true
    }

    /// `hasTrailingUndefined(Data, DataType)`.
    fn has_trailing_undefined(&self, data: &dyn Data, replacement_dt: &dyn DataType) -> bool {
        let address = data.get_min_address();
        let (Ok(start), Ok(end)) = (
            address.add(data.get_length() as i64),
            address.add(replacement_dt.get_length() as i64 - 1),
        ) else {
            return false;
        };
        Utilities.is_undefined_range(self.program, &start, &end)
    }

    /// `isStructDataTypeCompatibleWithExistingData(Structure, Data)`.
    fn is_struct_data_type_compatible_with_existing_data(&self, struct_dt: &dyn Structure, existing_data: &dyn Data) -> bool {
        let existing_data_dt = existing_data.get_base_data_type();
        if existing_data_dt.as_structure().is_some() {
            return existing_data_dt.is_equivalent(struct_dt);
        }

        // existing data wasn't a structure, test each location the proposed structure would
        // overwrite
        let address = existing_data.get_min_address();
        for dtc in struct_dt.get_defined_components() {
            let Ok(member_address) = address.add(dtc.get_offset() as i64) else {
                return false;
            };
            if let Some(data) = self.data_at(&member_address) {
                if !self.is_data_type_compatible_with_existing_data(dtc.get_data_type().as_ref(), data.as_ref()) {
                    return false;
                }
            }
        }
        let is_truncating = struct_dt.get_length() < existing_data.get_length();
        !is_truncating || self.allow_truncating
    }

    /// `isPointerDataTypeCompatibleWithExistingData(Pointer, Data)`.
    fn is_pointer_data_type_compatible_with_existing_data(&self, pdt: &dyn Pointer, existing_data: &dyn Data) -> bool {
        let existing_dt = existing_data.get_base_data_type();
        // allow 'upgrading' an integer type to a pointer
        let is_right_type = existing_dt.as_pointer().is_some() || existing_dt.is_integer_type();
        is_right_type && existing_dt.get_length() == pdt.get_length()
    }

    /// `isSimpleDataTypeCompatibleWithExistingData(DataType, Data)`: `simple_dt` is an int,
    /// char, float, or string data type.
    fn is_simple_data_type_compatible_with_existing_data(&self, simple_dt: &dyn DataType, existing_data: &dyn Data) -> bool {
        let is_same_len = is_same_len(simple_dt, existing_data);
        let existing_dt = existing_data.get_base_data_type();

        if is_char_data_type(simple_dt) && is_string_data_type(existing_dt.as_ref()) {
            // char overwriting a string
            return is_same_len || self.allow_truncating;
        }

        if is_same_len && is_undefined(existing_data.get_base_data_type()) {
            // some type overwriting an undefined
            return true;
        }

        is_instance_of_class_of(simple_dt, existing_dt.as_ref()) && is_same_len
    }

    /// `isEnumDataTypeCompatibleWithExistingData(Enum, Data)`: a very fuzzy check to see if the
    /// value located at address is compatible. Match if it's an enum or integer with correct
    /// size; the details about enum members are ignored.
    fn is_enum_data_type_compatible_with_existing_data(&self, enum_dt: &dyn Enum, existing_data: &dyn Data) -> bool {
        let existing_dt = existing_data.get_base_data_type();
        if !(existing_dt.as_enum().is_some() || existing_dt.is_integer_type()) {
            return false;
        }
        if existing_dt.is_boolean_type() {
            return false;
        }
        existing_dt.get_length() == enum_dt.get_length()
    }

    /// `isDataTypeCompatibleWithExistingData(DataType, Data)`.
    fn is_data_type_compatible_with_existing_data(&self, data_type: &dyn DataType, existing_data: &dyn Data) -> bool {
        if !existing_data.is_defined() {
            return true;
        }
        if let Some(array) = data_type.as_array() {
            return self.is_array_data_type_compatible_with_existing_data(array, existing_data);
        }
        if let Some(pointer) = data_type.as_pointer() {
            return self.is_pointer_data_type_compatible_with_existing_data(pointer, existing_data);
        }
        if let Some(structure) = data_type.as_structure() {
            return self.is_struct_data_type_compatible_with_existing_data(structure, existing_data);
        }
        if let Some(typedef) = data_type.as_typedef() {
            return self.is_data_type_compatible_with_existing_data(typedef.get_base_data_type().as_ref(), existing_data);
        }
        if let Some(enum_dt) = data_type.as_enum() {
            return self.is_enum_data_type_compatible_with_existing_data(enum_dt, existing_data);
        }
        if data_type.is_integer_type()
            || data_type.is_floating_point()
            || is_string_data_type(data_type)
            || is_wide_char_data_type(data_type)
        {
            return self.is_simple_data_type_compatible_with_existing_data(data_type, existing_data);
        }
        false
    }

    /// Whether `data_type` may be placed at `address`: the whole range is still undefined, or
    /// the data starting exactly at `address` is compatible with `data_type`
    /// (`isDataTypeCompatibleWithAddress(DataType, Address)`).
    pub fn is_data_type_compatible_with_address(&self, data_type: &dyn DataType, address: &Address) -> bool {
        if let Ok(end) = address.add(data_type.get_length() as i64 - 1) {
            if Utilities.is_undefined_range(self.program, address, &end) {
                return true;
            }
        }

        let Some(data) = self.program.get_listing().and_then(|l| l.get_data_containing(address)) else {
            return false; // will only get null if something is really screwed up
        };
        if data.get_min_address() != *address {
            return false; // was pointing to something in the middle of an existing data instance
        }
        self.is_data_type_compatible_with_existing_data(data_type, data.as_ref())
    }
}

/// `isSameLen(DataType, Data)`.
fn is_same_len(dt: &dyn DataType, existing_data: &dyn Data) -> bool {
    existing_data.get_length() == dt.get_length() || dt.as_dynamic().is_some_and(|d| d.can_specify_length())
}

#[cfg(test)]
mod tests {
    //! Expectations follow the Java logic case by case (there is no Java unit test for this
    //! class): undefined ranges always accept, otherwise the data starting exactly at the
    //! address must be compatible with the proposed type.
    use super::*;
    use std::sync::{Arc, RwLock};

    use crate::program::database::code::code_unit_owner::CodeUnitOwner;
    use crate::program::database::code::data_db::DataDB;
    use crate::program::database::code::test_support::TestCodeUnitOwner;
    use crate::program::model::address::{AddressSpace, AddressSpaceType};
    use crate::program::model::data::array_data_type::ArrayDataType;
    use crate::program::model::data::boolean_data_type::BooleanDataType;
    use crate::program::model::data::byte_data_type::ByteDataType;
    use crate::program::model::data::category_path::ROOT;
    use crate::program::model::data::composite::Composite;
    use crate::program::model::data::dword_data_type::DWordDataType;
    use crate::program::model::data::enum_data_type::EnumDataType;
    use crate::program::model::data::float_data_type::FloatDataType;
    use crate::program::model::data::pointer32_data_type::Pointer32DataType;
    use crate::program::model::data::structure_data_type::StructureDataType;
    use crate::program::model::data::typedef_data_type::TypedefDataType;
    use crate::program::model::data::undefined2_data_type::Undefined2DataType;
    use crate::program::model::data::undefined4_data_type::Undefined4DataType;
    use crate::program::model::data::word_data_type::WordDataType;
    use crate::program::model::listing::code_unit::CodeUnit;
    use crate::program::model::listing::{Listing, ManagerGuard, StubListing};
    use crate::program::model::mem::Memory;

    const BASE: i64 = 0x1000;
    const SIZE: usize = 0x40;

    /// A listing over a set of defined [`DataDB`]s; every other address holds undefined data.
    struct TestListing {
        owner: Arc<TestCodeUnitOwner>,
        defined: Vec<Arc<DataDB>>,
    }

    impl TestListing {
        fn undefined_at(&self, addr: &Address) -> Arc<dyn Data> {
            let owner: Arc<dyn CodeUnitOwner> = self.owner.clone();
            Arc::new(DataDB::new(owner, addr.offset(), addr.clone(), addr.offset(), None))
        }

        fn defined_containing(&self, addr: &Address) -> Option<&Arc<DataDB>> {
            self.defined.iter().find(|d| d.get_min_address() <= *addr && *addr <= d.get_max_address())
        }

        fn in_memory(&self, addr: &Address) -> bool {
            (BASE..BASE + SIZE as i64).contains(&addr.offset())
        }
    }

    impl StubListing for TestListing {
        fn get_data_at(&self, addr: &Address) -> Option<Arc<dyn Data>> {
            match self.defined_containing(addr) {
                Some(d) if d.get_min_address() == *addr => Some(d.clone() as Arc<dyn Data>),
                Some(_) => None,
                None => self.in_memory(addr).then(|| self.undefined_at(addr)),
            }
        }

        fn get_data_containing(&self, addr: &Address) -> Option<Arc<dyn Data>> {
            match self.defined_containing(addr) {
                Some(d) => Some(d.clone() as Arc<dyn Data>),
                None => self.in_memory(addr).then(|| self.undefined_at(addr)),
            }
        }

        fn get_defined_code_unit_after(&self, addr: &Address) -> Option<Arc<dyn CodeUnit>> {
            self.defined
                .iter()
                .filter(|d| d.get_min_address() > *addr)
                .min_by_key(|d| d.get_min_address().offset())
                .map(|d| d.clone() as Arc<dyn CodeUnit>)
        }
    }

    struct TestProgram {
        owner: Arc<TestCodeUnitOwner>,
        listing: RwLock<TestListing>,
    }

    // SAFETY: `Program` requires `Send + Sync`, but the code-unit fixtures behind the listing
    // (`TestCodeUnitOwner`, `DataDB`) are not thread-safe. Each test builds, uses and drops its
    // program on its own thread; nothing here is ever shared with or moved to another thread.
    unsafe impl Send for TestProgram {}
    unsafe impl Sync for TestProgram {}

    impl crate::framework::model::DomainObject for TestProgram {}

    impl Program for TestProgram {
        fn get_name(&self) -> String {
            "dwarf-test".to_string()
        }
        fn get_language_id(&self) -> String {
            "test:LE:32:default".to_string()
        }
        fn get_memory(&self) -> Option<Arc<dyn Memory>> {
            Some(self.owner.memory().clone())
        }
        fn get_listing(&self) -> Option<ManagerGuard<'_, dyn Listing>> {
            Some(ManagerGuard::write(&self.listing as &RwLock<dyn Listing>))
        }
    }

    /// A program whose listing holds `defined` (offset, data type) entries; `lengths` sets the
    /// length of dynamic (string) data.
    fn program(defined: Vec<(i64, Arc<dyn DataType>)>, lengths: &[(i64, i32)]) -> TestProgram {
        let space = AddressSpace::new("ram", 32, 1, AddressSpaceType::Ram, 1);
        let owner = Arc::new(TestCodeUnitOwner::new(space, BASE, vec![0; SIZE]));
        for &(offset, len) in lengths {
            owner.set_length_at(offset, len);
        }
        let defined = defined
            .into_iter()
            .map(|(offset, dt)| {
                let o: Arc<dyn CodeUnitOwner> = owner.clone();
                Arc::new(DataDB::new(o, offset, owner.address(offset), offset, Some(dt)))
            })
            .collect();
        TestProgram { owner: owner.clone(), listing: RwLock::new(TestListing { owner, defined }) }
    }

    fn at(p: &TestProgram, offset: i64) -> Address {
        p.owner.address(offset)
    }

    fn compatible(p: &TestProgram, dt: &dyn DataType, offset: i64) -> bool {
        DWARFDataInstanceHelper::new(p).is_data_type_compatible_with_address(dt, &at(p, offset))
    }

    fn strict(p: &TestProgram, dt: &dyn DataType, offset: i64) -> bool {
        DWARFDataInstanceHelper::new(p)
            .set_allow_truncating(false)
            .is_data_type_compatible_with_address(dt, &at(p, offset))
    }

    fn char_array(n: i32) -> ArrayDataType {
        ArrayDataType::new(CharDataType::data_type(), n).unwrap()
    }

    #[test]
    fn undefined_range_accepts_anything() {
        let p = program(vec![], &[]);
        assert!(compatible(&p, &DWordDataType::new(None), BASE));
        assert!(compatible(&p, &char_array(16), BASE + 8));
        // a range running past the end of the memory block is not undefined, and the undefined
        // data at the start is not "defined", so it is still compatible
        assert!(compatible(&p, &char_array(8), BASE + SIZE as i64 - 4));
    }

    #[test]
    fn simple_types_need_the_same_class_and_length() {
        let p = program(vec![(BASE, DWordDataType::data_type())], &[]);
        assert!(compatible(&p, &DWordDataType::new(None), BASE));
        assert!(!compatible(&p, &FloatDataType::new(None), BASE), "different class");
        assert!(!compatible(&p, &WordDataType::new(None), BASE), "different length");
        // in the middle of the existing dword
        assert!(!compatible(&p, &ByteDataType::new(None), BASE + 1));
    }

    #[test]
    fn simple_type_over_undefined_of_the_same_length() {
        // DataUtilities.isUndefinedRange counts undefinedN data as undefined, so any type fits
        // over an undefined4 on its own
        let p = program(vec![(BASE, Undefined4DataType::data_type())], &[]);
        assert!(compatible(&p, &FloatDataType::new(None), BASE));
        assert!(compatible(&p, &WordDataType::new(None), BASE));

        // a structure member landing on (defined) undefinedN data must have its length
        let p = program(
            vec![(BASE, Undefined2DataType::data_type()), (BASE + 2, ByteDataType::data_type())],
            &[],
        );
        let mut s = StructureDataType::new("s", 0);
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&WordDataType::data_type()), 2, Some("a".into()), None).unwrap();
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&ByteDataType::data_type()), 1, Some("b".into()), None).unwrap();
        assert!(compatible(&p, &s, BASE));
        let mut s = StructureDataType::new("s", 0);
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&DWordDataType::data_type()), 4, Some("a".into()), None).unwrap();
        assert!(!compatible(&p, &s, BASE));
    }

    #[test]
    fn char_family_matches_char_subclasses() {
        let p = program(vec![(BASE, SignedCharDataType::data_type())], &[]);
        // CharDataType.class.isInstance(signedChar)
        assert!(compatible(&p, &CharDataType::new(None), BASE));
        let p = program(vec![(BASE, CharDataType::data_type())], &[]);
        assert!(!compatible(&p, &SignedCharDataType::new(None), BASE));
    }

    #[test]
    fn pointer_may_upgrade_an_integer_of_the_same_length() {
        let p = program(vec![(BASE, DWordDataType::data_type()), (BASE + 8, WordDataType::data_type())], &[]);
        let ptr = Pointer32DataType::new(None::<Arc<dyn DataType>>).unwrap();
        assert!(compatible(&p, &ptr, BASE));
        assert!(!compatible(&p, &ptr, BASE + 8));
    }

    #[test]
    fn enum_needs_an_integer_or_enum_of_the_same_length_but_not_bool() {
        let p = program(
            vec![(BASE, DWordDataType::data_type()), (BASE + 8, BooleanDataType::data_type())],
            &[],
        );
        assert!(compatible(&p, &EnumDataType::new_in_category(ROOT.clone(), "E", 4), BASE));
        assert!(!compatible(&p, &EnumDataType::new_in_category(ROOT.clone(), "E", 2), BASE));
        assert!(!compatible(&p, &EnumDataType::new_in_category(ROOT.clone(), "E", 1), BASE + 8));
    }

    #[test]
    fn typedef_is_compared_by_its_base_type() {
        let p = program(vec![(BASE, DWordDataType::data_type())], &[]);
        let td = TypedefDataType::new_in_root("mydword", DWordDataType::data_type()).unwrap();
        assert!(compatible(&p, &td, BASE));
        let td = TypedefDataType::new_in_root("myfloat", FloatDataType::data_type()).unwrap();
        assert!(!compatible(&p, &td, BASE));
    }

    #[test]
    fn char_array_over_a_string() {
        let p = program(vec![(BASE, StringDataType::data_type())], &[(BASE, 4)]);
        assert!(compatible(&p, &char_array(4), BASE), "same length");
        assert!(compatible(&p, &char_array(2), BASE), "truncating allowed");
        assert!(!strict(&p, &char_array(2), BASE), "truncating disallowed");
        assert!(compatible(&p, &char_array(8), BASE), "only undefined data follows");
        // a non-char array over a string: Java dereferences a null element type
        let bytes = ArrayDataType::new(ByteDataType::data_type(), 4).unwrap();
        assert!(!compatible(&p, &bytes, BASE));

        let p = program(
            vec![(BASE, StringDataType::data_type()), (BASE + 6, ByteDataType::data_type())],
            &[(BASE, 4)],
        );
        assert!(!compatible(&p, &char_array(8), BASE), "defined data follows");
    }

    #[test]
    fn array_over_an_array_needs_equivalent_elements() {
        let p = program(vec![(BASE, Arc::new(char_array(4)) as Arc<dyn DataType>)], &[]);
        assert!(compatible(&p, &char_array(4), BASE));
        let words = ArrayDataType::new(WordDataType::data_type(), 2).unwrap();
        assert!(!compatible(&p, &words, BASE));
    }

    #[test]
    fn array_over_scalars_checks_every_element() {
        let p = program(vec![(BASE, ByteDataType::data_type()), (BASE + 2, ByteDataType::data_type())], &[]);
        let bytes = ArrayDataType::new(ByteDataType::data_type(), 4).unwrap();
        assert!(compatible(&p, &bytes, BASE));
        let p = program(vec![(BASE, ByteDataType::data_type()), (BASE + 2, WordDataType::data_type())], &[]);
        assert!(!compatible(&p, &bytes, BASE));
    }

    #[test]
    fn structure_over_scalars_checks_every_member() {
        let mut s = StructureDataType::new("s", 0);
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&ByteDataType::data_type()), 1, Some("a".into()), None).unwrap();
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&ByteDataType::data_type()), 1, Some("b".into()), None).unwrap();
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&WordDataType::data_type()), 2, Some("c".into()), None).unwrap();

        let p = program(vec![(BASE, ByteDataType::data_type())], &[]);
        assert!(compatible(&p, &s, BASE));
        let p = program(vec![(BASE, ByteDataType::data_type()), (BASE + 2, DWordDataType::data_type())], &[]);
        assert!(!compatible(&p, &s, BASE), "member c (word) over a dword");

        // a structure over an equivalent structure
        let p = program(vec![(BASE, Arc::new(s.clone()) as Arc<dyn DataType>)], &[]);
        assert!(compatible(&p, &s, BASE));
    }

    #[test]
    fn structure_truncating_existing_data() {
        let mut s = StructureDataType::new("s", 0);
        s.add_with_length_and_name(crate::program::seam_stubs::share_data_type(&ByteDataType::data_type()), 1, Some("a".into()), None).unwrap();
        let p = program(vec![(BASE, StringDataType::data_type())], &[(BASE, 4)]);
        // member a (byte) lands on the string: not a simple match
        assert!(!compatible(&p, &s, BASE));
        let p = program(vec![(BASE, Arc::new(char_array(4)) as Arc<dyn DataType>)], &[]);
        assert!(!compatible(&p, &s, BASE));
    }
}
