//! Port of `ghidra.app.util.bin.format.elf.ElfDynamicTable`.
//!
//! If an object file participates in dynamic linking, its program header table will have an
//! element of type `PT_DYNAMIC`. This "segment" contains the `.dynamic` section, an array of
//! `Elf32_Dyn`/`Elf64_Dyn` entries terminated by `DT_NULL`.
//!
//! Java keeps a back-pointer to the owning `ElfHeader` for its word size and for the dynamic type
//! registry used by `toDataType()`. The port records the word size and takes the header at call
//! time in [`to_data_type`](ElfDynamicTable::to_data_type).

use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;
use crate::app::util::bin::struct_converter::ToDataTypeError;
use crate::format::elf::elf_dynamic::ElfDynamic;
use crate::format::elf::elf_dynamic_type::{self, ElfDynamicType};
use crate::format::elf::elf_header::ElfHeader;
use crate::format::elf::elf_structs::{array, dword, enum_type, qword, ElfStruct};
use crate::program::model::data::data_type::DataType;
use crate::util::exception::NotFoundException;

/// The ELF `_DYNAMIC` array.
///
/// Mirrors `ghidra.app.util.bin.format.elf.ElfDynamicTable`.
#[derive(Debug, Clone)]
pub struct ElfDynamicTable {
    dynamics: Vec<ElfDynamic>,
    is_32bit: bool,
    file_offset: i64,
    addr_offset: i64,
}

impl ElfDynamicTable {
    /// Construct and parse an ELF dynamic table, reading entries up to and including `DT_NULL`.
    ///
    /// Mirrors `ElfDynamicTable(BinaryReader, ElfHeader, long, long)`. `addr_offset` should
    /// already be adjusted for pre-link.
    pub fn new(
        reader: &BinaryReader,
        header: &ElfHeader,
        file_offset: i64,
        addr_offset: i64,
    ) -> io::Result<Self> {
        // Collect set of all _DYNAMIC array tags specified in .dynamic section
        let mut entry_reader = reader.clone_at(file_offset as u64);
        let null_tag = elf_dynamic_type::dt_null().value;
        let mut dynamics = Vec::new();
        loop {
            let dyn_ = ElfDynamic::parse(&mut entry_reader, header)?;
            let tag = dyn_.get_tag();
            dynamics.push(dyn_);
            if tag == null_tag {
                break;
            }
        }
        Ok(ElfDynamicTable { dynamics, is_32bit: header.is32_bit(), file_offset, addr_offset })
    }

    /// Adds `dyn_` at `index`. Mirrors `addDynamic(ElfDynamic, int)`.
    ///
    /// # Panics
    /// If `index > len` (Java's `IndexOutOfBoundsException`).
    pub fn add_dynamic(&mut self, dyn_: ElfDynamic, index: usize) {
        self.dynamics.insert(index, dyn_);
    }

    /// All dynamic entries, in table order (including the terminating `DT_NULL`).
    pub fn get_dynamics(&self) -> &[ElfDynamic] {
        &self.dynamics
    }

    /// All dynamic entries whose tag equals `type_`. Mirrors `getDynamics(long)`.
    pub fn get_dynamics_of(&self, type_: i64) -> Vec<&ElfDynamic> {
        self.dynamics.iter().filter(|d| d.get_tag() as i64 == type_).collect()
    }

    /// All dynamic entries of type `type_`. Mirrors `getDynamics(ElfDynamicType)`.
    pub fn get_dynamics_of_type(&self, type_: &ElfDynamicType) -> Vec<&ElfDynamic> {
        self.get_dynamics_of(type_.value as i64)
    }

    /// The value of the first entry with tag `type_`. Mirrors `getDynamicValue(long)`.
    pub fn get_dynamic_value(&self, type_: i64) -> Result<i64, NotFoundException> {
        self.dynamics
            .iter()
            .find(|d| d.get_tag() as i64 == type_)
            .map(|d| d.get_value() as i64)
            .ok_or_else(|| {
                NotFoundException(format!("Dynamic table entry not found: 0x{:x}", type_))
            })
    }

    /// Mirrors `getDynamicValue(ElfDynamicType)`.
    pub fn get_dynamic_value_of_type(&self, type_: &ElfDynamicType) -> Result<i64, NotFoundException> {
        self.get_dynamic_value(type_.value as i64)
    }

    /// True if an entry with tag `type_` exists. Mirrors `containsDynamicValue(long)`.
    pub fn contains_dynamic_value(&self, type_: i64) -> bool {
        self.dynamics.iter().any(|d| d.get_tag() as i64 == type_)
    }

    /// Mirrors `containsDynamicValue(ElfDynamicType)`.
    pub fn contains_dynamic_value_of_type(&self, type_: &ElfDynamicType) -> bool {
        self.contains_dynamic_value(type_.value as i64)
    }

    /// The table's file offset.
    pub fn get_file_offset(&self) -> i64 {
        self.file_offset
    }

    /// The table's memory address offset.
    pub fn get_address_offset(&self) -> i64 {
        self.addr_offset
    }

    /// `dynamics.len() * entry size`.
    pub fn get_length(&self) -> i64 {
        self.dynamics.len() as i64 * self.get_entry_size() as i64
    }

    /// 8 bytes for ELF32, 16 for ELF64.
    pub fn get_entry_size(&self) -> i32 {
        if self.is_32bit {
            8
        } else {
            16
        }
    }

    /// An array of `Elf32_Dyn`/`Elf64_Dyn`. Mirrors `toDataType()`; the dynamic type registry and
    /// type suffix come from `header` at call time.
    pub fn to_data_type(&self, header: &ElfHeader) -> Result<Box<dyn DataType>, ToDataTypeError> {
        let type_suffix = header.get_type_suffix();
        let mut name = if self.is_32bit { "Elf32_Dyn" } else { "Elf64_Dyn" }.to_string();
        if let Some(suffix) = &type_suffix {
            name.push_str(suffix);
        }
        let mut s = ElfStruct::new(&name);
        s.add(self.get_tag_data_type(header), "d_tag")?;
        if self.is_32bit {
            s.add(dword(), "d_val")?;
        } else {
            s.add(qword(), "d_val")?;
        }
        let len = s.length();
        array(s.finish(), self.dynamics.len() as i32, len)
    }

    fn get_tag_data_type(&self, header: &ElfHeader) -> Box<dyn DataType> {
        let size = if self.is_32bit { 4 } else { 8 };
        match header.get_dynamic_type_map() {
            None => {
                if self.is_32bit {
                    dword()
                } else {
                    qword()
                }
            }
            Some(map) => {
                let mut name =
                    if self.is_32bit { "Elf32_DynTag" } else { "Elf64_DynTag" }.to_string();
                if let Some(suffix) = header.get_type_suffix() {
                    name.push_str(&suffix);
                }
                enum_type(&name, size, map.values().map(|t| (t.name.as_str(), t.value as i64)))
            }
        }
    }
}
