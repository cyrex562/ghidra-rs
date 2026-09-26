use std::io;

use crate::program::model::data::structure::Structure;

use super::data_type_mapper::DataTypeMapper;
use super::field_output_info::FieldOutputInfo;
use super::structure_context::StructureContext;
use super::structure_mapped::StructureMapped;

/// A function that adds a field to a Ghidra structure using annotated field information
/// found in a structure mapped type.
///
/// This is the Rust equivalent of the Java `FieldOutputFunction<T>` functional interface:
/// ```java
/// void addFieldToStructure(StructureContext<T> context, Structure structure,
///     FieldOutputInfo<T> fieldOutputInfo) throws IOException;
/// ```
/// The Rust [`StructureContext`] neither points back at its instance nor holds the mapper, so
/// both are passed alongside it. A `#[field_output(output_func = path)]` names a `fn` of this
/// shape; any matching closure or `fn` is a `FieldOutputFunction`.
pub trait FieldOutputFunction<T: StructureMapped> {
    /// Adds the field described by `field_output_info` to `structure`.
    ///
    /// # Errors
    /// Returns an error if the field cannot be added.
    fn add_field_to_structure(
        &self,
        context: &StructureContext<T>,
        instance: &T,
        mapper: &DataTypeMapper,
        structure: &mut dyn Structure,
        field_output_info: &FieldOutputInfo<T>,
    ) -> io::Result<()>;
}

impl<T, F> FieldOutputFunction<T> for F
where
    T: StructureMapped,
    F: Fn(&StructureContext<T>, &T, &DataTypeMapper, &mut dyn Structure, &FieldOutputInfo<T>) -> io::Result<()>,
{
    fn add_field_to_structure(
        &self,
        context: &StructureContext<T>,
        instance: &T,
        mapper: &DataTypeMapper,
        structure: &mut dyn Structure,
        field_output_info: &FieldOutputInfo<T>,
    ) -> io::Result<()> {
        self(context, instance, mapper, structure, field_output_info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::golang::structmapping::test_support::{byte_reader, simple, test_program, TagContext};
    use crate::format::golang::structmapping::{StructureMapped as DeriveStructureMapped, StructureReader};
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::program::model::data::category_path::ROOT;
    use std::sync::Arc;

    /// Java's `FieldOutputFunction` classes are named in `@FieldOutput(fieldOutputFunc = ..)`.
    fn two_byte_output(
        _ctx: &StructureContext<Custom>,
        _instance: &Custom,
        _mapper: &DataTypeMapper,
        structure: &mut dyn Structure,
        foi: &FieldOutputInfo<Custom>,
    ) -> io::Result<()> {
        structure
            .add_with_name(simple("custom2", 2), Some(foi.get_field().name.to_string()), None)
            .map(|_| ())
            .map_err(io::Error::other)
    }

    fn failing_output(
        _ctx: &StructureContext<Failing>,
        _instance: &Failing,
        _mapper: &DataTypeMapper,
        _structure: &mut dyn Structure,
        _foi: &FieldOutputInfo<Failing>,
    ) -> io::Result<()> {
        Err(io::Error::other("test error"))
    }

    #[derive(DeriveStructureMapped)]
    #[structure_mapping(structure_name = "Custom", reader)]
    struct Custom {
        #[context_field]
        context: StructureContext<Custom>,
        #[field_output(output_func = two_byte_output)]
        value: u8,
    }

    #[derive(DeriveStructureMapped)]
    #[structure_mapping(structure_name = "Failing", reader)]
    struct Failing {
        #[context_field]
        context: StructureContext<Failing>,
        #[field_output(output_func = failing_output)]
        value: u8,
    }

    impl StructureReader for Custom {
        fn read_structure(&mut self, r: &mut dyn BinaryReader, _m: &DataTypeMapper) -> io::Result<()> {
            self.value = r.read_next_byte()?;
            Ok(())
        }
    }

    impl StructureReader for Failing {
        fn read_structure(&mut self, r: &mut dyn BinaryReader, _m: &DataTypeMapper) -> io::Result<()> {
            self.value = r.read_next_byte()?;
            Ok(())
        }
    }

    fn mapper() -> DataTypeMapper {
        let (program, _) = test_program(vec![]);
        let mut mapper = DataTypeMapper::new(program, None).unwrap();
        mapper.add_program_search_category_path(&[ROOT.clone()]);
        mapper.register_structure::<Custom>(&TagContext(vec![])).unwrap();
        mapper.register_structure::<Failing>(&TagContext(vec![])).unwrap();
        mapper
    }

    #[test]
    fn field_output_function_trait_is_implementable() {
        let _func: &dyn FieldOutputFunction<Custom> = &two_byte_output;
        let mapper = mapper();
        let mut reader = byte_reader(vec![7], true);
        let c: Custom = mapper.read_structure(reader.as_mut()).unwrap();
        let dt = c.context.get_structure_data_type_for(&c, &mapper).unwrap();
        assert_eq!(dt.get_length(), 2, "the custom output function chose the field's type");
    }

    #[test]
    fn field_output_function_can_return_error() {
        let mapper = mapper();
        let mut reader = byte_reader(vec![7], true);
        let f: Failing = mapper.read_structure(reader.as_mut()).unwrap();
        let err = f.context.get_structure_data_type_for(&f, &mapper).err().unwrap();
        assert_eq!(err.to_string(), "test error");
        let _ = Arc::new(());
    }
}
