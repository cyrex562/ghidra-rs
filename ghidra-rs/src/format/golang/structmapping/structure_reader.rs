use std::io;

use crate::app::util::bin::binary_reader::BinaryReader;

use super::data_type_mapper::DataTypeMapper;

/// Indicates that a type can deserialize itself from raw binary data.
///
/// This is the Rust equivalent of the Java `StructureReader<T>` interface in
/// Ghidra's struct-mapping framework. Types that contain variable-length fields implement it so
/// the framework calls [`read_structure`](StructureReader::read_structure) after an instance is
/// created and its context initialised, instead of reading its mapped fields. A type opts in
/// with `#[structure_mapping(reader, ..)]` on its `#[derive(StructureMapped)]`.
///
/// Java's implementations read from `context.getReader()`, the reader the structure is being
/// read with, and leave it positioned after the structure. The instance does not hold that
/// reader in this port, so it is passed in, together with the mapper.
pub trait StructureReader {
    /// Called after an instance has been created and its context has been
    /// initialised, to allow the struct to deserialise itself from `reader`, which is
    /// positioned at the start of the structure.
    ///
    /// Returning an error aborts the overall read operation.
    fn read_structure(&mut self, reader: &mut dyn BinaryReader, mapper: &DataTypeMapper) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::StructureReader;
    use crate::app::util::bin::binary_reader::BinaryReader;
    use crate::format::golang::structmapping::test_support::{byte_reader, test_mapper};
    use crate::format::golang::structmapping::DataTypeMapper;
    use std::io;

    struct Fixed {
        data: Vec<u8>,
        read_called: bool,
    }

    impl StructureReader for Fixed {
        fn read_structure(&mut self, reader: &mut dyn BinaryReader, _mapper: &DataTypeMapper) -> io::Result<()> {
            self.read_called = true;
            self.data.push(reader.read_next_byte()? as u8);
            Ok(())
        }
    }

    #[test]
    fn read_is_called_and_mutates_state() {
        let mapper = test_mapper(vec![]);
        let mut reader = byte_reader(vec![9, 8], true);
        let mut s = Fixed { data: vec![1, 2, 3], read_called: false };
        s.read_structure(reader.as_mut(), &mapper).unwrap();
        assert!(s.read_called);
        assert_eq!(s.data, vec![1, 2, 3, 9]);
        assert_eq!(reader.get_pointer_index(), 1);
    }

    struct Fallible;

    impl StructureReader for Fallible {
        fn read_structure(&mut self, _reader: &mut dyn BinaryReader, _mapper: &DataTypeMapper) -> io::Result<()> {
            Err(io::Error::other("failed to deserialise structure"))
        }
    }

    #[test]
    fn read_propagates_errors() {
        let mapper = test_mapper(vec![]);
        let mut reader = byte_reader(vec![], true);
        let err = Fallible.read_structure(reader.as_mut(), &mapper).unwrap_err();
        assert!(err.to_string().contains("failed to deserialise structure"));
    }

    struct Noop;

    impl StructureReader for Noop {
        fn read_structure(&mut self, _reader: &mut dyn BinaryReader, _mapper: &DataTypeMapper) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn no_op_implementation_succeeds() {
        let mapper = test_mapper(vec![]);
        let mut reader = byte_reader(vec![], true);
        assert!(Noop.read_structure(reader.as_mut(), &mapper).is_ok());
    }
}
