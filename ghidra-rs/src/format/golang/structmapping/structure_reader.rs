/// Indicates that a type can deserialize itself from raw binary data.
///
/// This is the Rust equivalent of the Java `StructureReader<T>` interface in
/// Ghidra's struct-mapping framework.  In Java, types that contain variable-length
/// fields implement this interface so the framework can call `readStructure()` after
/// an instance is created and its context initialised.  In Rust the same contract
/// is expressed as a trait: any type that needs to perform its own deserialisation
/// implements `StructureReader` and the framework calls
/// [`read_structure`](StructureReader::read_structure).
pub trait StructureReader {
    /// Called after an instance has been created and its context has been
    /// initialised, to allow the struct to deserialise itself using the binary
    /// reader and other state found in its context.
    ///
    /// Returning an error aborts the overall read operation.
    fn read_structure(&mut self) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::StructureReader;

    struct Fixed {
        data: Vec<u8>,
        read_called: bool,
    }

    impl StructureReader for Fixed {
        fn read_structure(&mut self) -> anyhow::Result<()> {
            self.read_called = true;
            Ok(())
        }
    }

    #[test]
    fn read_is_called_and_mutates_state() {
        let mut s = Fixed { data: vec![1, 2, 3], read_called: false };
        s.read_structure().unwrap();
        assert!(s.read_called);
        assert_eq!(s.data, vec![1, 2, 3]);
    }

    struct Fallible;

    impl StructureReader for Fallible {
        fn read_structure(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("failed to deserialise structure")
        }
    }

    #[test]
    fn read_propagates_errors() {
        let mut f = Fallible;
        let err = f.read_structure().unwrap_err();
        assert!(err.to_string().contains("failed to deserialise structure"));
    }

    struct Noop;

    impl StructureReader for Noop {
        fn read_structure(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn no_op_implementation_succeeds() {
        let mut n = Noop;
        assert!(n.read_structure().is_ok());
    }
}
