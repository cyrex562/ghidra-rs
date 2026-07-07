/// Indicates that a type has a post-read hook to be invoked after its structure
/// fields have been populated from binary data.
///
/// This is the Rust equivalent of the Java `@AfterStructureRead` annotation used
/// in Ghidra's struct-mapping framework.  In Java a runtime-annotation is placed
/// on individual methods so the framework can discover and call them via
/// reflection.  In Rust the same contract is expressed as a trait: any type that
/// needs post-read processing implements `AfterStructureRead` and the framework
/// calls [`after_structure_read`](AfterStructureRead::after_structure_read) after
/// all fields have been read.
pub trait AfterStructureRead {
    /// Called after the structure's fields have been read from binary data.
    ///
    /// Implementors may perform validation, cross-field fixups, or any other
    /// post-initialisation work here.  Returning an error aborts the overall
    /// read operation.
    fn after_structure_read(&mut self) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AfterStructureRead;

    struct Dummy {
        value: i32,
        post_read_called: bool,
    }

    impl AfterStructureRead for Dummy {
        fn after_structure_read(&mut self) -> anyhow::Result<()> {
            self.post_read_called = true;
            Ok(())
        }
    }

    #[test]
    fn hook_is_called_and_mutates_state() {
        let mut d = Dummy { value: 42, post_read_called: false };
        d.after_structure_read().unwrap();
        assert!(d.post_read_called);
        assert_eq!(d.value, 42);
    }

    struct Fallible;

    impl AfterStructureRead for Fallible {
        fn after_structure_read(&mut self) -> anyhow::Result<()> {
            anyhow::bail!("post-read validation failed")
        }
    }

    #[test]
    fn hook_propagates_errors() {
        let mut f = Fallible;
        let err = f.after_structure_read().unwrap_err();
        assert!(err.to_string().contains("post-read validation failed"));
    }

    struct Noop;

    impl AfterStructureRead for Noop {
        fn after_structure_read(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn no_op_implementation_succeeds() {
        let mut n = Noop;
        assert!(n.after_structure_read().is_ok());
    }
}
