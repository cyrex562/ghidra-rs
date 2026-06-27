/// A marker trait that is a common bound for the real probe traits.
///
/// See [`GFileSystemProbeBytesOnly`] and [`GFileSystemProbeByteProvider`] for the
/// concrete probe variants that implementations will actually use.
///
/// This is the Rust equivalent of
/// `ghidra.formats.gfilesystem.factory.GFileSystemProbe`.
pub trait GFileSystemProbe {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyProbe;
    impl GFileSystemProbe for DummyProbe {}

    #[test]
    fn marker_trait_is_object_safe_and_implementable() {
        let _probe = DummyProbe;
    }

    #[test]
    fn boxed_dyn_probe_is_accepted() {
        let _probe: Box<dyn GFileSystemProbe> = Box::new(DummyProbe);
    }
}
