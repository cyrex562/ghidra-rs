//! Port of `ghidra.formats.gfilesystem.factory.GFileSystemProbe`.

/// A common base for the probe interfaces
/// ([`GFileSystemProbeBytesOnly`](super::g_file_system_probe_bytes_only::GFileSystemProbeBytesOnly),
/// [`GFileSystemProbeByteProvider`](super::g_file_system_probe_byte_provider::GFileSystemProbeByteProvider)).
///
/// Mirrors the empty Java marker interface `GFileSystemProbe`.
pub trait GFileSystemProbe {}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyProbe;
    impl GFileSystemProbe for DummyProbe {}

    #[test]
    fn boxed_dyn_probe_is_accepted() {
        let _probe: Box<dyn GFileSystemProbe> = Box::new(DummyProbe);
    }
}
