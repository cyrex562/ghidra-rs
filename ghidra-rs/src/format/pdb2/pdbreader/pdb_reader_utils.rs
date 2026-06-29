/// Utilities for PDB reader dump formatting.
///
/// Mirrors `PdbReaderUtils` from the Java source: helper functions that write padded
/// header/tail lines to any [`std::io::Write`] sink.
const DASHES: &str = "------------------------------------------------------------\n";

/// Writes a header line for `name`: the name followed by enough dashes to fill the line.
///
/// Total output width is always `DASHES.len()` characters (60 dashes + newline).
/// `name.len()` must not exceed `DASHES.len()` or this function will panic.
pub fn dump_head(writer: &mut impl std::io::Write, name: &str) -> std::io::Result<()> {
    writer.write_all(name.as_bytes())?;
    writer.write_all(DASHES[name.len()..].as_bytes())
}

/// Writes a tail line for `name`: `"End " + name` followed by enough dashes to fill the line.
///
/// `name.len() + 4` must not exceed `DASHES.len()` or this function will panic.
pub fn dump_tail(writer: &mut impl std::io::Write, name: &str) -> std::io::Result<()> {
    writer.write_all(b"End ")?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(DASHES[name.len() + 4..].as_bytes())
}

/// Returns the simple (unqualified) Rust type name for `T`.
///
/// Strips the leading module path, matching Java's `getClass().getSimpleName()`.
pub fn simple_type_name<T: ?Sized>() -> &'static str {
    let full = std::any::type_name::<T>();
    full.rsplit("::").next().unwrap_or(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DASHES_LEN: usize = 61; // 60 '-' + '\n'

    fn run_head(name: &str) -> String {
        let mut buf = Vec::new();
        dump_head(&mut buf, name).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn run_tail(name: &str) -> String {
        let mut buf = Vec::new();
        dump_tail(&mut buf, name).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn dump_head_starts_with_name() {
        let out = run_head("Foo");
        assert!(out.starts_with("Foo"));
    }

    #[test]
    fn dump_head_ends_with_newline() {
        let out = run_head("Foo");
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn dump_head_total_width_is_constant() {
        for name in &["", "A", "Foo", "PdbReader", "AbstractParsableItem"] {
            let out = run_head(name);
            assert_eq!(out.len(), DASHES_LEN, "wrong width for name={name:?}");
        }
    }

    #[test]
    fn dump_head_pads_with_dashes() {
        let out = run_head("X");
        // After the name come dashes until the newline
        let rest = &out["X".len()..out.len() - 1];
        assert!(rest.chars().all(|c| c == '-'), "expected dashes, got {rest:?}");
    }

    #[test]
    fn dump_head_empty_name_is_all_dashes() {
        let out = run_head("");
        let body = &out[..out.len() - 1];
        assert!(body.chars().all(|c| c == '-'));
    }

    #[test]
    fn dump_tail_starts_with_end_prefix() {
        let out = run_tail("Foo");
        assert!(out.starts_with("End Foo"));
    }

    #[test]
    fn dump_tail_ends_with_newline() {
        let out = run_tail("Foo");
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn dump_tail_total_width_is_constant() {
        for name in &["", "A", "Foo", "PdbReader"] {
            let out = run_tail(name);
            assert_eq!(out.len(), DASHES_LEN, "wrong width for name={name:?}");
        }
    }

    #[test]
    fn dump_tail_pads_with_dashes() {
        let out = run_tail("X");
        let prefix = "End X";
        let rest = &out[prefix.len()..out.len() - 1];
        assert!(rest.chars().all(|c| c == '-'), "expected dashes, got {rest:?}");
    }

    #[test]
    fn head_and_tail_are_same_width() {
        let head = run_head("MyType");
        let tail = run_tail("MyType");
        assert_eq!(head.len(), tail.len());
    }

    #[test]
    fn simple_type_name_strips_module_path() {
        struct Inner;
        // type_name returns something like "pdb_reader_utils::tests::Inner"
        let name = simple_type_name::<Inner>();
        assert_eq!(name, "Inner");
    }

    #[test]
    fn simple_type_name_primitive_has_no_path() {
        assert_eq!(simple_type_name::<u32>(), "u32");
    }
}
