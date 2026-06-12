/// Name used for Ghidra's special heap memory block.
///
/// This mirrors `MemoryConstants.HEAP_BLOCK_NAME`.
pub const HEAP_BLOCK_NAME: &str = "__HEAP__";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_block_name_matches_java_constant() {
        assert_eq!(HEAP_BLOCK_NAME, "__HEAP__");
    }
}
