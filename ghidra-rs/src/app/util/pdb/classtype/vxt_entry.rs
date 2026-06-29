/// Compiler-generated virtual "something" table entry — generic v-anything-table entry.
pub trait VxtEntry {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteVxtEntry;
    impl VxtEntry for ConcreteVxtEntry {}

    #[test]
    fn test_vxt_entry_implementable() {
        let _e = ConcreteVxtEntry;
    }
}
