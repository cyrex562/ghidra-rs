use super::vxt::Vxt;

/// Compiler-generated virtual base table.
pub trait VbTable: Vxt {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteVbTable;
    impl Vxt for ConcreteVbTable {}
    impl VbTable for ConcreteVbTable {}

    #[test]
    fn test_vb_table_implementable() {
        let _t = ConcreteVbTable;
    }
}
