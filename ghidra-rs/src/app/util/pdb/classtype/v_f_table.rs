use super::vxt::Vxt;

/// Compiler-generated virtual function table.
pub trait VfTable: Vxt {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteVfTable;
    impl Vxt for ConcreteVfTable {}
    impl VfTable for ConcreteVfTable {}

    #[test]
    fn test_vf_table_implementable() {
        let _t = ConcreteVfTable;
    }
}
