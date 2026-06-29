/// Compiler-generated virtual "something" table — generic v-anything-table from any toolchain.
pub trait Vxt {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteVxt;
    impl Vxt for ConcreteVxt {}

    #[test]
    fn test_vxt_implementable() {
        let _v = ConcreteVxt;
    }
}
