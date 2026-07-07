/// Generic marker to denote changes made to some object.
pub trait ChangeSet {}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConcreteChangeSet;
    impl ChangeSet for ConcreteChangeSet {}

    fn accepts_change_set<T: ChangeSet>(_cs: &T) {}

    #[test]
    fn test_impl_change_set() {
        let cs = ConcreteChangeSet;
        accepts_change_set(&cs);
    }

    #[test]
    fn test_dyn_change_set() {
        let cs: Box<dyn ChangeSet> = Box::new(ConcreteChangeSet);
        let _ = cs;
    }
}
