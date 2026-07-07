/// Marker trait for tests whose failures should be ignored when they arise from
/// unfinished (`TODOException`) components.
///
/// As a matter of practice, tests ought not to be committed into source control with this
/// trait implemented. Or, if they are, they should only have this for a short period.
/// Production code ought not to be throwing from unfinished stubs, but sometimes things
/// are "production ready" despite having some unfinished components. This marker allows
/// tests that identify those unfinished portions to remain active but ignored. The
/// implementation ought to be removed when it is time to finish those components, so
/// that failures due to unfinished code are quickly identified.
pub trait IgnoreUnfinished {}

#[cfg(test)]
mod tests {
    use super::IgnoreUnfinished;

    struct MyUnfinishedTest;
    impl IgnoreUnfinished for MyUnfinishedTest {}

    fn accepts_ignore_unfinished<T: IgnoreUnfinished>(_: &T) {}

    #[test]
    fn ignore_unfinished_is_implementable() {
        let t = MyUnfinishedTest;
        accepts_ignore_unfinished(&t);
    }
}
