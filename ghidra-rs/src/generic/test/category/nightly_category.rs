/// Marker trait for tests that should only be run nightly in automated test builds.
pub trait NightlyCategory {}

#[cfg(test)]
mod tests {
    use super::NightlyCategory;

    struct MyNightlyTest;
    impl NightlyCategory for MyNightlyTest {}

    fn accepts_nightly<T: NightlyCategory>(_: &T) {}

    #[test]
    fn nightly_category_is_implementable() {
        let t = MyNightlyTest;
        accepts_nightly(&t);
    }
}
