/// Marker trait for tests that should be run a fixed number of times.
///
/// As a matter of practice, no test should ever be committed into source control with this
/// trait implemented. It is only a tool for diagnosing non-deterministic test failures on the
/// developer's workstation. For example, suppose a test fails every other Tuesday on the CI
/// system, but never seems to fail on the developer's workstation. It might help to repeat a
/// test 100 times, including its set-up and tear-down, in a single test run.
///
/// Once the code is fixed and the test passes for the desired number of repetitions, the
/// implementation should be removed before the changes are committed.
pub trait Repeated {
    /// The number of times to repeat the test; must be positive.
    const VALUE: u32;
}

#[cfg(test)]
mod tests {
    use super::Repeated;

    struct RepeatedTest;
    impl Repeated for RepeatedTest {
        const VALUE: u32 = 10;
    }

    #[test]
    fn repeated_value_is_accessible() {
        assert_eq!(RepeatedTest::VALUE, 10);
    }

    struct SingleRepeatTest;
    impl Repeated for SingleRepeatTest {
        const VALUE: u32 = 1;
    }

    #[test]
    fn repeated_single_repetition() {
        assert_eq!(SingleRepeatTest::VALUE, 1);
    }

    struct HighRepeatTest;
    impl Repeated for HighRepeatTest {
        const VALUE: u32 = 100;
    }

    #[test]
    fn repeated_high_count() {
        assert_eq!(HighRepeatTest::VALUE, 100);
    }
}
