use crate::program::seam_stubs::Processor;
use crate::util::classfinder::extension_point::ExtensionPoint;

/// Allows implementations to determine if an instruction should be skipped during search operations.
///
/// This is an extension point that implementations can provide for specific processors.
pub trait InstructionSkipper: ExtensionPoint {
    /// Returns the processor this skipper is applicable for.
    fn get_applicable_processor(&self) -> Box<dyn Processor>;

    /// Determines whether an instruction should be skipped.
    ///
    /// # Arguments
    /// * `buffer` - The instruction bytes to check
    ///
    /// # Returns
    /// `true` if the instruction should be skipped, `false` otherwise
    fn should_skip(&self, buffer: &[u8]) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSkipper;

    impl ExtensionPoint for TestSkipper {}

    struct MockProcessor;

    impl Processor for MockProcessor {
        fn name(&self) -> String {
            "test_processor".to_string()
        }
    }

    impl InstructionSkipper for TestSkipper {
        fn get_applicable_processor(&self) -> Box<dyn Processor> {
            Box::new(MockProcessor)
        }

        fn should_skip(&self, buffer: &[u8]) -> bool {
            !buffer.is_empty()
        }
    }

    #[test]
    fn returns_applicable_processor() {
        let skipper = TestSkipper;
        let processor = skipper.get_applicable_processor();
        assert_eq!(processor.name(), "test_processor");
    }

    #[test]
    fn should_skip_non_empty_buffer() {
        let skipper = TestSkipper;
        assert!(skipper.should_skip(b"test"));
    }

    #[test]
    fn should_not_skip_empty_buffer() {
        let skipper = TestSkipper;
        assert!(!skipper.should_skip(b""));
    }

    #[test]
    fn usable_as_trait_object() {
        let skipper: Box<dyn InstructionSkipper> = Box::new(TestSkipper);
        let processor = skipper.get_applicable_processor();
        assert_eq!(processor.name(), "test_processor");
        assert!(skipper.should_skip(b"test"));
    }
}
