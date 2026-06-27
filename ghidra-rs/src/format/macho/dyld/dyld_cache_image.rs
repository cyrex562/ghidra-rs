/// A convenience trait for getting the address and path of a DYLD Cache image.
pub trait DyldCacheImage {
    /// Returns the address of the start of the image.
    fn address(&self) -> u64;

    /// Returns the path of the image.
    fn path(&self) -> &str;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestImage {
        addr: u64,
        p: String,
    }

    impl DyldCacheImage for TestImage {
        fn address(&self) -> u64 {
            self.addr
        }
        fn path(&self) -> &str {
            &self.p
        }
    }

    #[test]
    fn test_address_and_path() {
        let img = TestImage {
            addr: 0x1000_0000,
            p: "/usr/lib/libc.dylib".to_string(),
        };
        assert_eq!(img.address(), 0x1000_0000);
        assert_eq!(img.path(), "/usr/lib/libc.dylib");
    }

    #[test]
    fn test_zero_address() {
        let img = TestImage {
            addr: 0,
            p: "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
        };
        assert_eq!(img.address(), 0);
        assert!(!img.path().is_empty());
    }

    #[test]
    fn test_max_address() {
        let img = TestImage {
            addr: u64::MAX,
            p: "/path/to/image".to_string(),
        };
        assert_eq!(img.address(), u64::MAX);
    }
}
