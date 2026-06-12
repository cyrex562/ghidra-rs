use std::env;

pub struct SystemUtilities;

impl SystemUtilities {
    pub const TESTING_PROPERTY: &'static str = "GHIDRA_TESTING";
    pub const HEADLESS_PROPERTY: &'static str = "GHIDRA_HEADLESS";

    pub fn get_user_name() -> String {
        let raw_name = env::var("USER")
            .or_else(|_| env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        Self::get_clean_user_name(&raw_name)
    }

    pub fn get_clean_user_name(name: &str) -> String {
        let mut uname = name.to_string();

        // Remove spaces
        uname = uname.replace(' ', "");

        // Remove leading Domain Name if present (treat / and \ in a similar fashion)
        if let Some(slash_idx) = uname.rfind('\\') {
            uname = uname[slash_idx + 1..].to_string();
        }
        if let Some(slash_idx) = uname.rfind('/') {
            uname = uname[slash_idx + 1..].to_string();
        }

        uname
    }

    pub fn get_boolean_property(name: &str, default_value: bool) -> bool {
        match env::var(name) {
            Ok(val) => val.to_lowercase() == "true",
            Err(_) => default_value,
        }
    }

    pub fn is_in_testing_mode() -> bool {
        Self::get_boolean_property(Self::TESTING_PROPERTY, false)
    }

    pub fn is_in_headless_mode() -> bool {
        Self::get_boolean_property(Self::HEADLESS_PROPERTY, false)
    }

    pub fn is_in_development_mode() -> bool {
        cfg!(debug_assertions)
    }

    pub fn is_in_release_mode() -> bool {
        !Self::is_in_development_mode() && !Self::is_in_testing_mode()
    }

    pub fn get_default_thread_pool_size() -> usize {
        // Rust's num_cpus or similar?
        // For now, let's use a simple heuristic or a hardcoded value like the original Java code.
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let size = (num_cpus + 1).min(10);
        size.max(1)
    }

    pub fn is_equal<T: PartialEq>(o1: &T, o2: &T) -> bool {
        o1 == o2
    }

    pub fn compare_to<T: PartialOrd>(c1: &T, c2: &T) -> std::cmp::Ordering {
        c1.partial_cmp(c2).unwrap_or(std::cmp::Ordering::Equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_user_name() {
        assert_eq!(
            SystemUtilities::get_clean_user_name("MyDomain\\John Doe"),
            "JohnDoe"
        );
        assert_eq!(
            SystemUtilities::get_clean_user_name("MyDomain/John Doe"),
            "JohnDoe"
        );
        assert_eq!(SystemUtilities::get_clean_user_name("John Doe"), "JohnDoe");
    }

    #[test]
    fn test_modes() {
        // In test mode, debug_assertions should be true unless --release is used
        assert!(SystemUtilities::is_in_development_mode());
    }
}
