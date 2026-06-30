/// String constants identifying the built-in plugin categories.
///
/// Maps to `ghidra.app.plugin.GenericPluginCategoryNames`.
pub struct GenericPluginCategoryNames;

impl GenericPluginCategoryNames {
    pub const COMMON: &'static str = "Common";
    pub const SUPPORT: &'static str = "Support";
    pub const TESTING: &'static str = "Testing";
    pub const MISC: &'static str = "Miscellaneous";
    pub const EXAMPLES: &'static str = "Examples";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(GenericPluginCategoryNames::COMMON, "Common");
        assert_eq!(GenericPluginCategoryNames::SUPPORT, "Support");
        assert_eq!(GenericPluginCategoryNames::TESTING, "Testing");
        assert_eq!(GenericPluginCategoryNames::MISC, "Miscellaneous");
        assert_eq!(GenericPluginCategoryNames::EXAMPLES, "Examples");
    }
}
