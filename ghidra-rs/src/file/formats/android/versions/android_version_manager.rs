use super::android_version::AndroidVersion;

/// Name of XML attribute in the AndroidManifest.xml file.
pub const PLATFORM_BUILD_VERSION_NAME: &str = "platformBuildVersionName";

/// Name of XML attribute in the AndroidManifest.xml file.
pub const PLATFORM_BUILD_VERSION_CODE: &str = "platformBuildVersionCode";

/// Returns the [`AndroidVersion`]s for the given API level.
///
/// For example, Android API level `23` applies to versions `6.0` and `6.0.1`.
pub fn get_by_api(api: i32) -> Vec<AndroidVersion> {
    ALL_VERSIONS
        .iter()
        .copied()
        .filter(|v| v.api_version() == api)
        .collect()
}

/// Returns the [`AndroidVersion`] for the given version number.
///
/// For example, `"4.0"`, `"5.0.1"`, etc.
pub fn get_by_number(number: &str) -> AndroidVersion {
    ALL_VERSIONS
        .iter()
        .copied()
        .find(|v| v.version_number() == number)
        .unwrap_or(AndroidVersion::Unknown)
}

/// Returns the [`AndroidVersion`]s for the given version letter.
///
/// For example, Android `'M'` applies to versions `6.0` and `6.0.1`.
pub fn get_by_letter(letter: char) -> Vec<AndroidVersion> {
    ALL_VERSIONS
        .iter()
        .copied()
        .filter(|v| v.version_letter() == letter)
        .collect()
}

/// Returns the [`AndroidVersion`]s for the given version letter.
///
/// For example, Android `"M"` applies to versions `6.0` and `6.0.1`.
pub fn get_by_letter_str(letter: &str) -> Vec<AndroidVersion> {
    match letter.chars().next() {
        Some(c) => get_by_letter(c),
        None => Vec::new(),
    }
}

/// Returns the [`AndroidVersion`]s for the given version name.
///
/// For example, Android `"Marshmallow"` applies to versions `6.0` and `6.0.1`.
pub fn get_by_name(name: &str) -> Vec<AndroidVersion> {
    ALL_VERSIONS
        .iter()
        .copied()
        .filter(|v| v.version_name() == name)
        .collect()
}

/// Returns the [`AndroidVersion`] for the given code or name.
///
/// The code represents the API version. The name can specify either the version
/// number (e.g. `5.0.1`), version name (e.g. `Oreo`), or version letter (e.g. `M`).
/// The `PlatformBuildVersionCode` and `PlatformBuildVersionName` are specified in
/// the AndroidManifest.xml file:
///
/// ```text
/// platformBuildVersionCode="33"
/// platformBuildVersionName="T"
/// ```
pub fn get_by_platform_build_version(code: &str, name: &str) -> AndroidVersion {
    let api = to_integer(code);
    for version in ALL_VERSIONS.iter().copied() {
        if version.api_version() == api {
            return version;
        } else if version.version_name() == name {
            return version;
        } else if version.version_number() == name {
            return version;
        } else if version.version_letter().to_string() == name {
            return version;
        }
    }
    AndroidVersion::Unknown
}

fn to_integer(platform_build_version_code: &str) -> i32 {
    platform_build_version_code
        .parse::<i32>()
        .unwrap_or(AndroidVersion::INVALID_API_VALUE)
}

const ALL_VERSIONS: &[AndroidVersion] = &[
    AndroidVersion::Version1_5,
    AndroidVersion::Version1_6,
    AndroidVersion::Version2_0,
    AndroidVersion::Version2_0_1,
    AndroidVersion::Version2_1,
    AndroidVersion::Version2_2,
    AndroidVersion::Version2_2_1,
    AndroidVersion::Version2_2_2,
    AndroidVersion::Version2_2_3,
    AndroidVersion::Version2_3,
    AndroidVersion::Version2_3_1,
    AndroidVersion::Version2_3_2,
    AndroidVersion::Version2_3_3,
    AndroidVersion::Version2_3_4,
    AndroidVersion::Version2_3_5,
    AndroidVersion::Version2_3_6,
    AndroidVersion::Version2_3_7,
    AndroidVersion::Version3_0,
    AndroidVersion::Version3_1,
    AndroidVersion::Version3_2,
    AndroidVersion::Version3_2_1,
    AndroidVersion::Version3_2_2,
    AndroidVersion::Version3_2_3,
    AndroidVersion::Version3_2_4,
    AndroidVersion::Version3_2_5,
    AndroidVersion::Version3_2_6,
    AndroidVersion::Version4_0,
    AndroidVersion::Version4_0_1,
    AndroidVersion::Version4_0_2,
    AndroidVersion::Version4_0_3,
    AndroidVersion::Version4_0_4,
    AndroidVersion::Version4_1,
    AndroidVersion::Version4_1_1,
    AndroidVersion::Version4_1_2,
    AndroidVersion::Version4_2,
    AndroidVersion::Version4_2_1,
    AndroidVersion::Version4_2_2,
    AndroidVersion::Version4_3,
    AndroidVersion::Version4_3_1,
    AndroidVersion::Version4_4,
    AndroidVersion::Version4_4_1,
    AndroidVersion::Version4_4_2,
    AndroidVersion::Version4_4_3,
    AndroidVersion::Version4_4_4,
    AndroidVersion::Version4_4W,
    AndroidVersion::Version5_0,
    AndroidVersion::Version5_0_1,
    AndroidVersion::Version5_0_2,
    AndroidVersion::Version5_1,
    AndroidVersion::Version5_1_1,
    AndroidVersion::Version6_0,
    AndroidVersion::Version6_0_1,
    AndroidVersion::Version7_0,
    AndroidVersion::Version7_1,
    AndroidVersion::Version7_1_1,
    AndroidVersion::Version7_1_2,
    AndroidVersion::Version8_0,
    AndroidVersion::Version8_1,
    AndroidVersion::Version9,
    AndroidVersion::Version10,
    AndroidVersion::Version11,
    AndroidVersion::Version12,
    AndroidVersion::Version12L,
    AndroidVersion::Version13,
    AndroidVersion::Unknown,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_build_version_constants() {
        assert_eq!(PLATFORM_BUILD_VERSION_NAME, "platformBuildVersionName");
        assert_eq!(PLATFORM_BUILD_VERSION_CODE, "platformBuildVersionCode");
    }

    #[test]
    fn get_by_api_returns_all_matches() {
        let matches = get_by_api(8);
        assert_eq!(
            matches,
            vec![
                AndroidVersion::Version2_2,
                AndroidVersion::Version2_2_1,
                AndroidVersion::Version2_2_2,
                AndroidVersion::Version2_2_3,
            ]
        );
    }

    #[test]
    fn get_by_api_no_match_returns_empty() {
        assert!(get_by_api(-42).is_empty());
    }

    #[test]
    fn get_by_number_finds_exact_version() {
        assert_eq!(get_by_number("6.0"), AndroidVersion::Version6_0);
    }

    #[test]
    fn get_by_number_unknown_when_missing() {
        assert_eq!(get_by_number("999.0"), AndroidVersion::Unknown);
    }

    #[test]
    fn get_by_letter_char_returns_all_matches() {
        let matches = get_by_letter('M');
        assert_eq!(
            matches,
            vec![AndroidVersion::Version6_0, AndroidVersion::Version6_0_1]
        );
    }

    #[test]
    fn get_by_letter_str_uses_first_char() {
        assert_eq!(get_by_letter_str("M"), get_by_letter('M'));
    }

    #[test]
    fn get_by_letter_str_empty_returns_empty() {
        assert!(get_by_letter_str("").is_empty());
    }

    #[test]
    fn get_by_name_returns_all_matches() {
        let matches = get_by_name("Marshmallow");
        assert_eq!(
            matches,
            vec![AndroidVersion::Version6_0, AndroidVersion::Version6_0_1]
        );
    }

    #[test]
    fn get_by_platform_build_version_matches_code() {
        assert_eq!(
            get_by_platform_build_version("33", ""),
            AndroidVersion::Version13
        );
    }

    #[test]
    fn get_by_platform_build_version_matches_name() {
        assert_eq!(
            get_by_platform_build_version("", "T"),
            AndroidVersion::Version13
        );
    }

    #[test]
    fn get_by_platform_build_version_matches_version_number() {
        assert_eq!(
            get_by_platform_build_version("", "6.0.1"),
            AndroidVersion::Version6_0_1
        );
    }

    #[test]
    fn get_by_platform_build_version_matches_version_name() {
        assert_eq!(
            get_by_platform_build_version("", "Oreo"),
            AndroidVersion::Version8_0
        );
    }

    #[test]
    fn get_by_platform_build_version_unknown_when_no_match() {
        assert_eq!(
            get_by_platform_build_version("not-a-number", "does-not-exist"),
            AndroidVersion::Unknown
        );
    }
}
