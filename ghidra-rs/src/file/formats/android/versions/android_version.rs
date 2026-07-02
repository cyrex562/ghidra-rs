/// Android OS version mapping, mirroring
/// `ghidra.file.formats.android.versions.AndroidVersion`.
///
/// Maps each Android release to its API level, version string, codename letter,
/// and codename.
///
/// Sources:
/// - <https://developer.android.com/studio/releases/platforms>
/// - <https://en.wikipedia.org/wiki/Android_version_history#Overview>
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AndroidVersion {
    Version1_5,
    Version1_6,
    Version2_0,
    Version2_0_1,
    Version2_1,
    Version2_2,
    Version2_2_1,
    Version2_2_2,
    Version2_2_3,
    Version2_3,
    Version2_3_1,
    Version2_3_2,
    Version2_3_3,
    Version2_3_4,
    Version2_3_5,
    Version2_3_6,
    Version2_3_7,
    Version3_0,
    Version3_1,
    Version3_2,
    Version3_2_1,
    Version3_2_2,
    Version3_2_3,
    Version3_2_4,
    Version3_2_5,
    Version3_2_6,
    Version4_0,
    Version4_0_1,
    Version4_0_2,
    Version4_0_3,
    Version4_0_4,
    Version4_1,
    Version4_1_1,
    Version4_1_2,
    Version4_2,
    Version4_2_1,
    Version4_2_2,
    Version4_3,
    Version4_3_1,
    Version4_4,
    Version4_4_1,
    Version4_4_2,
    Version4_4_3,
    Version4_4_4,
    Version4_4W,
    Version5_0,
    Version5_0_1,
    Version5_0_2,
    Version5_1,
    Version5_1_1,
    Version6_0,
    Version6_0_1,
    Version7_0,
    Version7_1,
    Version7_1_1,
    Version7_1_2,
    Version8_0,
    Version8_1,
    Version9,
    Version10,
    Version11,
    Version12,
    Version12L,
    Version13,
    Unknown,
}

impl AndroidVersion {
    pub const INVALID_API_VALUE: i32 = -1;

    /// Returns the API level (e.g. 24, 25, 26).
    pub fn api_version(&self) -> i32 {
        match self {
            Self::Version1_5   =>  3,
            Self::Version1_6   =>  4,
            Self::Version2_0   =>  5,
            Self::Version2_0_1 =>  6,
            Self::Version2_1   =>  7,
            Self::Version2_2   =>  8,
            Self::Version2_2_1 =>  8,
            Self::Version2_2_2 =>  8,
            Self::Version2_2_3 =>  8,
            Self::Version2_3   =>  9,
            Self::Version2_3_1 =>  9,
            Self::Version2_3_2 =>  9,
            Self::Version2_3_3 => 10,
            Self::Version2_3_4 => 10,
            Self::Version2_3_5 => 10,
            Self::Version2_3_6 => 10,
            Self::Version2_3_7 => 10,
            Self::Version3_0   => 11,
            Self::Version3_1   => 12,
            Self::Version3_2   => 13,
            Self::Version3_2_1 => 13,
            Self::Version3_2_2 => 13,
            Self::Version3_2_3 => 13,
            Self::Version3_2_4 => 13,
            Self::Version3_2_5 => 13,
            Self::Version3_2_6 => 13,
            Self::Version4_0   => 14,
            Self::Version4_0_1 => 14,
            Self::Version4_0_2 => 14,
            Self::Version4_0_3 => 15,
            Self::Version4_0_4 => 15,
            Self::Version4_1   => 16,
            Self::Version4_1_1 => 16,
            Self::Version4_1_2 => 16,
            Self::Version4_2   => 17,
            Self::Version4_2_1 => 17,
            Self::Version4_2_2 => 17,
            Self::Version4_3   => 18,
            Self::Version4_3_1 => 18,
            Self::Version4_4   => 19,
            Self::Version4_4_1 => 19,
            Self::Version4_4_2 => 19,
            Self::Version4_4_3 => 19,
            Self::Version4_4_4 => 19,
            Self::Version4_4W => 20,
            Self::Version5_0   => 21,
            Self::Version5_0_1 => 21,
            Self::Version5_0_2 => 21,
            Self::Version5_1   => 22,
            Self::Version5_1_1 => 22,
            Self::Version6_0   => 23,
            Self::Version6_0_1 => 23,
            Self::Version7_0   => 24,
            Self::Version7_1   => 25,
            Self::Version7_1_1 => 25,
            Self::Version7_1_2 => 25,
            Self::Version8_0   => 26,
            Self::Version8_1   => 27,
            Self::Version9     => 28,
            Self::Version10    => 29,
            Self::Version11    => 30,
            Self::Version12    => 31,
            Self::Version12L   => 32,
            Self::Version13    => 33,
            Self::Unknown      =>  0,
        }
    }

    /// Returns the OS version string (e.g. `"4.0"`, `"5.0.1"`).
    pub fn version_number(&self) -> &'static str {
        match self {
            Self::Version1_5   => "1.5",
            Self::Version1_6   => "1.5",   // preserved from Java source
            Self::Version2_0   => "2.0",
            Self::Version2_0_1 => "2.0.1",
            Self::Version2_1   => "2.1",
            Self::Version2_2   => "2.2",
            Self::Version2_2_1 => "2.2.1",
            Self::Version2_2_2 => "2.2.2",
            Self::Version2_2_3 => "2.2.3",
            Self::Version2_3   => "2.3",
            Self::Version2_3_1 => "2.3.1",
            Self::Version2_3_2 => "2.3.2",
            Self::Version2_3_3 => "2.3.3",
            Self::Version2_3_4 => "2.3.4",
            Self::Version2_3_5 => "2.3.5",
            Self::Version2_3_6 => "2.3.6",
            Self::Version2_3_7 => "2.3.7",
            Self::Version3_0   => "3.0",
            Self::Version3_1   => "3.1",
            Self::Version3_2   => "3.2",
            Self::Version3_2_1 => "3.2.1",
            Self::Version3_2_2 => "3.2.2",
            Self::Version3_2_3 => "3.2.3",
            Self::Version3_2_4 => "3.2.4",
            Self::Version3_2_5 => "3.2.5",
            Self::Version3_2_6 => "3.2.6",
            Self::Version4_0   => "4.0",
            Self::Version4_0_1 => "4.0.1",
            Self::Version4_0_2 => "4.0.2",
            Self::Version4_0_3 => "4.0.3",
            Self::Version4_0_4 => "4.0.4",
            Self::Version4_1   => "4.1",
            Self::Version4_1_1 => "4.1.1",
            Self::Version4_1_2 => "4.1.2",
            Self::Version4_2   => "4.2",
            Self::Version4_2_1 => "4.2.1",
            Self::Version4_2_2 => "4.2.1",   // preserved from Java source
            Self::Version4_3   => "4.3",
            Self::Version4_3_1 => "4.3.1",
            Self::Version4_4   => "4.4",
            Self::Version4_4_1 => "4.4.1",
            Self::Version4_4_2 => "4.4.2",
            Self::Version4_4_3 => "4.4.3",
            Self::Version4_4_4 => "4.4.4",
            Self::Version4_4W => "4.4W",
            Self::Version5_0   => "5.0",
            Self::Version5_0_1 => "5.0.1",
            Self::Version5_0_2 => "5.0.2",
            Self::Version5_1   => "5.1",
            Self::Version5_1_1 => "5.1.1",
            Self::Version6_0   => "6.0",
            Self::Version6_0_1 => "6.0.1",
            Self::Version7_0   => "7.0",
            Self::Version7_1   => "7.1",
            Self::Version7_1_1 => "7.1.1",
            Self::Version7_1_2 => "7.1.2",
            Self::Version8_0   => "8.0",
            Self::Version8_1   => "8.1",
            Self::Version9     => "9",
            Self::Version10    => "10",
            Self::Version11    => "11",
            Self::Version12    => "12",
            Self::Version12L   => "12L",
            Self::Version13    => "13",
            Self::Unknown      => "0",
        }
    }

    /// Returns the version letter (e.g. `'S'`, `'T'`).
    pub fn version_letter(&self) -> char {
        match self {
            Self::Version1_5   => 'C',
            Self::Version1_6   => 'D',
            Self::Version2_0   => 'E',
            Self::Version2_0_1 => 'E',
            Self::Version2_1   => 'E',
            Self::Version2_2   => 'F',
            Self::Version2_2_1 => 'F',
            Self::Version2_2_2 => 'F',
            Self::Version2_2_3 => 'F',
            Self::Version2_3   => 'G',
            Self::Version2_3_1 => 'G',
            Self::Version2_3_2 => 'G',
            Self::Version2_3_3 => 'G',
            Self::Version2_3_4 => 'G',
            Self::Version2_3_5 => 'G',
            Self::Version2_3_6 => 'G',
            Self::Version2_3_7 => 'G',
            Self::Version3_0   => 'H',
            Self::Version3_1   => 'H',
            Self::Version3_2   => 'H',
            Self::Version3_2_1 => 'H',
            Self::Version3_2_2 => 'H',
            Self::Version3_2_3 => 'H',
            Self::Version3_2_4 => 'H',
            Self::Version3_2_5 => 'H',
            Self::Version3_2_6 => 'H',
            Self::Version4_0   => 'I',
            Self::Version4_0_1 => 'I',
            Self::Version4_0_2 => 'I',
            Self::Version4_0_3 => 'I',
            Self::Version4_0_4 => 'I',
            Self::Version4_1   => 'J',
            Self::Version4_1_1 => 'J',
            Self::Version4_1_2 => 'J',
            Self::Version4_2   => 'J',
            Self::Version4_2_1 => 'J',
            Self::Version4_2_2 => 'J',
            Self::Version4_3   => 'J',
            Self::Version4_3_1 => 'J',
            Self::Version4_4   => 'K',
            Self::Version4_4_1 => 'K',
            Self::Version4_4_2 => 'K',
            Self::Version4_4_3 => 'K',
            Self::Version4_4_4 => 'K',
            Self::Version4_4W => 'K',
            Self::Version5_0   => 'L',
            Self::Version5_0_1 => 'L',
            Self::Version5_0_2 => 'L',
            Self::Version5_1   => 'L',
            Self::Version5_1_1 => 'L',
            Self::Version6_0   => 'M',
            Self::Version6_0_1 => 'M',
            Self::Version7_0   => 'N',
            Self::Version7_1   => 'N',
            Self::Version7_1_1 => 'N',
            Self::Version7_1_2 => 'N',
            Self::Version8_0   => 'O',
            Self::Version8_1   => 'O',
            Self::Version9     => 'P',
            Self::Version10    => 'Q',
            Self::Version11    => 'R',
            Self::Version12    => 'S',
            Self::Version12L   => 'S',
            Self::Version13    => 'T',
            Self::Unknown      => '\0',
        }
    }

    /// Returns the version codename (e.g. `"KitKat"`, `"Oreo"`).
    pub fn version_name(&self) -> &'static str {
        match self {
            Self::Version1_5   => "Cupcake",
            Self::Version1_6   => "Donut",
            Self::Version2_0   => "Eclair",
            Self::Version2_0_1 => "Eclair",
            Self::Version2_1   => "Eclair",
            Self::Version2_2   => "Froyo",
            Self::Version2_2_1 => "Froyo",
            Self::Version2_2_2 => "Froyo",
            Self::Version2_2_3 => "Froyo",
            Self::Version2_3   => "Gingerbread",
            Self::Version2_3_1 => "Gingerbread",
            Self::Version2_3_2 => "Gingerbread",
            Self::Version2_3_3 => "Gingerbread",
            Self::Version2_3_4 => "Gingerbread",
            Self::Version2_3_5 => "Gingerbread",
            Self::Version2_3_6 => "Gingerbread",
            Self::Version2_3_7 => "Gingerbread",
            Self::Version3_0   => "Honeycomb",
            Self::Version3_1   => "Honeycomb",
            Self::Version3_2   => "Honeycomb",
            Self::Version3_2_1 => "Honeycomb",
            Self::Version3_2_2 => "Honeycomb",
            Self::Version3_2_3 => "Honeycomb",
            Self::Version3_2_4 => "Honeycomb",
            Self::Version3_2_5 => "Honeycomb",
            Self::Version3_2_6 => "Honeycomb",
            Self::Version4_0   => "Ice Cream Sandwich",
            Self::Version4_0_1 => "Ice Cream Sandwich",
            Self::Version4_0_2 => "Ice Cream Sandwich",
            Self::Version4_0_3 => "Ice Cream Sandwich",
            Self::Version4_0_4 => "Ice Cream Sandwich",
            Self::Version4_1   => "Jelly Bean",
            Self::Version4_1_1 => "Jelly Bean",
            Self::Version4_1_2 => "Jelly Bean",
            Self::Version4_2   => "Jelly Bean",
            Self::Version4_2_1 => "Jelly Bean",
            Self::Version4_2_2 => "Jelly Bean",
            Self::Version4_3   => "Jelly Bean",
            Self::Version4_3_1 => "Jelly Bean",
            Self::Version4_4   => "KitKat",
            Self::Version4_4_1 => "KitKat",
            Self::Version4_4_2 => "KitKat",
            Self::Version4_4_3 => "KitKat",
            Self::Version4_4_4 => "KitKat",
            Self::Version4_4W => "KitKat",
            Self::Version5_0   => "Lollipop",
            Self::Version5_0_1 => "Lollipop",
            Self::Version5_0_2 => "Lollipop",
            Self::Version5_1   => "Lollipop",
            Self::Version5_1_1 => "Lollipop",
            Self::Version6_0   => "Marshmallow",
            Self::Version6_0_1 => "Marshmallow",
            Self::Version7_0   => "Nougat",
            Self::Version7_1   => "Nougat",
            Self::Version7_1_1 => "Nougat",
            Self::Version7_1_2 => "Nougat",
            Self::Version8_0   => "Oreo",
            Self::Version8_1   => "Oreo",
            Self::Version9     => "Pie",
            Self::Version10    => "Quince Tart",
            Self::Version11    => "Red Velvet Cake",
            Self::Version12    => "Snow Cone",
            Self::Version12L   => "Snow Cone v2",
            Self::Version13    => "Tiramisu",
            Self::Unknown      => "",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_api_value_constant() {
        assert_eq!(AndroidVersion::INVALID_API_VALUE, -1);
    }

    #[test]
    fn unknown_has_zero_api() {
        assert_eq!(AndroidVersion::Unknown.api_version(), 0);
        assert_eq!(AndroidVersion::Unknown.version_number(), "0");
        assert_eq!(AndroidVersion::Unknown.version_letter(), '\0');
        assert_eq!(AndroidVersion::Unknown.version_name(), "");
    }

    #[test]
    fn version_1_5_cupcake() {
        let v = AndroidVersion::Version1_5;
        assert_eq!(v.api_version(), 3);
        assert_eq!(v.version_number(), "1.5");
        assert_eq!(v.version_letter(), 'C');
        assert_eq!(v.version_name(), "Cupcake");
    }

    #[test]
    fn version_4_4_kitkat() {
        let v = AndroidVersion::Version4_4;
        assert_eq!(v.api_version(), 19);
        assert_eq!(v.version_letter(), 'K');
        assert_eq!(v.version_name(), "KitKat");
    }

    #[test]
    fn version_13_tiramisu() {
        let v = AndroidVersion::Version13;
        assert_eq!(v.api_version(), 33);
        assert_eq!(v.version_number(), "13");
        assert_eq!(v.version_letter(), 'T');
        assert_eq!(v.version_name(), "Tiramisu");
    }

    #[test]
    fn version_12l_snow_cone_v2() {
        let v = AndroidVersion::Version12L;
        assert_eq!(v.api_version(), 32);
        assert_eq!(v.version_number(), "12L");
        assert_eq!(v.version_letter(), 'S');
        assert_eq!(v.version_name(), "Snow Cone v2");
    }

    #[test]
    fn version_4_4_w_kitkat_api20() {
        let v = AndroidVersion::Version4_4W;
        assert_eq!(v.api_version(), 20);
        assert_eq!(v.version_number(), "4.4W");
        assert_eq!(v.version_letter(), 'K');
        assert_eq!(v.version_name(), "KitKat");
    }

    #[test]
    fn java_source_quirk_version_1_6_number() {
        // Java source records VERSION_1_6 with version_number "1.5" — preserved verbatim.
        assert_eq!(AndroidVersion::Version1_6.version_number(), "1.5");
    }

    #[test]
    fn java_source_quirk_version_4_2_2_number() {
        // Java source records VERSION_4_2_2 with version_number "4.2.1" — preserved verbatim.
        assert_eq!(AndroidVersion::Version4_2_2.version_number(), "4.2.1");
    }

    #[test]
    fn froyo_versions_share_api8() {
        for v in [
            AndroidVersion::Version2_2,
            AndroidVersion::Version2_2_1,
            AndroidVersion::Version2_2_2,
            AndroidVersion::Version2_2_3,
        ] {
            assert_eq!(v.api_version(), 8);
            assert_eq!(v.version_letter(), 'F');
            assert_eq!(v.version_name(), "Froyo");
        }
    }

    #[test]
    fn variants_are_copy() {
        let v = AndroidVersion::Version9;
        let _v2 = v;
        let _v3 = v;
    }

    #[test]
    fn variants_are_eq() {
        assert_eq!(AndroidVersion::Version10, AndroidVersion::Version10);
        assert_ne!(AndroidVersion::Version10, AndroidVersion::Version11);
    }
}
