/// Android Pony EXpress (APEX) constants namespace.
///
/// Corresponds to the Android APEX format described at
/// <https://source.android.com/devices/tech/ota/apex> and the upstream
/// constant definitions at
/// <https://android.googlesource.com/platform/system/apex/+/refs/heads/master/apexd/apex_constants.h>.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApexContants;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_construct() {
        let _ = ApexContants;
    }

    #[test]
    fn default_equals_unit() {
        assert_eq!(ApexContants::default(), ApexContants);
    }

    #[test]
    fn clone_is_equal() {
        let a = ApexContants;
        assert_eq!(a, a.clone());
    }

    #[test]
    fn debug_formats() {
        let s = format!("{:?}", ApexContants);
        assert_eq!(s, "ApexContants");
    }
}
