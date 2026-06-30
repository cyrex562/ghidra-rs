/// Marker trait for code units that represent resources such as Bitmap, JPEG, PNG, etc.
pub trait Resource {}

#[cfg(test)]
mod tests {
    use super::*;

    struct BitmapResource;
    impl Resource for BitmapResource {}

    struct PngResource;
    impl Resource for PngResource {}

    #[test]
    fn struct_implements_resource() {
        fn accepts_resource<R: Resource>(_: &R) {}
        accepts_resource(&BitmapResource);
        accepts_resource(&PngResource);
    }

    #[test]
    fn usable_as_trait_object() {
        let r: &dyn Resource = &BitmapResource;
        let _ = r;
    }

    #[test]
    fn multiple_types_satisfy_marker() {
        fn is_resource<R: Resource>() -> bool {
            true
        }
        assert!(is_resource::<BitmapResource>());
        assert!(is_resource::<PngResource>());
    }
}
