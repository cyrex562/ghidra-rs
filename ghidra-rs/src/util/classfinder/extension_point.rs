/// Marker trait used to mark types that Ghidra will automatically search for
/// and load.
///
/// NOTE: ExtensionPoint logistics have changed! It is no longer sufficient to
/// implement `ExtensionPoint` in order for the class searcher to dynamically
/// pick up your type. Your type also needs to conform to a class name suffix
/// rule. The modules included in your application can have a file named
/// "{ModuleRoot}/data/ExtensionPoint.manifest". This file contains (one per
/// line) the suffixes that should be checked for inclusion into the class
/// searching. IF YOUR EXTENSION POINT DOES NOT HAVE A SUFFIX INDICATED IN ONE
/// OF THESE FILES, IT WILL NOT BE AUTOMATICALLY DISCOVERED.
///
/// Port of `ghidra.util.classfinder.ExtensionPoint`.
pub trait ExtensionPoint {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MyAnalyzer;

    impl ExtensionPoint for MyAnalyzer {}

    fn accepts_extension_point<T: ExtensionPoint>(_marker: &T) -> bool {
        true
    }

    #[test]
    fn marker_trait_is_implementable_and_object_safe() {
        let analyzer = MyAnalyzer;
        assert!(accepts_extension_point(&analyzer));

        let boxed: Box<dyn ExtensionPoint> = Box::new(MyAnalyzer);
        drop(boxed);
    }
}
