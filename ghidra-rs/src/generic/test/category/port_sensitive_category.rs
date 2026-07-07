/// Marker trait for tests that share ports and cannot be run concurrently.
pub trait PortSensitiveCategory {}

#[cfg(test)]
mod tests {
    use super::PortSensitiveCategory;

    struct MyPortSensitiveTest;
    impl PortSensitiveCategory for MyPortSensitiveTest {}

    fn accepts_port_sensitive<T: PortSensitiveCategory>(_: &T) {}

    #[test]
    fn port_sensitive_category_is_implementable() {
        let t = MyPortSensitiveTest;
        accepts_port_sensitive(&t);
    }
}
