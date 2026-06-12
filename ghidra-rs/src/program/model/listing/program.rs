pub trait Program: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_language_id(&self) -> &str;
}
