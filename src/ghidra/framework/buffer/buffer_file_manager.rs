pub trait BufferFileManager {
    fn get_current_version(&self) -> i32;
    fn get_buffer_file(&self, version: i32) -> std::fs::File;
    fn get_version_file(&self, version: i32) -> std::fs::File;
    fn get_change_data_file(&self, version: i32) -> std::fs::File;
    fn get_change_map_file(&self) -> std::fs::File;
    fn version_created(&self, version: i32, comment: &String, check_in_id: i64);
    fn update_ended(&self, check_in_id: i64);

}
