use std::fmt;

#[derive(Debug)] // derive std::fmt::Debug on AppError
pub struct GhidraError {
    pub(crate) code: isize,
    pub(crate) message: String,
}

impl GhidraError {
    pub fn new(code: isize, message: &str) -> GhidraError {
        GhidraError {
            code,
            message: message.to_string(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err_msg = match self.code {
            404 => "Sorry, Can not find the Page!",
            _ => "Sorry, something is wrong! Please Try Again!",
        };

        write!(f, "{}", err_msg)
    }
}
