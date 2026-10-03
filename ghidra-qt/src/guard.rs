//! Panic boundary for every `extern "Rust"` bridge function: a panic must
//! never unwind into C++ (cxx would abort). The message is extracted at catch
//! time (see memory note on panic-payload eager extraction).

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Runs `f`, converting a panic into `Err("<what> panicked: <message>")`.
/// Every `extern "Rust"` bridge function must return through this.
pub fn guard<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|payload| {
        let msg = if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_owned()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_owned()
        };
        format!("{what} panicked: {msg}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_value_passes_through() {
        assert_eq!(guard("f", || 7), Ok(7));
    }

    #[test]
    fn str_panic_becomes_err_with_context() {
        let r: Result<(), String> = guard("session_title", || panic!("boom"));
        assert_eq!(r, Err("session_title panicked: boom".to_owned()));
    }

    #[test]
    fn string_panic_becomes_err_with_context() {
        let r: Result<(), String> = guard("x", || panic!("{}", String::from("formatted 42")));
        assert_eq!(r, Err("x panicked: formatted 42".to_owned()));
    }
}
