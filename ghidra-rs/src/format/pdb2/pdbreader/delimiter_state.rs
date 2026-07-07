use crate::format::pdb2::pdbreader::abstract_parsable_item::AbstractParsableItem;

/// Utility struct, containing state, used for providing delimiters in a sequence of outputs.
pub struct DelimiterState {
    delim_start: String,
    delim: String,
    first: bool,
}

impl DelimiterState {
    /// Creates a new `DelimiterState`.
    ///
    /// `delim_start` is output before the first item in a list, only when at least one item is
    /// found in the list. `delim` is output prior to any outputs subsequent to the first output.
    pub fn new(delim_start: impl Into<String>, delim: impl Into<String>) -> Self {
        DelimiterState { delim_start: delim_start.into(), delim: delim.into(), first: true }
    }

    /// Resets the state so that the next output is treated as the first in the sequence.
    pub fn reset(&mut self) {
        self.first = true;
    }

    /// Adds delimiter information (based on the state) to `val`.
    ///
    /// `output` gives the caller a single-call way of conditionally emitting output: when
    /// `false`, this returns an empty string without consuming a "first" slot.
    pub fn out(&mut self, output: bool, val: &str) -> String {
        if !output {
            return String::new();
        }
        if self.first {
            self.first = false;
            format!("{}{}", self.delim_start, val)
        } else {
            format!("{}{}", self.delim, val)
        }
    }

    /// Adds delimiter information (based on the state) to the display string of `item`.
    pub fn out_item(&mut self, output: bool, item: &dyn AbstractParsableItem) -> String {
        self.out(output, &item.to_display_string())
    }

    /// Adds delimiter information (based on the state) to the string representation of `obj`.
    pub fn out_display<T: std::fmt::Display + ?Sized>(&mut self, output: bool, obj: &T) -> String {
        self.out(output, &obj.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Item(&'static str);
    impl AbstractParsableItem for Item {
        fn emit(&self, builder: &mut String) {
            builder.push_str(self.0);
        }
    }

    #[test]
    fn first_out_uses_delim_start() {
        let mut ds = DelimiterState::new("[", ", ");
        assert_eq!(ds.out(true, "a"), "[a");
    }

    #[test]
    fn subsequent_out_uses_delim() {
        let mut ds = DelimiterState::new("[", ", ");
        ds.out(true, "a");
        assert_eq!(ds.out(true, "b"), ", b");
        assert_eq!(ds.out(true, "c"), ", c");
    }

    #[test]
    fn skipped_output_returns_empty_and_preserves_state() {
        let mut ds = DelimiterState::new("[", ", ");
        assert_eq!(ds.out(false, "a"), "");
        assert_eq!(ds.out(true, "b"), "[b");
    }

    #[test]
    fn reset_restarts_the_sequence() {
        let mut ds = DelimiterState::new("[", ", ");
        ds.out(true, "a");
        ds.reset();
        assert_eq!(ds.out(true, "b"), "[b");
    }

    #[test]
    fn out_item_uses_item_display_string() {
        let mut ds = DelimiterState::new("", ",");
        assert_eq!(ds.out_item(true, &Item("first")), "first");
        assert_eq!(ds.out_item(true, &Item("second")), ",second");
    }

    #[test]
    fn out_display_uses_to_string() {
        let mut ds = DelimiterState::new("", ",");
        assert_eq!(ds.out_display(true, &1), "1");
        assert_eq!(ds.out_display(true, &2), ",2");
    }
}
