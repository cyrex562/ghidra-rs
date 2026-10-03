//! Port of `ghidra.app.plugin.core.terminal.vt.VtParser`.

use crate::app::seam_stubs::VtHandler;

use super::vt_charset::CharsetSlot;
use super::vt_state::VtState;

/// Initial capacity of each sequence buffer, as in Java (`ByteBuffer.allocate(100)`).
const INITIAL_BUFFER_CAPACITY: usize = 100;

/// The parser for a terminal emulator.
///
/// The only real concern of this parser is to separate escape sequences from normal character
/// output. All state not related to parsing is handled by a [`VtHandler`]. Most of the logic is
/// implemented in the machine state nodes: [`VtState`].
///
/// Java's CSI/OSC `ByteBuffer`s (grown by doubling when full) are `Vec<u8>`s here; a `Vec`
/// already grows on demand, so the explicit doubling helper has no Rust counterpart.
#[derive(Debug)]
pub struct VtParser<H: VtHandler> {
    pub(crate) handler: H,
    state: VtState,
    /// The charset slot being designated. Java leaves this `null` until an `ESC (`/`)`/`*`/`+`
    /// sets it; it is only read in the charset states, which are reachable only after that, so
    /// `G0` stands in for the unset value.
    pub(crate) cs_g: CharsetSlot,
    pub(crate) csi_param: Vec<u8>,
    pub(crate) csi_inter: Vec<u8>,
    pub(crate) osc_param: Vec<u8>,
}

impl<H: VtHandler> VtParser<H> {
    /// Construct a parser with the given handler.
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            state: VtState::Char,
            cs_g: CharsetSlot::G0,
            csi_param: Vec::with_capacity(INITIAL_BUFFER_CAPACITY),
            csi_inter: Vec::with_capacity(INITIAL_BUFFER_CAPACITY),
            osc_param: Vec::with_capacity(INITIAL_BUFFER_CAPACITY),
        }
    }

    /// The handler receiving parsed output.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// The handler receiving parsed output, mutably.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    /// The current machine state (kept across calls to [`process`](Self::process), so a sequence
    /// may be split between buffers).
    pub fn state(&self) -> VtState {
        self.state
    }

    /// Append a byte to the CSI parameter buffer.
    pub(crate) fn put_csi_param_byte(&mut self, b: u8) {
        self.csi_param.push(b);
    }

    /// Append a byte to the CSI intermediate buffer.
    pub(crate) fn put_csi_inter_byte(&mut self, b: u8) {
        self.csi_inter.push(b);
    }

    /// Append a byte to the OSC parameter buffer.
    pub(crate) fn put_osc_param_byte(&mut self, b: u8) {
        self.osc_param.push(b);
    }

    /// Create a copy of the CSI buffers, reconstructed as they were in the original stream
    /// (`[`, parameters, intermediates, then `b`), and clear them.
    ///
    /// This is used to re-process parsed bytes after a broken CSI sequence.
    pub(crate) fn copy_csi_buffer(&mut self, b: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.csi_param.len() + self.csi_inter.len());
        buf.push(b'[');
        buf.extend_from_slice(&self.csi_param);
        buf.extend_from_slice(&self.csi_inter);
        buf.push(b);
        self.csi_param.clear();
        self.csi_inter.clear();
        buf
    }

    /// Create a copy of the OSC buffer, reconstructed as it was in the original stream (`]`,
    /// parameters, then `b`), and clear it.
    ///
    /// This is used to re-process parsed bytes after a broken OSC sequence.
    pub(crate) fn copy_osc_buffer(&mut self, b: u8) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.osc_param.len());
        buf.push(b']');
        buf.extend_from_slice(&self.osc_param);
        buf.push(b);
        self.osc_param.clear();
        buf
    }

    /// Process the given bytes.
    ///
    /// This is likely fed from an input stream, usually of a pty.
    pub fn process(&mut self, buf: &[u8]) {
        self.state = self.do_process(self.state, buf);
    }

    /// Print a character to stderr for debugging: printable characters as-is, ISO control
    /// characters as `\xNN`.
    pub fn debug_char(c: char) {
        eprint!("{}", Self::debug_char_repr(c));
    }

    fn debug_char_repr(c: char) -> String {
        if !c.is_control() {
            c.to_string()
        } else {
            format!("\\x{:02x}", (c as u32) & 0xff)
        }
    }

    /// Process a given byte by delegating to the current state machine node.
    pub(crate) fn do_process_byte(&mut self, state: VtState, b: u8) -> VtState {
        state.handle_next(b, self)
    }

    /// Process a given byte buffer, one byte at a time, returning the resulting state.
    pub(crate) fn do_process(&mut self, mut state: VtState, buf: &[u8]) -> VtState {
        for &b in buf {
            state = self.do_process_byte(state, b);
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::plugin::core::terminal::vt::VtCharset;
    use crate::app::seam_stubs::KeyMode;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Ev {
        Char(u8),
        Csi(Vec<u8>, Vec<u8>, u8),
        Osc(Vec<u8>),
        Keypad(KeyMode),
        Save,
        Restore,
        ScrollDown(i32, bool),
        ScrollUp(i32),
        Charset(CharsetSlot, VtCharset),
        Reset,
    }

    #[derive(Debug, Default)]
    struct Recorder(Vec<Ev>);

    impl VtHandler for Recorder {
        fn handle_char_exc(&mut self, b: u8) {
            self.0.push(Ev::Char(b));
        }
        fn handle_csi_exc(&mut self, p: &[u8], i: &[u8], f: u8) {
            self.0.push(Ev::Csi(p.to_vec(), i.to_vec(), f));
        }
        fn handle_osc_exc(&mut self, p: &[u8]) {
            self.0.push(Ev::Osc(p.to_vec()));
        }
        fn handle_keypad_mode(&mut self, mode: KeyMode) {
            self.0.push(Ev::Keypad(mode));
        }
        fn handle_save_cursor_pos(&mut self) {
            self.0.push(Ev::Save);
        }
        fn handle_restore_cursor_pos(&mut self) {
            self.0.push(Ev::Restore);
        }
        fn handle_scroll_viewport_down(&mut self, n: i32, sb: bool) {
            self.0.push(Ev::ScrollDown(n, sb));
        }
        fn handle_scroll_viewport_up(&mut self, n: i32) {
            self.0.push(Ev::ScrollUp(n));
        }
        fn handle_set_charset(&mut self, g: CharsetSlot, cs: VtCharset) {
            self.0.push(Ev::Charset(g, cs));
        }
        fn handle_full_reset(&mut self) {
            self.0.push(Ev::Reset);
        }
    }

    fn run(input: &[u8]) -> (Vec<Ev>, VtState) {
        let mut p = VtParser::new(Recorder::default());
        p.process(input);
        let st = p.state();
        (p.handler.0, st)
    }

    fn chars(s: &[u8]) -> Vec<Ev> {
        s.iter().map(|&b| Ev::Char(b)).collect()
    }

    #[test]
    fn plain_characters_pass_through() {
        let (ev, st) = run(b"ab\r\n");
        assert_eq!(ev, chars(b"ab\r\n"));
        assert_eq!(st, VtState::Char);
    }

    #[test]
    fn csi_sequences() {
        let (ev, _) = run(b"\x1b[1;2H\x1b[ q\x1b[?25l");
        assert_eq!(
            ev,
            vec![
                Ev::Csi(b"1;2".to_vec(), vec![], b'H'),
                Ev::Csi(vec![], b" ".to_vec(), b'q'),
                Ev::Csi(b"?25".to_vec(), vec![], b'l'),
            ]
        );
    }

    #[test]
    fn sequence_split_across_process_calls() {
        let mut p = VtParser::new(Recorder::default());
        p.process(b"\x1b[1");
        assert_eq!(p.state(), VtState::CsiParam);
        p.process(b"0m");
        assert_eq!(p.handler().0, vec![Ev::Csi(b"10".to_vec(), vec![], b'm')]);
        assert_eq!(p.state(), VtState::Char);
    }

    #[test]
    fn long_csi_parameters_grow_past_initial_capacity() {
        let mut input = b"\x1b[".to_vec();
        input.extend(std::iter::repeat(b'1').take(250));
        input.push(b'm');
        let (ev, _) = run(&input);
        assert_eq!(ev, vec![Ev::Csi(vec![b'1'; 250], vec![], b'm')]);
    }

    #[test]
    fn osc_terminated_by_bel_or_st() {
        let (ev, _) = run(b"\x1b]0;title\x07\x1b]0;t\0\x1b\\");
        assert_eq!(ev, vec![Ev::Osc(b"0;title".to_vec()), Ev::Osc(b"0;t\0".to_vec())]);
    }

    #[test]
    fn simple_escapes() {
        let (ev, _) = run(b"\x1b7\x1b8\x1b=\x1b>\x1bD\x1bM\x1bc");
        assert_eq!(
            ev,
            vec![
                Ev::Save,
                Ev::Restore,
                Ev::Keypad(KeyMode::Application),
                Ev::Keypad(KeyMode::Normal),
                Ev::ScrollDown(1, true),
                Ev::ScrollUp(1),
                Ev::Reset,
            ]
        );
    }

    #[test]
    fn unknown_escape_emits_esc_and_byte() {
        let (ev, st) = run(b"\x1bz");
        assert_eq!(ev, chars(b"\x1bz"));
        assert_eq!(st, VtState::Char);
    }

    #[test]
    fn charset_designations() {
        let (ev, _) = run(b"\x1b(A\x1b)0\x1b*\"?\x1b+%5\x1b(&4\x1b)`");
        assert_eq!(
            ev,
            vec![
                Ev::Charset(CharsetSlot::G0, VtCharset::Uk),
                Ev::Charset(CharsetSlot::G1, VtCharset::DecSpecialLines),
                Ev::Charset(CharsetSlot::G2, VtCharset::DecGreek),
                Ev::Charset(CharsetSlot::G3, VtCharset::DecSupplementalGraphics),
                Ev::Charset(CharsetSlot::G0, VtCharset::DecCyrillic),
                Ev::Charset(CharsetSlot::G1, VtCharset::NorwegianDanish),
            ]
        );
    }

    #[test]
    fn broken_charset_reprocesses_bytes() {
        assert_eq!(run(b"\x1b(X").0, chars(b"\x1b(X"));
        assert_eq!(run(b"\x1b(\"X").0, chars(b"\x1b(\"X"));
        assert_eq!(run(b"\x1b)%X").0, chars(b"\x1b)%X"));
        assert_eq!(run(b"\x1b*&X").0, chars(b"\x1b*&X"));
        // Java's G3 records '-' as its byte, so that is what gets re-emitted, not '+'.
        assert_eq!(run(b"\x1b+X").0, chars(b"\x1b-X"));
    }

    #[test]
    fn broken_charset_can_start_a_new_sequence() {
        // The final byte is re-processed from CHAR, so an ESC there starts a new escape.
        let (ev, st) = run(b"\x1b(\x1b7");
        assert_eq!(ev, vec![Ev::Char(0x1b), Ev::Char(b'('), Ev::Save]);
        assert_eq!(st, VtState::Char);
    }

    #[test]
    fn broken_csi_reprocesses_and_clears_buffers() {
        let (ev, st) = run(b"\x1b[12 \x01\x1b[m");
        let mut expected = chars(b"\x1b[12 \x01");
        expected.push(Ev::Csi(vec![], vec![], b'm'));
        assert_eq!(ev, expected);
        assert_eq!(st, VtState::Char);
    }

    #[test]
    fn broken_csi_on_esc_leaves_escape_state() {
        let (ev, st) = run(b"\x1b[1\x1b");
        assert_eq!(ev, chars(b"\x1b[1"));
        assert_eq!(st, VtState::Esc);
    }

    #[test]
    fn high_byte_breaks_csi() {
        // Java compares signed bytes, so 0x80 falls outside every CSI range.
        assert_eq!(run(b"\x1b[\x80").0, chars(b"\x1b[\x80"));
    }

    #[test]
    fn broken_osc_reprocesses_bytes() {
        assert_eq!(run(b"\x1b]ab\x01").0, chars(b"\x1b]ab\x01"));
    }

    #[test]
    fn osc_esc_without_backslash_emits_esc_and_continues_osc() {
        let (ev, _) = run(b"\x1b]a\x1bX\x07");
        assert_eq!(ev, vec![Ev::Char(0x1b), Ev::Osc(b"aX".to_vec())]);
    }

    #[test]
    fn debug_char_repr_matches_java_format() {
        assert_eq!(VtParser::<Recorder>::debug_char_repr('a'), "a");
        assert_eq!(VtParser::<Recorder>::debug_char_repr('\x1b'), "\\x1b");
        assert_eq!(VtParser::<Recorder>::debug_char_repr('\u{85}'), "\\x85");
    }
}
