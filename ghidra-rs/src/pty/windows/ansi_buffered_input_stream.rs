//! ANSI-escape-stripping buffered input stream.

use std::io::{self, BufReader, Read};

use crate::util::msg::Msg;

const LINE_BUF_CAPACITY: usize = i16::MAX as usize; // Short.MAX_VALUE
const ESC_BUF_CAPACITY: usize = 1024;
const TITLE_BUF_CAPACITY: usize = 255;

pub const PRIV_12: &str = "12";
pub const PRIV_25: &str = "25";
pub const PRIV_1004: &str = "1004";
pub const PRIV_2004: &str = "2004";
pub const PRIV_9001: &str = "9001";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Chars,
    Esc,
    Csi,
    // Mirrors `Mode.CSI_p` in the Java source: present in the enum (and the
    // `processNext` dispatch) but never actually assigned to `mode` there
    // either, since `processCsi`'s default case calls
    // `processCsiParamOrCommand` directly instead of transitioning modes.
    #[allow(dead_code)]
    CsiP,
    CsiQ,
    Osc,
    WindowTitle,
    WindowTitleEsc,
}

/// A minimal fixed-capacity byte buffer mirroring the subset of
/// `java.nio.ByteBuffer` semantics (backing array, position, limit) used by
/// [`AnsiBufferedInputStream`].
struct ByteBuf {
    data: Vec<u8>,
    position: usize,
    limit: usize,
}

impl ByteBuf {
    fn allocate(capacity: usize) -> Self {
        ByteBuf {
            data: vec![0u8; capacity],
            position: 0,
            limit: capacity,
        }
    }

    fn capacity(&self) -> usize {
        self.data.len()
    }

    fn remaining(&self) -> usize {
        self.limit - self.position
    }

    fn has_remaining(&self) -> bool {
        self.position < self.limit
    }

    fn get_at(&self, index: usize) -> u8 {
        self.data[index]
    }

    fn get_into(&mut self, dst: &mut [u8]) {
        let n = dst.len();
        dst.copy_from_slice(&self.data[self.position..self.position + n]);
        self.position += n;
    }

    fn put(&mut self, b: u8) {
        self.data[self.position] = b;
        self.position += 1;
        // Java's ByteBuffer.put would overflow at the limit; this growable buffer
        // instead extends the limit so appends past the end grow the line.
        if self.position > self.limit {
            self.limit = self.position;
        }
    }

    fn put_at(&mut self, index: usize, b: u8) {
        self.data[index] = b;
    }

    fn set_position(&mut self, position: usize) {
        assert!(
            position <= self.limit,
            "position {position} exceeds limit {}",
            self.limit
        );
        self.position = position;
    }

    fn set_limit(&mut self, limit: usize) {
        assert!(
            limit <= self.capacity(),
            "limit {limit} exceeds capacity {}",
            self.capacity()
        );
        self.limit = limit;
        if self.position > limit {
            self.position = limit;
        }
    }

    fn clear(&mut self) {
        self.position = 0;
        self.limit = self.capacity();
    }

    fn flip(&mut self) {
        self.limit = self.position;
        self.position = 0;
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[self.position..self.limit]
    }

    fn fill(&mut self, from: usize, to: usize, value: u8) {
        self.data[from..to].fill(value);
    }

    fn fill_all(&mut self, value: u8) {
        self.data.fill(value);
    }
}

/// Decodes `bytes` as windows-1252, matching `Charset.forName("windows-1252")`.
///
/// Bytes `0x00..=0x7F` and `0xA0..=0xFF` map straight to their Latin-1
/// codepoints; `0x80..=0x9F` use the windows-1252 exceptions table (undefined
/// code points fall back to their Latin-1 codepoint, as the JDK's decoder does).
fn decode_windows_1252(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            let cp = match b {
                0x80 => 0x20AC,
                0x82 => 0x201A,
                0x83 => 0x0192,
                0x84 => 0x201E,
                0x85 => 0x2026,
                0x86 => 0x2020,
                0x87 => 0x2021,
                0x88 => 0x02C6,
                0x89 => 0x2030,
                0x8A => 0x0160,
                0x8B => 0x2039,
                0x8C => 0x0152,
                0x8E => 0x017D,
                0x91 => 0x2018,
                0x92 => 0x2019,
                0x93 => 0x201C,
                0x94 => 0x201D,
                0x95 => 0x2022,
                0x96 => 0x2013,
                0x97 => 0x2014,
                0x98 => 0x02DC,
                0x99 => 0x2122,
                0x9A => 0x0161,
                0x9B => 0x203A,
                0x9C => 0x0153,
                0x9E => 0x017E,
                0x9F => 0x0178,
                other => other as u32,
            };
            char::from_u32(cp).unwrap_or('\u{FFFD}')
        })
        .collect()
}

/// A [`Read`] adapter that strips VT/ANSI escape sequences from a terminal
/// byte stream, presenting only completed, newline-terminated lines.
///
/// Mirrors `ghidra.pty.windows.AnsiBufferedInputStream`: bytes are consumed
/// one at a time from the wrapped reader and fed through a small state
/// machine that interprets cursor movement, erase, and OSC window-title
/// sequences against an internal line buffer. Once a `\n` is seen, the line
/// is "baked" (trailing spaces trimmed, per [`Self::guess_end`]) and becomes
/// available to read out.
///
/// Unlike the Java original, which only wraps its input in a
/// `BufferedInputStream` when passed a `HandleInputStream` (to avoid 1-by-1
/// native reads), this always wraps `inner` in a [`BufReader`]: Rust has no
/// generic `instanceof` check, and buffering unconditionally is harmless.
pub struct AnsiBufferedInputStream<R> {
    inner: BufReader<R>,
    count_in: u64,
    line_baked: ByteBuf,
    line_buf: ByteBuf,
    esc_buf: ByteBuf,
    title_buf: ByteBuf,
    mode: Mode,
}

impl<R: Read> AnsiBufferedInputStream<R> {
    /// Creates a new ANSI-stripping stream wrapping `inner`.
    pub fn new(inner: R) -> Self {
        let mut line_buf = ByteBuf::allocate(LINE_BUF_CAPACITY);
        let mut line_baked = ByteBuf::allocate(LINE_BUF_CAPACITY);
        line_buf.set_limit(0);
        line_baked.set_limit(0);
        AnsiBufferedInputStream {
            inner: BufReader::new(inner),
            count_in: 0,
            line_baked,
            line_buf,
            esc_buf: ByteBuf::allocate(ESC_BUF_CAPACITY),
            title_buf: ByteBuf::allocate(TITLE_BUF_CAPACITY),
            mode: Mode::Chars,
        }
    }

    #[allow(dead_code)]
    fn print_debug_char(c: u8) {
        if (0x20..=0x7f).contains(&c) {
            eprint!("{}", c as char);
        } else {
            eprint!("<{:02x}>", c);
        }
    }

    /// Reads and processes bytes from `inner` until a baked line is
    /// available or EOF is reached. Returns `true` if a baked line is now
    /// available.
    fn read_until_baked(&mut self) -> io::Result<bool> {
        while !self.line_baked.has_remaining() {
            if !self.process_next()? {
                break;
            }
        }
        Ok(self.line_baked.has_remaining())
    }

    /// Reads one byte from `inner` and feeds it through the state machine.
    /// Returns `false` on EOF.
    fn process_next(&mut self) -> io::Result<bool> {
        let mut byte = [0u8; 1];
        if self.inner.read(&mut byte)? == 0 {
            return Ok(false);
        }
        let c = byte[0];
        match self.mode {
            Mode::Chars => self.process_chars(c),
            Mode::Esc => self.process_esc(c),
            Mode::Csi => self.process_csi(c),
            Mode::CsiP => self.process_csi_param_or_command(c),
            Mode::CsiQ => self.process_csi_q(c),
            Mode::Osc => self.process_osc(c),
            Mode::WindowTitle => self.process_window_title(c),
            Mode::WindowTitleEsc => self.process_window_title_esc(c),
        }
        self.count_in += 1;
        Ok(true)
    }

    /// There's not really a good way to know if any trailing space was
    /// intentional. For GDB/MI, that doesn't really matter.
    fn guess_end(&self) -> usize {
        for i in (0..self.line_buf.limit).rev() {
            let c = self.line_buf.get_at(i);
            if c != 0x20 && c != 0 {
                return i + 1;
            }
        }
        0
    }

    fn bake_line(&mut self) {
        self.line_buf.set_position(0);
        let end = self.guess_end();
        self.line_buf.set_limit(end + 1);
        let last = self.line_buf.limit - 1;
        self.line_buf.put_at(last, b'\n');
        std::mem::swap(&mut self.line_baked, &mut self.line_buf);
        self.line_buf.clear();
        self.line_buf.fill_all(0);
        self.line_buf.set_limit(0);
    }

    fn append_char(&mut self, c: u8) {
        if self.line_buf.position == self.line_buf.limit {
            self.line_buf.set_limit(self.line_buf.limit + 1);
        }
        self.line_buf.put(c);
    }

    fn process_chars(&mut self, c: u8) {
        match c {
            0x08 => {
                if self.line_buf.get_at(self.line_buf.position - 1) == b' ' {
                    self.line_buf.set_position(self.line_buf.position - 1);
                }
            }
            b'\n' => self.bake_line(),
            b'\r' => self.line_buf.set_position(0),
            0x1b => self.mode = Mode::Esc,
            _ => self.append_char(c),
        }
    }

    fn process_esc(&mut self, c: u8) {
        match c {
            b'[' => self.mode = Mode::Csi,
            b']' => self.mode = Mode::Osc,
            _ => panic!("Saw 'ESC {}' at {}", c as i8, self.count_in),
        }
    }

    fn process_csi(&mut self, c: u8) {
        match c {
            b'?' => self.mode = Mode::CsiQ,
            _ => self.process_csi_param_or_command(c),
        }
    }

    fn process_csi_param_or_command(&mut self, c: u8) {
        match c {
            b'A' => {
                self.exec_cursor_up();
                self.mode = Mode::Chars;
            }
            b'B' => {
                self.exec_cursor_down();
                self.mode = Mode::Chars;
            }
            b'C' => {
                self.exec_cursor_forward();
                self.mode = Mode::Chars;
            }
            b'D' => {
                self.exec_cursor_backward();
                self.mode = Mode::Chars;
            }
            b'G' => {
                self.exec_cursor_char_absolute();
                self.mode = Mode::Chars;
            }
            b'H' => {
                self.exec_cursor_position();
                self.mode = Mode::Chars;
            }
            b'J' => {
                self.exec_erase_in_display();
                self.mode = Mode::Chars;
            }
            b'K' => {
                self.exec_erase_in_line();
                self.mode = Mode::Chars;
            }
            b'X' => {
                self.exec_erase_character();
                self.mode = Mode::Chars;
            }
            b'm' => {
                self.exec_set_graphics_rendition();
                self.mode = Mode::Chars;
            }
            b'h' => {
                self.exec_private_sequence(true);
                self.mode = Mode::Chars;
            }
            b'l' => {
                self.exec_private_sequence(false);
                self.mode = Mode::Chars;
            }
            _ => self.esc_buf.put(c),
        }
    }

    fn process_csi_q(&mut self, c: u8) {
        match c {
            b'h' => {
                match self.read_and_clear_esc_buf().as_str() {
                    PRIV_12 => self.exec_text_cursor_enable_blinking(),
                    PRIV_25 => self.exec_text_cursor_enable_mode_show(),
                    PRIV_1004 => self.exec_enable_focus_report(),
                    PRIV_2004 => self.exec_enable_bracketed_paste_mode(),
                    PRIV_9001 => self.exec_enable_win32_input_mode(),
                    buf => panic!("Got CsiQ(h): {buf}"),
                }
                self.mode = Mode::Chars;
            }
            b'l' => {
                match self.read_and_clear_esc_buf().as_str() {
                    PRIV_12 => self.exec_text_cursor_disable_blinking(),
                    PRIV_25 => self.exec_text_cursor_disable_mode_show(),
                    PRIV_1004 => self.exec_disable_focus_report(),
                    PRIV_2004 => self.exec_disable_bracketed_paste_mode(),
                    PRIV_9001 => self.exec_disable_win32_input_mode(),
                    buf => panic!("Got CsiQ(l): {buf}"),
                }
                self.mode = Mode::Chars;
            }
            _ => self.esc_buf.put(c),
        }
    }

    fn process_osc(&mut self, c: u8) {
        match c {
            b';' => match self.read_and_clear_esc_buf().as_str() {
                "0" | "2" => self.mode = Mode::WindowTitle,
                other => panic!("processOsc: unexpected OSC code {other:?}"),
            },
            _ => self.esc_buf.put(c),
        }
    }

    fn process_window_title(&mut self, c: u8) {
        match c {
            0x07 => {
                self.exec_set_window_title();
                self.mode = Mode::Chars;
            }
            0x1b => self.mode = Mode::WindowTitleEsc,
            _ => self.title_buf.put(c),
        }
    }

    fn process_window_title_esc(&mut self, c: u8) {
        match c {
            b'\\' => {
                self.exec_set_window_title();
                self.mode = Mode::Chars;
            }
            _ => panic!("Saw <ST> ... ESC {} at {}", c as i8, self.count_in),
        }
    }

    fn read_and_clear(buf: &mut ByteBuf) -> String {
        buf.flip();
        let s = decode_windows_1252(buf.as_slice());
        buf.clear();
        s
    }

    fn read_and_clear_esc_buf(&mut self) -> String {
        Self::read_and_clear(&mut self.esc_buf)
    }

    fn parse_numeric_buffer(&mut self) -> i32 {
        let numeric = self.read_and_clear_esc_buf();
        if numeric.is_empty() {
            return 0;
        }
        numeric
            .parse::<i32>()
            .unwrap_or_else(|_| panic!("invalid numeric ANSI parameter {numeric:?}"))
    }

    fn parse_numeric_list_buffer(&mut self) -> Vec<i32> {
        let numeric_list = self.read_and_clear_esc_buf();
        if numeric_list.is_empty() {
            return Vec::new();
        }
        numeric_list
            .split(';')
            .map(|s| {
                s.parse::<i32>()
                    .unwrap_or_else(|_| panic!("invalid numeric ANSI parameter {s:?}"))
            })
            .collect()
    }

    fn to_usize_position(value: i32) -> usize {
        usize::try_from(value).expect("negative ANSI cursor position")
    }

    fn exec_cursor_up(&self) {
        panic!("Cursor Up");
    }

    fn exec_cursor_down(&self) {
        panic!("Cursor Down");
    }

    fn set_position(&mut self, new_position: usize) {
        if self.line_buf.limit < new_position {
            self.line_buf.set_limit(new_position);
        }
        self.line_buf.set_position(new_position);
    }

    fn exec_cursor_forward(&mut self) {
        let delta = self.parse_numeric_buffer();
        let new_position = self.line_buf.position as i32 + delta;
        self.set_position(Self::to_usize_position(new_position));
    }

    fn exec_cursor_backward(&mut self) {
        let delta = self.parse_numeric_buffer();
        let new_position = self.line_buf.position as i32 - delta;
        self.line_buf
            .set_position(Self::to_usize_position(new_position));
    }

    fn exec_cursor_char_absolute(&mut self) {
        let abs = self.parse_numeric_buffer();
        self.line_buf
            .set_position(Self::to_usize_position(abs - 1));
    }

    fn exec_cursor_position(&mut self) {
        let yx = self.parse_numeric_list_buffer();
        if yx.is_empty() {
            self.line_buf.set_position(0);
            return;
        }
        assert_eq!(yx.len(), 2, "execCursorPosition: expected 2 numeric params");
        if yx[0] != 1 {
            Msg::warn(
                "AnsiBufferedInputStream",
                &format!("ANSI: CursorPosition y != 1 ({})", yx[0]),
            );
        }
        self.set_position(Self::to_usize_position(yx[1] - 1));
    }

    fn exec_text_cursor_enable_blinking(&self) {
        // Don't care
    }

    fn exec_text_cursor_disable_blinking(&self) {
        // Don't care
    }

    fn exec_text_cursor_enable_mode_show(&self) {
        // Don't care
    }

    fn exec_text_cursor_disable_mode_show(&self) {
        // Don't care
    }

    fn exec_enable_focus_report(&self) {
        // Don't care
    }

    fn exec_disable_focus_report(&self) {
        // Don't care
    }

    fn exec_enable_bracketed_paste_mode(&self) {
        // Don't care
    }

    fn exec_disable_bracketed_paste_mode(&self) {
        // Don't care
    }

    fn exec_enable_win32_input_mode(&self) {
        // Don't care
    }

    fn exec_disable_win32_input_mode(&self) {
        // Don't care
    }

    fn exec_erase_in_display(&mut self) {
        // Because I have only one line, right?
        self.exec_erase_in_line();
    }

    fn exec_erase_in_line(&mut self) {
        match self.parse_numeric_buffer() {
            0 => {
                let pos = self.line_buf.position;
                let cap = self.line_buf.capacity();
                self.line_buf.fill(pos, cap, 0);
            }
            1 => {
                let pos = self.line_buf.position;
                self.line_buf.fill(0, pos + 1, 0);
            }
            2 => {
                // Erase the entire line. For this single-line model, clearing the whole
                // line resets it to empty so any following text is rewritten from column 0
                // instead of trailing behind the now-erased cursor position.
                self.line_buf.fill_all(0);
                self.line_buf.set_limit(0);
            }
            _ => {}
        }
    }

    fn exec_erase_character(&mut self) {
        let count = self.parse_numeric_buffer();
        let pos = self.line_buf.position;
        let end = Self::to_usize_position(pos as i32 + count);
        self.line_buf.fill(pos, end, b' ');
    }

    fn exec_set_graphics_rendition(&mut self) {
        // TODO: Maybe echo these or provide callbacks
        // Otherwise, don't care
        self.esc_buf.clear();
    }

    fn exec_set_window_title(&mut self) {
        // Maybe a callback. Otherwise, don't care
        self.title_buf.clear();
    }

    fn exec_private_sequence(&mut self, _enable: bool) {
        // These don't matter for input buffering.
        self.esc_buf.clear();
    }
}

impl<R: Read> Read for AnsiBufferedInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.line_baked.has_remaining() && !self.read_until_baked()? {
            return Ok(0);
        }
        let n = self.line_baked.remaining().min(buf.len());
        self.line_baked.get_into(&mut buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream_of(input: &[u8]) -> AnsiBufferedInputStream<&[u8]> {
        AnsiBufferedInputStream::new(input)
    }

    fn read_all(mut s: AnsiBufferedInputStream<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = s.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn plain_text_passes_through_with_newline() {
        let s = stream_of(b"hello\n");
        assert_eq!(read_all(s), b"hello\n");
    }

    #[test]
    fn trailing_spaces_are_trimmed_before_newline() {
        let s = stream_of(b"hello   \n");
        assert_eq!(read_all(s), b"hello\n");
    }

    #[test]
    fn multiple_lines_are_each_baked() {
        let s = stream_of(b"one\ntwo\n");
        assert_eq!(read_all(s), b"one\ntwo\n");
    }

    #[test]
    fn eof_without_trailing_newline_yields_nothing() {
        let s = stream_of(b"partial");
        assert_eq!(read_all(s), b"");
    }

    #[test]
    fn empty_input_yields_eof_immediately() {
        let mut s = stream_of(b"");
        let mut buf = [0u8; 8];
        assert_eq!(s.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn carriage_return_resets_position_for_overwrite() {
        // "abc\rXY\n" -> CR moves to col 0, then X,Y overwrite a,b -> "XYc\n"
        let s = stream_of(b"abc\rXY\n");
        assert_eq!(read_all(s), b"XYc\n");
    }

    #[test]
    fn backspace_over_space_erases_it() {
        // "ab \x08c\n" -> backspace deletes the trailing space, then 'c' overwrites it -> "abc\n"
        let s = stream_of(b"ab \x08c\n");
        assert_eq!(read_all(s), b"abc\n");
    }

    #[test]
    fn sgr_escape_sequence_is_stripped() {
        // ESC [ 3 1 m "red" ESC [ 0 m "\n"
        let s = stream_of(b"\x1b[31mred\x1b[0m\n");
        assert_eq!(read_all(s), b"red\n");
    }

    #[test]
    fn erase_in_line_mode_2_clears_whole_line() {
        // "hello" then CSI 2K (erase whole line), then "hi\n"
        let s = stream_of(b"hello\x1b[2Khi\n");
        assert_eq!(read_all(s), b"hi\n");
    }

    #[test]
    fn cursor_forward_pads_with_nul_bytes() {
        // CSI 3 C moves 3 columns right from col 0 without writing, then "x\n"
        let s = stream_of(b"\x1b[3Cx\n");
        // guessEnd trims trailing spaces/NULs from the end, but not embedded ones,
        // so the three skipped columns remain as NUL bytes followed by 'x'.
        assert_eq!(read_all(s), b"\0\0\0x\n");
    }

    #[test]
    fn dec_private_mode_sequence_is_consumed_without_output() {
        // CSI ? 25 h (show cursor) around visible text.
        let s = stream_of(b"\x1b[?25hvisible\x1b[?25l\n");
        assert_eq!(read_all(s), b"visible\n");
    }

    #[test]
    fn window_title_osc_sequence_is_consumed_without_output() {
        // OSC 0 ; "title" BEL, then visible text.
        let s = stream_of(b"\x1b]0;title\x07visible\n");
        assert_eq!(read_all(s), b"visible\n");
    }

    #[test]
    fn window_title_osc_terminated_by_st_is_consumed() {
        // OSC 2 ; "title" ESC \  (String Terminator form)
        let s = stream_of(b"\x1b]2;title\x1b\\visible\n");
        assert_eq!(read_all(s), b"visible\n");
    }

    #[test]
    #[should_panic(expected = "Cursor Up")]
    fn cursor_up_is_unsupported() {
        let mut s = stream_of(b"\x1b[1A\n");
        let mut buf = [0u8; 8];
        let _ = s.read(&mut buf);
    }

    #[test]
    fn byte_buf_grows_limit_on_append_at_end() {
        let mut buf = ByteBuf::allocate(4);
        buf.set_limit(0);
        buf.put(b'a');
        buf.put(b'b');
        assert_eq!(buf.position, 2);
        assert_eq!(buf.limit, 2);
    }

    #[test]
    fn byte_buf_flip_and_clear_roundtrip() {
        let mut buf = ByteBuf::allocate(4);
        buf.put(b'1');
        buf.put(b'2');
        buf.flip();
        assert_eq!(buf.as_slice(), b"12");
        buf.clear();
        assert_eq!(buf.position, 0);
        assert_eq!(buf.limit, buf.capacity());
    }

    #[test]
    fn windows_1252_decodes_ascii_identity() {
        assert_eq!(decode_windows_1252(b"12;34"), "12;34");
    }

    #[test]
    fn windows_1252_decodes_smart_quote_exception() {
        // 0x93 is windows-1252 LEFT DOUBLE QUOTATION MARK, not Latin-1 U+0093.
        assert_eq!(decode_windows_1252(&[0x93]), "\u{201C}");
    }
}
