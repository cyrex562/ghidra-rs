//! Port of `ghidra.app.plugin.core.terminal.vt.VtState`.

use crate::app::seam_stubs::{KeyMode, VtHandler};

use super::vt_charset::{CharsetSlot, VtCharset};
use super::vt_parser::VtParser;

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

/// The states of the terminal parser's state machine.
///
/// Each state decides, for the next byte, which handler call (if any) to make and which state
/// comes next. The parser itself ([`VtParser`]) only holds the buffers; the logic lives here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtState {
    /// The initial state: process output characters until an `ESC` is encountered.
    Char,
    /// An `ESC` was just encountered.
    Esc,
    /// `ESC` and a charset-selection byte were encountered; the charset byte comes next. Most are
    /// one byte, but some are two-byte codes.
    Charset,
    /// Selecting a two-byte charset, and `"` was just encountered.
    CharsetQuote,
    /// Selecting a two-byte charset, and `%` was just encountered.
    CharsetPercent,
    /// Selecting a two-byte charset, and `&` was just encountered.
    CharsetAmpersand,
    /// `CSI` was encountered: parsing parameters, intermediates, or the final character.
    CsiParam,
    /// CSI parameters are finished (or skipped): parsing intermediates or the final character.
    CsiInter,
    /// `OSC` was encountered: parsing parameters until `BEL` or `ST`.
    OscParam,
    /// The `ESC` of a possible `ST` was encountered inside an OSC sequence.
    OscEsc,
}

impl VtState {
    /// Handle the given byte, returning the resulting machine state.
    ///
    /// Mirrors Java's per-constant `handleNext(byte, VtParser, VtHandler)`; the handler is the
    /// one owned by `parser`.
    pub(crate) fn handle_next<H: VtHandler>(self, b: u8, parser: &mut VtParser<H>) -> VtState {
        match self {
            VtState::Char => {
                if b == ESC {
                    return VtState::Esc;
                }
                parser.handler.handle_char_exc(b);
                VtState::Char
            }
            VtState::Esc => {
                let h = &mut parser.handler;
                match b {
                    b'7' => h.handle_save_cursor_pos(),
                    b'8' => h.handle_restore_cursor_pos(),
                    b'(' => return Self::select_slot(parser, CharsetSlot::G0),
                    b')' => return Self::select_slot(parser, CharsetSlot::G1),
                    b'*' => return Self::select_slot(parser, CharsetSlot::G2),
                    b'+' => return Self::select_slot(parser, CharsetSlot::G3),
                    b'[' => return VtState::CsiParam,
                    b']' => return VtState::OscParam,
                    b'=' => h.handle_keypad_mode(KeyMode::Application),
                    b'>' => h.handle_keypad_mode(KeyMode::Normal),
                    b'D' => h.handle_scroll_viewport_down(1, true),
                    b'M' => h.handle_scroll_viewport_up(1),
                    b'c' => h.handle_full_reset(),
                    _ => {
                        h.handle_char_exc(ESC);
                        h.handle_char_exc(b);
                    }
                }
                VtState::Char
            }
            VtState::Charset => {
                let cs = match b {
                    b'"' => return VtState::CharsetQuote,
                    b'%' => return VtState::CharsetPercent,
                    b'&' => return VtState::CharsetAmpersand,
                    b'A' => VtCharset::Uk,
                    b'B' => VtCharset::UsAscii,
                    b'C' | b'5' => VtCharset::Finnish,
                    b'H' | b'7' => VtCharset::Swedish,
                    b'K' => VtCharset::German,
                    b'Q' | b'9' => VtCharset::FrenchCanadian,
                    b'R' | b'f' => VtCharset::French,
                    b'Y' => VtCharset::Italian,
                    b'Z' => VtCharset::Spanish,
                    b'4' => VtCharset::Dutch,
                    b'=' => VtCharset::Swiss,
                    b'`' | b'E' | b'6' => VtCharset::NorwegianDanish,
                    b'0' => VtCharset::DecSpecialLines,
                    b'<' => VtCharset::DecSupplemental,
                    b'>' => VtCharset::DecTechnical,
                    _ => return Self::broken_charset(parser, None, b),
                };
                Self::set_charset(parser, cs)
            }
            VtState::CharsetQuote => {
                let cs = match b {
                    b'>' => VtCharset::Greek,
                    b'4' => VtCharset::DecHebrew,
                    b'?' => VtCharset::DecGreek,
                    _ => return Self::broken_charset(parser, Some(b'"'), b),
                };
                Self::set_charset(parser, cs)
            }
            VtState::CharsetPercent => {
                let cs = match b {
                    b'2' => VtCharset::Turkish,
                    b'6' => VtCharset::Portugese,
                    b'=' => VtCharset::Hebrew,
                    b'0' => VtCharset::DecTurkish,
                    b'5' => VtCharset::DecSupplementalGraphics,
                    _ => return Self::broken_charset(parser, Some(b'%'), b),
                };
                Self::set_charset(parser, cs)
            }
            VtState::CharsetAmpersand => {
                if b == b'4' {
                    return Self::set_charset(parser, VtCharset::DecCyrillic);
                }
                Self::broken_charset(parser, Some(b'&'), b)
            }
            VtState::CsiParam => {
                if (0x30..=0x3f).contains(&b) {
                    parser.put_csi_param_byte(b);
                    return VtState::CsiParam;
                }
                Self::csi_inter_or_final(b, parser)
            }
            VtState::CsiInter => Self::csi_inter_or_final(b, parser),
            VtState::OscParam => {
                // For whatever reason, Windows includes the null terminator in titles
                if (0x20..=0x7f).contains(&b) || b == 0 {
                    parser.put_osc_param_byte(b);
                    return VtState::OscParam;
                }
                if b == BEL {
                    Self::handle_osc(parser);
                    return VtState::Char;
                }
                if b == ESC {
                    return VtState::OscEsc;
                }
                parser.handler.handle_char_exc(ESC);
                let buf = parser.copy_osc_buffer(b);
                parser.do_process(VtState::Char, &buf)
            }
            VtState::OscEsc => {
                if b == b'\\' {
                    Self::handle_osc(parser);
                    return VtState::Char;
                }
                parser.handler.handle_char_exc(ESC);
                parser.do_process_byte(VtState::OscParam, b)
            }
        }
    }

    fn select_slot<H: VtHandler>(parser: &mut VtParser<H>, slot: CharsetSlot) -> VtState {
        parser.cs_g = slot;
        VtState::Charset
    }

    fn set_charset<H: VtHandler>(parser: &mut VtParser<H>, cs: VtCharset) -> VtState {
        parser.handler.handle_set_charset(parser.cs_g, cs);
        VtState::Char
    }

    /// An unrecognized charset designation: emit the `ESC` as a character and re-process the
    /// bytes that followed it (the slot byte, the optional two-byte prefix, then `b`).
    ///
    /// Note the slot byte is the one Java's `VtCharset.G` records, which for `G3` is `-`, not the
    /// `+` that selected it; that quirk is preserved.
    fn broken_charset<H: VtHandler>(
        parser: &mut VtParser<H>,
        prefix: Option<u8>,
        b: u8,
    ) -> VtState {
        parser.handler.handle_char_exc(ESC);
        let slot_byte = parser.cs_g.as_byte();
        let mut state = parser.do_process_byte(VtState::Char, slot_byte);
        if let Some(p) = prefix {
            state = parser.do_process_byte(state, p);
        }
        parser.do_process_byte(state, b)
    }

    /// Shared tail of `CSI_PARAM` and `CSI_INTER`: an intermediate byte, a final byte, or a broken
    /// sequence.
    fn csi_inter_or_final<H: VtHandler>(b: u8, parser: &mut VtParser<H>) -> VtState {
        if (0x20..=0x2f).contains(&b) {
            parser.put_csi_inter_byte(b);
            return VtState::CsiInter;
        }
        if (0x40..=0x7e).contains(&b) {
            Self::handle_csi(b, parser);
            return VtState::Char;
        }
        parser.handler.handle_char_exc(ESC);
        let buf = parser.copy_csi_buffer(b);
        parser.do_process(VtState::Char, &buf)
    }

    /// Mirrors `handleCsi`: hand the collected CSI buffers to the handler and reset them.
    fn handle_csi<H: VtHandler>(csi_final: u8, parser: &mut VtParser<H>) {
        parser
            .handler
            .handle_csi_exc(&parser.csi_param, &parser.csi_inter, csi_final);
        parser.csi_param.clear();
        parser.csi_inter.clear();
    }

    /// Mirrors `handleOsc`: hand the collected OSC buffer to the handler and reset it.
    fn handle_osc<H: VtHandler>(parser: &mut VtParser<H>) {
        parser.handler.handle_osc_exc(&parser.osc_param);
        parser.osc_param.clear();
    }
}
