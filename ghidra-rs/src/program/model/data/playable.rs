/// Minimal stand-in for `javax.swing.Icon`.
///
/// The full Swing icon-painting contract (`paintIcon`/`getIconWidth`/`getIconHeight`) has no
/// counterpart in this port, since there is no Swing rendering pipeline. The only thing
/// [`Playable`] implementors actually need is a stable identity for the icon they display
/// (both known Java implementors, `AudioPlayer` and `ScorePlayer`, return a themed icon looked
/// up by key), so this trait exposes just that.
pub trait Icon {
    /// Returns an identifier for this icon (e.g. a theme icon key or file path).
    fn icon_id(&self) -> &str;
}

/// Minimal stand-in for `java.awt.event.MouseEvent`, carrying only the fields a
/// [`Playable::clicked`] implementation is likely to need.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseClickEvent {
    pub x: i32,
    pub y: i32,
    pub click_count: i32,
}

impl MouseClickEvent {
    pub fn new(x: i32, y: i32, click_count: i32) -> Self {
        Self { x, y, click_count }
    }
}

/// A data type value that can display an icon and respond to being clicked, such as an
/// embedded audio clip or MIDI score.
///
/// Port of `ghidra.program.model.data.Playable`.
pub trait Playable {
    /// Returns the icon to render for this playable value.
    fn get_image_icon(&self) -> Box<dyn Icon>;

    /// Called when the user clicks on the rendered icon.
    fn clicked(&self, event: &MouseClickEvent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct KeyedIcon {
        key: String,
    }

    impl Icon for KeyedIcon {
        fn icon_id(&self) -> &str {
            &self.key
        }
    }

    struct MockAudioPlayer {
        playing: AtomicBool,
    }

    impl Playable for MockAudioPlayer {
        fn get_image_icon(&self) -> Box<dyn Icon> {
            Box::new(KeyedIcon { key: "icon.data.type.audio.player".to_string() })
        }

        fn clicked(&self, _event: &MouseClickEvent) {
            let was_playing = self.playing.fetch_xor(true, Ordering::SeqCst);
            let _ = was_playing;
        }
    }

    #[test]
    fn get_image_icon_returns_expected_id() {
        let player = MockAudioPlayer { playing: AtomicBool::new(false) };
        assert_eq!(player.get_image_icon().icon_id(), "icon.data.type.audio.player");
    }

    #[test]
    fn clicked_toggles_playback_state() {
        let player = MockAudioPlayer { playing: AtomicBool::new(false) };
        let event = MouseClickEvent::new(10, 20, 1);
        player.clicked(&event);
        assert!(player.playing.load(Ordering::SeqCst));
        player.clicked(&event);
        assert!(!player.playing.load(Ordering::SeqCst));
    }

    #[test]
    fn usable_as_trait_object() {
        let player = MockAudioPlayer { playing: AtomicBool::new(false) };
        let dyn_player: &dyn Playable = &player;
        let icon = dyn_player.get_image_icon();
        assert_eq!(icon.icon_id(), "icon.data.type.audio.player");
        dyn_player.clicked(&MouseClickEvent::default());
    }

    #[test]
    fn mouse_click_event_default_is_origin() {
        let event = MouseClickEvent::default();
        assert_eq!(event.x, 0);
        assert_eq!(event.y, 0);
        assert_eq!(event.click_count, 0);
    }
}
