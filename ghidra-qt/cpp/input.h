#pragma once
// Key forwarding (keys go to Rust's context-sensitive dispatch first) and the
// event pump (drains the Rust UiEventQueue when its wake fd is readable).
#include <QObject>
#include <cstdint>
#include <functional>

class QSocketNotifier;

namespace ghidra_qt {

class MainWindow;

/// Application-level event filter: every key press goes to Rust
/// `dispatch_key` with the provider owning the receiving widget. Handled keys
/// (performed / disabled / ambiguous) are consumed; others pass through.
class KeyForwarder : public QObject {
public:
    explicit KeyForwarder(MainWindow* window);
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    MainWindow* m_window;
};

/// Watches the Rust wake fd; on readiness drains events and applies them.
class EventPump : public QObject {
public:
    /// `echoStatus` also prints "status: <text>" lines to stdout (smoke tests).
    EventPump(MainWindow* window, bool echoStatus);
    /// Drains and applies pending events now.
    void pump();

private:
    MainWindow* m_window;
    QSocketNotifier* m_notifier = nullptr;
    bool m_echo;
};

}  // namespace ghidra_qt
