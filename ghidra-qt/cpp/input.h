#pragma once
// Key forwarding (keys go to Rust's context-sensitive dispatch first) and the
// event pump (drains the Rust UiEventQueue when its wake fd is readable).
#include <QObject>
#include <QString>
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
    // The app-level filter sees a key event again for every parent it
    // propagates to; dispatch each event once.
    const QEvent* m_lastEvent = nullptr;
    unsigned long m_lastTimestamp = 0;
};

/// Watches the Rust wake fd; on readiness drains events and applies them.
class EventPump : public QObject {
public:
    /// `echoStatus` also prints "status: <text>" lines to stdout (smoke tests).
    EventPump(MainWindow* window, bool echoStatus);
    /// Smoke tests: answer every prompt with `answer` instead of showing a
    /// dialog, echoing "prompt: <title>".
    void setPromptAnswer(const QString& answer);
    /// Drains and applies pending events now.
    void pump();

private:
    void showPrompt(uint64_t id, const QString& title, const QString& label, const QString& initial);

public:

private:
    MainWindow* m_window;
    QSocketNotifier* m_notifier = nullptr;
    bool m_echo;
    bool m_autoAnswer = false;
    QString m_promptAnswer;
};

}  // namespace ghidra_qt
