#include "ghidra-qt/cpp/input.h"

#include <QApplication>
#include <QKeyEvent>
#include <QMenu>
#include <QSocketNotifier>
#include <QStatusBar>
#include <cstdio>

#include "DockWidget.h"
#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/cpp/main_window.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString qs(const rust::String& s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }
}  // namespace

KeyForwarder::KeyForwarder(MainWindow* window) : QObject(window), m_window(window) {}

bool KeyForwarder::eventFilter(QObject* watched, QEvent* event) {
    if (event->type() != QEvent::KeyPress) return false;
    auto* key = static_cast<QKeyEvent*>(event);
    const int64_t pid = m_window->providerOfObject(watched);
    KeyResult r;
    if (!bridgeCall(m_window->statusBar(), [&] {
            r = dispatch_key(key->key(), static_cast<uint32_t>(key->modifiers().toInt()), pid);
        })) {
        return false;
    }
    switch (r.code) {
        case 0:  // performed
            return true;
        case 1:  // valid but disabled: Java beeps
            QApplication::beep();
            return true;
        case 2: {  // ambiguous: Ghidra's action chooser
            QMenu chooser(m_window);
            for (uint64_t id : r.candidates) {
                QString name;
                bridgeCall(m_window->statusBar(), [&] { name = qs(action_name(id)); });
                QAction* a = chooser.addAction(name);
                QObject::connect(a, &QAction::triggered, &chooser, [this, id, pid] {
                    bridgeCall(m_window->statusBar(), [&] { invoke_action(id, pid); });
                });
            }
            chooser.exec(QCursor::pos());
            return true;
        }
        default:
            return false;
    }
}

EventPump::EventPump(MainWindow* window, bool echoStatus) : QObject(window), m_window(window), m_echo(echoStatus) {
    int fd = -1;
    if (bridgeCall(window->statusBar(), [&] { fd = wake_fd(); }) && fd >= 0) {
        m_notifier = new QSocketNotifier(fd, QSocketNotifier::Read, this);
        QObject::connect(m_notifier, &QSocketNotifier::activated, this, [this] { pump(); });
    }
}

void EventPump::pump() {
    rust::Vec<EventInfo> events;
    if (!bridgeCall(m_window->statusBar(), [&] { events = drain_events(); })) return;
    bool actionsChanged = false;
    for (const EventInfo& e : events) {
        switch (e.kind) {
            case 0: {
                const QString text = qs(e.text);
                m_window->statusBar()->showMessage(text, 5000);
                if (m_echo) {
                    std::printf("status: %s\n", text.toUtf8().constData());
                    std::fflush(stdout);
                }
                break;
            }
            case 1:
                m_window->showTaskProgress(qs(e.text), e.progress, e.maximum);
                break;
            case 2:
                m_window->showTaskProgress(QString(), 0, 0);
                if (!e.text.empty()) m_window->statusBar()->showMessage(qs(e.text), 5000);
                break;
            case 3:
                actionsChanged = true;
                break;
            default:
                break;
        }
    }
    if (actionsChanged) m_window->rebuildActions();
}

}  // namespace ghidra_qt
