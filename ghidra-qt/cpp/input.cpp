#include "ghidra-qt/cpp/input.h"

#include <QTimer>

#include <QInputDialog>

#include <QApplication>
#include <QAbstractSpinBox>
#include <QComboBox>
#include <QKeyEvent>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QTextEdit>
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

namespace {
// Java KeyBindingOverrideKeyEventDispatcher defers to text components for the
// keys they handle themselves (willBeHandledByTextComponent): standard edit
// sequences, and plain/shifted typing in editable fields.
bool handledByTextWidget(QObject* watched, QKeyEvent* key) {
    const bool textual = qobject_cast<QLineEdit*>(watched) || qobject_cast<QTextEdit*>(watched) ||
                         qobject_cast<QPlainTextEdit*>(watched) || qobject_cast<QAbstractSpinBox*>(watched);
    auto* combo = qobject_cast<QComboBox*>(watched);
    if (!textual && !(combo && combo->isEditable())) return false;
    for (auto std : {QKeySequence::Copy, QKeySequence::Paste, QKeySequence::Cut, QKeySequence::SelectAll,
                     QKeySequence::Undo, QKeySequence::Redo}) {
        if (key->matches(std)) return true;
    }
    const auto mods = key->modifiers() & ~(Qt::ShiftModifier | Qt::KeypadModifier);
    return mods == Qt::NoModifier && !key->text().isEmpty();
}
}  // namespace

bool KeyForwarder::eventFilter(QObject* watched, QEvent* event) {
    if (event->type() != QEvent::KeyPress) return false;
    auto* key = static_cast<QKeyEvent*>(event);
    if (event == m_lastEvent && key->timestamp() == m_lastTimestamp) return false;  // propagation repeat
    m_lastEvent = event;
    m_lastTimestamp = key->timestamp();
    // Java ignores docking actions while a menu is open (MenuKeyProcessor).
    if (QApplication::activePopupWidget()) return false;
    if (handledByTextWidget(watched, key)) return false;
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

void EventPump::setPromptAnswer(const QString& answer) {
    m_autoAnswer = true;
    m_promptAnswer = answer;
}

void EventPump::showPrompt(uint64_t id, const QString& title, const QString& label, const QString& initial) {
    if (m_autoAnswer) {
        std::printf("prompt: %s\n", title.toUtf8().constData());
        std::fflush(stdout);
        const QByteArray a = m_promptAnswer.toUtf8();
        bridgeCall(m_window->statusBar(), [&] { prompt_reply(id, true, rust::Str(a.constData(), static_cast<size_t>(a.size()))); });
        QTimer::singleShot(0, this, [this] { pump(); });
        return;
    }
    // Non-modal: the reply arrives through the dialog's signals.
    auto* dialog = new QInputDialog(m_window);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(title);
    dialog->setLabelText(label);
    dialog->setTextValue(initial);
    QObject::connect(dialog, &QInputDialog::finished, this, [this, dialog, id](int result) {
        const QByteArray a = dialog->textValue().toUtf8();
        bridgeCall(m_window->statusBar(), [&] {
            prompt_reply(id, result == QDialog::Accepted, rust::Str(a.constData(), static_cast<size_t>(a.size())));
        });
        pump();
    });
    dialog->open();
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
            case 6:
                showPrompt(e.task, qs(e.text), qs(e.label), qs(e.initial));
                break;
            case 7:
                m_window->viewChanged(static_cast<int64_t>(e.task));
                break;
            default:
                break;
        }
    }
    if (actionsChanged) m_window->rebuildActions();
}

}  // namespace ghidra_qt
