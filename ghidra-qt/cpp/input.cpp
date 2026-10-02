#include "ghidra-qt/cpp/input.h"

#include <QTimer>

#include <QInputDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QHBoxLayout>
#include <QDialogButtonBox>
#include <QDialog>
#include <QCheckBox>

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
    // Nor while a dialog is up: tool bindings belong to the tool window only
    // (Java KeyBindingOverrideKeyEventDispatcher checks the active window).
    if (QApplication::activeModalWidget()) return false;
    // Floating docks live in their own top-level windows but are still the
    // tool's: only widgets outside every provider and outside the main
    // window (other top-levels) are skipped.
    if (auto* w = qobject_cast<QWidget*>(watched); w && w->window() != m_window && m_window->providerOfObject(watched) < 0) return false;
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

namespace {
// A dialog drawn from a Rust DialogInfo: message, editable combo (with
// history), check boxes, status line, OK/Cancel. Rust decides what OK does.
class RustDialog : public QDialog {
public:
    RustDialog(uint64_t id, QStatusBar* status, EventPump* pump, QWidget* parent)
        : QDialog(parent), m_id(id), m_status(status), m_pump(pump) {
        setAttribute(Qt::WA_DeleteOnClose);
        auto* layout = new QVBoxLayout(this);
        m_message = new QLabel(this);
        layout->addWidget(m_message);
        m_combo = new QComboBox(this);
        m_combo->setEditable(true);
        m_combo->setInsertPolicy(QComboBox::NoInsert);
        layout->addWidget(m_combo);
        m_checkRow = new QHBoxLayout();
        layout->addLayout(m_checkRow);
        m_statusLine = new QLabel(this);
        m_statusLine->setStyleSheet(QStringLiteral("color: palette(link)"));
        layout->addWidget(m_statusLine);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, this, [this] { okPressed(); });
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        load(true);
    }

    bool loaded() const { return m_loaded; }

protected:
    void reject() override {
        bridgeCall(m_status, [&] { dialog_cancel(m_id); });
        QDialog::reject();
    }

private:
    void load(bool first) {
        DialogInfo d;
        m_loaded = bridgeCall(m_status, [&] { d = dialog_spec(m_id); });
        if (!m_loaded) return;
        if (first) {
            setWindowTitle(qs(d.title));
            m_message->setText(qs(d.message));
            for (const CheckInfo& c : d.checks) {
                auto* box = new QCheckBox(qs(c.label), this);
                box->setChecked(c.checked);
                box->setToolTip(qs(c.tooltip));
                box->setProperty("rustKey", qs(c.key));
                m_checkRow->addWidget(box);
                m_checks << box;
            }
            m_combo->setVisible(d.has_combo);
        }
        const QString typed = m_combo->currentText();
        m_combo->clear();
        for (const rust::String& item : d.combo_items) m_combo->addItem(qs(item));
        m_combo->setEditText(first ? qs(d.combo_text) : typed);
        m_statusLine->setText(qs(d.status));
        m_combo->lineEdit()->selectAll();
        m_combo->setFocus();
    }

    void okPressed() {
        rust::Vec<CheckInfo> checks;
        for (QCheckBox* box : m_checks) {
            const QByteArray key = box->property("rustKey").toString().toUtf8();
            checks.push_back(CheckInfo{rust::String(key.constData(), static_cast<size_t>(key.size())), rust::String(), rust::String(), box->isChecked()});
        }
        const QByteArray text = m_combo->currentText().toUtf8();
        bool done = false;
        if (!bridgeCall(m_status, [&] { done = dialog_ok(m_id, rust::Str(text.constData(), static_cast<size_t>(text.size())), std::move(checks)); })) return;
        m_pump->pump();
        if (done) {
            QDialog::accept();
        } else {
            load(false);
        }
    }

    uint64_t m_id;
    QStatusBar* m_status;
    EventPump* m_pump;
    QLabel* m_message;
    QComboBox* m_combo;
    QHBoxLayout* m_checkRow;
    QLabel* m_statusLine;
    QList<QCheckBox*> m_checks;
    bool m_loaded = false;
};
}  // namespace

void EventPump::showDialog(uint64_t id) {
    if (m_autoAnswer) {
        DialogInfo d;
        if (!bridgeCall(m_window->statusBar(), [&] { d = dialog_spec(id); })) return;
        std::printf("dialog: %s\n", qs(d.title).toUtf8().constData());
        const QByteArray a = m_promptAnswer.toUtf8();
        rust::Vec<CheckInfo> checks;
        bool done = false;
        bridgeCall(m_window->statusBar(), [&] { done = dialog_ok(id, rust::Str(a.constData(), static_cast<size_t>(a.size())), std::move(checks)); });
        if (!done) {
            bridgeCall(m_window->statusBar(), [&] { d = dialog_spec(id); });
            std::printf("dialog status: %s\n", qs(d.status).toUtf8().constData());
            bridgeCall(m_window->statusBar(), [&] { dialog_cancel(id); });
        }
        std::fflush(stdout);
        QTimer::singleShot(0, this, [this] { pump(); });
        return;
    }
    auto* dialog = new RustDialog(id, m_window->statusBar(), this, m_window);
    if (!dialog->loaded()) {
        delete dialog;
        return;
    }
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
            case 9:
                showDialog(e.task);
                break;
            case 8:
                m_window->showProvider(static_cast<int64_t>(e.task), e.progress != 0);
                break;
            default:
                break;
        }
    }
    if (actionsChanged) m_window->rebuildActions();
}

}  // namespace ghidra_qt
