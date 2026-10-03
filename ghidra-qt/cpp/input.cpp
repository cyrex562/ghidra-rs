#include "ghidra-qt/cpp/input.h"

#include <QTimer>

#include <QInputDialog>
#include <QItemSelectionModel>
#include <QFormLayout>
#include <QTreeView>
#include <QTableView>
#include <QSplitter>
#include <QScrollArea>
#include <QPushButton>
#include <QMessageBox>
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
#include "ghidra-qt/cpp/views/views.h"
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
        m_panes = new QSplitter(Qt::Horizontal, this);
        m_panes->setVisible(false);
        layout->addWidget(m_panes, 1);
        m_statusLine = new QLabel(this);
        m_statusLine->setStyleSheet(QStringLiteral("color: palette(link)"));
        layout->addWidget(m_statusLine);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        m_buttonBox = buttons;
        layout->addWidget(buttons);
        connect(buttons, &QDialogButtonBox::accepted, this, [this] { okPressed(); });
        connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
        load(true);
    }

    bool loaded() const { return m_loaded; }

public:
    void reject() override {
        flushEdits();  // a pending edit commits while the panes still exist
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
            m_message->setVisible(!d.message.empty());
            for (const ButtonInfo& b : d.buttons) addExtraButton(qs(b.key), qs(b.label), qs(b.confirm));
            if (d.has_panes) buildPanes();
        }
        const QString typed = m_combo->currentText();
        m_combo->clear();
        for (const rust::String& item : d.combo_items) m_combo->addItem(qs(item));
        m_combo->setEditText(first ? qs(d.combo_text) : typed);
        m_statusLine->setText(qs(d.status));
        if (d.has_combo) {
            m_combo->lineEdit()->selectAll();
            m_combo->setFocus();
        }
    }

    // Tree (categories) beside the form for the selected node; the views are
    // the generic provider views over dialog-scoped view models (Rust ids).
    void buildPanes() {
        PaneIds ids{};
        if (!bridgeCall(m_status, [&] { ids = dialog_panes(m_id); })) return;
        m_formPid = ids.form;
        m_tablePid = ids.table;
        QWidget* tree = createProviderView(ids.tree, 1, m_status, m_panes);
        m_panes->addWidget(tree);
        m_formHost = new QScrollArea(m_panes);
        m_formHost->setWidgetResizable(true);
        m_panes->addWidget(m_formHost);
        m_panes->setStretchFactor(1, 1);
        m_panes->setVisible(true);
        rebuildForm();
        if (auto* view = qobject_cast<QTreeView*>(tree)) {
            const uint64_t treePid = ids.tree;
            view->setCurrentIndex(view->model()->index(0, 0));
            view->expand(view->model()->index(0, 0));
            connect(view->selectionModel(), &QItemSelectionModel::currentChanged, this, [this, treePid](const QModelIndex& index) {
                if (!index.isValid()) return;
                bridgeCall(m_status, [&] { tree_select(treePid, static_cast<uint64_t>(index.internalId())); });
                rebuildForm();
            });
        }
        resize(820, 520);
    }

    // The right pane for the current selection: Rust says form or table.
    void rebuildForm() {
        if (!m_formHost) return;
        DialogInfo d;
        const bool table = bridgeCall(m_status, [&] { d = dialog_spec(m_id); }) && d.pane_kind == 1 && m_tablePid != 0;
        m_formHost->setWidget(createProviderView(table ? m_tablePid : m_formPid, table ? 0 : 3, m_status, m_formHost));
    }

public:
    // Selects the top-level tree node labelled `label` (smoke tests).
    bool selectNode(const QString& label) {
        auto* view = m_panes->findChild<QTreeView*>();
        if (!view) return false;
        const QModelIndex root = view->model()->index(0, 0);
        for (int r = 0; r < view->model()->rowCount(root); ++r) {
            const QModelIndex child = view->model()->index(r, 0, root);
            if (child.data().toString() == label) {
                view->setCurrentIndex(child);
                return true;
            }
        }
        return false;
    }

private:

    void addExtraButton(const QString& key, const QString& label, const QString& confirm) {
        QPushButton* b = m_buttonBox->addButton(label, QDialogButtonBox::ActionRole);
        connect(b, &QPushButton::clicked, this, [this, key, label, confirm] {
            if (!confirm.isEmpty() &&
                QMessageBox::question(this, label + QLatin1Char('?'), confirm) != QMessageBox::Yes) {
                return;
            }
            pressButton(key);
        });
    }

public:
    // Presses an extra button (smoke tests skip the confirmation).
    void pressButton(const QString& key) {
        flushEdits();
        const QByteArray k = key.toUtf8();
        bool done = false;
        if (!bridgeCall(m_status, [&] { done = dialog_button(m_id, rust::Str(k.constData(), static_cast<size_t>(k.size()))); })) return;
        m_pump->pump();
        if (done) {
            QDialog::accept();
        } else {
            load(false);
            rebuildForm();
        }
    }

    // "tree: <root>" and "form: <label>=<value>" lines (smoke tests).
    QStringList summary() const {
        QStringList out;
        if (auto* view = m_panes->findChild<QTreeView*>()) out << QStringLiteral("tree: ") + view->model()->index(0, 0).data().toString();
        if (auto* table = m_formHost ? m_formHost->findChild<QTableView*>() : nullptr) {
            for (int r = 0; r < table->model()->rowCount(); ++r) {
                out << QStringLiteral("row: %1=%2").arg(table->model()->index(r, 0).data().toString(), table->model()->index(r, 1).data().toString());
            }
        }
        if (m_formHost && m_formHost->widget()) {
            if (auto* form = qobject_cast<QFormLayout*>(m_formHost->widget()->layout())) {
                for (int r = 0; r < form->rowCount(); ++r) {
                    auto* l = qobject_cast<QLabel*>(form->itemAt(r, QFormLayout::LabelRole)->widget());
                    QWidget* e = form->itemAt(r, QFormLayout::FieldRole)->widget();
                    QString v;
                    if (auto* le = qobject_cast<QLineEdit*>(e)) v = le->text();
                    else if (auto* cb = qobject_cast<QCheckBox*>(e)) v = cb->isChecked() ? QStringLiteral("true") : QStringLiteral("false");
                    else if (auto* co = qobject_cast<QComboBox*>(e)) v = co->currentText();
                    out << QStringLiteral("form: %1=%2").arg(l ? l->text() : QString(), v);
                }
            }
        }
        return out;
    }

    // Edits form row `label` (or the table row whose first cell is `label`) as
    // a user would, then presses OK (smoke tests).
    void setFieldAndOk(const QString& label, const QString& value) {
        if (auto* table = m_formHost ? m_formHost->findChild<QTableView*>() : nullptr) {
            for (int r = 0; r < table->model()->rowCount(); ++r) {
                if (table->model()->index(r, 0).data().toString() == label) table->model()->setData(table->model()->index(r, 1), value);
            }
        }
        if (m_formHost && m_formHost->widget()) {
            if (auto* form = qobject_cast<QFormLayout*>(m_formHost->widget()->layout())) {
                for (int r = 0; r < form->rowCount(); ++r) {
                    auto* l = qobject_cast<QLabel*>(form->itemAt(r, QFormLayout::LabelRole)->widget());
                    if (!l || l->text() != label) continue;
                    if (auto* le = qobject_cast<QLineEdit*>(form->itemAt(r, QFormLayout::FieldRole)->widget())) {
                        le->setText(value);
                        emit le->editingFinished();
                    }
                }
            }
        }
        okPressed();
    }

private:

    // Commits the focused editor (its editingFinished) before the dialog acts:
    // where buttons take no focus on click, the last edit would otherwise be
    // missed by OK, or arrive after Cancel released the panes.
    void flushEdits() {
        if (QWidget* w = focusWidget()) w->clearFocus();
    }

    void okPressed() {
        flushEdits();
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
            rebuildForm();
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
    QSplitter* m_panes = nullptr;
    QScrollArea* m_formHost = nullptr;
    QDialogButtonBox* m_buttonBox = nullptr;
    uint64_t m_formPid = 0;
    uint64_t m_tablePid = 0;
};
}  // namespace

void EventPump::showDialog(uint64_t id) {
    if (m_autoAnswer) {
        DialogInfo probe;
        if (bridgeCall(m_window->statusBar(), [&] { probe = dialog_spec(id); }) && probe.has_panes) {
            // Build the real dialog (unshown), report it, apply "label=value" via its form.
            auto* dialog = new RustDialog(id, m_window->statusBar(), this, m_window);
            std::printf("dialog: %s\n", qs(probe.title).toUtf8().constData());
            // "<node> > <field>=<value>" selects a top-level node first.
            QString answer = m_promptAnswer;
            const int sep = answer.indexOf(QStringLiteral(" > "));
            if (sep > 0) {
                dialog->selectNode(answer.left(sep));
                answer = answer.mid(sep + 3);
            } else if (!answer.contains(QLatin1Char('='))) {
                dialog->selectNode(answer);
            }
            for (const QString& line : dialog->summary()) std::printf("%s\n", line.toUtf8().constData());
            const int eq = answer.indexOf(QLatin1Char('='));
            if (eq > 0) {
                dialog->setFieldAndOk(answer.left(eq), answer.mid(eq + 1));
            } else {
                dialog->reject();
            }
            std::fflush(stdout);
            dialog->deleteLater();
            QTimer::singleShot(0, this, [this] { pump(); });
            return;
        }
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
