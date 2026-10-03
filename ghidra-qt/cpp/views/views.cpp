#include "ghidra-qt/cpp/views/views.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QStatusBar>
#include <QTableView>
#include <QTextBrowser>
#include <QTextCharFormat>
#include <QTextCursor>
#include <QTreeView>
#include <QVBoxLayout>

#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/cpp/views/listing_view.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString qs(const rust::String& s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }
rust::Str rs(const QByteArray& utf8) { return rust::Str(utf8.constData(), static_cast<size_t>(utf8.size())); }
}  // namespace

// ---------------------------------------------------------------- table
RustTableModel::RustTableModel(uint64_t pid, QStatusBar* status, QObject* parent)
    : QAbstractTableModel(parent), m_pid(pid), m_status(status) {}

int RustTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    size_t n = 0;
    bridgeCall(m_status, [&] { n = table_row_count(m_pid); });
    return static_cast<int>(n);
}

int RustTableModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    size_t n = 0;
    bridgeCall(m_status, [&] { n = table_column_count(m_pid); });
    return static_cast<int>(n);
}

QVariant RustTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || (role != Qt::DisplayRole && role != Qt::EditRole)) return {};
    QVariant v;
    bridgeCall(m_status, [&] { v = qs(table_cell(m_pid, index.row(), index.column())); });
    return v;
}

QVariant RustTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
    QVariant v;
    bridgeCall(m_status, [&] { v = qs(table_column_name(m_pid, section)); });
    return v;
}

Qt::ItemFlags RustTableModel::flags(const QModelIndex& index) const {
    Qt::ItemFlags f = QAbstractTableModel::flags(index);
    bool editable = false;
    if (index.isValid()) bridgeCall(m_status, [&] { editable = table_editable(m_pid, index.row(), index.column()); });
    return editable ? (f | Qt::ItemIsEditable) : f;
}

bool RustTableModel::setData(const QModelIndex& index, const QVariant& value, int role) {
    if (!index.isValid() || role != Qt::EditRole) return false;
    const QByteArray utf8 = value.toString().toUtf8();
    const bool ok = bridgeCall(m_status, [&] { table_edit(m_pid, index.row(), index.column(), rs(utf8)); });
    if (ok) emit dataChanged(index, index);
    return ok;
}

void RustTableModel::sort(int column, Qt::SortOrder order) {
    beginResetModel();
    bridgeCall(m_status, [&] { table_sort(m_pid, column, order == Qt::AscendingOrder); });
    endResetModel();
}

void RustTableModel::setFilter(const QString& text) {
    const QByteArray utf8 = text.toUtf8();
    beginResetModel();
    bridgeCall(m_status, [&] { table_filter(m_pid, rs(utf8)); });
    endResetModel();
}

// ---------------------------------------------------------------- tree
RustTreeModel::RustTreeModel(uint64_t pid, QStatusBar* status, QObject* parent)
    : QAbstractItemModel(parent), m_pid(pid), m_status(status) {}

QModelIndex RustTreeModel::index(int row, int column, const QModelIndex& parent) const {
    if (column != 0 || row < 0) return {};
    uint64_t id = 0;
    bool ok;
    if (!parent.isValid()) {
        if (row != 0) return {};  // the Rust root is the single top-level item
        ok = bridgeCall(m_status, [&] { id = tree_root(m_pid); });
    } else {
        ok = bridgeCall(m_status, [&] { id = tree_child(m_pid, parent.internalId(), row); });
    }
    return ok ? createIndex(row, 0, static_cast<quintptr>(id)) : QModelIndex();
}

int RustTreeModel::rowInParent(uint64_t node) const {
    int64_t parent = -1;
    bridgeCall(m_status, [&] { parent = tree_parent(m_pid, node); });
    if (parent < 0) return 0;
    size_t n = 0;
    bridgeCall(m_status, [&] { n = tree_child_count(m_pid, static_cast<uint64_t>(parent)); });
    for (size_t i = 0; i < n; ++i) {
        uint64_t c = 0;
        bridgeCall(m_status, [&] { c = tree_child(m_pid, static_cast<uint64_t>(parent), i); });
        if (c == node) return static_cast<int>(i);
    }
    return 0;
}

QModelIndex RustTreeModel::parent(const QModelIndex& child) const {
    if (!child.isValid()) return {};
    int64_t parent = -1;
    bridgeCall(m_status, [&] { parent = tree_parent(m_pid, child.internalId()); });
    if (parent < 0) return {};
    const uint64_t p = static_cast<uint64_t>(parent);
    return createIndex(rowInParent(p), 0, static_cast<quintptr>(p));
}

int RustTreeModel::rowCount(const QModelIndex& parent) const {
    if (!parent.isValid()) return 1;
    size_t n = 0;
    bridgeCall(m_status, [&] { n = tree_child_count(m_pid, parent.internalId()); });
    return static_cast<int>(n);
}

int RustTreeModel::columnCount(const QModelIndex&) const { return 1; }

QVariant RustTreeModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || role != Qt::DisplayRole) return {};
    QVariant v;
    bridgeCall(m_status, [&] { v = qs(tree_label(m_pid, index.internalId())); });
    return v;
}

// ---------------------------------------------------------------- factories
namespace {

QWidget* makeTable(uint64_t pid, QStatusBar* status, QWidget* parent) {
    auto* box = new QWidget(parent);
    auto* layout = new QVBoxLayout(box);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* filter = new QLineEdit(box);
    filter->setPlaceholderText(QStringLiteral("Filter"));
    auto* view = new QTableView(box);
    auto* model = new RustTableModel(pid, status, view);
    view->setModel(model);
    view->setSortingEnabled(true);
    view->horizontalHeader()->setStretchLastSection(true);
    QObject::connect(filter, &QLineEdit::textChanged, model, [model](const QString& t) { model->setFilter(t); });
    // Java GhidraTable: double-click navigates to the row's program location.
    QObject::connect(view, &QTableView::doubleClicked, view, [pid, status](const QModelIndex& index) {
        if (!index.isValid()) return;
        bridgeCall(status, [&] {
            table_activate(pid, static_cast<size_t>(index.row()), static_cast<size_t>(index.column()));
        });
    });
    layout->addWidget(filter);
    layout->addWidget(view);
    return box;
}

QWidget* makeTree(uint64_t pid, QStatusBar* status, QWidget* parent) {
    auto* view = new QTreeView(parent);
    view->setHeaderHidden(true);
    view->setModel(new RustTreeModel(pid, status, view));
    view->expandToDepth(1);
    // Java ProgramTreePlugin.doubleClick: go to the fragment's minimum address.
    QObject::connect(view, &QTreeView::doubleClicked, view, [pid, status](const QModelIndex& index) {
        if (index.isValid()) bridgeCall(status, [&] { tree_activate(pid, static_cast<uint64_t>(index.internalId())); });
    });
    return view;
}

QWidget* makeText(uint64_t pid, QStatusBar* status, QWidget* parent) {
    auto* view = new QTextBrowser(parent);
    view->setOpenLinks(false);
    QFont mono(QStringLiteral("Monospace"));
    mono.setStyleHint(QFont::Monospace);
    view->setFont(mono);
    QTextCursor cursor(view->document());
    size_t lines = 0;
    bridgeCall(status, [&] { lines = text_line_count(pid); });
    for (size_t i = 0; i < lines; ++i) {
        bridgeCall(status, [&] {
            for (const RunInfo& run : text_line(pid, i)) {
                QTextCharFormat fmt;
                fmt.setFontWeight(run.bold ? QFont::Bold : QFont::Normal);
                fmt.setFontItalic(run.italic);
                if (!run.link.empty()) {
                    fmt.setAnchor(true);
                    fmt.setAnchorHref(qs(run.link));
                }
                cursor.insertText(qs(run.text), fmt);
            }
        });
        if (i + 1 < lines) cursor.insertBlock();
    }
    return view;
}

QWidget* makeForm(uint64_t pid, QStatusBar* status, QWidget* parent) {
    auto* box = new QWidget(parent);
    auto* form = new QFormLayout(box);
    bridgeCall(status, [&] {
        for (const FieldInfo& f : form_fields(pid)) {
            const QByteArray key = qs(f.key).toUtf8();
            auto commit = [pid, key, status](const QString& value) {
                const QByteArray v = value.toUtf8();
                bridgeCall(status, [&] { form_set(pid, rs(key), rs(v)); });
            };
            QWidget* editor = nullptr;
            if (f.kind == 2) {
                auto* cb = new QCheckBox(box);
                cb->setChecked(qs(f.value) == QStringLiteral("true"));
                QObject::connect(cb, &QCheckBox::toggled, cb,
                                 [commit](bool on) { commit(on ? QStringLiteral("true") : QStringLiteral("false")); });
                editor = cb;
            } else if (f.kind == 3) {
                auto* combo = new QComboBox(box);
                for (const auto& c : f.choices) combo->addItem(qs(c));
                combo->setCurrentText(qs(f.value));
                QObject::connect(combo, &QComboBox::currentTextChanged, combo, commit);
                editor = combo;
            } else {
                auto* line = new QLineEdit(qs(f.value), box);
                QObject::connect(line, &QLineEdit::editingFinished, line, [line, commit] { commit(line->text()); });
                editor = line;
            }
            editor->setToolTip(qs(f.tooltip));
            editor->setEnabled(!f.read_only);
            auto* label = new QLabel(qs(f.label), box);
            label->setToolTip(qs(f.tooltip));
            form->addRow(label, editor);
        }
    });
    return box;
}

}  // namespace

QWidget* createProviderView(uint64_t pid, uint8_t kind, QStatusBar* status, QWidget* parent) {
    switch (kind) {
        case 0: return makeTable(pid, status, parent);
        case 1: return makeTree(pid, status, parent);
        case 2: return makeText(pid, status, parent);
        case 3: return makeForm(pid, status, parent);
        case 4: return new ListingView(pid, status, parent);
        default: return new QLabel(QStringLiteral("(view not yet implemented)"), parent);
    }
}

}  // namespace ghidra_qt
