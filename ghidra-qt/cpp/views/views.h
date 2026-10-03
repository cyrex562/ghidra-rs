#pragma once
// Generic Qt views over Rust view models (spec §2): one widget per ViewKind.
// They render what the bridge returns and forward edits; no domain logic.
#include <QAbstractItemModel>
#include <QAbstractTableModel>
#include <QWidget>
#include <cstdint>

class QStatusBar;

namespace ghidra_qt {

/// QAbstractTableModel over a Rust TableModel (bridge table_* calls).
class RustTableModel : public QAbstractTableModel {
public:
    RustTableModel(uint64_t pid, QStatusBar* status, QObject* parent = nullptr);
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;
    bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;
    void sort(int column, Qt::SortOrder order = Qt::AscendingOrder) override;
    void setFilter(const QString& text);
    /// Re-reads rows after Rust changed them (row count, order, cells).
    void reload();

private:
    uint64_t m_pid;
    QStatusBar* m_status;
};

/// QAbstractItemModel over a Rust TreeModel; internalId() is the Rust node id.
class RustTreeModel : public QAbstractItemModel {
public:
    RustTreeModel(uint64_t pid, QStatusBar* status, QObject* parent = nullptr);
    QModelIndex index(int row, int column, const QModelIndex& parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex& child) const override;
    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;

private:
    int rowInParent(uint64_t node) const;
    uint64_t m_pid;
    QStatusBar* m_status;
};

/// Builds the widget for a provider of the given ViewKind code
/// (0 table, 1 tree, 2 text, 3 form); other kinds get a placeholder label.
QWidget* createProviderView(uint64_t pid, uint8_t kind, QStatusBar* status, QWidget* parent);

}  // namespace ghidra_qt
