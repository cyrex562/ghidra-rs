#pragma once
#include <QMainWindow>
#include <QString>

namespace ads {
class CDockManager;
}

namespace ghidra_qt {

// Top-level tool window. Owns the ADS dock manager; U1 populates it from the
// Rust DockLayout. Contains no domain logic.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const QString& title, QWidget* parent = nullptr);
    ads::CDockManager* dockManager() const { return m_dockManager; }

private:
    ads::CDockManager* m_dockManager;
};

}  // namespace ghidra_qt
