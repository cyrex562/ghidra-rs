#pragma once
#include <QMainWindow>
#include <QMap>
#include <QString>
#include <cstdint>

namespace ads {
class CDockManager;
class CDockWidget;
class CDockAreaWidget;
}  // namespace ads

namespace ghidra_qt {

// Top-level tool window: one ADS dock per Rust provider, placed by its
// WindowPosition (spec §4). Renders only; layout intent lives in Rust.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(const QString& title, QWidget* parent = nullptr);
    ads::CDockManager* dockManager() const { return m_dockManager; }

    // "title<TAB>area<TAB>view" per dock, for smoke tests.
    QStringList dockSummary() const;
    // Restores ADS geometry; false (and default placement kept) if rejected.
    bool restoreDockGeometry(const QByteArray& state);
    // The dock showing a provider title, or nullptr.
    ads::CDockWidget* dockByTitle(const QString& title) const;
    // Provider id of a dock (or -1).
    int64_t providerOf(ads::CDockWidget* dock) const;

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void buildDocks();
    ads::CDockManager* m_dockManager;
    QMap<ads::CDockWidget*, int64_t> m_providers;
    QMap<ads::CDockWidget*, QString> m_areaNames;
    QMap<ads::CDockWidget*, QString> m_viewNames;
};

}  // namespace ghidra_qt
