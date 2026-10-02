#pragma once
#include <QMainWindow>
#include <QMap>
#include <QString>
#include <cstdint>

class QProgressBar;
class QToolBar;

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
    // Disconnects application-wide signals before children are destroyed
    // (focusChanged fires during teardown).
    ~MainWindow() override;
    ads::CDockManager* dockManager() const { return m_dockManager; }

    // "title<TAB>area<TAB>view" per dock, for smoke tests.
    QStringList dockSummary() const;
    // Restores ADS geometry; false (and default placement kept) if rejected.
    // Afterwards every provider Rust says is visible is shown again, even if
    // the saved ADS state (from a different dock set) never mentioned it.
    bool restoreDockGeometry(const QByteArray& state);
    // The dock showing a provider title, or nullptr.
    ads::CDockWidget* dockByTitle(const QString& title) const;
    // Rust changed provider `pid`'s view state: refresh/repaint its view.
    void viewChanged(int64_t pid);
    // Provider id of a dock (or -1).
    int64_t providerOf(ads::CDockWidget* dock) const;
    // Provider id owning a widget/object (walks parents to its dock), or -1.
    int64_t providerOfObject(QObject* object) const;
    // Provider of the focused widget, or -1.
    int64_t focusedProvider() const;
    // Rebuilds menu bar and toolbar from Rust (focus/action changes).
    void rebuildActions();
    // Status-bar task progress; empty message + 0/0 hides it.
    void showTaskProgress(const QString& message, uint64_t progress, uint64_t maximum);
    // The built menu bar as text (smoke tests).
    QStringList menuSummary();
    // Stores ADS geometry in the Rust layout and writes the tool config.
    void saveLayout();
    // Whether saveLayout() already ran (close event); app.exit() skips it.
    bool layoutSaved() const { return m_layoutSaved; }
    // Gives keyboard focus to the main view inside a dock; false if none.
    bool focusDock(const QString& title);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void buildDocks();
    void placeDock(ads::CDockWidget* dock, uint8_t position);
    void showDocksRustConsidersVisible();
    QMap<int, ads::CDockAreaWidget*> m_areas;
    QMap<ads::CDockWidget*, uint8_t> m_positions;
    void installPopups();
    QToolBar* m_toolBar = nullptr;
    QProgressBar* m_progress = nullptr;
    bool m_layoutSaved = false;
    ads::CDockManager* m_dockManager;
    QMap<ads::CDockWidget*, int64_t> m_providers;
    QMap<ads::CDockWidget*, QString> m_areaNames;
    QMap<ads::CDockWidget*, QString> m_viewNames;
};

}  // namespace ghidra_qt
