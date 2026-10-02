#include "ghidra-qt/cpp/main_window.h"

#include <QCloseEvent>
#include <QStatusBar>

#include "DockAreaWidget.h"
#include "DockManager.h"
#include "DockWidget.h"
#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/cpp/views/views.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString qs(const rust::String& s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }

struct Placement {
    ads::DockWidgetArea area;
    const char* name;
};

// WindowPosition code (0 top, 1 bottom, 2 left, 3 right, 4 window, 5 stack) -> ADS area.
Placement placementFor(uint8_t position) {
    switch (position) {
        case 0: return {ads::TopDockWidgetArea, "Top"};
        case 1: return {ads::BottomDockWidgetArea, "Bottom"};
        case 2: return {ads::LeftDockWidgetArea, "Left"};
        case 3: return {ads::RightDockWidgetArea, "Right"};
        case 4: return {ads::NoDockWidgetArea, "Window"};
        default: return {ads::CenterDockWidgetArea, "Stack"};
    }
}

const char* viewName(uint8_t kind) {
    switch (kind) {
        case 0: return "table";
        case 1: return "tree";
        case 2: return "text";
        case 3: return "form";
        case 4: return "listing";
        default: return "custom";
    }
}
}  // namespace

MainWindow::MainWindow(const QString& title, QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(title);
    resize(1200, 800);
    statusBar();
    // Config flags must be set before the dock manager is created.
    ads::CDockManager::setConfigFlag(ads::CDockManager::OpaqueSplitterResize, true);
    m_dockManager = new ads::CDockManager(this);
    buildDocks();
}

void MainWindow::buildDocks() {
    rust::Vec<uint64_t> ids;
    if (!bridgeCall(statusBar(), [&] { ids = provider_ids(); })) return;
    QMap<int, ads::CDockAreaWidget*> areas;  // one area per placement; later docks tab into it
    for (uint64_t pid : ids) {
        ProviderInfo info;
        if (!bridgeCall(statusBar(), [&] { info = provider_info(pid); })) continue;
        auto* dock = new ads::CDockWidget(m_dockManager, qs(info.title));
        dock->setWidget(createProviderView(pid, info.kind, statusBar(), dock));
        const Placement p = placementFor(info.position);
        m_providers.insert(dock, static_cast<int64_t>(pid));
        m_areaNames.insert(dock, QString::fromLatin1(p.name));
        m_viewNames.insert(dock, QString::fromLatin1(viewName(info.kind)));
        if (p.area == ads::NoDockWidgetArea) {
            m_dockManager->addDockWidgetFloating(dock);
        } else if (areas.contains(p.area)) {
            m_dockManager->addDockWidgetTabToArea(dock, areas.value(p.area));
        } else {
            areas.insert(p.area, m_dockManager->addDockWidget(p.area, dock));
        }
        if (!info.visible) dock->toggleView(false);
    }
}

QStringList MainWindow::dockSummary() const {
    QStringList out;
    for (auto it = m_providers.constBegin(); it != m_providers.constEnd(); ++it) {
        out << QStringLiteral("%1\t%2\t%3").arg(it.key()->windowTitle(), m_areaNames.value(it.key()), m_viewNames.value(it.key()));
    }
    return out;
}

bool MainWindow::restoreDockGeometry(const QByteArray& state) {
    if (state.isEmpty()) return false;
    return m_dockManager->restoreState(state);
}

ads::CDockWidget* MainWindow::dockByTitle(const QString& title) const {
    for (auto it = m_providers.constBegin(); it != m_providers.constEnd(); ++it) {
        if (it.key()->windowTitle() == title) return it.key();
    }
    return nullptr;
}

int64_t MainWindow::providerOf(ads::CDockWidget* dock) const { return m_providers.value(dock, -1); }

void MainWindow::closeEvent(QCloseEvent* event) {
    const QByteArray state = m_dockManager->saveState();
    bridgeCall(statusBar(), [&] {
        set_layout_geometry(rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(state.constData()),
                                                       static_cast<size_t>(state.size())));
    });
    QMainWindow::closeEvent(event);
}

}  // namespace ghidra_qt
