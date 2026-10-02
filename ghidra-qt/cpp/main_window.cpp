#include "ghidra-qt/cpp/main_window.h"
#include "ghidra-qt/cpp/views/listing_view.h"

#include <algorithm>
#include <utility>
#include <vector>

#include <QAbstractItemView>
#include <QApplication>
#include <QCloseEvent>
#include <QContextMenuEvent>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QProgressBar>
#include <QTextEdit>
#include <QToolBar>
#include <QStatusBar>

#include "DockAreaWidget.h"
#include "DockManager.h"
#include "DockWidget.h"
#include "ghidra-qt/cpp/action_bridge.h"
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
    m_toolBar = addToolBar(QStringLiteral("Main"));
    m_toolBar->setObjectName(QStringLiteral("MainToolBar"));
    m_progress = new QProgressBar(this);
    m_progress->setMaximumWidth(200);
    m_progress->hide();
    statusBar()->addPermanentWidget(m_progress);
    buildDocks();
    installPopups();
    rebuildActions();
    connect(qApp, &QApplication::focusChanged, this, [this] { rebuildActions(); });
}

MainWindow::~MainWindow() { QObject::disconnect(qApp, nullptr, this, nullptr); }

int64_t MainWindow::providerOfObject(QObject* object) const {
    for (QObject* o = object; o; o = o->parent()) {
        if (auto* dock = qobject_cast<ads::CDockWidget*>(o)) return providerOf(dock);
    }
    return -1;
}

int64_t MainWindow::focusedProvider() const { return providerOfObject(QApplication::focusWidget()); }

void MainWindow::rebuildActions() {
    const FocusedProvider focused = [this] { return focusedProvider(); };
    rebuildMenuBar(menuBar(), statusBar(), focused);
    rebuildToolBar(m_toolBar, statusBar(), focused);
}

void MainWindow::showTaskProgress(const QString& message, uint64_t progress, uint64_t maximum) {
    if (message.isEmpty() && maximum == 0) {
        m_progress->hide();
        return;
    }
    m_progress->setRange(0, static_cast<int>(maximum));
    m_progress->setValue(static_cast<int>(progress));
    m_progress->setFormat(message + QStringLiteral(" %p%"));
    m_progress->show();
}

QStringList MainWindow::menuSummary() { return dumpMenuBar(menuBar()); }

void MainWindow::viewChanged(int64_t pid) {
    for (auto it = m_providers.cbegin(); it != m_providers.cend(); ++it) {
        if (it.value() != pid || !it.key()->widget()) continue;
        if (auto* listing = dynamic_cast<ListingView*>(it.key()->widget())) {
            listing->refresh();
        } else {
            it.key()->widget()->update();
        }
    }
}

void MainWindow::showProvider(int64_t pid, bool focus) {
    for (auto it = m_providers.cbegin(); it != m_providers.cend(); ++it) {
        if (it.value() != pid) continue;
        ads::CDockWidget* dock = it.key();
        if (dock->isClosed() && !dock->dockAreaWidget()) placeDock(dock, m_positions.value(dock));
        dock->toggleView(true);
        dock->setAsCurrentTab();
        dock->raise();
        // Java ShowComponentAction: showComponent(..., requestFocus = true)
        if (focus) focusDock(dock->windowTitle());
    }
}

bool MainWindow::focusDock(const QString& title) {
    ads::CDockWidget* dock = dockByTitle(title);
    if (!dock || !dock->widget()) return false;
    dock->toggleView(true);
    dock->setAsCurrentTab();
    // The provider's main view: the dock's widget itself when it is one (a
    // QTreeView's own children include its QHeaderView, which takes no focus),
    // else the first focusable view/editor inside it.
    QWidget* root = dock->widget();
    auto focusable = [](QWidget* w) { return w && w->focusPolicy() != Qt::NoFocus; };
    QWidget* target = nullptr;
    if ((qobject_cast<QAbstractItemView*>(root) || qobject_cast<QTextEdit*>(root)) && focusable(root)) target = root;
    for (QAbstractItemView* v : root->findChildren<QAbstractItemView*>()) {
        if (!target && focusable(v)) target = v;
    }
    for (QTextEdit* t : root->findChildren<QTextEdit*>()) {
        if (!target && focusable(t)) target = t;
    }
    for (QLineEdit* e : root->findChildren<QLineEdit*>()) {
        if (!target && focusable(e)) target = e;
    }
    if (!target) target = root;
    target->setFocus(Qt::OtherFocusReason);
    return true;
}

// Popups: a context-menu request inside a dock shows that provider's popup.
void MainWindow::installPopups() {
    for (auto it = m_providers.constBegin(); it != m_providers.constEnd(); ++it) {
        QWidget* content = it.key()->widget();
        if (!content) continue;
        const uint64_t pid = static_cast<uint64_t>(it.value());
        for (QWidget* w : content->findChildren<QWidget*>()) {
            w->setContextMenuPolicy(Qt::CustomContextMenu);
            connect(w, &QWidget::customContextMenuRequested, this, [this, w, pid](const QPoint& at) {
                QMenu* menu = buildPopup(pid, this, statusBar());
                if (!menu->isEmpty()) menu->exec(w->mapToGlobal(at));
                menu->deleteLater();
            });
        }
    }
}

void MainWindow::buildDocks() {
    rust::Vec<uint64_t> ids;
    if (!bridgeCall(statusBar(), [&] { ids = provider_ids(); })) return;
    std::vector<std::pair<uint64_t, ProviderInfo>> infos;
    for (uint64_t pid : ids) {
        ProviderInfo info;
        if (bridgeCall(statusBar(), [&] { info = provider_info(pid); })) infos.emplace_back(pid, std::move(info));
    }
    // ADS takes the central widget only as the first dock added.
    std::stable_partition(infos.begin(), infos.end(), [](const auto& p) { return p.second.central; });
    bool haveCentral = false;
    for (auto& [pid, info] : infos) {
        auto* dock = new ads::CDockWidget(m_dockManager, qs(info.title));
        dock->setWidget(createProviderView(pid, info.kind, statusBar(), dock));
        m_providers.insert(dock, static_cast<int64_t>(pid));
        m_positions.insert(dock, info.position);
        m_viewNames.insert(dock, QString::fromLatin1(viewName(info.kind)));
        if (info.central && !haveCentral && m_dockManager->setCentralWidget(dock)) {
            haveCentral = true;
            m_areaNames.insert(dock, QStringLiteral("Central"));
            continue;
        }
        m_areaNames.insert(dock, QString::fromLatin1(placementFor(info.position).name));
        placeDock(dock, info.position);
        if (!info.visible) dock->toggleView(false);
    }
}

// One area per placement; later docks with the same placement tab into it.
void MainWindow::placeDock(ads::CDockWidget* dock, uint8_t position) {
    const Placement p = placementFor(position);
    if (p.area == ads::NoDockWidgetArea) {
        m_dockManager->addDockWidgetFloating(dock);
        return;
    }
    ads::CDockAreaWidget* area = m_areas.value(p.area, nullptr);
    // isHidden, not isVisible: before the window is first shown nothing is
    // "visible", but an area emptied by closing its docks is explicitly hidden.
    if (area && area->dockManager() == m_dockManager && !area->isHidden()) {
        m_dockManager->addDockWidgetTabToArea(dock, area);
    } else {
        m_areas.insert(p.area, m_dockManager->addDockWidget(p.area, dock));
    }
}

void MainWindow::showDocksRustConsidersVisible() {
    m_areas.clear();  // areas may have been rebuilt by restoreState
    for (auto it = m_providers.constBegin(); it != m_providers.constEnd(); ++it) {
        ads::CDockWidget* dock = it.key();
        ProviderInfo info;
        if (!bridgeCall(statusBar(), [&] { info = provider_info(static_cast<uint64_t>(it.value())); })) continue;
        if (!info.visible || !dock->isClosed()) continue;
        if (!dock->dockAreaWidget()) {
            placeDock(dock, m_positions.value(dock));
        }
        dock->toggleView(true);
    }
}

QStringList MainWindow::dockSummary() const {
    QStringList out;
    for (auto it = m_providers.constBegin(); it != m_providers.constEnd(); ++it) {
        QString line = QStringLiteral("%1\t%2\t%3").arg(it.key()->windowTitle(), m_areaNames.value(it.key()), m_viewNames.value(it.key()));
        // Docks sharing one open area are tabs of it (Ghidra stacks same-position providers).
        if (auto* area = it.key()->dockAreaWidget(); area && area->openDockWidgetsCount() > 1) line += QStringLiteral("\ttabbed");
        if (it.key()->isClosed()) line += QStringLiteral("\tclosed");
        out << line;
    }
    return out;
}

bool MainWindow::restoreDockGeometry(const QByteArray& state) {
    const bool ok = !state.isEmpty() && m_dockManager->restoreState(state);
    showDocksRustConsidersVisible();
    return ok;
}

ads::CDockWidget* MainWindow::dockByTitle(const QString& title) const {
    for (auto it = m_providers.constBegin(); it != m_providers.constEnd(); ++it) {
        if (it.key()->windowTitle() == title) return it.key();
    }
    return nullptr;
}

int64_t MainWindow::providerOf(ads::CDockWidget* dock) const { return m_providers.value(dock, -1); }

void MainWindow::saveLayout() {
    m_layoutSaved = true;
    const QByteArray state = m_dockManager->saveState();
    bridgeCall(statusBar(), [&] {
        set_layout_geometry(rust::Slice<const uint8_t>(reinterpret_cast<const uint8_t*>(state.constData()),
                                                       static_cast<size_t>(state.size())));
    });
    bridgeCall(statusBar(), [&] { save_tool_config(); });
}

void MainWindow::closeEvent(QCloseEvent* event) {
    saveLayout();
    QMainWindow::closeEvent(event);
}

}  // namespace ghidra_qt
