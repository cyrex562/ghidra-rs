#include "ghidra-qt/cpp/main_window.h"

#include <QLabel>

#include "DockManager.h"
#include "DockWidget.h"

namespace ghidra_qt {

MainWindow::MainWindow(const QString& title, QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(title);
    resize(1200, 800);
    // Config flags must be set before the dock manager is created.
    ads::CDockManager::setConfigFlag(ads::CDockManager::OpaqueSplitterResize, true);
    m_dockManager = new ads::CDockManager(this);

    auto* label = new QLabel(QStringLiteral("%1 — Qt shell scaffold").arg(title));
    label->setAlignment(Qt::AlignCenter);
    auto* dock = new ads::CDockWidget(m_dockManager, QStringLiteral("Welcome"));
    dock->setWidget(label);
    m_dockManager->addDockWidget(ads::CenterDockWidgetArea, dock);
}

}  // namespace ghidra_qt
