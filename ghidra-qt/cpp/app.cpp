#include "ghidra-qt/cpp/app.h"

#include <QApplication>
#include <QFile>
#include <QPixmap>
#include <QString>
#include <QKeyEvent>
#include <QKeySequence>
#include <QTimer>
#include <cstdio>

#include "DockWidget.h"
#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/cpp/input.h"
#include "ghidra-qt/cpp/main_window.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString toQString(const rust::String& s) {
    return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size()));
}
}  // namespace

int32_t run_app(const UiSession& session, const AppOptions& options) {
    static int argc = 1;
    static char arg0[] = "ghidra-qt";
    static char* argv[] = {arg0, nullptr};
    QApplication app(argc, argv);

    QString title;
    try {
        title = toQString(session_title(session));
    } catch (const rust::Error& e) {
        std::fprintf(stderr, "ghidra-qt: %s\n", e.what());
        return 3;
    }

    MainWindow window(title);

    if (options.dump_menus) {
        for (const QString& line : window.menuSummary()) std::printf("%s\n", line.toUtf8().constData());
        std::fflush(stdout);
        return 0;
    }

    if (options.dump_docks) {
        if (!options.restore_geometry.empty()) {
            QFile f(toQString(options.restore_geometry));
            if (f.open(QIODevice::ReadOnly)) window.restoreDockGeometry(f.readAll());
        }
        for (const QString& line : window.dockSummary()) std::printf("%s\n", line.toUtf8().constData());
        std::fflush(stdout);
        return 0;
    }

    if (!options.restore_geometry.empty()) {
        QFile f(toQString(options.restore_geometry));
        if (f.open(QIODevice::ReadOnly)) window.restoreDockGeometry(f.readAll());
    }
    auto* keys = new KeyForwarder(&window);
    app.installEventFilter(keys);
    auto* pump = new EventPump(&window, !options.press.empty());
    window.show();

    if (!options.press.empty()) {
        const QString focus = toQString(options.focus);
        QString press = toQString(options.press);
        QTimer::singleShot(200, &window, [&window, focus, press, pump] {
            window.focusDock(focus);
            QWidget* target = QApplication::focusWidget();
            if (!target) target = window.dockByTitle(focus) ? window.dockByTitle(focus)->widget() : &window;
            const QKeySequence seq = QKeySequence::fromString(QString(press).replace(QLatin1Char('-'), QLatin1Char('+')));
            if (seq.isEmpty()) return;
            const QKeyCombination combo = seq[0];
            QApplication::postEvent(target, new QKeyEvent(QEvent::KeyPress, combo.key(), combo.keyboardModifiers()));
            QTimer::singleShot(300, pump, [pump] { pump->pump(); });
        });
    }

    if (options.invoke_missing_action) {
        QTimer::singleShot(100, &window, [&window] {
            bridgeCall(window.statusBar(), [&] { invoke_action(0xFFFFFFFFull, -1); });
        });
    }

    if (options.quit_after_ms > 0) {
        const QString shot = toQString(options.screenshot_path);
        QTimer::singleShot(static_cast<int>(options.quit_after_ms), &app, [&app, &window, shot]() {
            if (!shot.isEmpty() && !window.grab().save(shot, "PNG")) {
                std::fprintf(stderr, "ghidra-qt: could not write screenshot to %s\n",
                             shot.toUtf8().constData());
                app.exit(2);
                return;
            }
            app.exit(0);
        });
    }
    return app.exec();
}

}  // namespace ghidra_qt
