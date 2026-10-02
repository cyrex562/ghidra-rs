#include "ghidra-qt/cpp/app.h"

#include <QApplication>
#include <QPixmap>
#include <QString>
#include <QTimer>
#include <cstdio>

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
    window.show();

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
