#include "ghidra-qt/cpp/app.h"

#include <QApplication>
#include <QMenu>
#include <QMenuBar>
#include <functional>
#include <QClipboard>
#include <QGuiApplication>
#include <QPalette>
#include <QFont>
#include <QFile>
#include <QPixmap>
#include <QString>
#include <QStringList>
#include <QKeyEvent>
#include <QKeySequence>
#include <QTimer>
#include <cstdio>
#include <memory>

#include "DockWidget.h"
#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/cpp/input.h"
#include "ghidra-qt/cpp/main_window.h"
#include "ghidra-qt/cpp/views/listing_view.h"
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

    // Restore the tool config (provider visibility/placement + geometry)
    // before docks are built; a corrupt file is reported and ignored.
    bridgeCall(nullptr, [&] { load_tool_config(); });
    MainWindow window(title);

    // Geometry: an explicit file (tests) or the layout saved in the tool config.
    if (!options.restore_geometry.empty()) {
        QFile f(toQString(options.restore_geometry));
        if (f.open(QIODevice::ReadOnly)) window.restoreDockGeometry(f.readAll());
    } else {
        rust::Vec<uint8_t> saved;
        if (bridgeCall(window.statusBar(), [&] { saved = layout_geometry(); }) && !saved.empty()) {
            window.restoreDockGeometry(QByteArray(reinterpret_cast<const char*>(saved.data()), static_cast<int>(saved.size())));
        }
    }

    if (options.dump_menus) {
        for (const QString& line : window.menuSummary()) std::printf("%s\n", line.toUtf8().constData());
        std::fflush(stdout);
        return 0;
    }
    if (options.dump_docks) {
        for (const QString& line : window.dockSummary()) std::printf("%s\n", line.toUtf8().constData());
        std::fflush(stdout);
        return 0;
    }
    if (options.dump_listing > 0) {
        ads::CDockWidget* dock = window.dockByTitle(QStringLiteral("Listing"));
        auto* view = dock ? dynamic_cast<ListingView*>(dock->widget()) : nullptr;
        if (!view) return 5;
        for (const QString& line : view->dumpRows(static_cast<int>(options.dump_listing))) std::printf("%s\n", line.toUtf8().constData());
        std::fflush(stdout);
        return 0;
    }
    if (options.listing_font_change) {
        ads::CDockWidget* dock = window.dockByTitle(QStringLiteral("Listing"));
        auto* view = dock ? dynamic_cast<ListingView*>(dock->widget()) : nullptr;
        if (!view) return 5;
        view->scrollRows(3);
        std::printf("%s\n", view->firstRowSummary().toUtf8().constData());
        QFont f = view->font();
        f.setPointSizeF(f.pointSizeF() * 2);
        view->setFont(f);
        std::printf("%s\n", view->firstRowSummary().toUtf8().constData());
        std::fflush(stdout);
        return 0;
    }
    if (options.count_after_rebuilds > 0) {
        for (uint32_t i = 0; i < options.count_after_rebuilds; ++i) {
            window.rebuildActions();
            QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        }
        std::printf("%lld\n", static_cast<long long>(window.findChildren<QObject*>().size()));
        std::fflush(stdout);
        return 0;
    }

    auto* keys = new KeyForwarder(&window);
    app.installEventFilter(keys);
    auto* pump = new EventPump(&window, !options.press.empty());
    if (options.has_prompt_answer) pump->setPromptAnswer(toQString(options.prompt_answer));
    pump->pump();  // apply startup events (theme, restored state) before the first paint
    window.show();
    if (!options.float_dock.empty()) {
        if (ads::CDockWidget* d = window.dockByTitle(toQString(options.float_dock))) d->setFloating();
    }

    if (!options.press.empty()) {
        const QString focus = toQString(options.focus);
        QString press = toQString(options.press);
        // A comma-separated key sequence ("Shift-Down,Shift-Down"), each key
        // posted once focus is in the dock, 250ms apart.
        const QStringList keys = press.split(QLatin1Char(','), Qt::SkipEmptyParts);
        QTimer::singleShot(200, &window, [&window, focus, keys, pump] {
            window.focusDock(focus);
            auto* poll = new QTimer(&window);
            auto deadline = std::make_shared<int>(150);  // x20ms = 3s
            QObject::connect(poll, &QTimer::timeout, &window, [&window, focus, keys, pump, poll, deadline] {
                ads::CDockWidget* dock = window.dockByTitle(focus);
                QWidget* fw = QApplication::focusWidget();
                const bool landed = !dock || (fw && dock->widget() && dock->widget()->isAncestorOf(fw)) ||
                                    (fw && fw == dock->widget());
                if (!landed && --*deadline > 0) {
                    if (*deadline % 10 == 0) window.focusDock(focus);
                    return;
                }
                poll->stop();
                poll->deleteLater();
                if (!landed) std::fprintf(stderr, "ghidra-qt: focus never reached %s\n", focus.toUtf8().constData());
                for (int i = 0; i < keys.size(); ++i) {
                    const QString key = keys[i];
                    QTimer::singleShot(250 * i, &window, [&window, key, pump] {
                        QWidget* target = QApplication::focusWidget();
                        if (!target) target = &window;
                        const QKeySequence seq = QKeySequence::fromString(QString(key).replace(QLatin1Char('-'), QLatin1Char('+')));
                        if (seq.isEmpty()) return;
                        const QKeyCombination combo = seq[0];
                        // Printable unmodified keys carry text so line edits receive them.
                        const bool printable = combo.key() < 0x7f && !(combo.keyboardModifiers() & (Qt::ControlModifier | Qt::AltModifier));
                        const QString text = printable ? QString(QChar(static_cast<char16_t>(combo.key()))).toLower() : QString();
                        QApplication::postEvent(target, new QKeyEvent(QEvent::KeyPress, combo.key(), combo.keyboardModifiers(), text));
                        QTimer::singleShot(100, pump, [pump] { pump->pump(); });
                    });
                }
            });
            poll->start(20);
        });
    }

    if (!options.invoke_menu.empty()) {
        const QString text = toQString(options.invoke_menu);
        QTimer::singleShot(200, &window, [&window, text, pump] {
            std::function<bool(const QList<QAction*>&)> find = [&](const QList<QAction*>& actions) {
                for (QAction* a : actions) {
                    if (a->menu() && find(a->menu()->actions())) return true;
                    if (!a->menu() && QString(a->text()).remove(QLatin1Char('&')).section(QLatin1Char('\t'), 0, 0) == text) {
                        a->trigger();
                        return true;
                    }
                }
                return false;
            };
            if (!find(window.menuBar()->actions())) std::fprintf(stderr, "ghidra-qt: no menu item %s\n", text.toUtf8().constData());
            QTimer::singleShot(100, pump, [pump] { pump->pump(); });
        });
    }
    if (options.invoke_missing_action) {
        QTimer::singleShot(100, &window, [&window] {
            bridgeCall(window.statusBar(), [&] { invoke_action(0xFFFFFFFFull, -1); });
        });
    }

    if (options.quit_after_ms > 0) {
        const QString shot = toQString(options.screenshot_path);
        const bool printListing = options.print_listing_state;
        const bool printClipboard = options.print_clipboard;
        const bool printPalette = options.print_palette;
        QTimer::singleShot(static_cast<int>(options.quit_after_ms), &app, [&app, &window, shot, printListing, printClipboard, printPalette]() {
            if (printPalette) {
                std::printf("palette: base=%s\n", QApplication::palette().color(QPalette::Base).name().toUtf8().constData());
                std::fflush(stdout);
            }
            if (printClipboard) {
                for (const QString& line : QGuiApplication::clipboard()->text().split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
                    std::printf("clipboard: %s\n", line.toUtf8().constData());
                }
                std::fflush(stdout);
            }
            if (printListing) {
                ads::CDockWidget* dock = window.dockByTitle(QStringLiteral("Listing"));
                auto* view = dock ? dynamic_cast<ListingView*>(dock->widget()) : nullptr;
                std::printf("%s\n", view ? view->stateSummary().toUtf8().constData() : "no listing");
                std::fflush(stdout);
            }
            if (!shot.isEmpty() && !window.grab().save(shot, "PNG")) {
                std::fprintf(stderr, "ghidra-qt: could not write screenshot to %s\n",
                             shot.toUtf8().constData());
                app.exit(2);
                return;
            }
            app.exit(0);
        });
    }
    const int code = app.exec();
    if (!window.layoutSaved()) window.saveLayout();  // app.exit() skips closeEvent
    return code;
}

}  // namespace ghidra_qt
