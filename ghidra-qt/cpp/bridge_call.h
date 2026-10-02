#pragma once
// The one place C++ catches Rust bridge errors. Every call from a Qt slot,
// model or event handler into Rust goes through bridgeCall, so a rust::Error
// (a Rust Err or a panic converted by guard()) never escapes into Qt's event
// loop (U0 review M2). The error is shown in the status bar and logged.
#include <QStatusBar>
#include <QString>
#include <cstdio>
#include <utility>

#include "rust/cxx.h"

namespace ghidra_qt {

template <class F>
bool bridgeCall(QStatusBar* status, F&& f) {
    try {
        std::forward<F>(f)();
        return true;
    } catch (const rust::Error& e) {
        std::fprintf(stderr, "ghidra-qt: %s\n", e.what());
        if (status) {
            status->showMessage(QString::fromUtf8(e.what()), 5000);
        }
        return false;
    }
}

}  // namespace ghidra_qt
