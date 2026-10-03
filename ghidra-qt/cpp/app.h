#pragma once
#include "rust/cxx.h"
#include <cstdint>

namespace ghidra_qt {
struct UiSession;
struct AppOptions;

// Creates the QApplication and main window and runs the event loop. Returns the
// process exit code: 0 ok, 2 screenshot write failed, 3 bridge error.
int32_t run_app(const UiSession& session, const AppOptions& options);
}  // namespace ghidra_qt
