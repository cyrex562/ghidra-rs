#pragma once
// Renders Rust-ordered menus/toolbars/popups (ghidra_ui_model::menus) as Qt
// widgets and forwards activations back to Rust. Ordering, grouping,
// separators and enablement are decided in Rust; this file only draws them.
#include <QObject>
#include <QStringList>
#include <cstdint>
#include <functional>

class QMainWindow;
class QMenu;
class QMenuBar;
class QStatusBar;
class QToolBar;
class QWidget;

namespace ghidra_qt {

using FocusedProvider = std::function<int64_t()>;

/// Rebuilds `bar` from `menu_bar(focused)`.
void rebuildMenuBar(QMenuBar* bar, QStatusBar* status, const FocusedProvider& focused);
/// Rebuilds `toolbar` from `tool_bar(focused)`.
void rebuildToolBar(QToolBar* toolbar, QStatusBar* status, const FocusedProvider& focused);
/// A popup for provider `pid` (caller owns it).
QMenu* buildPopup(uint64_t pid, QWidget* parent, QStatusBar* status);
/// The built menu bar as text: two spaces per depth, "-" separators, "[x] " disabled.
QStringList dumpMenuBar(QMenuBar* bar);

}  // namespace ghidra_qt
