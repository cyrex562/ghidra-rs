#include "ghidra-qt/cpp/action_bridge.h"

#include <QAction>
#include <QMenu>
#include <QMenuBar>
#include <QStatusBar>
#include <QToolBar>
#include <QVector>

#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString qs(const rust::String& s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }

// "Copy" + mnemonic 'C' -> "&Copy"; literal '&' doubled.
QString withMnemonic(QString text, uint32_t mnemonic) {
    text.replace(QStringLiteral("&"), QStringLiteral("&&"));
    if (mnemonic == 0) return text;
    const int i = text.indexOf(QChar(mnemonic));
    if (i >= 0) text.insert(i, QLatin1Char('&'));
    return text;
}

QAction* makeItem(const MenuItemInfo& m, QObject* parent, QStatusBar* status, const FocusedProvider& focused) {
    QString text = withMnemonic(qs(m.text), m.mnemonic);
    // Shortcut text is display-only: keys are dispatched by Rust, never by
    // Qt shortcuts (spec §4), so no QAction::setShortcut.
    if (!m.key_text.empty()) text += QLatin1Char('\t') + qs(m.key_text);
    auto* a = new QAction(text, parent);
    a->setEnabled(m.enabled);
    a->setCheckable(m.checkable);
    a->setChecked(m.checked);
    const uint64_t id = m.action;
    QObject::connect(a, &QAction::triggered, a, [id, status, focused] {
        bridgeCall(status, [&] { invoke_action(id, focused ? focused() : -1); });
    });
    return a;
}

// Fills `root` (a QMenuBar or QMenu) from a flattened depth-first list.
template <class Root>
void fill(Root* root, const rust::Vec<MenuItemInfo>& items, QStatusBar* status, const FocusedProvider& focused) {
    QVector<QMenu*> stack;  // stack[d] = menu at depth d+1
    for (const MenuItemInfo& m : items) {
        stack.resize(static_cast<int>(m.depth));
        QWidget* parent = stack.isEmpty() ? static_cast<QWidget*>(root) : stack.last();
        auto addAction = [&](QAction* a) {
            if (stack.isEmpty()) root->addAction(a); else stack.last()->addAction(a);
        };
        if (m.kind == 0) {
            auto* sub = new QMenu(withMnemonic(qs(m.text), m.mnemonic), parent);
            addAction(sub->menuAction());
            stack.append(sub);
        } else if (m.kind == 1) {
            addAction(makeItem(m, parent, status, focused));
        } else {
            if (stack.isEmpty()) continue;
            stack.last()->addSeparator();
        }
    }
}

void dumpMenu(const QList<QAction*>& actions, int depth, QStringList& out) {
    for (QAction* a : actions) {
        const QString indent(depth * 2, QLatin1Char(' '));
        if (a->isSeparator()) {
            out << indent + QStringLiteral("-");
            continue;
        }
        QString text = a->text();
        text.replace(QStringLiteral("&&"), QStringLiteral("\x01")).remove(QLatin1Char('&')).replace(QStringLiteral("\x01"), QStringLiteral("&"));
        out << indent + (a->isEnabled() ? QString() : QStringLiteral("[x] ")) + text;
        if (QMenu* sub = a->menu()) dumpMenu(sub->actions(), depth + 1, out);
    }
}
}  // namespace

void rebuildMenuBar(QMenuBar* bar, QStatusBar* status, const FocusedProvider& focused) {
    bar->clear();
    rust::Vec<MenuItemInfo> items;
    if (!bridgeCall(status, [&] { items = menu_bar(focused ? focused() : -1); })) return;
    fill(bar, items, status, focused);
}

void rebuildToolBar(QToolBar* toolbar, QStatusBar* status, const FocusedProvider& focused) {
    toolbar->clear();
    rust::Vec<ToolBarInfo> items;
    if (!bridgeCall(status, [&] { items = tool_bar(focused ? focused() : -1); })) return;
    for (const ToolBarInfo& t : items) {
        if (t.kind == 1) {
            toolbar->addSeparator();
            continue;
        }
        // Theme icons are resolved in a later milestone; show the name.
        auto* a = toolbar->addAction(qs(t.tooltip));
        a->setToolTip(qs(t.tooltip));
        a->setEnabled(t.enabled);
        const uint64_t id = t.action;
        QObject::connect(a, &QAction::triggered, a, [id, status, focused] {
            bridgeCall(status, [&] { invoke_action(id, focused ? focused() : -1); });
        });
    }
}

QMenu* buildPopup(uint64_t pid, QWidget* parent, QStatusBar* status) {
    auto* menu = new QMenu(parent);
    rust::Vec<MenuItemInfo> items;
    if (!bridgeCall(status, [&] { items = popup_menu(pid); })) return menu;
    const int64_t p = static_cast<int64_t>(pid);
    fill(menu, items, status, [p] { return p; });
    return menu;
}

QStringList dumpMenuBar(QMenuBar* bar) {
    QStringList out;
    dumpMenu(bar->actions(), 0, out);
    return out;
}

}  // namespace ghidra_qt
