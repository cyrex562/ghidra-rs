#pragma once
// Custom-painted code listing (spec §5). Rust computes every row's layout
// from the font metrics this view reports; the view only paints the
// positioned runs and forwards scrolling, clicks and cursor keys. Indices
// are u128 decimal strings; all index arithmetic happens in Rust.
#include <QAbstractScrollArea>
#include <QString>
#include <QStringList>
#include <cstdint>

class QStatusBar;

namespace ghidra_qt {

class ListingView : public QAbstractScrollArea {
public:
    ListingView(uint64_t pid, QStatusBar* status, QWidget* parent = nullptr);
    // Text of the first n rows as painted ("a  b  c  d"), for smoke tests.
    QStringList dumpRows(int n);
    // Scroll by delta rows as the wheel does (smoke tests).
    void scrollRows(int64_t delta);
    // "index: x0 x1 ..." of the first painted row (smoke tests).
    QString firstRowSummary();

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void scrollContentsBy(int dx, int dy) override;
    void changeEvent(QEvent* event) override;

private:
    void reportMetrics();
    void setTop(const QString& top);
    void syncScrollBar();
    void ensureCursorVisible();

    uint64_t m_pid;
    QStatusBar* m_status;
    QString m_top = QStringLiteral("0");
    QString m_cursorIndex;
    uint32_t m_cursorField = 0;
    uint32_t m_cursorCol = 0;
    bool m_syncing = false;
};

}  // namespace ghidra_qt
