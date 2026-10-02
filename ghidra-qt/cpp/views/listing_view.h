#pragma once
// Custom-painted code listing (spec §5). All listing state (top row, cursor,
// selection, highlight, history) lives in the Rust ListingController; this
// view reports font metrics and viewport size, forwards input as intents,
// and paints the frame Rust returns.
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
    // "top=<i> cursor=<addr> selected=<n>" (smoke tests).
    QString stateSummary();
    // Sends a listing intent (see the bridge's listing_intent) and refreshes.
    void intent(uint8_t kind, int64_t a, int64_t b, bool extend);
    // Re-pulls the frame: scrollbar, repaint, and (when `announce`) the
    // cursor location in the status bar.
    void refresh(bool announce = true);

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void keyPressEvent(QKeyEvent* event) override;
    void scrollContentsBy(int dx, int dy) override;
    void changeEvent(QEvent* event) override;

private:
    void reportMetrics();
    void reportViewport();
    void ensureViewportRows(int n);

    uint64_t m_pid;
    QStatusBar* m_status;
    bool m_syncing = false;
    int m_wheelRemainder = 0;
};

}  // namespace ghidra_qt
