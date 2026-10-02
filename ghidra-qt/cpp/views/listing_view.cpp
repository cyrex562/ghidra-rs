#include "ghidra-qt/cpp/views/listing_view.h"

#include <QFontDatabase>
#include <QFontMetrics>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QScrollBar>
#include <QStatusBar>
#include <QWheelEvent>

#include "ghidra-qt/cpp/bridge_call.h"
#include "ghidra-qt/src/bridge.rs.h"

namespace ghidra_qt {
namespace {
QString qs(const rust::String& s) { return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size())); }
rust::Str rs(const QByteArray& b) { return rust::Str(b.constData(), static_cast<size_t>(b.size())); }
constexpr int kScrollRange = 1000000;
}  // namespace

ListingView::ListingView(uint64_t pid, QStatusBar* status, QWidget* parent)
    : QAbstractScrollArea(parent), m_pid(pid), m_status(status) {
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setFocusPolicy(Qt::StrongFocus);
    verticalScrollBar()->setRange(0, kScrollRange);
    reportMetrics();
}

void ListingView::reportMetrics() {
    const QFontMetrics fm(font());
    QFont bold = font();
    bold.setBold(true);
    const QFontMetrics fmb(bold);
    MetricsInfo m{fm.horizontalAdvance(QLatin1Char('0')), fmb.horizontalAdvance(QLatin1Char('0')), fm.ascent(),
                  fm.descent(), fm.leading()};
    bridgeCall(m_status, [&] { listing_set_metrics(m_pid, m); });
}

int ListingView::pageRows() const {
    const int h = QFontMetrics(font()).height();
    return h > 0 ? qMax(1, viewport()->height() / h) : 1;
}

void ListingView::setTop(const QString& top) {
    m_top = top;
    syncScrollBar();
    viewport()->update();
}

void ListingView::syncScrollBar() {
    double f = 0;
    const QByteArray t = m_top.toUtf8();
    bridgeCall(m_status, [&] { f = listing_fraction(m_pid, rs(t)); });
    m_syncing = true;
    verticalScrollBar()->setValue(static_cast<int>(f * kScrollRange));
    m_syncing = false;
}

void ListingView::scrollContentsBy(int, int) {
    if (m_syncing) return;
    QString top;
    const double f = static_cast<double>(verticalScrollBar()->value()) / kScrollRange;
    if (bridgeCall(m_status, [&] { top = qs(listing_top_for_fraction(m_pid, f)); })) {
        m_top = top;
        viewport()->update();
    }
}

void ListingView::wheelEvent(QWheelEvent* event) {
    const int steps = -event->angleDelta().y() / 40;  // ~3 rows per notch
    QString top;
    const QByteArray t = m_top.toUtf8();
    if (bridgeCall(m_status, [&] { top = qs(listing_scroll(m_pid, rs(t), steps)); })) setTop(top);
    event->accept();
}

void ListingView::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    viewport()->update();
}

void ListingView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.fillRect(viewport()->rect(), palette().base());
    p.setFont(font());
    rust::Vec<RowInfo> rows;
    const QByteArray t = m_top.toUtf8();
    if (!bridgeCall(m_status, [&] { rows = listing_rows(m_pid, rs(t), viewport()->height()); })) return;
    const int ascent = QFontMetrics(font()).ascent();
    for (const RowInfo& row : rows) {
        if (qs(row.index) == m_cursorIndex) {
            p.fillRect(QRect(0, row.y, viewport()->width(), row.height), palette().alternateBase());
        }
        for (const RunPosInfo& run : row.runs) {
            QFont f = font();
            f.setBold(run.bold);
            p.setFont(f);
            p.setPen(palette().text().color());
            p.drawText(run.x + 4, row.y + ascent, qs(run.text));
        }
    }
}

void ListingView::mousePressEvent(QMouseEvent* event) {
    const int h = QFontMetrics(font()).height();
    if (h <= 0) return;
    QString index;
    const QByteArray t = m_top.toUtf8();
    if (!bridgeCall(m_status, [&] { index = qs(listing_scroll(m_pid, rs(t), event->position().y() / h)); })) return;
    CursorInfo c;
    const QByteArray ib = index.toUtf8();
    if (bridgeCall(m_status, [&] { c = listing_hit(m_pid, rs(ib), static_cast<int>(event->position().x()) - 4); }) && c.valid) {
        m_cursorIndex = qs(c.index);
        m_cursorField = c.field;
        m_cursorCol = c.col;
        viewport()->update();
    }
}

void ListingView::ensureCursorVisible() {
    // Keep the cursor row on screen: scroll so it sits at the top when it
    // left the viewport upward, or at the bottom when it left downward.
    double ft = 0, fc = 0;
    const QByteArray t = m_top.toUtf8();
    const QByteArray c = m_cursorIndex.toUtf8();
    bridgeCall(m_status, [&] {
        ft = listing_fraction(m_pid, rs(t));
        fc = listing_fraction(m_pid, rs(c));
    });
    QString bottomTop;
    bridgeCall(m_status, [&] { bottomTop = qs(listing_scroll(m_pid, rs(c), -(pageRows() - 1))); });
    if (fc < ft) {
        setTop(m_cursorIndex);
    } else {
        double fb = 0;
        const QByteArray bt = bottomTop.toUtf8();
        bridgeCall(m_status, [&] { fb = listing_fraction(m_pid, rs(bt)); });
        if (fb > ft) setTop(bottomTop);
    }
    viewport()->update();
}

void ListingView::keyPressEvent(QKeyEvent* event) {
    uint8_t dir;
    switch (event->key()) {
        case Qt::Key_Up: dir = 0; break;
        case Qt::Key_Down: dir = 1; break;
        case Qt::Key_Left: dir = 2; break;
        case Qt::Key_Right: dir = 3; break;
        case Qt::Key_PageUp: dir = 4; break;
        case Qt::Key_PageDown: dir = 5; break;
        case Qt::Key_Home: dir = 6; break;
        case Qt::Key_End: dir = 7; break;
        default: QAbstractScrollArea::keyPressEvent(event); return;
    }
    if (m_cursorIndex.isEmpty()) m_cursorIndex = m_top;
    const QByteArray ci = m_cursorIndex.toUtf8();
    CursorInfo cur{rust::String(ci.constData(), static_cast<size_t>(ci.size())), m_cursorField, m_cursorCol, true};
    CursorInfo next;
    if (bridgeCall(m_status, [&] { next = listing_move(m_pid, std::move(cur), dir, static_cast<uint32_t>(pageRows())); }) && next.valid) {
        m_cursorIndex = qs(next.index);
        m_cursorField = next.field;
        m_cursorCol = next.col;
        ensureCursorVisible();
    }
    event->accept();
}

QStringList ListingView::dumpRows(int n) {
    QStringList out;
    rust::Vec<RowInfo> rows;
    const int h = QFontMetrics(font()).height();
    const QByteArray t = m_top.toUtf8();
    if (!bridgeCall(m_status, [&] { rows = listing_rows(m_pid, rs(t), h * n); })) return out;
    for (const RowInfo& row : rows) {
        if (out.size() >= n) break;
        QStringList parts;
        for (const RunPosInfo& run : row.runs) parts << qs(run.text);
        out << parts.join(QStringLiteral("  "));
    }
    return out;
}

}  // namespace ghidra_qt
