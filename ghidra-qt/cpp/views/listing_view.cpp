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
}  // namespace

ListingView::ListingView(uint64_t pid, QStatusBar* status, QWidget* parent)
    : QAbstractScrollArea(parent), m_pid(pid), m_status(status) {
    setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    setFocusPolicy(Qt::StrongFocus);
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

void ListingView::changeEvent(QEvent* event) {
    QAbstractScrollArea::changeEvent(event);
    if (event->type() == QEvent::FontChange || event->type() == QEvent::StyleChange) {
        // Rows are laid out in Rust from these metrics; the top index stays put.
        reportMetrics();
        setTop(m_top);
    }
}

void ListingView::setTop(const QString& top) {
    m_top = top;
    syncScrollBar();
    viewport()->update();
}

void ListingView::syncScrollBar() {
    ScrollbarInfo sb{0, 1};
    int value = 0;
    const QByteArray t = m_top.toUtf8();
    const int vp = viewport()->height();
    if (!bridgeCall(m_status, [&] {
            sb = listing_scrollbar(m_pid, vp);
            value = listing_value_for_top(m_pid, rs(t), vp);
        }))
        return;
    m_syncing = true;
    verticalScrollBar()->setRange(0, sb.max);
    verticalScrollBar()->setPageStep(sb.page_step);
    verticalScrollBar()->setSingleStep(1);
    verticalScrollBar()->setValue(value);
    m_syncing = false;
}

void ListingView::scrollContentsBy(int, int) {
    if (m_syncing) return;
    QString top;
    const int value = verticalScrollBar()->value();
    if (bridgeCall(m_status, [&] { top = qs(listing_top_for_value(m_pid, value, viewport()->height())); })) {
        m_top = top;
        viewport()->update();
    }
}

void ListingView::wheelEvent(QWheelEvent* event) {
    const int steps = -event->angleDelta().y() / 40;  // ~3 rows per notch
    QString top;
    const QByteArray t = m_top.toUtf8();
    if (bridgeCall(m_status, [&] { top = qs(listing_scroll(m_pid, rs(t), steps, viewport()->height())); })) setTop(top);
    event->accept();
}

void ListingView::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    // A taller viewport lowers the maximum top; re-clamp and resync.
    QString top;
    const QByteArray t = m_top.toUtf8();
    if (bridgeCall(m_status, [&] { top = qs(listing_scroll(m_pid, rs(t), 0, viewport()->height())); })) setTop(top);
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
    CursorInfo c;
    const QByteArray t = m_top.toUtf8();
    const int x = static_cast<int>(event->position().x()) - 4;
    const int y = static_cast<int>(event->position().y());
    if (bridgeCall(m_status, [&] { c = listing_hit(m_pid, rs(t), x, y, viewport()->height()); }) && c.valid) {
        m_cursorIndex = qs(c.index);
        m_cursorField = c.field;
        m_cursorCol = c.col;
        viewport()->update();
    }
}

void ListingView::ensureCursorVisible() {
    QString top;
    const QByteArray t = m_top.toUtf8();
    const QByteArray c = m_cursorIndex.toUtf8();
    if (bridgeCall(m_status, [&] { top = qs(listing_ensure_visible(m_pid, rs(t), rs(c), viewport()->height())); })) setTop(top);
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
    if (bridgeCall(m_status, [&] { next = listing_move(m_pid, std::move(cur), dir, viewport()->height()); }) && next.valid) {
        m_cursorIndex = qs(next.index);
        m_cursorField = next.field;
        m_cursorCol = next.col;
        ensureCursorVisible();
    }
    event->accept();
}

void ListingView::scrollRows(int64_t delta) {
    QString top;
    const QByteArray t = m_top.toUtf8();
    if (bridgeCall(m_status, [&] { top = qs(listing_scroll(m_pid, rs(t), delta, viewport()->height())); })) setTop(top);
}

QString ListingView::firstRowSummary() {
    rust::Vec<RowInfo> rows;
    const QByteArray t = m_top.toUtf8();
    if (!bridgeCall(m_status, [&] { rows = listing_rows(m_pid, rs(t), 1); }) || rows.empty()) return {};
    QStringList xs;
    for (const RunPosInfo& run : rows[0].runs) xs << QString::number(run.x);
    return qs(rows[0].index) + QStringLiteral(": ") + xs.join(QLatin1Char(' '));
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
