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
constexpr int kTextInset = 4;  // left margin before the first field
constexpr uint8_t kKey = 0, kClick = 1, kMiddle = 2, kWheel = 3, kScrollValue = 4;
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

void ListingView::reportViewport() {
    const int h = viewport()->height();
    bridgeCall(m_status, [&] { listing_set_viewport(m_pid, h); });
}

void ListingView::changeEvent(QEvent* event) {
    QAbstractScrollArea::changeEvent(event);
    if (event->type() == QEvent::FontChange || event->type() == QEvent::StyleChange) {
        // Rows are laid out in Rust from these metrics; the top row stays put.
        reportMetrics();
        refresh(false);
    }
}

void ListingView::refresh(bool announce) {
    FrameInfo f;
    if (!bridgeCall(m_status, [&] { f = listing_frame(m_pid); })) return;
    m_syncing = true;
    verticalScrollBar()->setRange(0, f.scroll_max);
    verticalScrollBar()->setPageStep(f.scroll_page);
    verticalScrollBar()->setSingleStep(1);
    verticalScrollBar()->setValue(f.scroll_value);
    m_syncing = false;
    if (announce && !f.location.empty()) m_status->showMessage(qs(f.location));
    viewport()->update();
}

void ListingView::intent(uint8_t kind, int64_t a, int64_t b, bool extend) {
    if (bridgeCall(m_status, [&] { listing_intent(m_pid, kind, a, b, extend); })) refresh();
}

void ListingView::scrollContentsBy(int, int) {
    if (!m_syncing) intent(kScrollValue, verticalScrollBar()->value(), 0, false);
}

void ListingView::wheelEvent(QWheelEvent* event) {
    // Accumulate so smooth-scrolling touchpads (small deltas) still move.
    m_wheelRemainder += -event->angleDelta().y();
    const int steps = m_wheelRemainder / 40;  // ~3 rows per 120-unit notch
    m_wheelRemainder %= 40;
    if (steps != 0) intent(kWheel, steps, 0, false);
    event->accept();
}

void ListingView::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    reportViewport();
    refresh(false);
}

void ListingView::mousePressEvent(QMouseEvent* event) {
    const int x = static_cast<int>(event->position().x()) - kTextInset;
    const int y = static_cast<int>(event->position().y());
    if (event->button() == Qt::MiddleButton) {
        intent(kMiddle, x, y, false);
    } else if (event->button() == Qt::LeftButton) {
        intent(kClick, x, y, event->modifiers() & Qt::ShiftModifier);
    }
    event->accept();
}

void ListingView::keyPressEvent(QKeyEvent* event) {
    // Only plain or shifted cursor keys belong to the field panel; anything
    // with Ctrl/Alt/Meta was offered to the actions first and falls through.
    const Qt::KeyboardModifiers mods = event->modifiers() & ~Qt::KeypadModifier;
    if (mods & ~Qt::ShiftModifier) {
        QAbstractScrollArea::keyPressEvent(event);
        return;
    }
    int64_t dir;
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
    intent(kKey, dir, 0, mods & Qt::ShiftModifier);
    event->accept();
}

void ListingView::paintEvent(QPaintEvent*) {
    QPainter p(viewport());
    p.fillRect(viewport()->rect(), palette().base());
    FrameInfo f;
    if (!bridgeCall(m_status, [&] { f = listing_frame(m_pid); })) return;
    const int ascent = QFontMetrics(font()).ascent();
    QFont bold = font();
    bold.setBold(true);
    const QColor highlight(255, 255, 0, 140);  // Ghidra's middle-mouse highlight is yellow
    for (const FrameRowInfo& row : f.rows) {
        if (row.selected) p.fillRect(QRect(0, row.y, viewport()->width(), row.height), palette().highlight().color().lighter(170));
        for (const SpanInfo& s : row.highlights) p.fillRect(QRect(s.x + kTextInset, row.y, s.width, row.height), highlight);
        p.setPen(palette().text().color());
        for (const RunPosInfo& run : row.runs) {
            p.setFont(run.bold ? bold : font());
            p.drawText(run.x + kTextInset, row.y + ascent, qs(run.text));
        }
        if (row.cursor_x >= 0) p.fillRect(QRect(row.cursor_x + kTextInset, row.y, 2, row.height), palette().text().color());
    }
}

void ListingView::ensureViewportRows(int n) {
    // Smoke hooks may run before the first resize: make the viewport hold n rows.
    const int need = qMax(viewport()->height(), QFontMetrics(font()).height() * n + 1);
    bridgeCall(m_status, [&] { listing_set_viewport(m_pid, need); });
}

void ListingView::scrollRows(int64_t delta) {
    ensureViewportRows(5);
    intent(kWheel, delta, 0, false);
}

QString ListingView::firstRowSummary() {
    FrameInfo f;
    if (!bridgeCall(m_status, [&] { f = listing_frame(m_pid); }) || f.rows.empty()) return {};
    QStringList xs;
    for (const RunPosInfo& run : f.rows[0].runs) xs << QString::number(run.x);
    return qs(f.rows[0].index) + QStringLiteral(": ") + xs.join(QLatin1Char(' '));
}

QString ListingView::stateSummary() {
    FrameInfo f;
    if (!bridgeCall(m_status, [&] { f = listing_frame(m_pid); })) return {};
    int selected = 0;
    for (const FrameRowInfo& row : f.rows) selected += row.selected ? 1 : 0;
    return QStringLiteral("top=%1 cursor=%2 selected=%3 status=%4")
        .arg(qs(f.top), qs(f.location))
        .arg(selected)
        .arg(m_status->currentMessage());
}

QStringList ListingView::dumpRows(int n) {
    QStringList out;
    ensureViewportRows(n);
    FrameInfo f;
    if (!bridgeCall(m_status, [&] { f = listing_frame(m_pid); })) return out;
    for (const FrameRowInfo& row : f.rows) {
        if (out.size() >= n) break;
        QStringList parts;
        for (const RunPosInfo& run : row.runs) parts << qs(run.text);
        out << parts.join(QStringLiteral("  "));
    }
    return out;
}

}  // namespace ghidra_qt
