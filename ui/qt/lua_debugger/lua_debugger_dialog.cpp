/* lua_debugger_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "lua_debugger_dialog.h"
#include "accordion_frame.h"
#include "lua_debugger_code_view.h"
#include "lua_debugger_find_frame.h"
#include "lua_debugger_goto_line_frame.h"
#include "lua_debugger_pause_overlay.h"
#include "lua_debugger_item_utils.h"
#include "main_application.h"
#include "main_window.h"
#include "ui_lua_debugger_dialog.h"
#include "utils/stock_icon.h"
#include "widgets/collapsible_section.h"

#ifdef HAVE_LIBPCAP
#include <ui/capture.h>
#endif

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QChildEvent>
#include <QClipboard>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QEvent>
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QKeyCombination>
#endif
#include <QKeyEvent>
#include <QColor>
#include <QComboBox>
#include <QDir>
#include <QAbstractItemView>
#include <QDirIterator>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QFontMetricsF>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHeaderView>
#include <QIcon>
#include <QJsonArray>
#include <QJsonParseError>
#include <QLineEdit>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QList>
#include <QMenu>
#include <QMessageBox>
#include <QMouseEvent>
#include <QMetaObject>
#include <QPainter>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointer>
#include <QShowEvent>
#include <QSet>
#include <QSizePolicy>
#include <QStandardPaths>
#include <QStyle>
#include <QTextBlock>
#include <QTextDocument>
#include <QSplitter>
#include <QPersistentModelIndex>
#include <QTimer>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QAbstractItemModel>
#include <QItemSelectionModel>
#include <QModelIndex>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTreeView>
#include <QTextStream>
#include <QUrl>

#include <QVBoxLayout>
#include <QToolButton>
#include <QHBoxLayout>
#include <algorithm>

#include <glib.h>

#include "app/application_flavor.h"
#include "wsutil/filesystem.h"
#include <epan/prefs.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <ui/qt/utils/qt_ui_utils.h>

#define LUA_DEBUGGER_SETTINGS_FILE "lua_debugger.json"

using namespace LuaDebuggerItems;

namespace
{
/** Global personal config path — debugger settings are not profile-specific. */
QString
luaDebuggerSettingsFilePath()
{
    char *p = get_persconffile_path(
        LUA_DEBUGGER_SETTINGS_FILE, false,
        application_configuration_environment_prefix());
    return gchar_free_to_qstring(p);
}

/** Fullwidth ＋ (U+FF0B) and － (U+FF0D): same advance; reads wider than ASCII +/−. */
static const QString kLuaDbgHeaderPlus{QStringLiteral("\uFF0B")};
static const QString kLuaDbgHeaderMinus{QStringLiteral("\uFF0D")};

/** Tight, flat so glyphs sit in the same vertical band as the HLine. */
static const QString kLuaDbgHeaderToolButtonStyle{QStringLiteral(
    "QToolButton { border: none; padding: 0px; margin: 0px; }")};

namespace {

/**
 * Visual mode for the Breakpoints header “activate all / deactivate all”
 * control. The dot mirrors the gutter convention — red @c #DC3545 when any
 * breakpoint is active, gray @c #808080 when all are inactive — so the
 * header aggregates what the gutter shows. Click flips the aggregate state.
 */
enum class LuaDbgBpHeaderIconMode
{
    NoBreakpoints, /**< Gray, control disabled (Qt dims it automatically). */
    ActivateAll,   /**< Gray — all BPs inactive, click activates all. */
    DeactivateAll, /**< Red — any BP active, click deactivates all. */
};

/**
 * Breakpoint header: same geometry and fill/rim as @c LineNumberArea
 * (diameter @c 2*(h/2-2) from the editor @c QFontMetrics), centered in
 * @a headerSide. Renders at @a dpr (device pixels) for crisp icons on HiDPI,
 * like @c updateEnabledCheckboxIcon(). @a editorFont nullptr uses
 * @c QGuiApplication::font.
 */
static QIcon
luaDbgBreakpointHeaderIconForMode(const QFont *editorFont,
                                  LuaDbgBpHeaderIconMode mode, int headerSide,
                                  qreal dpr)
{
    if (headerSide < 4)
    {
        headerSide = 12;
    }
    if (dpr <= 0.0 || dpr > 8.0)
    {
        dpr = 1.0;
    }
    const QFont f =
        editorFont != nullptr ? *editorFont : QGuiApplication::font();
    const QFontMetrics fm(f);
    /* Match line_number_area: radius = h/2 - 2, diameter 2*radius. */
    const int r = fm.height() / 2 - 2;
    int diam = 2 * qMax(0, r);
    diam = qMax(6, qMin(diam, headerSide - 4));
    const qreal s = static_cast<qreal>(headerSide);
    const qreal d = static_cast<qreal>(diam);
    const QRectF circleRect((s - d) / 2.0, (s - d) / 2.0, d, d);

    QPixmap pm(QSize(headerSide, headerSide) * dpr);
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    {
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing, true);
        QColor fill;
        switch (mode)
        {
        case LuaDbgBpHeaderIconMode::NoBreakpoints:
        case LuaDbgBpHeaderIconMode::ActivateAll:
            /* Match LineNumberArea disabled-breakpoint @c #808080. */
            fill = QColor(QStringLiteral("#808080"));
            break;
        case LuaDbgBpHeaderIconMode::DeactivateAll:
            fill = QColor(QStringLiteral("#DC3545"));
            break;
        }
        p.setBrush(fill);
        p.setPen(QPen(fill.darker(140), 1.0));
        p.drawEllipse(circleRect);
    }
    /* Only register the Normal pixmap so Qt dims the disabled state itself,
     * giving the @c NoBreakpoints case a visibly different look. */
    return QIcon(pm);
}

} // namespace

static void
styleLuaDebuggerHeaderBreakpointToggleButton(QToolButton *btn, int side)
{
    btn->setToolButtonStyle(Qt::ToolButtonIconOnly);
    btn->setIconSize(QSize(side, side));
    btn->setFixedSize(side, side);
    btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    btn->setText(QString());
}

/**
 * @a glyphs: shrink key is @a glyphs.first() (＋/－: first only, matching legacy);
 * grow step requires all glyphs' bounding heights to fit.
 */
static void
styleLuaDebuggerHeaderFittedTextButton(QToolButton *btn, int side,
                                       const QFont &titleFont,
                                       const QStringList &glyphs)
{
    if (glyphs.isEmpty()) {
        return;
    }
    const QString &shrinkKey = glyphs[0];
    btn->setToolButtonStyle(Qt::ToolButtonTextOnly);
    QFont f = titleFont;
    for (int k = 0; k < 45 && f.pointSizeF() > 3.0; ++k) {
        QFontMetricsF m(f);
        const QRectF r = m.boundingRect(shrinkKey);
        if (m.height() <= static_cast<qreal>(side) + 0.5
            && r.height() <= static_cast<qreal>(side) + 0.5) {
            break;
        }
        f.setPointSizeF(f.pointSizeF() - 0.5);
    }
    for (int k = 0; k < 3; ++k) {
        QFont tryF = f;
        tryF.setPointSizeF(f.pointSizeF() + 0.5);
        QFontMetricsF m(tryF);
        qreal rMax = 0.0;
        for (const QString &g : glyphs) {
            rMax = std::max(rMax, m.boundingRect(g).height());
        }
        if (m.height() <= static_cast<qreal>(side) + 0.5
            && rMax <= static_cast<qreal>(side) + 0.5) {
            f = tryF;
        } else {
            break;
        }
    }
    btn->setFont(f);
    btn->setFixedSize(side, side);
    btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    btn->setIcon(QIcon());
}

/** Plain +/− labels: same @a side as @c CollapsibleSection::titleButtonHeight. */
static void
styleLuaDebuggerHeaderPlusMinusButton(QToolButton *btn, int side,
                                      const QFont &titleFont)
{
    const QStringList pm{kLuaDbgHeaderPlus, kLuaDbgHeaderMinus};
    styleLuaDebuggerHeaderFittedTextButton(btn, side, titleFont, pm);
}

/** Trash icon, same @a side as ＋/− on macOS; 2 px smaller elsewhere. */
static void
styleLuaDebuggerHeaderRemoveAllButton(QToolButton *btn, int side)
{
    btn->setToolButtonStyle(Qt::ToolButtonIconOnly);
    btn->setIcon(QIcon::fromTheme(QStringLiteral("edit-delete"),
                                  StockIcon(QStringLiteral("edit-clear"))));
#ifdef Q_OS_MAC
    const int btnSide = side;
#else
    /* The themed trash glyph rendered at headerHeight() looks slightly too
     * tall next to the +/-/toggle buttons on Linux/Windows; trim 4 px so the
     * trailing button row reads as one set of equal-sized controls. */
    const int btnSide = qMax(1, side - 4);
#endif
    btn->setIconSize(QSize(btnSide, btnSide));
    btn->setFixedSize(btnSide, btnSide);
    btn->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    btn->setText(QString());
}


/* Application-wide event filter installed while the debugger is paused.
 *
 * Two responsibilities:
 *
 *  1. Swallow user-input and WM-close events destined for any
 *     top-level window other than the debugger dialog. This is
 *     defense-in-depth on top of the setEnabled(false) cuts the
 *     dialog applies to other top-level widgets, the main window's
 *     centralWidget(), and every QAction outside the debugger — it
 *     catches widgets that pop up DURING the pause (e.g. dialogs
 *     spawned from queued signals or nested-loop timers) and events
 *     that bypass the enabled check (notably WM-delivered Close).
 *
 *  2. Swallow QEvent::UpdateRequest and QEvent::LayoutRequest
 *     destined for the main window. While Lua is suspended inside a
 *     paint-triggered dissection (the very common case where the
 *     user scrolled the packet list and the next visible row hits a
 *     breakpoint), the outer paint cycle is still on the call stack
 *     above us. Letting the nested event loop process more
 *     UpdateRequests on the same window drives QWidgetRepaintManager
 *     into a re-entrant paintAndFlush() against the same
 *     QCALayerBackingStore, which on macOS faults inside
 *     QCALayerBackingStore::blitBuffer() (buffer already in flight to
 *     CoreAnimation). The wslua_debugger_is_paused() guard in
 *     dissect_lua/heur_dissect_lua prevents the Lua-VM half of the
 *     re-entrancy, but it cannot prevent the platform plugin from
 *     touching the still-live backing store of the outer paint.
 *     Filtering UpdateRequest/LayoutRequest at the top of the main
 *     window's event delivery is the cleanest fence: no paint pass
 *     starts on the main window for the duration of the pause.
 *
 * This is not a Q_OBJECT because it has no signals/slots/property use;
 * overriding eventFilter() only requires subclassing QObject. */
class PauseInputFilter : public QObject
{
  public:
    explicit PauseInputFilter(QWidget *debugger_dialog,
                              QWidget *main_window,
                              QObject *parent = nullptr)
        : QObject(parent), debugger_dialog_(debugger_dialog),
          main_window_(main_window)
    {
    }

    bool eventFilter(QObject *watched, QEvent *event) override
    {
        const QEvent::Type type = event->type();

        /* Paint/layout suppression for the main window only. */
        if (type == QEvent::UpdateRequest ||
            type == QEvent::LayoutRequest)
        {
            if (main_window_ && watched == main_window_) {
                event->accept();
                return true;
            }
            return QObject::eventFilter(watched, event);
        }

        /* Close events get policy-aware routing rather than being
         * uniformly forwarded or uniformly swallowed:
         *
         *  - Main window: must reach MainWindow::closeEvent() so it
         *    can ignore() and record a deferred close. Swallowing
         *    here would hide the window without running closeEvent,
         *    which ends with epan_cleanup() running while cf->epan
         *    is still alive and file_scope is still entered.
         *
         *  - Debugger dialog (and any window parented under it,
         *    e.g. QMessageBox prompts): forward, so the user can
         *    close the debugger normally and the dialog's own
         *    closeEvent gets to do the synchronous unfreeze.
         *
         *  - Any other top-level window (e.g. I/O Graph, About,
         *    preferences, statistics dialogs): swallow. We are sitting
         *    in handlePause()'s nested event loop with the rest of
         *    the UI deliberately frozen; closing a stats dialog from
         *    underneath the application -- typically because macOS
         *    Dock-Quit fanned a single Close pulse out to every
         *    top-level window -- destroys widgets whose models are
         *    still referenced by suspended slots and queued events. */
        if (type == QEvent::Close) {
            QWidget *w = qobject_cast<QWidget *>(watched);
            if (!w) {
                return QObject::eventFilter(watched, event);
            }
            if (main_window_ && w == main_window_) {
                return QObject::eventFilter(watched, event);
            }
            if (isOwnedByDebugger(w)) {
                return QObject::eventFilter(watched, event);
            }
            if (w->isWindow()) {
                event->ignore();
                return true;
            }
            return QObject::eventFilter(watched, event);
        }

        switch (type)
        {
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonRelease:
        case QEvent::MouseButtonDblClick:
        case QEvent::KeyPress:
        case QEvent::KeyRelease:
        case QEvent::Wheel:
        case QEvent::Shortcut:
        case QEvent::ShortcutOverride:
        case QEvent::ContextMenu:
            break;
        default:
            return QObject::eventFilter(watched, event);
        }

        QWidget *w = qobject_cast<QWidget *>(watched);
        if (!w) {
            return QObject::eventFilter(watched, event);
        }

        /* Allow the debugger UI and any separate window that is a child
         * in the object tree of the debugger (QMessageBox, QDialog,
         * etc. parented with the debugger as QDialog::parent()).
         * Those popups are top-level windows themselves, so a plain
         * QWidget::isAncestorOf() check returns false (it short-circuits
         * at window boundaries) and a top == debugger_dialog_ check
         * would swallow the popups' button input. */
        if (isOwnedByDebugger(w))
        {
            return QObject::eventFilter(watched, event);
        }

        /* Swallow: prevent user input from reaching suspended Qt
         * widgets whose callbacks could reenter Lua or invalidate
         * dissection state. */
        event->accept();
        return true;
    }

  private:
    /* True when w is the debugger dialog, or any widget reachable
     * from the debugger via the QObject parent chain. Walks the
     * object tree (which crosses window boundaries via
     * QObject::setParent), unlike QWidget::isAncestorOf which is
     * scoped to a single window and so returns false for child
     * QMessageBoxes / QDialogs created with the debugger as their
     * parent. The walk also climbs out of the popup's children
     * (button -> layout widget -> ... -> messagebox -> debugger). */
    bool isOwnedByDebugger(const QWidget *w) const
    {
        if (!debugger_dialog_ || !w) {
            return false;
        }
        for (const QObject *o = w; o; o = o->parent()) {
            if (o == debugger_dialog_) {
                return true;
            }
        }
        return false;
    }

    QWidget *debugger_dialog_;
    QWidget *main_window_;
};
} // namespace

extern "C" void wslua_debugger_ui_callback(const char *file_path, int64_t line)
{
    LuaDebuggerDialog *dialog = LuaDebuggerDialog::instance();
    if (dialog)
    {
        dialog->handlePause(file_path, line);
    }
}

LuaDebuggerDialog *LuaDebuggerDialog::_instance = nullptr;
int32_t LuaDebuggerDialog::currentTheme_ = WSLUA_DEBUGGER_THEME_AUTO;
bool LuaDebuggerDialog::s_captureSuppressionActive_ = false;
bool LuaDebuggerDialog::s_captureSuppressionPrevEnabled_ = false;
bool LuaDebuggerDialog::s_mainCloseDeferredByPause_ = false;

bool LuaDebuggerDialog::handleMainCloseIfPaused(QCloseEvent *event)
{
    LuaDebuggerDialog *dbg = _instance;
    if (!wslua_debugger_is_paused())
    {
        /* Keep main-window quit and debugger Ctrl+Q consistent: if the
         * debugger owns unsaved script edits, run the debugger close gate
         * first so Save/Discard/Cancel semantics stay identical. */
        if (!dbg || !dbg->isVisible() || !dbg->hasUnsavedChanges())
        {
            return false;
        }
        event->ignore();
        s_mainCloseDeferredByPause_ = true;
        QMetaObject::invokeMethod(dbg, "close", Qt::QueuedConnection);
        dbg->raise();
        dbg->activateWindow();
        return true;
    }
    event->ignore();
    s_mainCloseDeferredByPause_ = true;
    if (dbg)
    {
        dbg->raise();
        dbg->activateWindow();
    }
    return true;
}

void LuaDebuggerDialog::deliverDeferredMainCloseIfPending()
{
    if (!s_mainCloseDeferredByPause_)
    {
        return;
    }
    s_mainCloseDeferredByPause_ = false;

    /* Queue the close on the next event loop tick rather than calling
     * close() inline. We are still inside handlePause()'s post-loop
     * cleanup; the Lua C stack above us has not unwound yet, and
     * MainWindow::closeEvent ultimately invokes mainApp->quit() which
     * tears down epan. Running that synchronously would re-introduce
     * the wmem_cleanup_scopes() abort the deferral exists to avoid. */
    if (mainApp)
    {
        QWidget *mw = mainApp->mainWindow();
        if (mw)
        {
            QMetaObject::invokeMethod(mw, "close", Qt::QueuedConnection);
        }
    }
}

bool LuaDebuggerDialog::isSuppressedByLiveCapture()
{
    return s_captureSuppressionActive_;
}

bool LuaDebuggerDialog::enterLiveCaptureSuppression()
{
    /* Suppress on the very first start-ish event of a session.
     * "prepared" already commits us to a live capture, and the
     * dumpcap child may begin writing packets before the
     * "update_started" / "fixed_started" event arrives. */
    if (s_captureSuppressionActive_)
    {
        return false;
    }
    s_captureSuppressionPrevEnabled_ = wslua_debugger_is_enabled();
    s_captureSuppressionActive_ = true;
    if (s_captureSuppressionPrevEnabled_)
    {
        wslua_debugger_set_enabled(false);
    }
    return true;
}

bool LuaDebuggerDialog::exitLiveCaptureSuppression()
{
    if (!s_captureSuppressionActive_)
    {
        return false;
    }
    const bool restore_enabled = s_captureSuppressionPrevEnabled_;
    s_captureSuppressionActive_ = false;
    s_captureSuppressionPrevEnabled_ = false;
    if (restore_enabled)
    {
        wslua_debugger_set_enabled(true);
    }
    return true;
}

void LuaDebuggerDialog::reconcileWithLiveCaptureOnStartup()
{
    /* The capture-session callback (onCaptureSessionEvent) is registered
     * at process start by LuaDebuggerUiCallbackRegistrar, so by the time
     * this dialog opens, s_captureSuppressionActive_ already reflects
     * whether a live capture is in progress. We use that as the source
     * of truth (no dependency on main-window internals).
     *
     * What this method exists to fix: ctor init paths can re-enable the
     * core debugger after the callback already established suppression.
     * Specifically, applyDialogSettings() → wslua_debugger_add_breakpoint,
     * then updateBreakpoints() → ensureDebuggerEnabledForActiveBreakpoints
     * can re-enable. Without this reconciliation step, opening the
     * dialog during a live capture would leave the core enabled despite
     * suppression being "active". */
    if (!s_captureSuppressionActive_)
    {
        return;
    }
    if (wslua_debugger_is_enabled())
    {
        /* Force the core back off without touching
         * s_captureSuppressionPrevEnabled_ — it was correctly snapshotted
         * to the user's pre-capture intent when the capture started, and
         * is what should be restored on capture stop. */
        wslua_debugger_set_enabled(false);
    }
    /* Always refresh state chrome: even if we didn't have to flip
     * the core, the early state sync above happened
     * before applyDialogSettings()/updateBreakpoints() ran, so the
     * widgets may still reflect a transient state. */
    refreshDebuggerStateUi();
}

void LuaDebuggerDialog::onCaptureSessionEvent(int event,
                                              struct _capture_session *cap_session,
                                              void *user_data)
{
    Q_UNUSED(cap_session);
    Q_UNUSED(user_data);

#ifdef HAVE_LIBPCAP
    bool state_changed = false;

    switch (event)
    {
    case capture_cb_capture_prepared:
    case capture_cb_capture_update_started:
    case capture_cb_capture_fixed_started:
        state_changed = enterLiveCaptureSuppression();
        break;
    case capture_cb_capture_update_finished:
    case capture_cb_capture_fixed_finished:
    case capture_cb_capture_failed:
        state_changed = exitLiveCaptureSuppression();
        break;
    default:
        break;
    }

    if (state_changed && _instance)
    {
        _instance->refreshDebuggerStateUi();
    }
#else
    Q_UNUSED(event);
#endif
}

int32_t LuaDebuggerDialog::currentTheme() {
    return currentTheme_;
}

namespace
{
// ============================================================================
// Settings Keys (for JSON persistence)
// ============================================================================
namespace SettingsKeys
{
constexpr const char *Theme = "theme";
constexpr const char *MainSplitter = "mainSplitterState";
constexpr const char *LeftSplitter = "leftSplitterState";
constexpr const char *SectionVariables = "sectionVariables";
constexpr const char *SectionStack = "sectionStack";
constexpr const char *SectionFiles = "sectionFiles";
constexpr const char *SectionBreakpoints = "sectionBreakpoints";
constexpr const char *SectionEval = "sectionEval";
constexpr const char *SectionSettings = "sectionSettings";
constexpr const char *SectionWatch = "sectionWatch";
constexpr const char *Breakpoints = "breakpoints";
constexpr const char *Watches = "watches";
} // namespace SettingsKeys

/** QVariantMap values for JSON arrays are typically QVariantList of QVariantMap. */
static QJsonArray
jsonArrayFromSettingsMap(const QVariantMap &map, const char *key)
{
    const QVariant v = map.value(QString::fromUtf8(key));
    if (!v.isValid())
    {
        return QJsonArray();
    }
    return QJsonValue::fromVariant(v).toArray();
}

// ============================================================================
// Tree Widget User Roles
// ============================================================================
constexpr qint32 FileTreePathRole = static_cast<qint32>(Qt::UserRole);
constexpr qint32 FileTreeIsDirectoryRole = static_cast<qint32>(Qt::UserRole + 1);
constexpr qint32 BreakpointFileRole = static_cast<qint32>(Qt::UserRole + 2);
constexpr qint32 BreakpointLineRole = static_cast<qint32>(Qt::UserRole + 3);
constexpr qint32 StackItemFileRole = static_cast<qint32>(Qt::UserRole + 4);
constexpr qint32 StackItemLineRole = static_cast<qint32>(Qt::UserRole + 5);
constexpr qint32 StackItemNavigableRole = static_cast<qint32>(Qt::UserRole + 6);
constexpr qint32 StackItemLevelRole = static_cast<qint32>(Qt::UserRole + 7);
constexpr qint32 VariablePathRole = static_cast<qint32>(Qt::UserRole + 8);
constexpr qint32 VariableTypeRole = static_cast<qint32>(Qt::UserRole + 9);
constexpr qint32 VariableCanExpandRole = static_cast<qint32>(Qt::UserRole + 10);
constexpr qint32 WatchSpecRole = static_cast<qint32>(Qt::UserRole + 11);
constexpr qint32 WatchSubpathRole = static_cast<qint32>(Qt::UserRole + 13);
constexpr qint32 WatchPendingNewRole = static_cast<qint32>(Qt::UserRole + 15);
/*
 * Expansion state for watch roots and Variables sections is tracked in
 * LuaDebuggerDialog::watchExpansion_ and variablesExpansion_ (runtime-only
 * QHashes). The dialog members are the single source of truth and survive
 * child-item destruction during pause / resume / step.
 *
 * "Value changed since last pause" baselines live on the dialog too
 * (LuaDebuggerDialog::watchRootBaseline_ / watchChildBaseline_ /
 * variablesBaseline_ and their *Current_ mirrors); see the header.
 */
/** Monotonic flash generation id stored on a value cell so a pending
 *  clear-timer only clears its own flash, not a fresher one. */
constexpr qint32 ChangedFlashSerialRole =
    static_cast<qint32>(Qt::UserRole + 20);

constexpr qsizetype WATCH_TOOLTIP_MAX_CHARS = 4096;
constexpr int WATCH_EXPR_MAX_CHARS = 65536;
/** Transient background-flash duration for a value that just changed. */
constexpr int CHANGED_FLASH_MS = 500;
/**
 * Delay before applying the "Watch column shows —" placeholder after a step
 * resume. A typical Lua single-step re-pauses well within a few ms; running
 * the placeholder repaint immediately would visibly flicker every Watch row
 * value→—→value across the resume / re-pause boundary, even when the value
 * did not change. handlePause() bumps watchPlaceholderEpoch_, so any timer
 * scheduled with a stale epoch is dropped without touching the Watch tree.
 * Long-running steps (or scripts that simply terminate) still see the
 * placeholder appear after this delay.
 */
constexpr int WATCH_PLACEHOLDER_DEFER_MS = 250;
/** Separator used in composite (stackLevel, path) baseline-map keys. */
constexpr QChar CHANGE_KEY_SEP = QChar(0x1F); // ASCII Unit Separator

/** @brief Registers the UI callback with the Lua debugger core at load time.
 *
 * Also wires up a capture-session observer (when libpcap is available)
 * so the debugger is force-disabled for the duration of any live
 * capture; see LuaDebuggerDialog::onCaptureSessionEvent for rationale. */
class LuaDebuggerUiCallbackRegistrar
{
  public:
    LuaDebuggerUiCallbackRegistrar()
    {
        wslua_debugger_register_ui_callback(wslua_debugger_ui_callback);
#ifdef HAVE_LIBPCAP
        capture_callback_add(&LuaDebuggerDialog::onCaptureSessionEvent,
                             nullptr);
#endif
    }

    ~LuaDebuggerUiCallbackRegistrar()
    {
        wslua_debugger_register_ui_callback(NULL);
#ifdef HAVE_LIBPCAP
        capture_callback_remove(&LuaDebuggerDialog::onCaptureSessionEvent,
                                nullptr);
#endif
    }
};

static LuaDebuggerUiCallbackRegistrar g_luaDebuggerUiCallbackRegistrar;

/** @brief Build a key sequence from a key event for matching QAction shortcuts. */
static QKeySequence luaSeqFromKeyEvent(const QKeyEvent *ke)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return QKeySequence(QKeyCombination(ke->modifiers(), static_cast<Qt::Key>(ke->key())));
#else
    return QKeySequence(ke->key() | ke->modifiers());
#endif
}

/** @brief Sequences for context-menu labels and eventFilter (must match). */
const QKeySequence kCtxGoToLine(QKeySequence(Qt::CTRL | Qt::Key_G));
const QKeySequence kCtxRunToLine(QKeySequence(Qt::CTRL | Qt::Key_F10));
const QKeySequence kCtxWatchEdit(Qt::Key_F2);
const QKeySequence kCtxWatchCopyValue(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_C));
const QKeySequence kCtxWatchDuplicate(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_D));
const QKeySequence kCtxWatchRemoveAll(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_K));
const QKeySequence kCtxAddWatch(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_W));
const QKeySequence kCtxToggleBreakpoint(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_B));
const QKeySequence kCtxReloadLuaPlugins(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_L));
const QKeySequence kCtxRemoveAllBreakpoints(QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_F9));

/**
 * @brief True if @a pressed is one of the debugger shortcuts that overlap the
 * main window and must be reserved in ShortcutOverride.
 */
static bool matchesLuaDebuggerShortcutKeys(Ui::LuaDebuggerDialog *ui,
                                           const QKeySequence &pressed)
{
    return (pressed.matches(ui->actionFind->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionSaveFile->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionGoToLine->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionReloadLuaPlugins->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionAddWatch->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionContinue->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(ui->actionStepIn->shortcut()) == QKeySequence::ExactMatch) ||
           (pressed.matches(kCtxRunToLine) == QKeySequence::ExactMatch) ||
           (pressed.matches(kCtxToggleBreakpoint) == QKeySequence::ExactMatch) ||
           (pressed.matches(kCtxWatchCopyValue) == QKeySequence::ExactMatch) ||
           (pressed.matches(kCtxWatchDuplicate) == QKeySequence::ExactMatch);
}

/**
 * @brief Run debugger toolbar actions that share shortcuts with the main window.
 *
 * When a capture file is open, Wireshark enables Find Packet (Ctrl+F) and
 * Go to Packet (Ctrl+G). QEvent::ShortcutOverride is handled separately: we only
 * accept() there so Qt does not activate the main-window QAction; triggering
 * happens on KeyPress only. Doing both would call showAccordionFrame(..., true)
 * twice and toggle the bar closed immediately after opening.
 *
 * @return True if @a pressed matches one of these shortcuts (handled or not).
 */
static bool triggerLuaDebuggerShortcuts(Ui::LuaDebuggerDialog *ui,
                                        const QKeySequence &pressed)
{
    if (pressed.matches(ui->actionFind->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionFind->isEnabled())
        {
            ui->actionFind->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionSaveFile->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionSaveFile->isEnabled())
        {
            ui->actionSaveFile->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionGoToLine->shortcut()) == QKeySequence::ExactMatch)
    {
        if (ui->actionGoToLine->isEnabled())
        {
            ui->actionGoToLine->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionReloadLuaPlugins->shortcut()) ==
        QKeySequence::ExactMatch)
    {
        if (ui->actionReloadLuaPlugins->isEnabled())
        {
            ui->actionReloadLuaPlugins->trigger();
        }
        return true;
    }
    if (pressed.matches(ui->actionAddWatch->shortcut()) ==
        QKeySequence::ExactMatch)
    {
        if (ui->actionAddWatch->isEnabled())
        {
            ui->actionAddWatch->trigger();
        }
        return true;
    }
    return false;
}

static LuaDebuggerCodeView *codeViewFromObject(QObject *obj)
{
    for (QObject *o = obj; o; o = o->parent())
    {
        if (auto *cv = qobject_cast<LuaDebuggerCodeView *>(o))
        {
            return cv;
        }
    }
    return nullptr;
}

static QStandardItem *watchRootItem(QStandardItem *item)
{
    while (item && item->parent())
    {
        item = item->parent();
    }
    return item;
}

/**
 * @brief Return the Lua identifier under the given cursor position, or
 *        an empty string if the position is not on an identifier.
 *
 * Lua identifiers are `[A-Za-z_][A-Za-z0-9_]*`. The bracket grammar that
 * the Watch panel accepts (`a.b[1]`, `a.b["k"]`) is not synthesized here
 * — only the bare identifier under the caret is returned, mirroring the
 * "double-click to select word" affordance Qt's text editors offer.
 */
static QString luaIdentifierUnderCursor(const QTextCursor &cursor)
{
    const QString block = cursor.block().text();
    const int posInBlock = cursor.positionInBlock();
    if (block.isEmpty() || posInBlock < 0 || posInBlock > block.size())
    {
        return {};
    }

    auto isIdentChar = [](QChar c)
    {
        return c.isLetterOrNumber() || c == QLatin1Char('_');
    };
    auto isIdentStart = [](QChar c)
    {
        return c.isLetter() || c == QLatin1Char('_');
    };

    /* Caret may sit one past the end of the identifier; expand left
     * until we are inside, then sweep both directions. */
    int start = posInBlock;
    int end = posInBlock;
    if (start > 0 && !isIdentChar(block.at(start - 1)) &&
        (start >= block.size() || !isIdentChar(block.at(start))))
    {
        return {};
    }
    while (start > 0 && isIdentChar(block.at(start - 1)))
    {
        --start;
    }
    while (end < block.size() && isIdentChar(block.at(end)))
    {
        ++end;
    }
    if (start >= end)
    {
        return {};
    }
    if (!isIdentStart(block.at(start)))
    {
        return {};
    }
    return block.mid(start, end - start);
}

/**
 * True when a watch spec resolves against `_G` (i.e. not frame-dependent).
 * Used by changeKey() to avoid invalidating a Globals watch when the user
 * switches the call-stack frame.
 */
static bool watchSpecIsGlobalScoped(const QString &spec)
{
    const QString t = spec.trimmed();
    return t.startsWith(QLatin1String("Globals")) ||
           t == QLatin1String("_G") ||
           t.startsWith(QLatin1String("_G."));
}

/**
 * True when a Variables tree path is under `Globals` (frame-independent).
 */
static bool variablesPathIsGlobalScoped(const QString &path)
{
    return path == QLatin1String("Globals") ||
           path.startsWith(QLatin1String("Globals."));
}

/** Compose a baseline-map key from (stackLevel, path). */
static QString changeKey(int stackLevel, const QString &path)
{
    return QString::number(stackLevel) + CHANGE_KEY_SEP + path;
}

/** Parse the "spec" portion out of a composite key produced by changeKey(). */
static QString watchSpecFromChangeKey(const QString &key)
{
    const qsizetype sep = key.indexOf(CHANGE_KEY_SEP);
    return sep < 0 ? key : key.mid(sep + 1);
}

/**
 * Lookup / compare in one place. Returns true when @a key was recorded in
 * @a baseline with a different value, or (when @a flashNew is set) when @a
 * key was absent from @a baseline but @a baseline itself is non-empty —
 * i.e. we have *some* prior snapshot to compare against, so the absence of
 * this key means the variable appeared since the last pause.
 *
 * An empty-string baseline is still a valid recorded value and can signal a
 * change.
 *
 * The @a flashNew heuristic is used for runtime-discovered rows
 * (Variables tree, Watch children inside an expanded table) but is
 * deliberately false for Watch *roots* since a root with no baseline is
 * almost always one the user just added and should not flash on its first
 * evaluation.
 *
 * Factored out so the unit tests can exercise it without a live dialog.
 */
template <class Key, class Map>
static bool shouldMarkChanged(const Map &baseline, const Key &key,
                              const QString &newVal, bool flashNew = false)
{
    const auto it = baseline.constFind(key);
    if (it != baseline.constEnd())
    {
        return *it != newVal;
    }
    return flashNew && !baseline.isEmpty();
}


/** Top-level Variables section key (`Locals` / `Globals` / `Upvalues`). */
static QString variableSectionRootKeyFromItem(const QStandardItem *item)
{
    if (!item)
    {
        return QString();
    }
    const QStandardItem *walk = item;
    while (walk->parent())
    {
        walk = walk->parent();
    }
    return walk->data(VariablePathRole).toString();
}

static bool watchSpecUsesPathResolution(const QString &spec)
{
    const QByteArray ba = spec.toUtf8();
    return wslua_debugger_watch_spec_uses_path_resolution(ba.constData());
}

/** Child variable path under @a parentPath (Variables tree and path-based Watch rows). */
static QString variableTreeChildPath(const QString &parentPath,
                                     const QString &nameText)
{
    if (parentPath.isEmpty())
    {
        return nameText;
    }
    if (nameText.startsWith(QLatin1Char('[')))
    {
        return parentPath + nameText;
    }
    return parentPath + QLatin1Char('.') + nameText;
}

/** Globals subtree is sorted by name; Locals/Upvalues keep engine order. */
static bool variableChildrenShouldSortByName(const QString &parentPath)
{
    return !parentPath.isEmpty() &&
           parentPath.startsWith(QLatin1String("Globals"));
}

/**
 * Shared fields extracted from a `wslua_variable_t` for populating either the
 * Variables tree or a Watch child row. Kept here so both call sites agree on
 * how engine data maps to UI strings.
 */
struct VariableRowFields
{
    QString name;
    QString value;
    QString type;
    bool canExpand = false;
    QString childPath;
};

static VariableRowFields readVariableRowFields(const wslua_variable_t &v,
                                               const QString &parentPath)
{
    VariableRowFields f;
    f.name = QString::fromUtf8(v.name ? v.name : "");
    f.value = QString::fromUtf8(v.value ? v.value : "");
    f.type = QString::fromUtf8(v.type ? v.type : "");
    f.canExpand = v.can_expand ? true : false;
    f.childPath = variableTreeChildPath(parentPath, f.name);
    return f;
}

/**
 * Install the expansion indicator on @a item and (optionally) a dummy child
 * placeholder so that onItemExpanded can lazily populate children. Watch rows
 * use `enabledOnlyPlaceholder=true` so the placeholder never becomes selectable.
 */
static void applyVariableExpansionIndicator(QStandardItem *col0,
                                            bool canExpand,
                                            bool enabledOnlyPlaceholder,
                                            int columnCount = 3)
{
    if (!canExpand)
    {
        return;
    }
    if (columnCount == 2)
    {
        auto *p0 = new QStandardItem();
        auto *p1 = new QStandardItem();
        if (enabledOnlyPlaceholder)
        {
            p0->setFlags(Qt::ItemIsEnabled);
            p1->setFlags(Qt::ItemIsEnabled);
        }
        col0->appendRow({p0, p1});
        return;
    }
    auto *p0 = new QStandardItem();
    auto *p1 = new QStandardItem();
    auto *p2 = new QStandardItem();
    if (enabledOnlyPlaceholder)
    {
        p0->setFlags(Qt::ItemIsEnabled);
        p1->setFlags(Qt::ItemIsEnabled);
        p2->setFlags(Qt::ItemIsEnabled);
    }
    else
    {
        for (QStandardItem *p : {p0, p1, p2})
        {
            p->setFlags((p->flags() | Qt::ItemIsSelectable | Qt::ItemIsEnabled) &
                        ~Qt::ItemIsEditable);
        }
    }
    col0->appendRow({p0, p1, p2});
}

/** Full Variables path for path-style watches (e.g. Locals.foo for "foo"). */
static QString watchVariablePathForSpec(const QString &spec)
{
    char *p =
        wslua_debugger_watch_variable_path_for_spec(spec.toUtf8().constData());
    if (!p)
    {
        return QString();
    }
    QString s = QString::fromUtf8(p);
    g_free(p);
    return s;
}

/**
 * Variables-tree path for UI (matches locals / upvalues / globals resolution for
 * the first path segment when paused; otherwise same as watchVariablePathForSpec).
 */
static QString watchResolvedVariablePathForTooltip(const QString &spec)
{
    if (spec.trimmed().isEmpty())
    {
        return QString();
    }
    char *p = wslua_debugger_watch_resolved_variable_path_for_spec(
        spec.toUtf8().constData());
    if (!p)
    {
        return QString();
    }
    QString s = QString::fromUtf8(p);
    g_free(p);
    return s;
}

/** Sets VariablePathRole on a watch root from spec (resolved section when paused). */
static void watchRootSetVariablePathRoleFromSpec(QStandardItem *row,
                                                 const QString &spec)
{
    if (!row)
    {
        return;
    }
    const QString t = spec.trimmed();
    if (t.isEmpty())
    {
        row->setData(QVariant(), VariablePathRole);
        return;
    }
    const QString vpRes = watchResolvedVariablePathForTooltip(t);
    if (!vpRes.isEmpty())
    {
        row->setData(vpRes, VariablePathRole);
        return;
    }
    const QString vp = watchVariablePathForSpec(t);
    if (!vp.isEmpty())
    {
        row->setData(vp, VariablePathRole);
    }
    else
    {
        row->setData(QVariant(), VariablePathRole);
    }
}

/** Locals / Upvalues / Globals line for watch tooltips (full variable-tree path). */
static QString watchPathOriginSuffix(const QStandardItem *item,
                                     const QString &spec)
{
    /* Prefer resolver output (matches lookup order for unqualified names). */
    QString vp;
    if (!spec.trimmed().isEmpty())
    {
        vp = watchResolvedVariablePathForTooltip(spec);
    }
    if (vp.isEmpty() && item)
    {
        vp = item->data(VariablePathRole).toString();
    }
    if (vp.startsWith(QLatin1String("Locals.")) ||
        vp == QLatin1String("Locals"))
    {
        return QStringLiteral("\n%1").arg(
            LuaDebuggerDialog::tr("From: Locals"));
    }
    if (vp.startsWith(QLatin1String("Upvalues.")) ||
        vp == QLatin1String("Upvalues"))
    {
        return QStringLiteral("\n%1").arg(
            LuaDebuggerDialog::tr("From: Upvalues"));
    }
    if (vp.startsWith(QLatin1String("Globals.")) ||
        vp == QLatin1String("Globals"))
    {
        return QStringLiteral("\n%1").arg(
            LuaDebuggerDialog::tr("From: Globals"));
    }
    return QString();
}

static QString capWatchTooltipText(const QString &s)
{
    if (s.size() <= WATCH_TOOLTIP_MAX_CHARS)
    {
        return s;
    }
    return s.left(WATCH_TOOLTIP_MAX_CHARS) +
           LuaDebuggerDialog::tr("\n… (truncated)");
}

/** Parent path key for Locals.a.b / a[1].x style watch paths (expression subpaths or variable paths). */
static QString watchPathParentKey(const QString &path)
{
    if (path.isEmpty())
    {
        return QString();
    }
    if (path.endsWith(QLatin1Char(']')))
    {
        int depth = 0;
        for (int i = static_cast<int>(path.size()) - 1; i >= 0; --i)
        {
            const QChar c = path.at(i);
            if (c == QLatin1Char(']'))
            {
                depth++;
            }
            else if (c == QLatin1Char('['))
            {
                depth--;
                if (depth == 0)
                {
                    return path.left(i);
                }
            }
        }
        return QString();
    }
    const qsizetype dot = path.lastIndexOf(QLatin1Char('.'));
    if (dot > 0)
    {
        return path.left(dot);
    }
    return QString();
}

/**
 * Populate the text and tooltip cells for one Watch-tree child row.
 * "Value changed since last pause" visuals (accent + bold + optional flash)
 * are applied by the dialog via `applyChangedVisuals` once this function
 * has installed the display text; see `fillWatchPathChildren`.
 */
static void applyWatchChildRowTextAndTooltip(QStandardItem *col0,
                                             const QString &rawVal,
                                             const QString &typeText)
{
    auto *wm = qobject_cast<QStandardItemModel *>(col0->model());
    if (!wm)
    {
        return;
    }
    setText(wm, col0, 1, rawVal);
    const QString tooltipSuffix =
        typeText.isEmpty()
            ? QString()
            : LuaDebuggerDialog::tr("Type: %1").arg(typeText);
    setToolTip(
        wm, col0, 0,
        capWatchTooltipText(
            tooltipSuffix.isEmpty()
                ? col0->text()
                : QStringLiteral("%1\n%2").arg(col0->text(), tooltipSuffix)));
    setToolTip(
        wm, col0, 1,
        capWatchTooltipText(
            tooltipSuffix.isEmpty()
                ? rawVal
                : QStringLiteral("%1\n%2").arg(rawVal, tooltipSuffix)));
}

static int watchSubpathBoundaryCount(const QString &subpath)
{
    QString p = subpath;
    if (p.startsWith(QLatin1Char('.')))
    {
        p = p.mid(1);
    }
    int n = 0;
    for (QChar ch : p)
    {
        if (ch == QLatin1Char('.') || ch == QLatin1Char('['))
        {
            n++;
        }
    }
    return n;
}

static QStandardItem *findWatchItemBySubpathOrPathKey(QStandardItem *subtree,
                                                        const QString &key)
{
    if (!subtree || key.isEmpty())
    {
        return nullptr;
    }
    QList<QStandardItem *> queue;
    queue.append(subtree);
    while (!queue.isEmpty())
    {
        QStandardItem *it = queue.takeFirst();
        const QString sp = it->data(WatchSubpathRole).toString();
        const QString vp = it->data(VariablePathRole).toString();
        if ((!sp.isEmpty() && sp == key) || (!vp.isEmpty() && vp == key))
        {
            return it;
        }
        for (int i = 0; i < it->rowCount(); ++i)
        {
            queue.append(it->child(i));
        }
    }
    return nullptr;
}

/** Variables tree: match @a key against VariablePathRole only. */
static QStandardItem *findVariableTreeItemByPathKey(QStandardItem *subtree,
                                                      const QString &key)
{
    if (!subtree || key.isEmpty())
    {
        return nullptr;
    }
    QList<QStandardItem *> queue;
    queue.append(subtree);
    while (!queue.isEmpty())
    {
        QStandardItem *it = queue.takeFirst();
        if (it->data(VariablePathRole).toString() == key)
        {
            return it;
        }
        for (int i = 0; i < it->rowCount(); ++i)
        {
            queue.append(it->child(i));
        }
    }
    return nullptr;
}

using TreePathKeyFinder = QStandardItem *(*)(QStandardItem *,
                                                const QString &);

/**
 * Re-expand @a subtree's descendants whose path key matches one of @a pathKeys.
 * Ancestors are expanded first so that Qt's lazy expand handlers populate each
 * level before we descend.
 *
 * Shared by Watch (`findWatchItemBySubpathOrPathKey`, `onWatchItemExpanded`)
 * and Variables (`findVariableTreeItemByPathKey`, `onVariableItemExpanded`).
 *
 * Keys are processed shallow-first (by path-boundary count). The per-key
 * ancestor chain handles deep-only keys whose intermediate ancestors are not
 * in @a pathKeys; missing items are skipped (structural gaps between pauses).
 */
static void reexpandTreeDescendantsByPathKeys(QTreeView *tree,
                                              QStandardItemModel *model,
                                              QStandardItem *subtree,
                                              QStringList pathKeys,
                                              TreePathKeyFinder findByKey)
{
    if (!tree || !model || !subtree || pathKeys.isEmpty() || !findByKey)
    {
        return;
    }
    std::sort(pathKeys.begin(), pathKeys.end(),
              [](const QString &a, const QString &b)
              {
                  const int ca = watchSubpathBoundaryCount(a);
                  const int cb = watchSubpathBoundaryCount(b);
                  if (ca != cb)
                  {
                      return ca < cb;
                  }
                  return a < b;
              });
    for (const QString &pathKey : pathKeys)
    {
        QStringList chain;
        for (QString cur = pathKey; !cur.isEmpty();
             cur = watchPathParentKey(cur))
        {
            chain.prepend(cur);
        }
        for (const QString &k : chain)
        {
            QStandardItem *n = findByKey(subtree, k);
            if (!n)
            {
                continue;
            }
            const QModelIndex ix = model->indexFromItem(n);
            if (ix.isValid() && !tree->isExpanded(ix))
            {
                tree->setExpanded(ix, true);
            }
        }
    }
}

static void reexpandWatchDescendantsByPathKeys(QTreeView *tree,
                                               QStandardItemModel *model,
                                               QStandardItem *subtree,
                                               QStringList pathKeys)
{
    reexpandTreeDescendantsByPathKeys(tree, model, subtree, std::move(pathKeys),
                                       findWatchItemBySubpathOrPathKey);
}

static void clearWatchFilterErrorChrome(QStandardItem *col0, QTreeView *tree)
{
    auto *wm = qobject_cast<QStandardItemModel *>(col0 ? col0->model() : nullptr);
    if (!wm || !tree)
    {
        return;
    }
    const QPalette &pal = tree->palette();
    setForeground(wm, col0, 0, pal.brush(QPalette::Text));
    setForeground(wm, col0, 1, pal.brush(QPalette::Text));
    setBackground(wm, col0, 0, QBrush());
    setBackground(wm, col0, 1, QBrush());
}

static void applyWatchFilterErrorChrome(QStandardItem *col0, QTreeView *tree)
{
    Q_UNUSED(tree);
    auto *wm = qobject_cast<QStandardItemModel *>(col0 ? col0->model() : nullptr);
    if (!wm)
    {
        return;
    }
    QColor fg = ColorUtils::fromColorT(&prefs.gui_filter_invalid_fg);
    QColor bg = ColorUtils::fromColorT(&prefs.gui_filter_invalid_bg);
    setForeground(wm, col0, 0, fg);
    setForeground(wm, col0, 1, fg);
    setBackground(wm, col0, 0, bg);
    setBackground(wm, col0, 1, bg);
}

/* Initialize a freshly-created top-level watch row from a canonical spec.
 * The on-disk "watches" array is a flat list of spec strings (see
 * storeWatchList / rebuildWatchTreeFromSettings). */
static void setupWatchRootItemFromSpec(QStandardItem *col0, QStandardItem *col1,
                                       const QString &spec)
{
    col0->setFlags(col0->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled |
                   Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    /* Value column: drag the whole watch row, not a single cell, when reordering. */
    col1->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    col0->setText(spec);
    col1->setText(QString());
    col0->setData(spec, WatchSpecRole);
    col0->setData(QString(), WatchSubpathRole);
    col0->setData(QVariant(false), WatchPendingNewRole);
    watchRootSetVariablePathRoleFromSpec(col0, spec);
    auto *const ph0 = new QStandardItem();
    auto *const ph1 = new QStandardItem();
    ph0->setFlags(Qt::ItemIsEnabled);
    ph1->setFlags(Qt::ItemIsEnabled);
    col0->appendRow({ph0, ph1});
}

/**
 * Watch list: @c QStandardItemModel::dropMimeData() uses the drop @a column when
 * resolving the target index, so a drop on the Value column (column 1) can
 * re-parent a row or move a single "cell" instead of reordering the
 * two-column watch entry. For top-level drops, use column 0. For any index
 * on a top-level watch row, use the Watch-spec column (0) as the parent/anchor.
 */
class WatchItemModel : public QStandardItemModel
{
  public:
    using QStandardItemModel::QStandardItemModel;

  protected:
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row,
                      int column, const QModelIndex &parent) override
    {
        int c = column;
        QModelIndex p = parent;
        if (!p.isValid())
        {
            c = 0;
        }
        else if (!p.parent().isValid() && p.column() != 0)
        {
            p = p.sibling(p.row(), 0);
        }
        return QStandardItemModel::dropMimeData(data, action, row, c, p);
    }
};

/**
 * @brief Watch tree that only allows top-level reordering via drag-and-drop.
 *
 * The view uses @c QAbstractItemView::SelectRows so the drop line spans both
 * columns (Qt 6+). The Value column is drag-enabled for watch roots. Nested
 * watch rows are not valid drop targets. A drop on a top-level row’s center
 * (@c OnItem) is applied like @c AboveItem: insert that row at the same index
 * the view would use for a drop just above, instead of re-parenting as a
 * child of the target row.
 *
 * The dialog's settings map (`settings_`) is refreshed from the tree only at
 * close time via `storeDialogSettings()` / `saveSettingsFile()`, so a drop
 * event has no persistence work to do beyond the model’s internal move. After
 * a successful move, panel monospace fonts are re-applied on the watch tree
 * and related panels.
 *
 * Only top-level (watch spec) rows may be dragged: starting a drag is blocked
 * when the selection includes any expanded variable (child) index.
 */
class WatchTreeWidget : public QTreeView
{
  public:
    explicit WatchTreeWidget(LuaDebuggerDialog *dlg, QWidget *parent = nullptr)
        : QTreeView(parent), dialog_(dlg)
    {
    }

  protected:
    void startDrag(Qt::DropActions supportedActions) override
    {
        const QModelIndexList list = selectedIndexes();
        for (const QModelIndex &ix : list)
        {
            if (ix.isValid() && ix.parent().isValid())
            {
                return;
            }
        }
        QTreeView::startDrag(supportedActions);
    }

    void dragMoveEvent(QDragMoveEvent *event) override
    {
        QTreeView::dragMoveEvent(event);
        if (!event->isAccepted())
        {
            return;
        }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        const QPoint pos = event->position().toPoint();
#else
        const QPoint pos = event->pos();
#endif
        const QModelIndex idx = indexAt(pos);
        if (idx.isValid() && idx.parent().isValid())
        {
            /* Nested (expanded variable) rows: do not make them drop targets. */
            event->ignore();
        }
    }

    void dropEvent(QDropEvent *event) override
    {
        if (dragDropMode() == QAbstractItemView::InternalMove &&
            (event->source() != this || !(event->possibleActions() & Qt::MoveAction)))
        {
            return;
        }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        const QPoint pos = event->position().toPoint();
#else
        const QPoint pos = event->pos();
#endif
        const QModelIndex raw = indexAt(pos);
        if (raw.isValid() && raw.parent().isValid())
        {
            event->ignore();
            return;
        }
        /* OnItem on a top-level index would insert as a child; treat like Above. */
        if (raw.isValid() && !raw.parent().isValid() &&
            dropIndicatorPosition() == QAbstractItemView::OnItem)
        {
            if (auto *m = qobject_cast<QStandardItemModel *>(model()))
            {
                const int destRow = raw.row();
                if (m->dropMimeData(event->mimeData(), Qt::MoveAction, destRow,
                                    0, QModelIndex()))
                {
                    event->setDropAction(Qt::MoveAction);
                    event->accept();
                }
                else
                {
                    event->ignore();
                }
            }
            else
            {
                event->ignore();
            }
            stopAutoScroll();
            setState(QAbstractItemView::NoState);
            if (viewport())
            {
                viewport()->update();
            }
            if (event->isAccepted() && dialog_)
            {
                LuaDebuggerDialog *const d = dialog_;
                QTimer::singleShot(0, d, [d]()
                                   { d->reapplyMonospacePanelFonts(); });
            }
            return;
        }
        QTreeView::dropEvent(event);
        if (event->isAccepted() && dialog_)
        {
            LuaDebuggerDialog *const d = dialog_;
            QTimer::singleShot(0, d, [d]() { d->reapplyMonospacePanelFonts(); });
        }
    }

  private:
    LuaDebuggerDialog *dialog_ = nullptr;
};

/** Variables tree: block inline editors on all columns (read-only display). */
class VariablesReadOnlyDelegate : public QStyledItemDelegate
{
  public:
    using QStyledItemDelegate::QStyledItemDelegate;

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override
    {
        Q_UNUSED(parent);
        Q_UNUSED(option);
        Q_UNUSED(index);
        return nullptr;
    }
};

/** Elide long values in the Value column (plan: Qt::ElideMiddle). */
class WatchValueColumnDelegate : public QStyledItemDelegate
{
  public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter *painter, const QStyleOptionViewItem &option,
               const QModelIndex &index) const override
    {
        QStyleOptionViewItem opt = option;
        initStyleOption(&opt, index);
        const QString full = index.data(Qt::DisplayRole).toString();
        const int avail = qMax(opt.rect.width() - 8, 1);
        opt.text = opt.fontMetrics.elidedText(full, Qt::ElideMiddle, avail);
        const QWidget *w = opt.widget;
        QStyle *style = w ? w->style() : QApplication::style();
        style->drawControl(QStyle::CE_ItemViewItem, &opt, painter, w);
    }

    /* The Value column is read-only: block the default item editor so
     * double-click / F2 cannot open a line edit here. The item's
     * Qt::ItemIsEditable flag is kept because column 0 (the Watch spec)
     * remains editable through WatchRootDelegate. */
    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override
    {
        Q_UNUSED(parent);
        Q_UNUSED(option);
        Q_UNUSED(index);
        return nullptr;
    }
};

static QStandardItem *
itemFromTreeIndex(const QTreeView *tree, const QModelIndex &index)
{
    auto *m = qobject_cast<QStandardItemModel *>(tree ? tree->model() : nullptr);
    return m ? m->itemFromIndex(index) : nullptr;
}

class WatchRootDelegate : public QStyledItemDelegate
{
  public:
    WatchRootDelegate(QTreeView *tree, LuaDebuggerDialog *dialog,
                      QObject *parent = nullptr)
        : QStyledItemDelegate(parent), tree_(tree), dialog_(dialog)
    {
    }

    QWidget *createEditor(QWidget *parent, const QStyleOptionViewItem &option,
                          const QModelIndex &index) const override;
    void setEditorData(QWidget *editor, const QModelIndex &index) const override;
    void setModelData(QWidget *editor, QAbstractItemModel *model,
                      const QModelIndex &index) const override;

  private:
    QTreeView *tree_;
    LuaDebuggerDialog *dialog_;
};

QWidget *
WatchRootDelegate::createEditor(QWidget *parent,
                                const QStyleOptionViewItem &option,
                                const QModelIndex &index) const
{
    Q_UNUSED(option);
    if (!tree_ || !index.isValid() || index.column() != 0)
    {
        return nullptr;
    }
    QStandardItem *it = itemFromTreeIndex(tree_, index);
    if (!it || it->parent() != nullptr)
    {
        return nullptr;
    }
    return new QLineEdit(parent);
}

void WatchRootDelegate::setEditorData(QWidget *editor,
                                      const QModelIndex &index) const
{
    auto *le = qobject_cast<QLineEdit *>(editor);
    if (!le || !tree_)
    {
        return;
    }
    QStandardItem *it = itemFromTreeIndex(tree_, index);
    if (!it)
    {
        return;
    }
    QString s = it->data(WatchSpecRole).toString();
    if (s.isEmpty())
    {
        s = it->text();
    }
    le->setText(s);
}

void WatchRootDelegate::setModelData(QWidget *editor, QAbstractItemModel *model,
                                     const QModelIndex &index) const
{
    Q_UNUSED(model);
    auto *le = qobject_cast<QLineEdit *>(editor);
    if (!le || !dialog_ || !tree_)
    {
        return;
    }
    QStandardItem *it = itemFromTreeIndex(tree_, index);
    if (!it)
    {
        return;
    }
    dialog_->commitWatchRootSpec(it, le->text());
}

} // namespace

LuaDebuggerDialog::LuaDebuggerDialog(QWidget *parent)
    : GeometryStateDialog(parent), ui(new Ui::LuaDebuggerDialog),
      eventLoop(nullptr), enabledCheckBox(nullptr), breakpointTabsPrimed(false),
      debuggerPaused(false), reloadDeferred(false), pauseInputFilter(nullptr),
      stackSelectionLevel(0), variablesSection(nullptr),
      watchSection(nullptr), stackSection(nullptr), breakpointsSection(nullptr),
      filesSection(nullptr), evalSection(nullptr), settingsSection(nullptr),
      variablesTree(nullptr), variablesModel(nullptr), watchTree(nullptr),
      watchModel(nullptr), stackTree(nullptr), stackModel(nullptr),
      fileTree(nullptr), fileModel(nullptr), breakpointsTree(nullptr),
      breakpointsModel(nullptr),
      evalInputEdit(nullptr), evalOutputEdit(nullptr), evalButton(nullptr),
      evalClearButton(nullptr), themeComboBox(nullptr), watchRemoveButton_(nullptr),
      watchRemoveAllButton_(nullptr), breakpointHeaderToggleButton_(nullptr),
      breakpointHeaderRemoveAllButton_(nullptr)
{
    _instance = this;
    setAttribute(Qt::WA_DeleteOnClose);
    ui->setupUi(this);
    ui->actionAddWatch->setShortcut(kCtxAddWatch);
    ui->actionAddWatch->setToolTip(
        tr("Add Watch (%1)")
            .arg(kCtxAddWatch.toString(QKeySequence::NativeText)));
    loadGeometry();

    lastOpenDirectory =
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    if (lastOpenDirectory.isEmpty())
    {
        lastOpenDirectory = QDir::homePath();
    }

    // Create collapsible sections with their content widgets
    createCollapsibleSections();

    fileTree->setRootIsDecorated(true);
    fileTree->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    fileTree->header()->setStretchLastSection(true);
    fileTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);

    // Compact toolbar styling with consistent icons
    ui->toolBar->setIconSize(QSize(18, 18));
    ui->toolBar->setToolButtonStyle(Qt::ToolButtonIconOnly);
    ui->toolBar->setStyleSheet(QStringLiteral(
        "QToolBar {"
        "  background-color: palette(window);"
        "  border: none;"
        "  spacing: 4px;"
        "  padding: 2px 4px;"
        "}"));
    ui->actionOpenFile->setIcon(StockIcon("document-open"));
    ui->actionSaveFile->setIcon(
        style()->standardIcon(QStyle::SP_DialogSaveButton));
    ui->actionContinue->setIcon(StockIcon("x-lua-debug-continue"));
    ui->actionStepOver->setIcon(StockIcon("x-lua-debug-step-over"));
    ui->actionStepIn->setIcon(StockIcon("x-lua-debug-step-in"));
    ui->actionStepOut->setIcon(StockIcon("x-lua-debug-step-out"));
    ui->actionRunToLine->setIcon(StockIcon("x-lua-debug-run-to-line"));
    ui->actionReloadLuaPlugins->setIcon(StockIcon("view-refresh"));
    ui->actionAddWatch->setIcon(StockIcon("list-add"));
    ui->actionFind->setIcon(StockIcon("edit-find"));
    ui->actionOpenFile->setToolTip(tr("Open Lua Script"));
    ui->actionSaveFile->setToolTip(tr("Save (%1)").arg(
        QKeySequence(QKeySequence::Save)
            .toString(QKeySequence::NativeText)));
    ui->actionContinue->setToolTip(tr("Continue execution (F5)"));
    ui->actionStepOver->setToolTip(tr("Step over (F10)"));
    ui->actionStepIn->setToolTip(tr("Step into (F11)"));
    ui->actionStepOut->setToolTip(tr("Step out (Shift+F11)"));
    ui->actionRunToLine->setToolTip(
        tr("Run to line (%1)")
            .arg(kCtxRunToLine.toString(QKeySequence::NativeText)));
    ui->actionReloadLuaPlugins->setToolTip(
        tr("Reload Lua Plugins (Ctrl+Shift+L)"));
    ui->actionAddWatch->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionFind->setToolTip(tr("Find in script (%1)")
                                   .arg(QKeySequence(QKeySequence::Find)
                                            .toString(QKeySequence::NativeText)));
    ui->actionGoToLine->setToolTip(tr("Go to line (%1)")
                                       .arg(kCtxGoToLine
                                            .toString(QKeySequence::NativeText)));
    ui->actionContinue->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStepOver->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStepIn->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionStepOut->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionReloadLuaPlugins->setShortcut(kCtxReloadLuaPlugins);
    ui->actionReloadLuaPlugins->setShortcutContext(
        Qt::WidgetWithChildrenShortcut);
    ui->actionSaveFile->setShortcut(QKeySequence::Save);
    ui->actionSaveFile->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionFind->setShortcut(QKeySequence::Find);
    ui->actionFind->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    ui->actionGoToLine->setShortcut(kCtxGoToLine);
    ui->actionGoToLine->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    folderIcon = StockIcon("folder");
    fileIcon = StockIcon("text-x-generic");

    // Toolbar controls - Checkbox for enable/disable
    // Order: Checkbox | Separator | Continue | Step Over/In/Out | Separator |
    // Open | Reload
    QAction *firstAction = ui->toolBar->actions().isEmpty()
                               ? nullptr
                               : ui->toolBar->actions().first();

    // Enable/Disable checkbox with colored icon
    enabledCheckBox = new QCheckBox(ui->toolBar);
    enabledCheckBox->setChecked(wslua_debugger_is_enabled());
    ui->toolBar->insertWidget(firstAction, enabledCheckBox);

    connect(enabledCheckBox, &QCheckBox::toggled, this,
            &LuaDebuggerDialog::onDebuggerToggled);
    connect(ui->actionContinue, &QAction::triggered, this,
            &LuaDebuggerDialog::onContinue);
    connect(ui->actionStepOver, &QAction::triggered, this,
            &LuaDebuggerDialog::onStepOver);
    connect(ui->actionStepIn, &QAction::triggered, this,
            &LuaDebuggerDialog::onStepIn);
    connect(ui->actionStepOut, &QAction::triggered, this,
            &LuaDebuggerDialog::onStepOut);
    connect(ui->actionRunToLine, &QAction::triggered, this,
            &LuaDebuggerDialog::onRunToLine);
    connect(ui->actionAddWatch, &QAction::triggered, this, [this]() {
        QString fromEditor;
        if (LuaDebuggerCodeView *cv = currentCodeView())
        {
            if (cv->textCursor().hasSelection())
            {
                fromEditor = cv->textCursor().selectedText().trimmed();
            }
        }
        if (fromEditor.isEmpty())
        {
            insertNewWatchRow(QString(), true);
        }
        else
        {
            insertNewWatchRow(fromEditor, false);
        }
    });
    connect(ui->actionOpenFile, &QAction::triggered, this,
            &LuaDebuggerDialog::onOpenFile);
    connect(ui->actionSaveFile, &QAction::triggered, this,
            &LuaDebuggerDialog::onSaveFile);
    connect(ui->actionFind, &QAction::triggered, this,
            &LuaDebuggerDialog::onEditorFind);
    connect(ui->actionGoToLine, &QAction::triggered, this,
            &LuaDebuggerDialog::onEditorGoToLine);
    connect(ui->actionReloadLuaPlugins, &QAction::triggered, this,
            &LuaDebuggerDialog::onReloadLuaPlugins);
    addAction(ui->actionContinue);
    addAction(ui->actionStepOver);
    addAction(ui->actionStepIn);
    addAction(ui->actionStepOut);
    addAction(ui->actionReloadLuaPlugins);
    addAction(ui->actionAddWatch);
    addAction(ui->actionSaveFile);
    addAction(ui->actionFind);
    addAction(ui->actionGoToLine);

    /* "Remove All Breakpoints" needs a real, dialog-wide shortcut so
     * Ctrl+Shift+F9 fires regardless of focus. Setting the keys only
     * on the right-click menu action (built on demand) made the
     * shortcut a label without a binding. */
    actionRemoveAllBreakpoints_ = new QAction(tr("Remove All Breakpoints"), this);
    actionRemoveAllBreakpoints_->setShortcut(kCtxRemoveAllBreakpoints);
    actionRemoveAllBreakpoints_->setShortcutContext(
        Qt::WidgetWithChildrenShortcut);
    actionRemoveAllBreakpoints_->setEnabled(false);
    connect(actionRemoveAllBreakpoints_, &QAction::triggered, this,
            &LuaDebuggerDialog::onClearBreakpoints);
    addAction(actionRemoveAllBreakpoints_);

    ui->luaDebuggerFindFrame->hide();
    ui->luaDebuggerGoToLineFrame->hide();

    // Tab Widget
    connect(ui->codeTabWidget, &QTabWidget::tabCloseRequested, this,
            &LuaDebuggerDialog::onCodeTabCloseRequested);
    connect(ui->codeTabWidget, &QTabWidget::currentChanged, this,
            [this](int)
            {
                updateSaveActionState();
                updateLuaEditorAuxFrames();
                updateBreakpointHeaderButtonState();
                updateContinueActionState();
            });

    // Breakpoints
    connect(breakpointsModel, &QStandardItemModel::itemChanged, this,
            &LuaDebuggerDialog::onBreakpointItemChanged);
    connect(breakpointsTree, &QTreeView::doubleClicked, this,
            &LuaDebuggerDialog::onBreakpointItemDoubleClicked);
    connect(breakpointsTree, &QTreeView::customContextMenuRequested, this,
            &LuaDebuggerDialog::onBreakpointContextMenuRequested);
    connect(breakpointsModel, &QAbstractItemModel::rowsInserted, this, [this]() {
        updateBreakpointHeaderButtonState();
    });
    connect(breakpointsModel, &QAbstractItemModel::rowsRemoved, this, [this]() {
        updateBreakpointHeaderButtonState();
    });
    connect(breakpointsModel, &QAbstractItemModel::modelReset, this, [this]() {
        updateBreakpointHeaderButtonState();
    });
    updateBreakpointHeaderButtonState();

    QHeaderView *breakpointHeader = breakpointsTree->header();
    breakpointHeader->setStretchLastSection(false);
    breakpointHeader->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    breakpointHeader->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    breakpointHeader->setSectionResizeMode(2, QHeaderView::Stretch);
    breakpointsModel->setHeaderData(2, Qt::Horizontal, tr("Location"));
    breakpointsTree->setColumnHidden(1, true);

    // Variables
    connect(variablesTree, &QTreeView::expanded, this,
            &LuaDebuggerDialog::onVariableItemExpanded);
    connect(variablesTree, &QTreeView::collapsed, this,
            &LuaDebuggerDialog::onVariableItemCollapsed);
    variablesTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(variablesTree, &QTreeView::customContextMenuRequested, this,
            &LuaDebuggerDialog::onVariablesContextMenuRequested);

    /* onWatchItemExpanded updates watchExpansion_ (the runtime expansion
     * map) and performs lazy child fill; onWatchItemCollapsed mirrors the
     * update on collapse. No storeWatchList() call is needed on expand /
     * collapse because expansion state is intentionally not persisted to
     * lua_debugger.json. */
    connect(watchTree, &QTreeView::expanded, this,
            &LuaDebuggerDialog::onWatchItemExpanded);
    connect(watchTree, &QTreeView::collapsed, this,
            &LuaDebuggerDialog::onWatchItemCollapsed);
    watchTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(watchTree, &QTreeView::customContextMenuRequested, this,
            &LuaDebuggerDialog::onWatchContextMenuRequested);
    watchTree->setItemDelegateForColumn(
        0, new WatchRootDelegate(watchTree, this, watchTree));
    watchTree->setItemDelegateForColumn(
        1, new WatchValueColumnDelegate(watchTree));
    watchTree->viewport()->installEventFilter(this);

    connect(watchTree->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &LuaDebuggerDialog::onWatchCurrentItemChanged);
    /* Header Remove button reflects the current selection; selectionChanged
     * fires for every selection mutation (click, Shift/Ctrl+click, keyboard).
     * No separate currentChanged hook is needed — the header buttons depend
     * on selectedRows(), not on the current index. */
    connect(watchTree->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, [this]() { updateWatchHeaderButtonState(); });
    connect(watchModel, &QAbstractItemModel::rowsInserted, this, [this]() {
        updateWatchHeaderButtonState();
    });
    connect(watchModel, &QAbstractItemModel::rowsRemoved, this, [this]() {
        updateWatchHeaderButtonState();
    });
    connect(watchModel, &QAbstractItemModel::modelReset, this, [this]() {
        updateWatchHeaderButtonState();
    });
    connect(variablesTree->selectionModel(),
            &QItemSelectionModel::currentChanged, this,
            &LuaDebuggerDialog::onVariablesCurrentItemChanged);
    updateWatchHeaderButtonState();

    // Files
    connect(fileTree, &QTreeView::doubleClicked, this,
            [this](const QModelIndex &index)
            {
                if (!fileModel || !index.isValid())
                {
                    return;
                }
                QStandardItem *item =
                    fileModel->itemFromIndex(index.sibling(index.row(), 0));
                if (!item || item->data(FileTreeIsDirectoryRole).toBool())
                {
                    return;
                }
                const QString path = item->data(FileTreePathRole).toString();
                if (!path.isEmpty())
                {
                    loadFile(path);
                }
            });
    fileTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(fileTree, &QTreeView::customContextMenuRequested, this,
            &LuaDebuggerDialog::onFileTreeContextMenuRequested);

    connect(stackTree, &QTreeView::doubleClicked, this,
            &LuaDebuggerDialog::onStackItemDoubleClicked);
    connect(stackTree->selectionModel(), &QItemSelectionModel::currentChanged,
            this, &LuaDebuggerDialog::onStackCurrentItemChanged);
    stackTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(stackTree, &QTreeView::customContextMenuRequested, this,
            &LuaDebuggerDialog::onStackContextMenuRequested);

    // Evaluate panel
    connect(evalButton, &QPushButton::clicked, this,
            &LuaDebuggerDialog::onEvaluate);
    connect(evalClearButton, &QPushButton::clicked, this,
            &LuaDebuggerDialog::onEvalClear);

    configureVariablesTreeColumns();
    configureWatchTreeColumns();
    configureStackTreeColumns();
    applyMonospaceFonts();
    /* Seed the accent + flash brushes from the initial palette so the very
     * first pause shows correctly themed cues without having to wait for a
     * preference / color-scheme change. */
    refreshChangedValueBrushes();

    /*
     * Register our reload callback with the debugger core.
     * This callback is invoked by wslua_reload_plugins() BEFORE
     * Lua scripts are reloaded, allowing us to refresh our cached
     * script content from disk.
     */
    wslua_debugger_register_reload_callback(
        LuaDebuggerDialog::onLuaReloadCallback);

    /*
     * Register a callback to be notified AFTER Lua plugins are reloaded.
     * This allows us to refresh the file tree with newly loaded scripts.
     */
    wslua_debugger_register_post_reload_callback(
        LuaDebuggerDialog::onLuaPostReloadCallback);

    /*
     * Register a callback to be notified when a Lua script is loaded.
     * This allows us to add the script to the file tree immediately.
     */
    wslua_debugger_register_script_loaded_callback(
        LuaDebuggerDialog::onScriptLoadedCallback);

    if (mainApp)
    {
        connect(mainApp, &MainApplication::zoomMonospaceFont, this,
                &LuaDebuggerDialog::onMonospaceFontUpdated, Qt::UniqueConnection);
        connect(mainApp, &MainApplication::appInitialized, this,
                &LuaDebuggerDialog::onMainAppInitialized, Qt::UniqueConnection);
        connect(mainApp, &MainApplication::preferencesChanged, this,
                &LuaDebuggerDialog::onPreferencesChanged, Qt::UniqueConnection);
        /*
         * Connect to colorsChanged signal to update code view themes when
         * Wireshark's color scheme changes. This is important when the debugger
         * theme preference is set to "Auto (follow color scheme)".
         */
        connect(mainApp, &MainApplication::colorsChanged, this,
                &LuaDebuggerDialog::onColorsChanged, Qt::UniqueConnection);
        if (mainApp->isInitialized())
        {
            onMainAppInitialized();
        }
    }

    refreshAvailableScripts();
    refreshDebuggerStateUi();

    /*
     * Apply all settings from JSON file (theme, font, sections, splitters,
     * breakpoints). This is done after all widgets are created.
     */
    applyDialogSettings();
    updateBreakpoints();
    updateSaveActionState();
    updateLuaEditorAuxFrames();

    installDescendantShortcutFilters();

    /* Reconcile with any live capture in progress AFTER all init paths
     * that may have re-enabled the core debugger (applyDialogSettings
     * / updateBreakpoints, including ensureDebuggerEnabledForActiveBreakpoints). */
    reconcileWithLiveCaptureOnStartup();
}

LuaDebuggerDialog::~LuaDebuggerDialog()
{
    /*
     * Persist JSON only from closeEvent(); if the dialog is destroyed without
     * a normal close (rare), flush once here.
     */
    if (!luaDebuggerJsonSaved_)
    {
        storeDialogSettings();
        saveSettingsFile();
    }

    /*
     * Unregister our reload callbacks when the dialog is destroyed.
     */
    wslua_debugger_register_reload_callback(NULL);
    wslua_debugger_register_post_reload_callback(NULL);
    wslua_debugger_register_script_loaded_callback(NULL);

    delete ui;
    _instance = nullptr;
}

void LuaDebuggerDialog::createCollapsibleSections()
{
    QSplitter *splitter = ui->leftSplitter;

    // --- Variables Section ---
    variablesSection = new CollapsibleSection(tr("Variables"), this);
    variablesSection->setToolTip(
        tr("<p><b>Locals</b><br/>"
           "Parameters and local variables for the selected stack frame.</p>"
           "<p><b>Upvalues</b><br/>"
           "Outer variables that this function actually uses from surrounding code. "
           "Anything the function does not reference does not appear here.</p>"
           "<p><b>Globals</b><br/>"
           "Names from the global environment table.</p>"
           "<p>Values that differ from the previous pause are drawn in a "
           "<b>bold accent color</b>, and briefly flash on the pause that "
           "introduced the change.</p>"));
    variablesModel = new QStandardItemModel(this);
    variablesModel->setColumnCount(3);
    variablesModel->setHorizontalHeaderLabels({tr("Name"), tr("Value"), tr("Type")});
    variablesTree = new QTreeView();
    variablesTree->setModel(variablesModel);
    /* Type is folded into Name/Value tooltips; keep the column for model data. */
    variablesTree->setColumnHidden(2, true);
    variablesTree->setItemDelegate(
        new VariablesReadOnlyDelegate(variablesTree));
    variablesTree->setUniformRowHeights(true);
    variablesTree->setWordWrap(false);
    variablesSection->setContentWidget(variablesTree);
    variablesSection->setExpanded(true);
    splitter->addWidget(variablesSection);

    /*
     * Watch panel: two columns; formats, expansion persistence, depth cap
     * WSLUA_WATCH_MAX_PATH_SEGMENTS, drag reorder, error styling, muted em dash
     * when no live value.
     */
    // --- Watch Section ---
    watchSection = new CollapsibleSection(tr("Watch"), this);
    watchSection->setToolTip(
        tr("<p>Each row is a <b>Variables-tree path</b>, not a Lua "
           "expression. Accepted forms:</p>"
           "<ul>"
           "<li>Section-qualified: <code>Locals.<i>name</i></code>, "
           "<code>Upvalues.<i>name</i></code>, "
           "<code>Globals.<i>name</i></code>.</li>"
           "<li>Section root alone: <code>Locals</code>, "
           "<code>Upvalues</code>, <code>Globals</code> "
           "(<code>_G</code> is an alias for <code>Globals</code>).</li>"
           "<li>Unqualified name: resolved in "
           "<b>Locals &rarr; Upvalues &rarr; Globals</b> order; the row "
           "tooltip shows which section matched.</li>"
           "</ul>"
           "<p>After the first segment, chain <code>.field</code> or "
           "bracket keys &mdash; integer "
           "(<code>[1]</code>, <code>[-1]</code>, <code>[0x1F]</code>), "
           "boolean (<code>[true]</code>), or short-literal string "
           "(<code>[\"key\"]</code>, <code>['k']</code>). Depth is capped "
           "at 32 segments. Use the <b>Evaluate</b> panel below for "
           "arbitrary Lua expressions.</p>"
           "<p>Values are only read while the debugger is "
           "<b>paused</b>; otherwise the Value column shows a muted "
           "em dash. Values that differ from the previous pause are "
           "drawn in a <b>bold accent color</b>, and briefly flash on "
           "the pause that introduced the change.</p>"
           "<p>Double-click or press <b>F2</b> to edit a row; "
           "<b>Delete</b> removes it; drag rows to reorder.</p>"));
    watchTree = new WatchTreeWidget(this);
    watchModel = new WatchItemModel(this);
    watchModel->setColumnCount(2);
    watchModel->setHorizontalHeaderLabels({tr("Watch"), tr("Value")});
    watchTree->setModel(watchModel);
    watchTree->setRootIsDecorated(true);
    watchTree->setDragDropMode(QAbstractItemView::InternalMove);
    watchTree->setDefaultDropAction(Qt::MoveAction);
    /* Row selection + full-row focus: horizontal drop line spans all columns. */
    watchTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    watchTree->setAllColumnsShowFocus(true);
    watchTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    watchTree->setUniformRowHeights(true);
    watchTree->setWordWrap(false);
    {
        auto *watchWrap = new QWidget();
        auto *watchOuter = new QVBoxLayout(watchWrap);
        watchOuter->setContentsMargins(0, 0, 0, 0);
        watchOuter->setSpacing(4);
        watchOuter->addWidget(watchTree, 1);
        watchSection->setContentWidget(watchWrap);
    }
    {
        const int hdrH = watchSection->titleButtonHeight();
        const QFont hdrTitleFont = watchSection->titleButtonFont();
        auto *const watchHeaderBtnRow = new QWidget(watchSection);
        auto *const watchHeaderBtnLayout = new QHBoxLayout(watchHeaderBtnRow);
        watchHeaderBtnLayout->setContentsMargins(0, 0, 0, 0);
        watchHeaderBtnLayout->setSpacing(4);
        watchHeaderBtnLayout->setAlignment(Qt::AlignVCenter);
        QToolButton *const watchAddBtn = new QToolButton(watchHeaderBtnRow);
        styleLuaDebuggerHeaderPlusMinusButton(watchAddBtn, hdrH, hdrTitleFont);
        watchAddBtn->setText(kLuaDbgHeaderPlus);
        watchAddBtn->setAutoRaise(true);
        watchAddBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        /* Compute tooltip directly from the action's shortcut so this block
         * does not depend on actionAddWatch's tooltip having already been set. */
        watchAddBtn->setToolTip(
            tr("Add Watch (%1)")
                .arg(ui->actionAddWatch->shortcut()
                         .toString(QKeySequence::NativeText)));
        connect(watchAddBtn, &QToolButton::clicked, ui->actionAddWatch,
                &QAction::trigger);
        QToolButton *const watchRemBtn = new QToolButton(watchHeaderBtnRow);
        watchRemoveButton_ = watchRemBtn;
        styleLuaDebuggerHeaderPlusMinusButton(watchRemBtn, hdrH, hdrTitleFont);
        watchRemBtn->setText(kLuaDbgHeaderMinus);
        watchRemBtn->setAutoRaise(true);
        watchRemBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        watchRemBtn->setEnabled(false);
        watchRemBtn->setToolTip(
            tr("Remove Watch (%1)")
                .arg(QKeySequence(QKeySequence::Delete)
                         .toString(QKeySequence::NativeText)));
        QToolButton *const watchRemAllBtn = new QToolButton(watchHeaderBtnRow);
        watchRemoveAllButton_ = watchRemAllBtn;
        styleLuaDebuggerHeaderRemoveAllButton(watchRemAllBtn, hdrH);
        watchRemAllBtn->setAutoRaise(true);
        watchRemAllBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        watchRemAllBtn->setEnabled(false);
        watchRemAllBtn->setToolTip(
            tr("Remove All Watches (%1)")
                .arg(
                    kCtxWatchRemoveAll.toString(QKeySequence::NativeText)));
        watchHeaderBtnLayout->addWidget(watchAddBtn);
        watchHeaderBtnLayout->addWidget(watchRemBtn);
        watchHeaderBtnLayout->addWidget(watchRemAllBtn);
        connect(watchRemBtn, &QToolButton::clicked, this, [this]() {
            const QList<QStandardItem *> del = selectedWatchRootItemsForRemove();
            if (!del.isEmpty())
            {
                deleteWatchRows(del);
            }
        });
        connect(watchRemAllBtn, &QToolButton::clicked, this,
                &LuaDebuggerDialog::removeAllWatchTopLevelItems);
        watchSection->setHeaderTrailingWidget(watchHeaderBtnRow);
    }
    watchSection->setExpanded(true);
    splitter->addWidget(watchSection);

    // --- Stack Trace Section ---
    stackSection = new CollapsibleSection(tr("Stack Trace"), this);
    stackModel = new QStandardItemModel(this);
    stackModel->setColumnCount(2);
    stackModel->setHorizontalHeaderLabels({tr("Function"), tr("Location")});
    stackTree = new QTreeView();
    stackTree->setModel(stackModel);
    stackTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    stackTree->setRootIsDecorated(true);
    stackTree->setToolTip(
        tr("Select a row to inspect locals and upvalues for that frame. "
           "Double-click a Lua frame to open its source location."));
    stackSection->setContentWidget(stackTree);
    stackSection->setExpanded(true);
    splitter->addWidget(stackSection);

    // --- Breakpoints Section ---
    breakpointsSection = new CollapsibleSection(tr("Breakpoints"), this);
    breakpointsModel = new QStandardItemModel(this);
    breakpointsModel->setColumnCount(3);
    breakpointsModel->setHorizontalHeaderLabels(
        {tr("Active"), tr("Line"), tr("File")});
    breakpointsTree = new QTreeView();
    breakpointsTree->setModel(breakpointsModel);
    breakpointsTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    breakpointsTree->setRootIsDecorated(false);
    breakpointsTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    breakpointsTree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    breakpointsTree->setAllColumnsShowFocus(true);
    breakpointsTree->setContextMenuPolicy(Qt::CustomContextMenu);
    breakpointsSection->setContentWidget(breakpointsTree);
    {
        const int hdrH = breakpointsSection->titleButtonHeight();
        auto *const bpHeaderBtnRow = new QWidget(breakpointsSection);
        auto *const bpHeaderBtnLayout = new QHBoxLayout(bpHeaderBtnRow);
        bpHeaderBtnLayout->setContentsMargins(0, 0, 0, 0);
        bpHeaderBtnLayout->setSpacing(4);
        bpHeaderBtnLayout->setAlignment(Qt::AlignVCenter);
        QToolButton *const bpTglBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderToggleButton_ = bpTglBtn;
        styleLuaDebuggerHeaderBreakpointToggleButton(bpTglBtn, hdrH);
        bpTglBtn->setIcon(
            luaDbgBreakpointHeaderIconForMode(
                nullptr, LuaDbgBpHeaderIconMode::NoBreakpoints, hdrH,
                bpTglBtn->devicePixelRatioF()));
        bpTglBtn->setAutoRaise(true);
        bpTglBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        bpTglBtn->setEnabled(false);
        bpTglBtn->setToolTip(tr("No breakpoints"));
        QToolButton *const bpRemAllBtn = new QToolButton(bpHeaderBtnRow);
        breakpointHeaderRemoveAllButton_ = bpRemAllBtn;
        styleLuaDebuggerHeaderRemoveAllButton(bpRemAllBtn, hdrH);
        bpRemAllBtn->setAutoRaise(true);
        bpRemAllBtn->setStyleSheet(kLuaDbgHeaderToolButtonStyle);
        bpRemAllBtn->setEnabled(false);
        bpRemAllBtn->setToolTip(
            tr("Remove All Breakpoints (%1)")
                .arg(
                    kCtxRemoveAllBreakpoints.toString(
                        QKeySequence::NativeText)));
        bpHeaderBtnLayout->addWidget(bpTglBtn);
        bpHeaderBtnLayout->addWidget(bpRemAllBtn);
        connect(bpTglBtn, &QToolButton::clicked, this,
                &LuaDebuggerDialog::toggleAllBreakpointsActiveFromHeader);
        connect(bpRemAllBtn, &QToolButton::clicked, this,
                &LuaDebuggerDialog::onClearBreakpoints);
        breakpointsSection->setHeaderTrailingWidget(bpHeaderBtnRow);
    }
    breakpointsSection->setExpanded(true);
    splitter->addWidget(breakpointsSection);

    // --- Files Section ---
    filesSection = new CollapsibleSection(tr("Files"), this);
    fileModel = new QStandardItemModel(this);
    fileModel->setColumnCount(1);
    fileModel->setHorizontalHeaderLabels({tr("Files")});
    fileTree = new QTreeView();
    fileTree->setModel(fileModel);
    fileTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fileTree->setRootIsDecorated(false);
    filesSection->setContentWidget(fileTree);
    filesSection->setExpanded(true);
    splitter->addWidget(filesSection);

    // --- Evaluate Section ---
    evalSection = new CollapsibleSection(tr("Evaluate"), this);
    QWidget *evalWidget = new QWidget();
    QVBoxLayout *evalMainLayout = new QVBoxLayout(evalWidget);
    evalMainLayout->setContentsMargins(0, 0, 0, 0);
    evalMainLayout->setSpacing(4);

    QSplitter *evalSplitter = new QSplitter(Qt::Vertical);
    evalInputEdit = new QPlainTextEdit();
    evalInputEdit->setPlaceholderText(
        tr("Enter Lua expression (prefix with = to return value)"));
    evalInputEdit->setToolTip(
        tr("<b>Lua Expression Evaluation</b><br><br>"
           "Code is executed using <code>lua_pcall()</code> in a protected "
           "environment. "
           "Runtime errors are caught and displayed in the output.<br><br>"
           "<b>Prefix with <code>=</code></b> to return a value (e.g., "
           "<code>=my_var</code>).<br><br>"
           "<b>What works:</b><ul>"
           "<li>Read/modify global variables (<code>_G.x = 42</code>)</li>"
           "<li>Modify table contents (<code>my_table.field = 99</code>)</li>"
           "<li>Call functions and inspect return values</li>"
           "</ul>"
           "<b>Limitations:</b><ul>"
           "<li>Local variables cannot be modified directly (use "
           "<code>debug.setlocal()</code>)</li>"
           "<li>Long-running expressions are automatically aborted</li>"
           "<li><b>Warning:</b> Changes to globals persist and can affect "
           "ongoing dissection</li>"
           "</ul>"));
    evalOutputEdit = new QPlainTextEdit();
    evalOutputEdit->setReadOnly(true);
    evalOutputEdit->setPlaceholderText(tr("Output"));
    evalSplitter->addWidget(evalInputEdit);
    evalSplitter->addWidget(evalOutputEdit);
    evalMainLayout->addWidget(evalSplitter, 1);

    QHBoxLayout *evalButtonLayout = new QHBoxLayout();
    evalButton = new QPushButton(tr("Evaluate"));
    evalButton->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_Return));
    evalButton->setToolTip(tr("Execute the Lua code (Ctrl+Return)"));
    evalClearButton = new QPushButton(tr("Clear"));
    evalClearButton->setToolTip(tr("Clear input and output"));
    evalButtonLayout->addWidget(evalButton);
    evalButtonLayout->addWidget(evalClearButton);
    evalButtonLayout->addStretch();
    evalMainLayout->addLayout(evalButtonLayout);

    evalSection->setContentWidget(evalWidget);
    evalSection->setExpanded(false);
    splitter->addWidget(evalSection);

    // --- Settings Section ---
    settingsSection = new CollapsibleSection(tr("Settings"), this);
    QWidget *settingsWidget = new QWidget();
    QFormLayout *settingsLayout = new QFormLayout(settingsWidget);
    settingsLayout->setContentsMargins(4, 4, 4, 4);
    settingsLayout->setSpacing(6);

    themeComboBox = new QComboBox();
    themeComboBox->addItem(tr("Auto (follow color scheme)"),
                           WSLUA_DEBUGGER_THEME_AUTO);
    themeComboBox->addItem(tr("Dark"), WSLUA_DEBUGGER_THEME_DARK);
    themeComboBox->addItem(tr("Light"), WSLUA_DEBUGGER_THEME_LIGHT);
    themeComboBox->setToolTip(tr("Color theme for the code editor"));
    // Theme will be set by applyDialogSettings() later
    settingsLayout->addRow(tr("Code View Theme:"), themeComboBox);

    connect(themeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LuaDebuggerDialog::onThemeChanged);

    settingsSection->setContentWidget(settingsWidget);
    settingsSection->setExpanded(false);
    splitter->addWidget(settingsSection);

    QList<int> sizes;
    int headerH = variablesSection->headerHeight();
    sizes << 120 << 70 << 100 << headerH << 80 << headerH << headerH;
    splitter->setSizes(sizes);

    /* Tell QSplitter that every section is allowed to absorb surplus
     * vertical space. Collapsed sections cap themselves at headerHeight via
     * setMaximumHeight, so this stretch only takes effect for sections that
     * are actually expanded; without it, expanding one section while the
     * others stay collapsed leaves the leftover height unallocated and the
     * expanded section never grows past its savedHeight. */
    for (int i = 0; i < splitter->count(); ++i)
        splitter->setStretchFactor(i, 1);

    /* Trailing stretch in leftPanelLayout: absorbs leftover vertical space
     * when every section is collapsed (in tandem with leftSplitter being
     * clamped to its content height by updateLeftPanelStretch()), so the
     * toolbar and section headers stay pinned to the top of the panel.
     * When at least one section is expanded the stretch is set to 0 and
     * the splitter takes all extra height. */
    ui->leftPanelLayout->addStretch(0);

    const QList<CollapsibleSection *> allSections = {
        variablesSection, watchSection,    stackSection, breakpointsSection,
        filesSection,     evalSection,     settingsSection};
    for (CollapsibleSection *s : allSections)
        connect(s, &CollapsibleSection::toggled,
                this, &LuaDebuggerDialog::updateLeftPanelStretch);
    updateLeftPanelStretch();
}

void LuaDebuggerDialog::updateLeftPanelStretch()
{
    if (!ui || !ui->leftSplitter || !ui->leftPanelLayout)
        return;

    const QList<CollapsibleSection *> sections = {
        variablesSection, watchSection,    stackSection, breakpointsSection,
        filesSection,     evalSection,     settingsSection};

    bool anyExpanded = false;
    int contentH = 0;
    int counted = 0;
    for (CollapsibleSection *s : sections)
    {
        if (!s)
            continue;
        if (s->isExpanded())
            anyExpanded = true;
        contentH += s->headerHeight();
        ++counted;
    }
    if (counted > 1)
        contentH += (counted - 1) * ui->leftSplitter->handleWidth();

    const int splitterIdx = ui->leftPanelLayout->indexOf(ui->leftSplitter);
    /* The trailing stretch is the last layout item appended in
     * createCollapsibleSections(). */
    const int stretchIdx = ui->leftPanelLayout->count() - 1;
    if (splitterIdx < 0 || stretchIdx < 0 || splitterIdx == stretchIdx)
        return;

    if (anyExpanded)
    {
        ui->leftSplitter->setMaximumHeight(QWIDGETSIZE_MAX);
        ui->leftPanelLayout->setStretch(splitterIdx, 1);
        ui->leftPanelLayout->setStretch(stretchIdx, 0);
    }
    else
    {
        ui->leftSplitter->setMaximumHeight(contentH);
        ui->leftPanelLayout->setStretch(splitterIdx, 0);
        ui->leftPanelLayout->setStretch(stretchIdx, 1);
    }
}

LuaDebuggerDialog *LuaDebuggerDialog::instance(QWidget *parent)
{
    if (!_instance)
    {
        QWidget *resolved_parent = parent;
        if (!resolved_parent && mainApp && mainApp->isInitialized())
        {
            resolved_parent = mainApp->mainWindow();
        }
        new LuaDebuggerDialog(resolved_parent);
    }
    return _instance;
}

void LuaDebuggerDialog::handlePause(const char *file_path, int64_t line)
{
    // Prevent deletion while in event loop
    setAttribute(Qt::WA_DeleteOnClose, false);

    // Bring to front
    show();
    raise();
    activateWindow();

    QString normalizedPath = normalizedFilePath(QString::fromUtf8(file_path));
    ensureFileTreeEntry(normalizedPath);
    LuaDebuggerCodeView *view = loadFile(normalizedPath);
    if (view)
    {
        view->setCurrentLine(static_cast<qint32>(line));
    }

    debuggerPaused = true;

    /* Cancel any deferred "Watch column shows —" placeholder still pending
     * from the previous resume (typical for runDebuggerStep): we are
     * about to repaint the Watch tree with real values, so the user must
     * never see it briefly flip to "—" and back to the same value. */
    ++watchPlaceholderEpoch_;

    /* One snapshot per pause entry: rotate last pause's "current" values
     * into the baseline so every refresh below compares against them.
     * This MUST happen before any refresh that walks the Watch / Variables
     * trees, otherwise the very first refresh would overwrite
     * *Current_ with this pause's values and the snapshot would then
     * rotate those values into *Baseline_, losing the "changed since last
     * pause" signal. updateWidgets() calls refreshWatchDisplay(), so it
     * counts as such a refresh and must be preceded by the rotation.
     *
     * isPauseEntryRefresh_ is also set here so that every refresh inside
     * the pause-entry sequence — including the one triggered by
     * updateWidgets() — gets the transient row-flash in addition to the
     * persistent bold accent. Subsequent intra-pause refreshes
     * (stack-frame switch, theme change, watch edit, eval) read from the
     * same baseline and stay stable. */
    snapshotBaselinesOnPauseEntry();
    /* Decide whether the just-rotated baseline still describes the same
     * Lua function at frame 0. It does not after a call or return, and the
     * cue must be suppressed for this one pause; see
     * changeHighlightAllowed() and updatePauseEntryFrameIdentity(). Must
     * run before the first refresh below so the gate is in effect for
     * every paint in the pause-entry sequence. */
    updatePauseEntryFrameIdentity();
    isPauseEntryRefresh_ = true;
    updateWidgets();

    stackSelectionLevel = 0;
    /* Anchor the changed-value cue to the level we're about to paint at;
     * intra-pause stack-frame switches will compare stackSelectionLevel
     * against this and suppress the cue at every other level (see
     * changeHighlightAllowed()). */
    pauseEntryStackLevel_ = stackSelectionLevel;
    updateStack();
    if (variablesModel)
        {
            variablesModel->removeRows(0, variablesModel->rowCount());
        }
    updateVariables(nullptr, QString());
    restoreVariablesExpansionState();
    refreshWatchDisplay();
    isPauseEntryRefresh_ = false;

    /*
     * If an event loop is already running (e.g. we were called from a step
     * action which triggered an immediate re-pause), reuse it instead of nesting.
     * The outer loop.exec() is still on the stack and will return when we
     * eventually quit it via Continue or close.
     *
     * The outer frame already set up UI freezing (disabled top-levels,
     * overlay, application event filter) and suspended the live-capture
     * pipe source; the re-entrant call leaves all that in place.
     */
    if (eventLoop)
    {
        return;
    }

    /*
     * Freeze the rest of the application while Lua is suspended.
     *
     * The main window's dissection/capture state and any Lua-owned
     * objects that the paused dissector still references must not be
     * mutated by the main application while we are on the Lua call
     * stack. Lua tap/dissector callbacks hold pointers into packet
     * scopes, tvbs, and the Lua state itself; letting the main
     * application continue leads to use-after-free and VM reentrancy.
     *
     * Strategy:
     *   1. setEnabled(false) every visible top-level except this dialog
     *      so existing dialogs (I/O Graph, Conversations, Follow Stream,
     *      Preferences, Lua-spawned TextWindows, …) visibly gray out
     *      and reject input.
     *   2. Install an application-level event filter as defense in
     *      depth for widgets created DURING the pause and for events
     *      that bypass the enabled check (e.g. WM-delivered Close).
     *   3. Show a translucent overlay on the main window with a
     *      pulsing pause glyph so the user can tell the frozen UI is
     *      intentional rather than hung.
     *   4. Detach the live-capture pipe GSource from glib's main
     *      context so no new packets are delivered (and therefore no
     *      redissection) while Lua is paused. The GSource is kept
     *      alive via g_source_ref and reattached on resume, so no
     *      packets are lost.
     *
     * All four steps are guarded by the outermost-frame check above so
     * a re-entrant pause does not double-disable or flicker the
     * overlay.
     */
    /* Mark the freeze as active; endPauseFreeze() will flip this back
     * on the first call (either from handlePause's post-loop or from
     * closeEvent during a main-window close while paused). */
    pauseUnfrozen_ = false;

    frozenTopLevels.clear();
    /* Build the set of widgets we must NOT disable: ourselves, plus
     * every parent up the chain. Qt's setEnabled(false) propagates
     * through QObject::children() *across* window boundaries, so
     * disabling the main window would also disable this dialog
     * (toolbar, Continue/Step actions, watch tree, eval pane) and
     * make stepping impossible. We walk parentWidget() manually
     * because QWidget::isAncestorOf() stops at window boundaries —
     * since this dialog is a Qt::Window, isAncestorOf() would
     * incorrectly report that the main window is NOT an ancestor.
     *
     * The main window remains protected from user input by the
     * PauseInputFilter installed below and is visually marked as
     * paused by the LuaDebuggerPauseOverlay. */
    QSet<QWidget *> ancestors;
    ancestors.insert(this);
    for (QWidget *p = parentWidget(); p; p = p->parentWidget()) {
        ancestors.insert(p);
    }

    const QList<QWidget *> top_level_widgets = QApplication::topLevelWidgets();
    for (QWidget *w : top_level_widgets)
    {
        if (!w || ancestors.contains(w))
            continue;
        if (!w->isVisible() || !w->isEnabled())
            continue;
        w->setEnabled(false);
        frozenTopLevels.append(QPointer<QWidget>(w));
    }

    MainWindow *mw = mainApp ? mainApp->mainWindow() : nullptr;

    /* Disable every QAction outside the debugger dialog across the
     * pause: menu items, toolbar buttons, and keyboard shortcuts.
     *
     * Why we cannot rely solely on the QApplication PauseInputFilter:
     *
     *   - On macOS the menu bar is native (NSMenuBar/NSMenuItem).
     *     Native menu clicks fire the NSMenuItem's action selector
     *     and Qt translates that directly to QAction::triggered()
     *     WITHOUT generating QMouseEvents — so the event filter
     *     never sees them. The same path is used for menu keyboard
     *     equivalents (Cmd+I, Cmd+S, …).
     *   - Qt::ApplicationShortcut actions on background top-level
     *     dialogs can fire from any focused window, including the
     *     debugger dialog, even though those background dialogs are
     *     setEnabled(false).
     *
     * A disabled QAction grays out and inerts every UI representation
     * of the action. Walking every top-level widget except the
     * debugger dialog and disabling all QAction descendants gives a
     * single, unambiguous "everything outside the debugger is inert"
     * state — the user is not left guessing which menu item or
     * shortcut is still live. */
    frozenActions.clear();
    /* Snapshot every QAction that lives inside the debugger dialog's
     * QObject subtree so we never disable any of them, regardless of
     * which top-level we walk below. The dialog is parented to the
     * main window, so QObject::findChildren<QAction *>() on the main
     * window recursively returns every debugger action (Continue,
     * Step Over/In/Out, Reload, Add Watch, Open/Save File, Find, Go
     * to Line, …) in addition to the main window's own. Without this
     * exclusion list those would get setEnabled(false) along with
     * everything else and the user could not control the debugger
     * while paused. */
    const QList<QAction *> debugger_actions = this->findChildren<QAction *>();
    QSet<QAction *> debugger_action_set;
    debugger_action_set.reserve(debugger_actions.size());
    for (QAction *a : debugger_actions)
    {
        if (a)
            debugger_action_set.insert(a);
    }
    for (QWidget *tlw : top_level_widgets)
    {
        if (!tlw || tlw == this)
            continue;
        const QList<QAction *> actions = tlw->findChildren<QAction *>();
        for (QAction *a : actions)
        {
            if (a && a->isEnabled() && !debugger_action_set.contains(a))
            {
                a->setEnabled(false);
                frozenActions.append(QPointer<QAction>(a));
            }
        }
    }

    /* Disable the main window's central widget subtree — packet list,
     * details tree, byte view, and whatever sits in the splitters
     * around them. The pause overlay is a plain child widget with
     * Qt::WA_TransparentForMouseEvents, so any click that reaches
     * the widget under it is also handed straight through; the
     * QApplication-level PauseInputFilter is supposed to swallow
     * those but a disabled widget is the authoritative fence: Qt
     * refuses to deliver user input to it or any descendant
     * regardless of event source. A disabled subtree also re-enables
     * paint via Qt's update() cascade on setEnabled(true) in the
     * resume path, which is what gets the packet list out of its
     * "stuck paused" state — the UpdateRequest filter swallowed every
     * main-window paint during the pause, so without a forced
     * repaint on resume the viewport backing store is left showing
     * whatever it had when the filter went up. centralWidget() is
     * NOT an ancestor of this dialog (the dialog is parented to the
     * QMainWindow, not to its central widget) so disabling it does
     * not inert the debugger. */
    frozenCentralWidget.clear();
    if (mw)
    {
        if (QWidget *cw = mw->centralWidget())
        {
            if (cw->isEnabled())
            {
                cw->setEnabled(false);
                frozenCentralWidget = QPointer<QWidget>(cw);
            }
        }
    }

    /* Create the pause overlay as a child of the main window and size
     * it to cover the entire main-window client area (menu bar and
     * toolbars included — the vignette reads more unified that way).
     * The overlay is mouse-transparent and has no widget children of
     * its own, so input remains governed by the setEnabled() fence
     * and the PauseInputFilter installed below.
     *
     * Ordering matters — both are deliberate:
     *
     *  1. Create / show / repaint BEFORE PauseInputFilter is
     *     installed. show() only *schedules* a paint by posting a
     *     QEvent::UpdateRequest on the main window; the filter we
     *     install next swallows every main-window UpdateRequest for
     *     the rest of the pause, so a queued paint from show() alone
     *     would never actually run and the overlay would stay
     *     invisible. repaint() bypasses the event loop entirely —
     *     it paints synchronously onto the main window's backing
     *     store before the filter exists — so the overlay becomes
     *     visible on the very same stack frame as the pause setup.
     *
     *  2. Once painted, the overlay is otherwise static — no
     *     animation. The one thing that does still reach the main
     *     window while paused is the window manager's resize
     *     (QEvent::Resize is not in PauseInputFilter's filtered set),
     *     so the overlay installs its own event filter on the parent
     *     to track the new geometry and synchronously repaint. See
     *     LuaDebuggerPauseOverlay::eventFilter. */
    if (mw && !pauseOverlay) {
        pauseOverlay = new LuaDebuggerPauseOverlay(mw);
        pauseOverlay->raise();
        pauseOverlay->show();
        pauseOverlay->repaint();
    }

    /* Keep the debugger dialog in front — it is the only top-level
     * the user is supposed to interact with while paused. */
    this->raise();
    this->activateWindow();

    pauseInputFilter = new PauseInputFilter(this, mw);
    qApp->installEventFilter(pauseInputFilter);

    /* Note: live capture cannot be running here. The live-capture
     * observer (onCaptureSessionEvent) force-disables the debugger
     * for the duration of any capture, so wslua_debug_hook never
     * dispatches into us while dumpcap is feeding the pipe. That is
     * the only sane policy: suspending the pipe GSource for the
     * duration of the pause is fragile (g_source_destroy frees the
     * underlying GIOChannel, breaking any later resume) and racing
     * the dumpcap child while a Lua dissector is on the C stack
     * invites re-entrant dissection of partially-read packets. */

    QEventLoop loop;
    eventLoop = &loop;

    /*
     * If the parent window is destroyed while we're paused (e.g. the
     * application is shutting down), quit the event loop so the Lua
     * call stack can unwind cleanly.
     */
    QPointer<QWidget> parentGuard(parentWidget());
    QMetaObject::Connection parentConn;
    if (parentGuard) {
        parentConn = connect(parentGuard, &QObject::destroyed, &loop,
                             &QEventLoop::quit);
    }

    // Enter event loop - blocks until Continue or dialog close
    loop.exec();

    if (parentConn) {
        disconnect(parentConn);
    }

    /* Undo the pause-entry UI freeze. Idempotent — may already have
     * run from closeEvent() if the user closed the main window while
     * we were paused (see endPauseFreeze() for details). */
    endPauseFreeze();

    // Restore delete-on-close behavior and clear event loop pointer
    eventLoop = nullptr;
    setAttribute(Qt::WA_DeleteOnClose, true);

    /*
     * If a Lua plugin reload was requested while we were paused,
     * schedule it now that the Lua/C call stack has fully unwound.
     * We must NOT schedule it from inside the event loop (via
     * QTimer::singleShot) because the timer can fire before the
     * loop exits, running cf_close/wslua_reload_plugins while
     * cf_read is still on the C call stack.
     */
    if (reloadDeferred) {
        reloadDeferred = false;
        if (mainApp) {
            mainApp->reloadLuaPluginsDelayed();
        }
    }

    /* If the user (or the OS, e.g. macOS Dock-Quit) tried to close
     * the main window while we were paused, MainWindow::closeEvent
     * recorded the request via handleMainCloseIfPaused() and
     * ignored the QCloseEvent. The pause has now ended, so re-issue
     * the close on the main window. Queued so it runs after the Lua
     * C stack above us has unwound. */
    deliverDeferredMainCloseIfPending();

    /* If the debugger window was closed while paused, closeEvent ran with
     * WA_DeleteOnClose temporarily disabled, so Qt hid the dialog but kept
     * this instance alive until the pause loop unwound. Tear that hidden
     * instance down now so the next open always starts from a fresh, fully
     * initialized dialog state instead of reusing a half-torn-down one. */
    if (!isVisible())
    {
        deleteLater();
    }
}

void LuaDebuggerDialog::onContinue()
{
    resumeDebuggerAndExitLoop();
    updateWidgets();
}

void LuaDebuggerDialog::runDebuggerStep(void (*step_fn)(void))
{
    if (!debuggerPaused)
    {
        return;
    }

    debuggerPaused = false;
    clearPausedStateUi();

    /*
     * The step function resumes the VM and may synchronously hit handlePause()
     * again. handlePause() detects that eventLoop is already set and reuses
     * it instead of nesting a new one — so the stack does NOT grow with each
     * step.
     */
    step_fn();

    /* Synchronous re-pause: handlePause() already ran the full refresh
     * (including the Watch tree) with debuggerPaused=true. Anything we do
     * here would either be redundant or, worse, blank the freshly painted
     * values back to the "—" placeholder. */
    if (debuggerPaused)
    {
        return;
    }

    /*
     * If handlePause() was NOT called (e.g. step landed in C code
     * and the hook didn't fire), we need to quit the event loop so
     * the original handlePause() caller can return.
     */
    if (eventLoop)
    {
        eventLoop->quit();
    }

    /* Update the non-Watch chrome (window title, action enabled-state, eval
     * panel placeholder) immediately so the user sees the debugger is no
     * longer paused. The Watch tree is a special case: a typical step
     * re-pauses within a few ms and immediately blanking every Watch value
     * to "—" only to repaint the same value right back looks like every
     * row is "blinking". Defer the placeholder application; if handlePause()
     * arrives before the timer it bumps watchPlaceholderEpoch_ and the
     * deferred refresh becomes a no-op. If no pause arrives in the deferral
     * window (long-running step, script ended), the placeholder is applied
     * normally so stale values are not left displayed. */
    updateEnabledCheckboxIcon();
    updateStatusLabel();
    updateContinueActionState();
    updateEvalPanelState();

    const qint32 epoch = ++watchPlaceholderEpoch_;
    QPointer<LuaDebuggerDialog> guard(this);
    QTimer::singleShot(WATCH_PLACEHOLDER_DEFER_MS, this, [guard, epoch]() {
        if (!guard || guard->debuggerPaused ||
            guard->watchPlaceholderEpoch_ != epoch)
        {
            return;
        }
        guard->refreshWatchDisplay();
    });
}

void LuaDebuggerDialog::onStepOver()
{
    runDebuggerStep(wslua_debugger_step_over);
}

void LuaDebuggerDialog::onStepIn()
{
    runDebuggerStep(wslua_debugger_step_in);
}

void LuaDebuggerDialog::onStepOut()
{
    runDebuggerStep(wslua_debugger_step_out);
}

void LuaDebuggerDialog::onDebuggerToggled(bool checked)
{
    if (isSuppressedByLiveCapture())
    {
        /* The checkbox is normally setEnabled(false) while a live
         * capture is running, but a programmatic toggle (e.g. via
         * QAbstractButton::click in tests, or any path that bypasses
         * the disabled state) must not be allowed to flip the core
         * enable on or off. Remember the user's intent so it is
         * applied automatically when the capture stops, and re-sync
         * the checkbox to the (still suppressed) core state. */
        s_captureSuppressionPrevEnabled_ = checked;
        refreshDebuggerStateUi();
        return;
    }
    wslua_debugger_set_user_explicitly_disabled(!checked);
    if (!checked && debuggerPaused)
    {
        onContinue();
    }
    wslua_debugger_set_enabled(checked);
    if (!checked)
    {
        debuggerPaused = false;
        clearPausedStateUi();
        /* Disabling the debugger breaks the "changed since last pause"
         * chain; drop every baseline so the next enable → pause cycle
         * starts clean instead of comparing against a stale snapshot. */
        clearAllChangeBaselines();
    }
    refreshDebuggerStateUi();
}

void LuaDebuggerDialog::reject()
{
    /* Base QDialog::reject() calls done(Rejected), which hides() without
     * delivering QCloseEvent, so our closeEvent() unsaved-scripts check does
     * not run (e.g. Esc). Synchronous close() from keyPressEvent → reject()
     * can fail to finish closing; queue close() so closeEvent() runs on the
     * next event-loop turn (same path as the window close control). */
    QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
}

void LuaDebuggerDialog::closeEvent(QCloseEvent *event)
{
    const bool pausedOnEntry = debuggerPaused || wslua_debugger_is_paused();
    if (!ensureUnsavedChangesHandled(tr("Lua Debugger")))
    {
        /* User cancelled the debugger unsaved-file prompt; cancel any
         * deferred app-quit request attached to this close attempt. */
        s_mainCloseDeferredByPause_ = false;
        event->ignore();
        return;
    }

    storeDialogSettings();
    saveSettingsFile();
    luaDebuggerJsonSaved_ = true;

    /* Disable the debugger so breakpoints won't fire and reopen the
     * dialog after it has been closed. */
    wslua_debugger_renounce_restore_after_reload();
    /* "Stay off" is scoped to a visible dialog. Clear it so the next
     * open can call ensureDebuggerEnabledForActiveBreakpoints() (same
     * as pre–user-explicit–C–flag behavior: enable when BPs are active). */
    wslua_debugger_set_user_explicitly_disabled(false);
    wslua_debugger_set_enabled(false);
    resumeDebuggerAndExitLoop();
    debuggerPaused = false;
    clearPausedStateUi();
    refreshDebuggerStateUi();

    /* Tear the pause freeze down synchronously. If this closeEvent is
     * running because WiresharkMainWindow::closeEvent called
     * dbg->close() while the debugger was paused, control returns to
     * main_window's closeEvent as soon as we return — and its
     * tryClosingCaptureFile() may pop up a "Save unsaved capture?"
     * modal that must be interactive. The nested QEventLoop inside
     * handlePause has been asked to quit by resumeDebuggerAndExitLoop
     * above but hasn't unwound yet; by the time it does,
     * endPauseFreeze() there is a no-op thanks to pauseUnfrozen_. */
    endPauseFreeze();

    /* For non-paused closes we can re-deliver a deferred main close now.
     * Paused closes must wait for handlePause() post-loop cleanup so the
     * Lua C stack is unwound first. */
    if (!pausedOnEntry)
    {
        deliverDeferredMainCloseIfPending();
    }

    /*
     * Do not call QDialog::closeEvent (GeometryStateDialog inherits it):
     * QDialog::closeEvent invokes reject(); our reject() queues close()
     * asynchronously, so the dialog stays visible and Qt then ignores the
     * close event (see qdialog.cpp: if (that && isVisible()) e->ignore()).
     * QWidget::closeEvent only accepts the event so the window can close.
     */
    QWidget::closeEvent(event);
}

void LuaDebuggerDialog::showEvent(QShowEvent *event)
{
    GeometryStateDialog::showEvent(event);
    /* Re-apply "enable if active breakpoints" on each show; closeEvent
     * clears user-explicit-disable so this matches pre–C–flag behavior. */
    ensureDebuggerEnabledForActiveBreakpoints();
    updateWidgets();
}

void LuaDebuggerDialog::handleEscapeKey()
{
    QWidget *const modal = QApplication::activeModalWidget();
    if (modal && modal != this)
    {
        return;
    }
    if (ui->luaDebuggerFindFrame->isVisible())
    {
        ui->luaDebuggerFindFrame->animatedHide();
        return;
    }
    if (ui->luaDebuggerGoToLineFrame->isVisible())
    {
        ui->luaDebuggerGoToLineFrame->animatedHide();
        return;
    }
    QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
}

void LuaDebuggerDialog::installDescendantShortcutFilters()
{
    installEventFilter(this);
    for (QWidget *w : findChildren<QWidget *>())
    {
        w->installEventFilter(this);
    }
}

void LuaDebuggerDialog::childEvent(QChildEvent *event)
{
    if (event->added())
    {
        if (auto *w = qobject_cast<QWidget *>(event->child()))
        {
            w->installEventFilter(this);
            for (QWidget *d : w->findChildren<QWidget *>())
            {
                d->installEventFilter(this);
            }
        }
    }
    QDialog::childEvent(event);
}

bool LuaDebuggerDialog::eventFilter(QObject *obj, QEvent *event)
{
    QWidget *const receiver = qobject_cast<QWidget *>(obj);
    const bool inDebuggerUi =
        receiver && isVisible() && isAncestorOf(receiver);

    if (watchTree && obj == watchTree->viewport() &&
        event->type() == QEvent::MouseButtonDblClick)
    {
        auto *me = static_cast<QMouseEvent *>(event);
        if (me->button() == Qt::LeftButton &&
            !watchTree->indexAt(me->pos()).isValid())
        {
            insertNewWatchRow(QString(), true);
            return true;
        }
    }

    if (inDebuggerUi && event->type() == QEvent::ShortcutOverride)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        const QKeySequence pressed = luaSeqFromKeyEvent(ke);
        /*
         * Reserve debugger-owned overlaps before Qt can dispatch app-level
         * shortcuts in the main window. Keep this matcher aligned with any
         * debugger shortcut that can collide with global actions.
         */
        if (pressed.matches(QKeySequence::Quit) == QKeySequence::ExactMatch ||
            matchesLuaDebuggerShortcutKeys(ui, pressed))
        {
            ke->accept();
            return false;
        }
    }

    if (inDebuggerUi && event->type() == QEvent::KeyPress)
    {
        auto *ke = static_cast<QKeyEvent *>(event);
        if (breakpointsTree &&
            (obj == breakpointsTree || obj == breakpointsTree->viewport()))
        {
            if (breakpointsTree->hasFocus() ||
                (breakpointsTree->viewport() &&
                 breakpointsTree->viewport()->hasFocus()))
            {
                const QKeySequence pressedB = luaSeqFromKeyEvent(ke);
                if (pressedB.matches(QKeySequence::Delete) == QKeySequence::ExactMatch ||
                    pressedB.matches(Qt::Key_Backspace) == QKeySequence::ExactMatch)
                {
                    if (removeSelectedBreakpoints())
                    {
                        return true;
                    }
                }
            }
        }
        if (watchTree && (obj == watchTree || obj == watchTree->viewport()))
        {
            if (watchTree->hasFocus() ||
                (watchTree->viewport() && watchTree->viewport()->hasFocus()))
            {
                const QKeySequence pressedW = luaSeqFromKeyEvent(ke);
                if (pressedW.matches(kCtxWatchRemoveAll) ==
                        QKeySequence::ExactMatch &&
                    watchModel && watchModel->rowCount() > 0)
                {
                    removeAllWatchTopLevelItems();
                    return true;
                }

                const QModelIndex curIx = watchTree->currentIndex();
                QStandardItem *const cur =
                    watchModel
                        ? watchModel->itemFromIndex(
                              curIx.sibling(curIx.row(), 0))
                        : nullptr;
                if (cur)
                {
                    if (pressedW.matches(kCtxWatchCopyValue) ==
                        QKeySequence::ExactMatch)
                    {
                        copyWatchValueForItem(cur, curIx);
                        return true;
                    }
                }
                if (cur && cur->parent() == nullptr)
                {
                    if (pressedW.matches(kCtxWatchDuplicate) ==
                        QKeySequence::ExactMatch)
                    {
                        duplicateWatchRootItem(cur);
                        return true;
                    }
                }
                if (cur && cur->parent() == nullptr)
                {
                    if (pressedW.matches(QKeySequence::Delete) ==
                            QKeySequence::ExactMatch ||
                        pressedW.matches(Qt::Key_Backspace) ==
                            QKeySequence::ExactMatch)
                    {
                        QList<QStandardItem *> del;
                        if (watchTree->selectionModel())
                        {
                            for (const QModelIndex &six :
                                 watchTree->selectionModel()
                                     ->selectedIndexes())
                            {
                                if (six.column() != 0)
                                {
                                    continue;
                                }
                                QStandardItem *it =
                                    watchModel->itemFromIndex(six);
                                if (it && it->parent() == nullptr)
                                {
                                    del.append(it);
                                }
                            }
                        }
                        if (del.isEmpty())
                        {
                            del.append(cur);
                        }
                        deleteWatchRows(del);
                        return true;
                    }
                    if (pressedW.matches(kCtxWatchEdit) ==
                        QKeySequence::ExactMatch)
                    {
                        const QModelIndex editIx =
                            watchModel->indexFromItem(cur);
                        if (editIx.isValid())
                        {
                            watchTree->edit(editIx);
                        }
                        return true;
                    }
                }
            }
        }
        {
            LuaDebuggerCodeView *const focusCv = codeViewFromObject(obj);
            if (focusCv)
            {
                if (focusCv->hasFocus() ||
                    (focusCv->viewport() &&
                     focusCv->viewport()->hasFocus()))
                {
                    const QKeySequence pCv = luaSeqFromKeyEvent(ke);
                    const qint32 line = static_cast<qint32>(
                        focusCv->textCursor().blockNumber() + 1);
                    if (pCv.matches(kCtxToggleBreakpoint) ==
                        QKeySequence::ExactMatch)
                    {
                        toggleBreakpointOnCodeViewLine(focusCv, line);
                        return true;
                    }
                    if (eventLoop && pCv.matches(kCtxRunToLine) ==
                                       QKeySequence::ExactMatch)
                    {
                        runToCurrentLineInPausedEditor(focusCv, line);
                        return true;
                    }
                }
            }
        }
        /*
         * Esc must be handled here: QPlainTextEdit accepts Key_Escape without
         * propagating to QDialog::keyPressEvent, so reject() never runs.
         * Dismiss inline find/go bars first; then queue close() so closeEvent()
         * runs (unsaved-scripts prompt). Skip if a different modal dialog owns
         * the event (e.g. nested prompt).
         */
        const QKeySequence pressed = luaSeqFromKeyEvent(ke);
        if (pressed.matches(Qt::Key_Escape) == QKeySequence::ExactMatch)
        {
            QWidget *const modal = QApplication::activeModalWidget();
            if (modal && modal != this)
            {
                return QDialog::eventFilter(obj, event);
            }
            handleEscapeKey();
            return true;
        }
        if (pressed.matches(QKeySequence::Quit) == QKeySequence::ExactMatch)
        {
            /*
             * Keep Ctrl+Q semantics identical to main-window quit when the
             * debugger has unsaved scripts: run the debugger close gate first
             * (Save/Discard/Cancel), then re-deliver main close if accepted.
             */
            QWidget *const modal = QApplication::activeModalWidget();
            if (modal && modal != this)
            {
                return QDialog::eventFilter(obj, event);
            }
            s_mainCloseDeferredByPause_ = true;
            QMetaObject::invokeMethod(this, "close", Qt::QueuedConnection);
            return true;
        }
        if (triggerLuaDebuggerShortcuts(ui, pressed))
        {
            return true;
        }
    }
    return QDialog::eventFilter(obj, event);
}

void LuaDebuggerDialog::onClearBreakpoints()
{
    // Confirmation dialog
    const unsigned count = wslua_debugger_get_breakpoint_count();
    if (count == 0)
    {
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Clear All Breakpoints"),
        tr("Are you sure you want to remove %Ln breakpoint(s)?", "", count),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }

    wslua_debugger_clear_breakpoints();
    updateBreakpoints();
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
            view->updateBreakpointMarkers();
    }
}

void LuaDebuggerDialog::updateBreakpoints()
{
    if (!breakpointsModel)
    {
        return;
    }
    breakpointsModel->removeRows(0, breakpointsModel->rowCount());
    breakpointsModel->setHeaderData(2, Qt::Horizontal, tr("Location"));
    unsigned count = wslua_debugger_get_breakpoint_count();
    bool hasActiveBreakpoint = false;
    const bool collectInitialFiles = !breakpointTabsPrimed;
    QVector<QString> initialBreakpointFiles;
    QSet<QString> seenInitialFiles;
    for (unsigned i = 0; i < count; i++)
    {
        const char *file_path;
        int64_t line;
        bool active;
        if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active))
        {
            QString normalizedPath =
                normalizedFilePath(QString::fromUtf8(file_path));

            /* Check if file exists */
            QFileInfo fileInfo(normalizedPath);
            bool fileExists = fileInfo.exists() && fileInfo.isFile();

            QStandardItem *const i0 = new QStandardItem();
            QStandardItem *const i1 = new QStandardItem();
            QStandardItem *const i2 = new QStandardItem();
            i0->setCheckable(true);
            i0->setCheckState(active ? Qt::Checked : Qt::Unchecked);
            i0->setData(normalizedPath, BreakpointFileRole);
            i0->setData(static_cast<qlonglong>(line), BreakpointLineRole);
            i0->setToolTip(tr("Enable or disable this breakpoint"));
            i1->setText(QString::number(line));
            const QString fileDisplayName = fileInfo.fileName();
            QString locationText =
                QStringLiteral("%1:%2")
                    .arg(fileDisplayName.isEmpty() ? normalizedPath
                                                    : fileDisplayName)
                    .arg(line);
            i2->setText(locationText);
            i2->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);

            if (!fileExists)
            {
                /* Mark stale breakpoints with warning icon and gray text */
                i2->setIcon(QIcon::fromTheme("dialog-warning"));
                i2->setToolTip(tr("File not found: %1").arg(normalizedPath));
                i0->setForeground(QBrush(Qt::gray));
                i1->setForeground(QBrush(Qt::gray));
                i2->setForeground(QBrush(Qt::gray));
                /* Disable the checkbox for stale breakpoints */
                i0->setFlags(i0->flags() & ~Qt::ItemIsUserCheckable);
                i0->setCheckState(Qt::Unchecked);
            }
            else
            {
                i2->setToolTip(tr("%1\nLine %2").arg(normalizedPath).arg(line));
            }

            if (active && fileExists)
            {
                hasActiveBreakpoint = true;
            }

            breakpointsModel->appendRow({i0, i1, i2});

            /* Only add to file tree if file exists */
            if (fileExists)
            {
                ensureFileTreeEntry(normalizedPath);
            }

            /* Only open existing files initially */
            if (collectInitialFiles && fileExists &&
                !seenInitialFiles.contains(normalizedPath))
            {
                initialBreakpointFiles.append(normalizedPath);
                seenInitialFiles.insert(normalizedPath);
            }
        }
    }

    if (hasActiveBreakpoint)
    {
        ensureDebuggerEnabledForActiveBreakpoints();
    }
    refreshDebuggerStateUi();

    if (collectInitialFiles)
    {
        breakpointTabsPrimed = true;
        openInitialBreakpointFiles(initialBreakpointFiles);
    }

    updateBreakpointHeaderButtonState();
}

void LuaDebuggerDialog::updateStack()
{
    if (!stackTree)
    {
        return;
    }

    const bool signalsWereBlocked = stackTree->blockSignals(true);
    if (stackModel)
    {
        stackModel->removeRows(0, stackModel->rowCount());
    }

    int32_t frameCount = 0;
    wslua_stack_frame_t *stack = wslua_debugger_get_stack(&frameCount);
    QStandardItem *itemToSelect = nullptr;
    if (stack && frameCount > 0)
    {
        const int maxLevel = static_cast<int>(frameCount) - 1;
        stackSelectionLevel = qBound(0, stackSelectionLevel, maxLevel);
        wslua_debugger_set_variable_stack_level(
            static_cast<int32_t>(stackSelectionLevel));

        for (int32_t frameIndex = 0; frameIndex < frameCount; ++frameIndex)
        {
            QStandardItem *const nameItem = new QStandardItem();
            QStandardItem *const locItem = new QStandardItem();
            nameItem->setData(static_cast<qlonglong>(frameIndex),
                              StackItemLevelRole);
            const char *rawSource = stack[frameIndex].source;
            const bool isLuaFrame = rawSource && rawSource[0] == '@';
            const QString functionName = QString::fromUtf8(
                stack[frameIndex].name ? stack[frameIndex].name : "?");
            QString locationText;
            QString resolvedPath;
            if (isLuaFrame)
            {
                const QString filePath = QString::fromUtf8(rawSource + 1);
                resolvedPath = normalizedFilePath(filePath);
                if (resolvedPath.isEmpty())
                {
                    resolvedPath = filePath;
                }
                const QString fileDisplayName =
                    QFileInfo(resolvedPath).fileName();
                locationText = QStringLiteral("%1:%2")
                                   .arg(fileDisplayName.isEmpty() ? resolvedPath
                                                                 : fileDisplayName)
                                   .arg(stack[frameIndex].line);
                locItem->setToolTip(QStringLiteral("%1:%2")
                                        .arg(resolvedPath)
                                        .arg(stack[frameIndex].line));
            }
            else
            {
                locationText = QString::fromUtf8(rawSource ? rawSource : "[C]");
            }

            nameItem->setText(functionName);
            locItem->setText(locationText);

            if (isLuaFrame)
            {
                nameItem->setData(true, StackItemNavigableRole);
                nameItem->setData(resolvedPath, StackItemFileRole);
                nameItem->setData(static_cast<qlonglong>(stack[frameIndex].line),
                                  StackItemLineRole);
            }
            else
            {
                nameItem->setData(false, StackItemNavigableRole);
                QColor disabledColor =
                    palette().color(QPalette::Disabled, QPalette::Text);
                nameItem->setForeground(disabledColor);
                locItem->setForeground(disabledColor);
            }

            stackModel->appendRow({nameItem, locItem});

            if (frameIndex == stackSelectionLevel)
            {
                itemToSelect = nameItem;
            }
        }
        wslua_debugger_free_stack(stack, frameCount);
    }
    else
    {
        stackSelectionLevel = 0;
        wslua_debugger_set_variable_stack_level(0);
    }

    if (itemToSelect && stackModel)
    {
        const QModelIndex ix = stackModel->indexFromItem(itemToSelect);
        stackTree->setCurrentIndex(ix);
    }
    stackTree->blockSignals(signalsWereBlocked);
}

void LuaDebuggerDialog::refreshVariablesForCurrentStackFrame()
{
    if (!variablesTree || !debuggerPaused || !wslua_debugger_is_paused())
    {
        return;
    }
    if (variablesModel)
        {
            variablesModel->removeRows(0, variablesModel->rowCount());
        }
    updateVariables(nullptr, QString());
    restoreVariablesExpansionState();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::onStackCurrentItemChanged(const QModelIndex &current,
                                                  const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (!stackTree || !stackModel || !current.isValid() || !debuggerPaused ||
        !wslua_debugger_is_paused())
    {
        return;
    }
    QStandardItem *const rowItem =
        stackModel->itemFromIndex(current.sibling(current.row(), 0));
    if (!rowItem)
    {
        return;
    }

    const int level =
        static_cast<int>(rowItem->data(StackItemLevelRole).toLongLong());
    if (level < 0 || level == stackSelectionLevel)
    {
        return;
    }

    stackSelectionLevel = level;
    wslua_debugger_set_variable_stack_level(static_cast<int32_t>(level));
    refreshVariablesForCurrentStackFrame();
    syncVariablesTreeToCurrentWatch();
}

void LuaDebuggerDialog::updateVariables(QStandardItem *parent,
                                        const QString &path)
{
    if (!variablesModel)
    {
        return;
    }
    int32_t variableCount = 0;
    wslua_variable_t *variables = wslua_debugger_get_variables(
        path.isEmpty() ? NULL : path.toUtf8().constData(), &variableCount);

    /* "First-time expansion" guard for the new-child flash: the children
     * about to be appended belong to @p path, and a child absent from
     * baseline is only meaningfully "new" if @p path was *visited* (and
     * therefore its then-children captured) at the previous pause. We
     * record that directly — the companion set variablesCurrentParents_
     * gets @p path's own change key on every paint and rotates into
     * variablesBaselineParents_ at pause entry. Scanning baseline value
     * keys by prefix cannot answer this question: a parent that was
     * expanded last pause but had no children to show (e.g. a function
     * with no locals yet, an empty table) would look identical to one
     * that was collapsed, so the FIRST child appearing now could never
     * flash. The level matches the one used for the child keys (Globals
     * anchor to -1, everything else follows the current stack frame). */
    const int parentChildLevel =
        variablesPathIsGlobalScoped(path) ? -1 : stackSelectionLevel;
    const QString parentVisitedKey = changeKey(parentChildLevel, path);
    const bool parentVisitedInBaseline =
        variablesBaselineParents_.contains(parentVisitedKey);
    variablesCurrentParents_.insert(parentVisitedKey);

    if (variables)
    {
        for (int32_t variableIndex = 0; variableIndex < variableCount;
             ++variableIndex)
        {
            auto *nameItem = new QStandardItem();
            auto *valueItem = new QStandardItem();
            auto *typeItem = new QStandardItem();

            const VariableRowFields f =
                readVariableRowFields(variables[variableIndex], path);

            nameItem->setText(f.name);
            valueItem->setText(f.value);
            typeItem->setText(f.type);

            const QString tooltipSuffix =
                f.type.isEmpty() ? QString() : tr("Type: %1").arg(f.type);
            nameItem->setToolTip(tooltipSuffix.isEmpty()
                                     ? f.name
                                     : QStringLiteral("%1\n%2")
                                           .arg(f.name, tooltipSuffix));
            valueItem->setToolTip(tooltipSuffix.isEmpty()
                                      ? f.value
                                      : QStringLiteral("%1\n%2")
                                            .arg(f.value, tooltipSuffix));
            typeItem->setToolTip(tooltipSuffix.isEmpty()
                                      ? f.type
                                      : QStringLiteral("%1\n%2")
                                            .arg(f.type, tooltipSuffix));
            nameItem->setData(f.type, VariableTypeRole);
            nameItem->setData(f.canExpand, VariableCanExpandRole);
            nameItem->setData(f.childPath, VariablePathRole);

            for (QStandardItem *cell : {nameItem, valueItem, typeItem})
            {
                cell->setFlags(cell->flags() & ~Qt::ItemIsEditable);
            }

            if (parent)
            {
                parent->appendRow({nameItem, valueItem, typeItem});
            }
            else
            {
                variablesModel->appendRow({nameItem, valueItem, typeItem});
            }

            /* Scope Globals watchers by level=-1 so changing the selected
             * stack frame does not invalidate a Globals baseline. All other
             * paths are scoped by the current stack level. */
            const bool isGlobal = variablesPathIsGlobalScoped(f.childPath);
            const int level = isGlobal ? -1 : stackSelectionLevel;
            const QString vk = changeKey(level, f.childPath);
            /* flashNew=parentVisitedInBaseline: a variable absent from
             * the previous pause's snapshot but present now is "new" (e.g.
             * a fresh local binding, a key added to a table, a new upvalue)
             * and gets the same visual cue as a value change — but ONLY
             * when @p path itself was painted at the previous pause.
             * Otherwise this is a first-time expansion and treating every
             * child as "new" would be visual noise, not information.
             *
             * Non-Globals comparisons are also gated on
             * changeHighlightAllowed(): walking to a different stack frame
             * inside the same pause shows locals/upvalues from an unrelated
             * scope where comparing against the pause-entry baseline at the
             * same numeric level would either flag every variable as "new"
             * or compare against an unrelated previous-pause snapshot. The
             * cue resumes automatically when the user navigates back to the
             * pause-entry frame. Globals are anchored to level=-1 and stay
             * comparable across frames, so they keep their highlight. */
            const bool changed =
                (isGlobal || changeHighlightAllowed()) &&
                shouldMarkChanged(variablesBaseline_, vk, f.value,
                                  /*flashNew=*/parentVisitedInBaseline);
            applyChangedVisuals(nameItem, changed, isPauseEntryRefresh_);
            variablesCurrent_[vk] = f.value;

            applyVariableExpansionIndicator(nameItem, f.canExpand,
                                            /*enabledOnlyPlaceholder=*/false);
        }
        // Sort Globals alphabetically; preserve declaration order for
        // Locals and Upvalues since that is more natural for debugging.
        if (variableChildrenShouldSortByName(path))
        {
            if (parent)
            {
                parent->sortChildren(0, Qt::AscendingOrder);
            }
            else
            {
                variablesModel->sort(0, Qt::AscendingOrder);
            }
        }

        wslua_debugger_free_variables(variables, variableCount);
    }
}

void LuaDebuggerDialog::onVariableItemExpanded(const QModelIndex &index)
{
    if (!variablesModel || !index.isValid())
    {
        return;
    }
    QStandardItem *item =
        variablesModel->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    const QString section = variableSectionRootKeyFromItem(item);
    if (!item->parent())
    {
        recordTreeSectionRootExpansion(variablesExpansion_, section, true);
    }
    else
    {
        const QString key = item->data(VariablePathRole).toString();
        recordTreeSectionSubpathExpansion(variablesExpansion_, section, key,
                                          true);
    }

    if (item->rowCount() == 1 && item->child(0) &&
        item->child(0)->text().isEmpty())
    {
        item->removeRow(0);

        QString varPath = item->data(VariablePathRole).toString();
        updateVariables(item, varPath);
    }
}

void LuaDebuggerDialog::onVariableItemCollapsed(const QModelIndex &index)
{
    if (!variablesModel || !index.isValid())
    {
        return;
    }
    QStandardItem *item =
        variablesModel->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    const QString section = variableSectionRootKeyFromItem(item);
    if (!item->parent())
    {
        recordTreeSectionRootExpansion(variablesExpansion_, section, false);
    }
    else
    {
        const QString key = item->data(VariablePathRole).toString();
        recordTreeSectionSubpathExpansion(variablesExpansion_, section, key,
                                          false);
    }
}

LuaDebuggerCodeView *LuaDebuggerDialog::loadFile(const QString &file_path)
{
    QString normalizedPath = normalizedFilePath(file_path);
    if (normalizedPath.isEmpty())
    {
        normalizedPath = file_path;
    }

    /* Check if file exists before creating a tab */
    QFileInfo fileInfo(normalizedPath);
    if (!fileInfo.exists() || !fileInfo.isFile())
    {
        /* File doesn't exist - don't create a tab */
        return nullptr;
    }

    // Check if already open
    const qint32 existingTabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < existingTabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view && view->getFilename() == normalizedPath)
        {
            ui->codeTabWidget->setCurrentIndex(static_cast<int>(tabIndex));
            return view;
        }
    }

    // Create new tab
    LuaDebuggerCodeView *codeView = new LuaDebuggerCodeView(ui->codeTabWidget);
    codeView->setEditorFont(effectiveMonospaceFont(true));
    codeView->setFilename(normalizedPath);

    QFile file(normalizedPath);
    if (file.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        codeView->setPlainText(file.readAll());
    }
    else
    {
        /* This should not happen since we checked exists() above,
         * but handle it gracefully just in case */
        delete codeView;
        return nullptr;
    }

    ensureFileTreeEntry(normalizedPath);

    // Connect signals
    codeView->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(codeView, &QWidget::customContextMenuRequested, this,
            &LuaDebuggerDialog::onCodeViewContextMenu);

    connect(
        codeView, &LuaDebuggerCodeView::breakpointToggled,
        [this](const QString &file_path, qint32 line, bool toggleActive)
        {
            const int32_t state = wslua_debugger_get_breakpoint_state(
                file_path.toUtf8().constData(), line);
            if (state == -1)
            {
                wslua_debugger_add_breakpoint(file_path.toUtf8().constData(),
                                              line);
                if (toggleActive)
                {
                    /* Shift+click on a bare gutter line: still create
                     * the breakpoint, but mark it inactive so the user
                     * can pre-arm a line without paying the line-hook
                     * cost until they activate it. Skip the
                     * ensure-enabled call because the new row carries
                     * no active flag yet. */
                    wslua_debugger_set_breakpoint_active(
                        file_path.toUtf8().constData(), line, false);
                }
                else
                {
                    ensureDebuggerEnabledForActiveBreakpoints();
                }
            }
            else if (toggleActive)
            {
                /* Shift+click on an existing breakpoint: enable/disable
                 * without removing. */
                wslua_debugger_set_breakpoint_active(
                    file_path.toUtf8().constData(), line, state == 0);
            }
            else
            {
                wslua_debugger_remove_breakpoint(file_path.toUtf8().constData(),
                                                 line);
                refreshDebuggerStateUi();
            }
            updateBreakpoints();
            // Update all views as breakpoint might affect them (unlikely but
            // safe)
            const qint32 tabCount =
                static_cast<qint32>(ui->codeTabWidget->count());
            for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
            {
                LuaDebuggerCodeView *tabView =
                    qobject_cast<LuaDebuggerCodeView *>(
                        ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
                if (tabView)
                    tabView->updateBreakpointMarkers();
            }
        });

    connect(codeView->document(), &QTextDocument::modificationChanged, this,
            [this, codeView]()
            {
                updateTabTextForCodeView(codeView);
                updateWindowModifiedState();
                if (ui->codeTabWidget->currentWidget() == codeView)
                {
                    updateSaveActionState();
                }
            });
    connect(codeView, &QPlainTextEdit::cursorPositionChanged, this,
            &LuaDebuggerDialog::updateBreakpointHeaderButtonState);

    ui->codeTabWidget->addTab(codeView, QFileInfo(normalizedPath).fileName());
    updateTabTextForCodeView(codeView);
    ui->codeTabWidget->setCurrentWidget(codeView);
    ui->codeTabWidget->show();
    updateSaveActionState();
    updateWindowModifiedState();
    updateLuaEditorAuxFrames();
    return codeView;
}

LuaDebuggerCodeView *LuaDebuggerDialog::currentCodeView() const
{
    return qobject_cast<LuaDebuggerCodeView *>(
        ui->codeTabWidget->currentWidget());
}

qint32 LuaDebuggerDialog::unsavedOpenScriptTabCount() const
{
    qint32 count = 0;
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view && view->document()->isModified())
        {
            ++count;
        }
    }
    return count;
}

bool LuaDebuggerDialog::hasUnsavedChanges() const
{
    return unsavedOpenScriptTabCount() > 0;
}

bool LuaDebuggerDialog::ensureUnsavedChangesHandled(const QString &title)
{
    if (!hasUnsavedChanges())
    {
        return true;
    }

    const qint32 unsavedCount = unsavedOpenScriptTabCount();
    const QMessageBox::StandardButton reply = QMessageBox::question(
        this, title,
        tr("There are unsaved changes in %Ln open file(s).", "", unsavedCount),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel,
        QMessageBox::Save);

    if (reply == QMessageBox::Cancel)
    {
        return false;
    }
    if (reply == QMessageBox::Save)
    {
        return saveAllModified();
    }
    clearAllDocumentModified();
    return true;
}

void LuaDebuggerDialog::clearAllDocumentModified()
{
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->document()->setModified(false);
        }
    }
}

bool LuaDebuggerDialog::saveCodeView(LuaDebuggerCodeView *view)
{
    if (!view)
    {
        return false;
    }
    const QString path = view->getFilename();
    if (path.isEmpty())
    {
        return false;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(
            this, tr("Save Lua Script"),
            tr("Could not write to %1:\n%2").arg(path, file.errorString()));
        return false;
    }
    QTextStream out(&file);
    out << view->toPlainText();
    file.close();
    view->document()->setModified(false);
    return true;
}

bool LuaDebuggerDialog::saveAllModified()
{
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view && view->document()->isModified())
        {
            if (!saveCodeView(view))
            {
                return false;
            }
        }
    }
    return true;
}

void LuaDebuggerDialog::updateTabTextForCodeView(LuaDebuggerCodeView *view)
{
    if (!view)
    {
        return;
    }
    const int tabIndex = ui->codeTabWidget->indexOf(view);
    if (tabIndex < 0)
    {
        return;
    }
    QString label = QFileInfo(view->getFilename()).fileName();
    if (view->document()->isModified())
    {
        label += QStringLiteral(" *");
    }
    ui->codeTabWidget->setTabText(tabIndex, label);
}

void LuaDebuggerDialog::updateSaveActionState()
{
    LuaDebuggerCodeView *view = currentCodeView();
    ui->actionSaveFile->setEnabled(view && view->document()->isModified());
}

void LuaDebuggerDialog::updateWindowModifiedState()
{
    setWindowModified(hasUnsavedChanges());
}

void LuaDebuggerDialog::showAccordionFrame(AccordionFrame *show_frame,
                                           bool toggle)
{
    QList<AccordionFrame *> frame_list =
        QList<AccordionFrame *>() << ui->luaDebuggerFindFrame
                                  << ui->luaDebuggerGoToLineFrame;
    frame_list.removeAll(show_frame);
    for (AccordionFrame *af : frame_list)
    {
        if (af)
        {
            af->animatedHide();
        }
    }
    if (!show_frame)
    {
        return;
    }
    if (toggle && show_frame->isVisible())
    {
        show_frame->animatedHide();
        return;
    }
    LuaDebuggerGoToLineFrame *const goto_frame =
        qobject_cast<LuaDebuggerGoToLineFrame *>(show_frame);
    if (goto_frame)
    {
        goto_frame->syncLineFieldFromEditor();
    }
    show_frame->animatedShow();
    if (LuaDebuggerFindFrame *const find_frame =
            qobject_cast<LuaDebuggerFindFrame *>(show_frame))
    {
        find_frame->scheduleFindFieldFocus();
    }
    else if (goto_frame)
    {
        goto_frame->scheduleLineFieldFocus();
    }
}

void LuaDebuggerDialog::updateLuaEditorAuxFrames()
{
    QPlainTextEdit *ed = currentCodeView();
    ui->luaDebuggerFindFrame->setTargetEditor(ed);
    ui->luaDebuggerGoToLineFrame->setTargetEditor(ed);
}

void LuaDebuggerDialog::onEditorFind()
{
    updateLuaEditorAuxFrames();
    showAccordionFrame(ui->luaDebuggerFindFrame, true);
}

void LuaDebuggerDialog::onEditorGoToLine()
{
    updateLuaEditorAuxFrames();
    showAccordionFrame(ui->luaDebuggerGoToLineFrame, true);
}

void LuaDebuggerDialog::onSaveFile()
{
    LuaDebuggerCodeView *view = currentCodeView();
    if (!view || !view->document()->isModified())
    {
        return;
    }
    saveCodeView(view);
    updateSaveActionState();
}

void LuaDebuggerDialog::onCodeTabCloseRequested(int idx)
{
    QWidget *widget = ui->codeTabWidget->widget(idx);
    LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(widget);
    if (view && view->document()->isModified())
    {
        const QMessageBox::StandardButton reply = QMessageBox::question(
            this, tr("Lua Debugger"),
            tr("Save changes to %1 before closing?")
                .arg(QFileInfo(view->getFilename()).fileName()),
            QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel,
            QMessageBox::Save);
        if (reply == QMessageBox::Cancel)
        {
            return;
        }
        if (reply == QMessageBox::Save)
        {
            if (!saveCodeView(view))
            {
                return;
            }
        }
        else
        {
            view->document()->setModified(false);
        }
    }

    ui->codeTabWidget->removeTab(idx);
    delete widget;
    updateSaveActionState();
    updateWindowModifiedState();
}

void LuaDebuggerDialog::onBreakpointItemChanged(QStandardItem *item)
{
    if (!item || item->column() != 0)
    {
        return;
    }
    const QString file = item->data(BreakpointFileRole).toString();
    const int64_t lineNumber = item->data(BreakpointLineRole).toLongLong();
    const bool active = item->checkState() == Qt::Checked;
    wslua_debugger_set_breakpoint_active(file.toUtf8().constData(), lineNumber,
                                         active);
    /* Activating or deactivating a breakpoint must never change the
     * debugger's enabled state. This is especially important during a live
     * capture, where debugging is suppressed and any flip (direct or
     * deferred via s_captureSuppressionPrevEnabled_) would silently
     * re-enable the debugger when the capture ends. Just refresh the UI to
     * mirror the (unchanged) core state. */
    refreshDebuggerStateUi();

    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (tabView && tabView->getFilename() == file)
            tabView->updateBreakpointMarkers();
    }

    /* The Breakpoints table is the only mutation path that does not flow
     * through updateBreakpoints(); refresh the section-header dot here so
     * its color mirrors the new aggregate active state. */
    updateBreakpointHeaderButtonState();
}

void LuaDebuggerDialog::onBreakpointItemDoubleClicked(const QModelIndex &index)
{
    if (!index.isValid() || !breakpointsModel)
    {
        return;
    }
    QStandardItem *item = breakpointsModel->item(index.row(), 0);
    if (!item)
    {
        return;
    }

    const QString file = item->data(BreakpointFileRole).toString();
    const int64_t lineNumber = item->data(BreakpointLineRole).toLongLong();
    LuaDebuggerCodeView *view = loadFile(file);
    if (view)
    {
        view->moveCaretToLineStart(static_cast<qint32>(lineNumber));
    }
}

bool LuaDebuggerDialog::removeBreakpointRows(const QList<int> &rows)
{
    if (!breakpointsModel || rows.isEmpty())
    {
        return false;
    }

    /* Collect (file, line) pairs for the requested rows before touching the
     * model: rebuilding the model in updateBreakpoints() would invalidate
     * any QStandardItem pointers we held. De-duplicate row indices so callers
     * can pass selectionModel()->selectedIndexes() directly. */
    QVector<QPair<QString, int64_t>> toRemove;
    QSet<int> seenRows;
    for (int row : rows)
    {
        if (row < 0 || seenRows.contains(row))
        {
            continue;
        }
        seenRows.insert(row);
        QStandardItem *const row0 = breakpointsModel->item(row, 0);
        if (!row0)
        {
            continue;
        }
        toRemove.append({row0->data(BreakpointFileRole).toString(),
                         row0->data(BreakpointLineRole).toLongLong()});
    }
    if (toRemove.isEmpty())
    {
        return false;
    }

    QSet<QString> touchedFiles;
    for (const auto &bp : toRemove)
    {
        wslua_debugger_remove_breakpoint(bp.first.toUtf8().constData(),
                                         bp.second);
        touchedFiles.insert(bp.first);
    }
    updateBreakpoints();

    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (tabView && touchedFiles.contains(tabView->getFilename()))
        {
            tabView->updateBreakpointMarkers();
        }
    }
    return true;
}

bool LuaDebuggerDialog::removeSelectedBreakpoints()
{
    if (!breakpointsTree)
    {
        return false;
    }
    QItemSelectionModel *const sm = breakpointsTree->selectionModel();
    if (!sm)
    {
        return false;
    }
    QList<int> rows;
    for (const QModelIndex &ix : sm->selectedIndexes())
    {
        if (ix.isValid())
        {
            rows.append(ix.row());
        }
    }
    return removeBreakpointRows(rows);
}

void LuaDebuggerDialog::onBreakpointContextMenuRequested(const QPoint &pos)
{
    if (!breakpointsTree || !breakpointsModel)
    {
        return;
    }

    const QModelIndex ix = breakpointsTree->indexAt(pos);
    /* Ensure the row under the cursor is part of the selection so "Remove"
     * operates on something sensible even when the user right-clicks a row
     * that was not previously selected. */
    if (ix.isValid() && breakpointsTree->selectionModel() &&
        !breakpointsTree->selectionModel()->isRowSelected(
            ix.row(), ix.parent()))
    {
        breakpointsTree->setCurrentIndex(ix);
    }

    QMenu menu(this);
    QAction *openAct = nullptr;
    QAction *removeAct = nullptr;
    if (ix.isValid())
    {
        openAct = menu.addAction(tr("Open Source"));
        menu.addSeparator();
        removeAct = menu.addAction(tr("Remove"));
        removeAct->setShortcut(QKeySequence::Delete);
    }
    QAction *removeAllAct = nullptr;
    if (breakpointsModel->rowCount() > 0)
    {
        removeAllAct = menu.addAction(tr("Remove All Breakpoints"));
        removeAllAct->setShortcut(kCtxRemoveAllBreakpoints);
    }
    if (menu.isEmpty())
    {
        return;
    }

    QAction *chosen = menu.exec(breakpointsTree->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }
    if (chosen == openAct)
    {
        onBreakpointItemDoubleClicked(ix);
        return;
    }
    if (chosen == removeAct)
    {
        removeSelectedBreakpoints();
        return;
    }
    if (chosen == removeAllAct)
    {
        onClearBreakpoints();
        return;
    }
}

void LuaDebuggerDialog::onCodeViewContextMenu(const QPoint &pos)
{
    LuaDebuggerCodeView *codeView =
        qobject_cast<LuaDebuggerCodeView *>(sender());
    if (!codeView)
        return;

    QMenu menu(this);

    QAction *undoAct = menu.addAction(tr("Undo"));
    undoAct->setShortcut(QKeySequence::Undo);
    undoAct->setEnabled(codeView->document()->isUndoAvailable());
    connect(undoAct, &QAction::triggered, codeView, &QPlainTextEdit::undo);

    QAction *redoAct = menu.addAction(tr("Redo"));
    redoAct->setShortcut(QKeySequence::Redo);
    redoAct->setEnabled(codeView->document()->isRedoAvailable());
    connect(redoAct, &QAction::triggered, codeView, &QPlainTextEdit::redo);

    menu.addSeparator();

    QAction *cutAct = menu.addAction(tr("Cut"));
    cutAct->setShortcut(QKeySequence::Cut);
    cutAct->setEnabled(codeView->textCursor().hasSelection());
    connect(cutAct, &QAction::triggered, codeView, &QPlainTextEdit::cut);

    QAction *copyAct = menu.addAction(tr("Copy"));
    copyAct->setShortcut(QKeySequence::Copy);
    copyAct->setEnabled(codeView->textCursor().hasSelection());
    connect(copyAct, &QAction::triggered, codeView, &QPlainTextEdit::copy);

    QAction *pasteAct = menu.addAction(tr("Paste"));
    pasteAct->setShortcut(QKeySequence::Paste);
    pasteAct->setEnabled(codeView->canPaste());
    connect(pasteAct, &QAction::triggered, codeView, &QPlainTextEdit::paste);

    QAction *selAllAct = menu.addAction(tr("Select All"));
    selAllAct->setShortcut(QKeySequence::SelectAll);
    connect(selAllAct, &QAction::triggered, codeView, &QPlainTextEdit::selectAll);

    menu.addSeparator();
    menu.addAction(ui->actionFind);
    menu.addAction(ui->actionGoToLine);

    menu.addSeparator();

    QTextCursor cursor = codeView->cursorForPosition(pos);
    const qint32 lineNumber = static_cast<qint32>(cursor.blockNumber() + 1);

    // Check if breakpoint exists
    const int32_t state = wslua_debugger_get_breakpoint_state(
        codeView->getFilename().toUtf8().constData(), lineNumber);

    if (state == -1)
    {
        QAction *addBp = menu.addAction(tr("Add Breakpoint"));
        addBp->setShortcut(kCtxToggleBreakpoint);
        connect(addBp, &QAction::triggered,
                [this, codeView, lineNumber]()
                { toggleBreakpointOnCodeViewLine(codeView, lineNumber); });
    }
    else
    {
        QAction *removeBp = menu.addAction(tr("Remove Breakpoint"));
        removeBp->setShortcut(kCtxToggleBreakpoint);
        connect(removeBp, &QAction::triggered,
                [this, codeView, lineNumber]()
                { toggleBreakpointOnCodeViewLine(codeView, lineNumber); });
    }

    if (eventLoop)
    { // Only if paused
        QAction *runToLine = menu.addAction(tr("Run to this line"));
        runToLine->setShortcut(kCtxRunToLine);
        connect(runToLine, &QAction::triggered,
                [this, codeView, lineNumber]()
                { runToCurrentLineInPausedEditor(codeView, lineNumber); });
    }

    /* Add Watch is available regardless of paused state, mirroring the
     * toolbar action and the Watch-panel header `+` button. Prefer the
     * current selection; otherwise fall back to the Lua identifier
     * under the caret so a single right-click on a variable name is
     * enough — no manual selection required. While the debugger is not
     * paused the watch row simply renders a muted em dash for its
     * value and resolves on the next pause. */
    {
        QString watchSpec = codeView->textCursor().selectedText().trimmed();
        if (watchSpec.isEmpty())
        {
            const QTextCursor caretCursor =
                codeView->cursorForPosition(pos);
            watchSpec = luaIdentifierUnderCursor(caretCursor);
        }
        if (!watchSpec.isEmpty())
        {
            menu.addSeparator();
            const QString shortLabel = watchSpec.length() > 48
                                           ? watchSpec.left(48) +
                                                 QStringLiteral("…")
                                           : watchSpec;
            QAction *addWatch = menu.addAction(
                tr("Add Watch: \"%1\"").arg(shortLabel));
            addWatch->setShortcut(ui->actionAddWatch->shortcut());
            connect(addWatch, &QAction::triggered,
                    [this, watchSpec]()
                    {
                        const QString t = watchSpec.trimmed();
                        if (!watchSpecUsesPathResolution(t))
                        {
                            showPathOnlyVariablePathWatchMessage();
                            return;
                        }
                        addWatchFromSpec(t);
                    });
        }
    }

    menu.exec(codeView->mapToGlobal(pos));
}

void LuaDebuggerDialog::onStackItemDoubleClicked(const QModelIndex &index)
{
    if (!stackModel || !index.isValid())
    {
        return;
    }
    QStandardItem *item =
        stackModel->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    if (!item->data(StackItemNavigableRole).toBool())
    {
        return;
    }
    const QString file = item->data(StackItemFileRole).toString();
    const qint64 line = item->data(StackItemLineRole).toLongLong();
    if (file.isEmpty() || line <= 0)
    {
        return;
    }
    LuaDebuggerCodeView *view = loadFile(file);
    if (view)
    {
        view->moveCaretToLineStart(static_cast<qint32>(line));
    }
}

void LuaDebuggerDialog::onMonospaceFontUpdated(const QFont &font)
{
    applyCodeEditorFonts(font);
}

void LuaDebuggerDialog::onMainAppInitialized()
{
    applyMonospaceFonts();
}

void LuaDebuggerDialog::onPreferencesChanged()
{
    applyCodeViewThemes();
    applyMonospaceFonts();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::onThemeChanged(int idx)
{
    if (themeComboBox)
    {
        int32_t theme = themeComboBox->itemData(idx).toInt();

        /* Update static theme for CodeView syntax highlighting */
        currentTheme_ = theme;

        /* Store theme in our JSON settings */
        if (theme == WSLUA_DEBUGGER_THEME_DARK)
            settings_["theme"] = "dark";
        else if (theme == WSLUA_DEBUGGER_THEME_LIGHT)
            settings_["theme"] = "light";
        else
            settings_["theme"] = "auto";

        applyCodeViewThemes();
    }
}

void LuaDebuggerDialog::onColorsChanged()
{
    /*
     * When Wireshark's color scheme changes and the debugger theme is set to
     * "Auto (follow color scheme)", we need to re-apply themes to all code
     * views. The applyCodeViewThemes() function will query
     * ColorUtils::themeIsDark() to determine the effective theme.
     */
    applyCodeViewThemes();
    refreshWatchDisplay();
}

/**
 * @brief Static callback invoked before Lua plugins are reloaded.
 *
 * This callback is registered with wslua_debugger_register_reload_callback()
 * and is called by wslua_reload_plugins() BEFORE any Lua scripts are
 * unloaded or reloaded.
 *
 * The callback forwards to the dialog instance to reload all open
 * script files from disk. This ensures that when a breakpoint is hit
 * during the reload, the debugger displays the current version of
 * the script (which the user may have edited externally).
 */
void LuaDebuggerDialog::onLuaReloadCallback()
{
    LuaDebuggerDialog *dialog = _instance;
    if (dialog)
    {
        /*
         * Plugin reload wipes the Lua state, so the set of variables /
         * locals / globals the user is looking at may be meaningless after
         * reload. Reset all baselines to avoid falsely flagging values as
         * "changed" simply because the world was rebuilt.
         */
        dialog->clearAllChangeBaselines();
        dialog->enterReloadUiStateIfEnabled();

        /*
         * If the debugger was paused, the UI layer called
         * wslua_debugger_notify_reload() which disabled the debugger
         * (continuing execution) and invoked this callback.
         * Exit the nested event loop so the Lua call stack can unwind.
         * handlePause() will schedule a deferred reload afterwards.
         */
        if (dialog->debuggerPaused && dialog->eventLoop)
        {
            dialog->debuggerPaused = false;
            dialog->clearPausedStateUi();
            dialog->refreshDebuggerStateUi();
            dialog->reloadDeferred = true;
            dialog->eventLoop->quit();
            return;
        }

        /*
         * Reload all script files from disk.
         * This must happen BEFORE Lua executes any code.
         */
        dialog->reloadAllScriptFiles();

        /*
         * Update breakpoint markers in all open code views.
         * This ensures the gutter shows correct breakpoint indicators.
         *
         * Note: refreshAvailableScripts() and updateBreakpoints() are now
         * called in onLuaPostReloadCallback() AFTER plugins are loaded,
         * so new scripts appear in the file tree.
         */
        if (dialog->ui->codeTabWidget)
        {
            const qint32 tabCount =
                static_cast<qint32>(dialog->ui->codeTabWidget->count());
            for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
            {
                LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
                    dialog->ui->codeTabWidget->widget(
                        static_cast<int>(tabIndex)));
                if (view)
                {
                    view->updateBreakpointMarkers();
                }
            }
        }
        dialog->refreshDebuggerStateUi();
    }
}

/**
 * @brief Static callback invoked AFTER Lua plugins are reloaded.
 *
 * This callback refreshes the file tree with newly loaded scripts.
 * It is called after wslua_init() completes, so the plugin list
 * now contains all the new scripts.
 */
void LuaDebuggerDialog::onLuaPostReloadCallback()
{
    LuaDebuggerDialog *dialog = _instance;
    if (dialog)
    {
        dialog->exitReloadUiState();
        /*
         * Refresh the file tree with newly loaded scripts.
         * This is the correct place to do it because we're called
         * AFTER wslua_init() has loaded all plugins.
         */
        dialog->refreshAvailableScripts();
        dialog->updateBreakpoints();
    }
}

/**
 * @brief Static callback invoked when a Lua script is loaded.
 *
 * This callback is called by the Lua loader for each script that is
 * successfully loaded. We add the script to the file tree.
 */
void LuaDebuggerDialog::onScriptLoadedCallback(const char *file_path)
{
    LuaDebuggerDialog *dialog = _instance;
    if (dialog && file_path)
    {
        dialog->ensureFileTreeEntry(QString::fromUtf8(file_path));
        dialog->fileModel->sort(0, Qt::AscendingOrder);
    }
}

void LuaDebuggerDialog::reloadAllScriptFiles()
{
    if (!ui->codeTabWidget)
    {
        return;
    }

    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            if (view->document()->isModified())
            {
                /* Keep in-memory edits when this reload was not preceded by a
                 * save/discard prompt (e.g. Analyze → Reload Lua Plugins). */
                continue;
            }
            QString filePath = view->getFilename();
            if (!filePath.isEmpty())
            {
                QFile file(filePath);
                if (file.open(QIODevice::ReadOnly | QIODevice::Text))
                {
                    QTextStream in(&file);
                    QString content = in.readAll();
                    file.close();
                    view->setPlainText(content);
                }
            }
        }
    }
}

void LuaDebuggerDialog::applyCodeViewThemes()
{
    ui->luaDebuggerFindFrame->updateStyleSheet();
    ui->luaDebuggerGoToLineFrame->updateStyleSheet();
    /* Theme / palette changed — recompute the accent + flash brushes used
     * by applyChangedVisuals so the Watch and Variables cues track the
     * active light/dark theme. */
    refreshChangedValueBrushes();
    if (!ui->codeTabWidget)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->applyTheme();
        }
    }
}

/**
 * @brief Callback function for wslua_debugger_foreach_loaded_script.
 *
 * This C callback receives each loaded script path from the Lua subsystem
 * and adds it to the file tree via the dialog instance.
 */
static void loaded_script_callback(const char *file_path, void *user_data)
{
    LuaDebuggerDialog *dialog = static_cast<LuaDebuggerDialog *>(user_data);
    if (dialog && file_path)
    {
        dialog->ensureFileTreeEntry(QString::fromUtf8(file_path));
    }
}

void LuaDebuggerDialog::refreshAvailableScripts()
{
    /* Clear existing file tree entries */
    if (fileModel)
    {
        fileModel->removeRows(0, fileModel->rowCount());
    }

    /*
     * First, scan the plugin directories to show all available .lua files.
     * This includes files that may not be loaded yet.
     */
    const char *envPrefix = application_configuration_environment_prefix();
    if (envPrefix)
    {
        const char *personal = get_plugins_pers_dir(envPrefix);
        const char *global = get_plugins_dir(envPrefix);
        if (personal && personal[0])
        {
            scanScriptDirectory(QString::fromUtf8(personal));
        }
        if (global && global[0])
        {
            scanScriptDirectory(QString::fromUtf8(global));
        }
    }

    /*
     * Then, add any loaded scripts that might be outside the plugin
     * directories (e.g., command-line scripts).
     */
    wslua_debugger_foreach_loaded_script(loaded_script_callback, this);

    fileModel->sort(0, Qt::AscendingOrder);
    fileTree->expandAll();
}

void LuaDebuggerDialog::scanScriptDirectory(const QString &dir_path)
{
    if (dir_path.isEmpty())
    {
        return;
    }

    QDir scriptDirectory(dir_path);
    if (!scriptDirectory.exists())
    {
        return;
    }

    QDirIterator scriptIterator(dir_path, QStringList() << "*.lua", QDir::Files,
                                QDirIterator::Subdirectories);
    while (scriptIterator.hasNext())
    {
        ensureFileTreeEntry(scriptIterator.next());
    }
}

bool LuaDebuggerDialog::ensureFileTreeEntry(const QString &file_path)
{
    if (!fileModel)
    {
        return false;
    }
    QString normalized = normalizedFilePath(file_path);
    if (normalized.isEmpty())
    {
        return false;
    }

    QVector<QPair<QString, QString>> components;
    if (!appendPathComponents(normalized, components))
    {
        return false;
    }

    QStandardItem *parent = nullptr;
    bool createdLeaf = false;
    const qint32 componentCount = static_cast<qint32>(components.size());
    for (qint32 componentIndex = 0; componentIndex < componentCount;
         ++componentIndex)
    {
        const bool isLeaf = (componentIndex == componentCount - 1);
        const QString displayName =
            components.at(static_cast<int>(componentIndex)).first;
        const QString absolutePath =
            components.at(static_cast<int>(componentIndex)).second;
        QStandardItem *item = findChildItemByPath(parent, absolutePath);
        if (!item)
        {
            item = new QStandardItem();
            item->setText(displayName);
            item->setToolTip(absolutePath);
            item->setData(absolutePath, FileTreePathRole);
            item->setData(!isLeaf, FileTreeIsDirectoryRole);
            item->setIcon(isLeaf ? fileIcon : folderIcon);
            if (parent)
            {
                parent->appendRow(item);
                parent->sortChildren(0, Qt::AscendingOrder);
            }
            else if (fileModel)
            {
                fileModel->appendRow(item);
                fileModel->sort(0, Qt::AscendingOrder);
            }
            if (isLeaf)
            {
                createdLeaf = true;
            }
        }
        parent = item;
    }

    if (createdLeaf)
    {
        fileTree->expandAll();
    }

    return createdLeaf;
}

QString LuaDebuggerDialog::normalizedFilePath(const QString &file_path) const
{
    QString trimmed = file_path.trimmed();
    if (trimmed.startsWith("@"))
    {
        trimmed = trimmed.mid(1);
    }

    QFileInfo info(trimmed);
    QString absolutePath = info.absoluteFilePath();

    if (info.exists())
    {
        QString canonical = info.canonicalFilePath();
        if (!canonical.isEmpty())
        {
            return canonical;
        }
        return QDir::cleanPath(absolutePath);
    }

    if (!absolutePath.isEmpty())
    {
        return QDir::cleanPath(absolutePath);
    }

    return trimmed;
}

QStandardItem *
LuaDebuggerDialog::findChildItemByPath(QStandardItem *parent,
                                       const QString &path) const
{
    if (parent)
    {
        const qint32 childCount = static_cast<qint32>(parent->rowCount());
        for (qint32 childIndex = 0; childIndex < childCount; ++childIndex)
        {
            QStandardItem *child =
                parent->child(static_cast<int>(childIndex));
            if (child->data(FileTreePathRole).toString() == path)
            {
                return child;
            }
        }
        return nullptr;
    }

    const qint32 topLevelCount =
        static_cast<qint32>(fileModel->rowCount());
    for (qint32 topLevelIndex = 0; topLevelIndex < topLevelCount;
         ++topLevelIndex)
    {
        QStandardItem *item =
            fileModel->item(static_cast<int>(topLevelIndex));
        if (item->data(FileTreePathRole).toString() == path)
        {
            return item;
        }
    }
    return nullptr;
}

bool LuaDebuggerDialog::appendPathComponents(
    const QString &absolute_path,
    QVector<QPair<QString, QString>> &components) const
{
    QString forwardPath = QDir::fromNativeSeparators(absolute_path);
    QStringList segments = forwardPath.split('/', Qt::SkipEmptyParts);
    const qint32 segmentCount = static_cast<qint32>(segments.size());
    QString currentForward;
    qint32 segmentStartIndex = 0;

    if (absolute_path.startsWith("\\\\") || absolute_path.startsWith("//"))
    {
        if (segmentCount < 2)
        {
            return false;
        }
        currentForward =
            QStringLiteral("//%1/%2").arg(segments.at(0), segments.at(1));
        QString display =
            QStringLiteral("\\\\%1\\%2").arg(segments.at(0), segments.at(1));
        components.append({display, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 2;
    }
    else if (segmentCount > 0 && segments.first().endsWith(QLatin1Char(':')))
    {
        currentForward = segments.first();
        QString storedRoot = currentForward;
        if (!storedRoot.endsWith(QLatin1Char('/')))
        {
            storedRoot += QLatin1Char('/');
        }
        components.append(
            {currentForward, QDir::toNativeSeparators(storedRoot)});
        segmentStartIndex = 1;
    }
    else if (absolute_path.startsWith('/'))
    {
        currentForward = QStringLiteral("/");
        components.append({currentForward, currentForward});
    }
    else if (segmentCount > 0)
    {
        currentForward = segments.first();
        components.append(
            {currentForward, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 1;
    }

    if (currentForward.isEmpty() && segmentCount > 0)
    {
        currentForward = segments.first();
        components.append(
            {currentForward, QDir::toNativeSeparators(currentForward)});
        segmentStartIndex = 1;
    }

    for (qint32 segmentIndex = segmentStartIndex; segmentIndex < segmentCount;
         ++segmentIndex)
    {
        const QString &segment = segments.at(static_cast<int>(segmentIndex));
        if (currentForward.isEmpty() || currentForward == "/")
        {
            currentForward = currentForward == "/"
                                 ? QStringLiteral("/%1").arg(segment)
                                 : segment;
        }
        else
        {
            currentForward += "/" + segment;
        }
        components.append({segment, QDir::toNativeSeparators(currentForward)});
    }

    return !components.isEmpty();
}

void LuaDebuggerDialog::openInitialBreakpointFiles(
    const QVector<QString> &files)
{
    for (const QString &path : files)
    {
        loadFile(path);
    }
}

void LuaDebuggerDialog::configureVariablesTreeColumns()
{
    if (!variablesTree || !variablesModel || !variablesTree->header())
    {
        return;
    }
    QHeaderView *header = variablesTree->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    /* Visible columns: Name, Value (column 2 Type is hidden). */
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    // Initial width for Name column - Value column stretches to fill the rest
    header->resizeSection(0, 150);
}

void LuaDebuggerDialog::configureWatchTreeColumns()
{
    if (!watchTree || !watchTree->header())
    {
        return;
    }
    QHeaderView *header = watchTree->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    header->resizeSection(0, 200);
}

void LuaDebuggerDialog::configureStackTreeColumns()
{
    if (!stackTree || !stackTree->header())
    {
        return;
    }
    QHeaderView *header = stackTree->header();
    header->setStretchLastSection(true);
    header->setSectionsMovable(false);
    header->setSectionResizeMode(0, QHeaderView::Interactive);
    header->setSectionResizeMode(1, QHeaderView::Stretch);
    // Initial width for Function column - Location column stretches to fill the
    // rest
    header->resizeSection(0, 150);
}

void LuaDebuggerDialog::clearPausedStateUi()
{
    if (variablesTree)
    {
        if (variablesModel)
        {
            variablesModel->removeRows(0, variablesModel->rowCount());
        }
    }
    if (stackModel)
    {
        stackModel->removeRows(0, stackModel->rowCount());
    }
    clearAllCodeHighlights();
}

void LuaDebuggerDialog::resumeDebuggerAndExitLoop()
{
    if (debuggerPaused)
    {
        wslua_debugger_continue();
        debuggerPaused = false;
        clearPausedStateUi();
    }

    if (eventLoop)
    {
        eventLoop->quit();
    }
}

void LuaDebuggerDialog::endPauseFreeze()
{
    /* Idempotent: called both from handlePause()'s post-loop cleanup
     * (normal Continue/Step exit) and from closeEvent() when the user
     * closes the main window while we are paused. In the latter case
     * the nested QEventLoop has been asked to quit via
     * resumeDebuggerAndExitLoop() but has not yet unwound, so
     * WiresharkMainWindow::closeEvent will continue running straight
     * after dbg->close() returns — tryClosingCaptureFile() may then
     * pop up a "Save unsaved capture?" modal. Tearing the pause
     * freeze down here, synchronously, is what lets those prompts
     * respond to input; by the time handlePause returns to this
     * function the second call is a no-op. */
    if (pauseUnfrozen_) {
        return;
    }
    pauseUnfrozen_ = true;

    MainWindow *mw = mainApp ? mainApp->mainWindow() : nullptr;

    /* Remove the input/paint filter FIRST so the upcoming
     * setEnabled(true) cascades can post normal QEvent::UpdateRequest
     * events to the main window and actually repaint it. */
    if (pauseInputFilter)
    {
        qApp->removeEventFilter(pauseInputFilter);
        delete pauseInputFilter;
        pauseInputFilter = nullptr;
    }

    /* Tear the overlay down before re-enabling the main window so the
     * setEnabled(true) cascade below repaints fresh viewport pixels
     * with nothing on top. */
    if (pauseOverlay) {
        delete pauseOverlay;
        pauseOverlay = nullptr;
    }

    /* Re-enable the main window's central widget. setEnabled(true)
     * triggers Qt's internal update() cascade over the widget and all
     * its descendants (packet list, details tree, byte view, ...),
     * which is what actually repaints the viewport backing store
     * after the pause — without this pass the packet list would stay
     * rendered as the frozen-at-pause-entry repaint() produced and
     * appear "still paused" until an unrelated expose event (e.g.
     * switching macOS spaces) forced a repaint. The PauseInputFilter
     * has already been removed above, so the UpdateRequests posted by
     * this cascade flow to the main window normally. Doing this
     * BEFORE re-enabling the other top-levels lets the visually most
     * prominent area of the app refresh first. */
    if (frozenCentralWidget) {
        frozenCentralWidget->setEnabled(true);
    }
    frozenCentralWidget.clear();

    /* Re-enable top-levels that were disabled at pause entry. QPointer
     * guards against any that were destroyed during the pause (e.g.
     * Qt reaped them when the main window closed). */
    const QList<QPointer<QWidget>> frozen_snapshot = frozenTopLevels;
    frozenTopLevels.clear();
    for (const QPointer<QWidget> &w : frozen_snapshot)
    {
        if (w) {
            w->setEnabled(true);
        }
    }

    /* Re-enable QActions disabled at pause entry. */
    const QList<QPointer<QAction>> action_snapshot = frozenActions;
    frozenActions.clear();
    for (const QPointer<QAction> &a : action_snapshot)
    {
        if (a) {
            a->setEnabled(true);
        }
    }

    /* Force a full repaint of the main window once the call stack has
     * unwound. handlePause() is commonly entered from inside
     * QWidgetRepaintManager::paintAndFlush() (scroll → packet list
     * paintEvent → dissect_lua → Lua hook → handlePause), which means
     * we are STILL inside the outer paint cycle right now. mw->update()
     * here would post a QEvent::UpdateRequest, but Qt's repaint manager
     * will mark the dirty regions of that update as "satisfied" by the
     * outer paint that is finishing above us — the packet list ends up
     * stuck rendered as it was at pause entry until the user does
     * something that genuinely invalidates the viewport (resize,
     * scroll, switch macOS Spaces, …). Queue an explicit repaint on
     * the next event-loop iteration via QTimer::singleShot(0, …): by
     * then the outer paint has fully completed, mw->repaint() runs
     * synchronously on a clean stack, and every visible child widget
     * (packet list, details tree, byte view) gets a fresh paintEvent.
     * The QPointer guard handles the unlikely case that the main
     * window is destroyed before the timer fires; QTimer::singleShot
     * with mw as receiver also auto-cancels in that case. */
    if (mw) {
        QPointer<QWidget> mw_p(mw);
        QTimer::singleShot(0, mw, [mw_p]() {
            if (mw_p) {
                mw_p->repaint();
            }
        });
    }
}

void LuaDebuggerDialog::onVariablesContextMenuRequested(const QPoint &pos)
{
    if (!variablesTree || !variablesModel)
    {
        return;
    }

    const QModelIndex ix = variablesTree->indexAt(pos);
    if (!ix.isValid())
    {
        return;
    }
    QStandardItem *item =
        variablesModel->itemFromIndex(ix.sibling(ix.row(), 0));
    if (!item)
    {
        return;
    }

    const QString nameText = item->text();
    const QString valueText = text(variablesModel, item, 1);
    const QString bothText =
        valueText.isEmpty() ? nameText : tr("%1 = %2").arg(nameText, valueText);

    const QString varPath = item->data(VariablePathRole).toString();

    QMenu menu(this);
    QAction *copyName = menu.addAction(tr("Copy Name"));
    QAction *copyValue = menu.addAction(tr("Copy Value"));
    QAction *copyPath = nullptr;
    if (!varPath.isEmpty())
    {
        copyPath = menu.addAction(tr("Copy Path"));
    }
    QAction *copyNameValue = menu.addAction(tr("Copy Name && Value"));

    auto copyToClipboard = [](const QString &text)
    {
        if (QClipboard *clipboard = QGuiApplication::clipboard())
        {
            clipboard->setText(text);
        }
    };

    connect(copyName, &QAction::triggered, this,
            [copyToClipboard, nameText]() { copyToClipboard(nameText); });
    connect(copyValue, &QAction::triggered, this,
            [copyToClipboard, valueText]() { copyToClipboard(valueText); });
    if (copyPath)
    {
        connect(copyPath, &QAction::triggered, this,
                [copyToClipboard, varPath]() { copyToClipboard(varPath); });
    }
    connect(copyNameValue, &QAction::triggered, this,
        [copyToClipboard, bothText]() { copyToClipboard(bothText); });

    menu.addSeparator();
    if (!varPath.isEmpty())
    {
        QAction *addWatch =
            menu.addAction(tr("Add Watch: \"%1\"")
                                .arg(varPath.length() > 48
                                        ? varPath.left(48) +
                                                QStringLiteral("…")
                                        : varPath));
        connect(addWatch, &QAction::triggered, this,
                [this, varPath]() { addWatchFromSpec(varPath); });
    }

    menu.exec(variablesTree->viewport()->mapToGlobal(pos));
}

void LuaDebuggerDialog::onFileTreeContextMenuRequested(const QPoint &pos)
{
    if (!fileTree || !fileModel)
    {
        return;
    }
    const QModelIndex ix = fileTree->indexAt(pos);
    if (!ix.isValid())
    {
        return;
    }
    QStandardItem *item =
        fileModel->itemFromIndex(ix.sibling(ix.row(), 0));
    if (!item || item->data(FileTreeIsDirectoryRole).toBool())
    {
        /* Only file leaves get a menu — directory rows are
         * decorative groupings. */
        return;
    }
    const QString path = item->data(FileTreePathRole).toString();
    if (path.isEmpty())
    {
        return;
    }

    QMenu menu(this);
    QAction *openAct = menu.addAction(tr("Open Source"));
    QAction *revealAct = menu.addAction(tr("Reveal in File Manager"));
    menu.addSeparator();
    QAction *copyPathAct = menu.addAction(tr("Copy Path"));

    QAction *chosen = menu.exec(fileTree->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }
    if (chosen == openAct)
    {
        loadFile(path);
        return;
    }
    if (chosen == revealAct)
    {
        /* Open the *parent* directory rather than the file itself: the
         * file might be associated with an external editor that would
         * launch on open, which is not what "Reveal" implies. */
        const QString parentDir = QFileInfo(path).absolutePath();
        if (!parentDir.isEmpty())
        {
            QDesktopServices::openUrl(QUrl::fromLocalFile(parentDir));
        }
        return;
    }
    if (chosen == copyPathAct)
    {
        if (QClipboard *clip = QGuiApplication::clipboard())
        {
            clip->setText(path);
        }
        return;
    }
}

void LuaDebuggerDialog::onStackContextMenuRequested(const QPoint &pos)
{
    if (!stackTree || !stackModel)
    {
        return;
    }
    const QModelIndex ix = stackTree->indexAt(pos);
    if (!ix.isValid())
    {
        return;
    }
    QStandardItem *item =
        stackModel->itemFromIndex(ix.sibling(ix.row(), 0));
    if (!item)
    {
        return;
    }

    const bool navigable = item->data(StackItemNavigableRole).toBool();
    const QString file = item->data(StackItemFileRole).toString();
    const qint64 line = item->data(StackItemLineRole).toLongLong();

    QMenu menu(this);
    QAction *openAct = menu.addAction(tr("Open Source"));
    /* C frames cannot be opened — gray the entry instead of hiding it
     * so the menu stays positionally consistent across rows. */
    openAct->setEnabled(navigable && !file.isEmpty() && line > 0);
    QAction *copyLocAct = menu.addAction(tr("Copy Location"));
    copyLocAct->setEnabled(!file.isEmpty() && line > 0);

    QAction *chosen = menu.exec(stackTree->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }
    if (chosen == openAct && openAct->isEnabled())
    {
        LuaDebuggerCodeView *view = loadFile(file);
        if (view)
        {
            view->moveCaretToLineStart(static_cast<qint32>(line));
        }
        return;
    }
    if (chosen == copyLocAct && copyLocAct->isEnabled())
    {
        if (QClipboard *clip = QGuiApplication::clipboard())
        {
            clip->setText(QStringLiteral("%1:%2").arg(file).arg(line));
        }
        return;
    }
}

void LuaDebuggerDialog::clearAllCodeHighlights()
{
    if (!ui->codeTabWidget)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->clearCurrentLineHighlight();
        }
    }
}

void LuaDebuggerDialog::applyMonospaceFonts()
{
    applyCodeEditorFonts(effectiveMonospaceFont(true));
    applyMonospacePanelFonts();
}

void LuaDebuggerDialog::applyCodeEditorFonts(const QFont &monoFont)
{
    QFont font = monoFont;
    if (font.family().isEmpty())
    {
        font = effectiveMonospaceFont(true);
    }

    if (!ui->codeTabWidget)
    {
        return;
    }
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *view = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (view)
        {
            view->setEditorFont(font);
        }
    }
}

/**
 * @brief Walk the watch @c QStandardItemModel tree: set each item’s
 * @c QFont to the panel monospace while preserving the existing bold bit
 * (change-highlight) so it wins over the tree widget font after row moves.
 */
// NOLINTNEXTLINE(misc-no-recursion)
static void reapplyMonospaceToWatchItemModelRecursive(const QFont &base,
                                                      QStandardItemModel *m,
                                                      const QModelIndex &parent)
{
    if (!m)
    {
        return;
    }
    const int rows = m->rowCount(parent);
    const int cols = m->columnCount(parent);
    for (int r = 0; r < rows; ++r)
    {
        for (int c = 0; c < cols; ++c)
        {
            const QModelIndex idx = m->index(r, c, parent);
            if (QStandardItem *it = m->itemFromIndex(idx))
            {
                QFont f = base;
                f.setBold(it->font().bold());
                it->setFont(f);
            }
        }
        const QModelIndex col0 = m->index(r, 0, parent);
        if (col0.isValid() && m->rowCount(col0) > 0)
        {
            reapplyMonospaceToWatchItemModelRecursive(base, m, col0);
        }
    }
}

void LuaDebuggerDialog::reapplyMonospaceToWatchItemFonts()
{
    if (!watchModel)
    {
        return;
    }
    reapplyMonospaceToWatchItemModelRecursive(
        effectiveMonospaceFont(false), watchModel, QModelIndex());
    if (watchTree)
    {
        watchTree->update();
    }
}

void LuaDebuggerDialog::applyMonospacePanelFonts()
{
    const QFont panelMono = effectiveMonospaceFont(false);
    const QFont headerFont = effectiveRegularFont();

    const QList<QWidget *> widgets = {variablesTree, watchTree, stackTree,
                                      breakpointsTree, evalInputEdit,
                                      evalOutputEdit};
    for (QWidget *widget : widgets)
    {
        if (widget)
        {
            widget->setFont(panelMono);
        }
    }

    const QList<QTreeView *> treesWithStandardHeaders = {
        variablesTree, watchTree, stackTree, fileTree, breakpointsTree};
    for (QTreeView *tree : treesWithStandardHeaders)
    {
        if (tree && tree->header())
        {
            tree->header()->setFont(headerFont);
        }
    }
    reapplyMonospaceToWatchItemFonts();
}

QFont LuaDebuggerDialog::effectiveMonospaceFont(bool zoomed) const
{
    /* Monospace font for panels and the script editor. */
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->monospaceFont(zoomed);
    }

    /* Fall back to system fixed font */
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
}

QFont LuaDebuggerDialog::effectiveRegularFont() const
{
    if (mainApp && mainApp->isInitialized())
    {
        return mainApp->font();
    }
    return QGuiApplication::font();
}

void LuaDebuggerDialog::syncDebuggerToggleWithCore()
{
    if (!enabledCheckBox)
    {
        return;
    }
    if (reloadUiActive_)
    {
        bool previousState = enabledCheckBox->blockSignals(true);
        enabledCheckBox->setChecked(true);
        enabledCheckBox->setEnabled(false);
        enabledCheckBox->blockSignals(previousState);
        return;
    }
    const bool debuggerEnabled = wslua_debugger_is_enabled();
    bool previousState = enabledCheckBox->blockSignals(true);
    enabledCheckBox->setChecked(debuggerEnabled);
    enabledCheckBox->blockSignals(previousState);
    /* Lock the toggle while a live capture is forcing the debugger
     * off so the checkbox cannot drift out of sync with the core
     * state, and the user gets an obvious "this is intentional, not
     * me" affordance. The disabled icon's tooltip explains why. */
    enabledCheckBox->setEnabled(!isSuppressedByLiveCapture());
}

void LuaDebuggerDialog::refreshDebuggerStateUi()
{
    /* Full reconciliation is centralized in updateWidgets() (which syncs
     * the checkbox to the C core, then repaints status chrome). */
    updateWidgets();
}

void LuaDebuggerDialog::enterReloadUiStateIfEnabled()
{
    if (!enabledCheckBox || reloadUiActive_)
    {
        return;
    }

    bool shouldActivate = reloadUiRequestWasEnabled_;
    if (!shouldActivate)
    {
        shouldActivate = enabledCheckBox->isChecked();
    }
    if (!shouldActivate)
    {
        return;
    }

    reloadUiSavedCheckboxChecked_ = enabledCheckBox->isChecked();
    reloadUiSavedCheckboxEnabled_ = enabledCheckBox->isEnabled();
    reloadUiActive_ = true;

    bool previousState = enabledCheckBox->blockSignals(true);
    enabledCheckBox->setChecked(true);
    enabledCheckBox->setEnabled(false);
    enabledCheckBox->blockSignals(previousState);

    updateWidgets();
}

void LuaDebuggerDialog::exitReloadUiState()
{
    reloadUiRequestWasEnabled_ = false;
    if (!enabledCheckBox || !reloadUiActive_)
    {
        return;
    }

    bool previousState = enabledCheckBox->blockSignals(true);
    enabledCheckBox->setChecked(reloadUiSavedCheckboxChecked_);
    enabledCheckBox->setEnabled(reloadUiSavedCheckboxEnabled_);
    enabledCheckBox->blockSignals(previousState);

    reloadUiActive_ = false;
    refreshDebuggerStateUi();
}

LuaDebuggerDialog::DebuggerUiStatus
LuaDebuggerDialog::currentDebuggerUiStatus() const
{
    if (reloadUiActive_)
    {
        return DebuggerUiStatus::Running;
    }
    const bool debuggerEnabled = wslua_debugger_is_enabled();
    const bool showPausedChrome = wslua_debugger_is_paused() ||
                                  (debuggerEnabled && debuggerPaused);
    if (showPausedChrome)
    {
        return DebuggerUiStatus::Paused;
    }
    if (!debuggerEnabled)
    {
        if (isSuppressedByLiveCapture())
        {
            return DebuggerUiStatus::DisabledLiveCapture;
        }
        return DebuggerUiStatus::Disabled;
    }
    return DebuggerUiStatus::Running;
}

void LuaDebuggerDialog::updateEnabledCheckboxIcon()
{
    if (!enabledCheckBox)
    {
        return;
    }

    // Create a colored circle icon to indicate enabled/disabled state.
    // Render at the screen's native pixel density so the circle stays
    // crisp on Retina / HiDPI displays instead of being upscaled from
    // a 16x16 bitmap.
    const qreal dpr = enabledCheckBox->devicePixelRatioF();
    QPixmap pixmap(QSize(16, 16) * dpr);
    pixmap.setDevicePixelRatio(dpr);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    const DebuggerUiStatus uiStatus = currentDebuggerUiStatus();
    QColor fill;
    switch (uiStatus)
    {
    case DebuggerUiStatus::Paused:
        // Yellow circle for paused
        fill = QColor("#FFC107");
        enabledCheckBox->setToolTip(
            tr("Debugger is paused. Uncheck to disable."));
        break;
    case DebuggerUiStatus::Running:
        // Green circle for enabled
        fill = QColor("#28A745");
        enabledCheckBox->setToolTip(
            tr("Debugger is enabled. Uncheck to disable."));
        break;
    case DebuggerUiStatus::DisabledLiveCapture:
        // Red circle with a "locked by live capture" tooltip so
        // the user understands the toggle is inert by design.
        fill = QColor("#DC3545");
        enabledCheckBox->setToolTip(
            tr("Debugger is disabled while a live capture is running. "
               "Stop the capture to re-enable."));
        break;
    case DebuggerUiStatus::Disabled:
        // Gray circle for disabled
        fill = QColor("#808080");
        enabledCheckBox->setToolTip(
            tr("Debugger is disabled. Check to enable."));
        break;
    }

    // Thin darker rim gives the circle definition on both light and dark backgrounds.
    painter.setBrush(fill);
    painter.setPen(QPen(fill.darker(140), 1));
    painter.drawEllipse(QRectF(2.5, 2.5, 12.0, 12.0));
    painter.end();

    /* Register the colored pixmap for BOTH QIcon::Normal and
     * QIcon::Disabled. The checkbox widget is disabled in the
     * "suppressed by live capture" state (see
     * syncDebuggerToggleWithCore), and with only a Normal pixmap
     * supplied, Qt synthesizes a Disabled pixmap by desaturating it.
     * macOS's Cocoa style does this subtly enough that the red stays
     * visible, but Linux styles (Fusion / Breeze / Adwaita / gtk3)
     * desaturate aggressively, making the red circle look gray. */
    QIcon icon;
    icon.addPixmap(pixmap, QIcon::Normal);
    icon.addPixmap(pixmap, QIcon::Disabled);
    enabledCheckBox->setIcon(icon);
}

void LuaDebuggerDialog::updateStatusLabel()
{
    const DebuggerUiStatus uiStatus = currentDebuggerUiStatus();
    /* [*] is required for setWindowModified() to show an unsaved
     * indicator in the title. */
    QString title = QStringLiteral("[*]%1").arg(tr("Lua Debugger"));

#ifdef Q_OS_MAC
        // On macOS we separate with a unicode em dash
        title += QString(" " UTF8_EM_DASH " ");
#else
        title += QString(" - ");
#endif

    switch (uiStatus)
    {
    case DebuggerUiStatus::Paused:
        title += tr("Paused");
        break;
    case DebuggerUiStatus::DisabledLiveCapture:
        title += tr("Disabled (live capture)");
        break;
    case DebuggerUiStatus::Disabled:
        title += tr("Disabled");
        break;
    case DebuggerUiStatus::Running:
        title += tr("Running");
        break;
    }

    setWindowTitle(title);
    updateWindowModifiedState();
}

void LuaDebuggerDialog::updateContinueActionState()
{
    const bool allowContinue = wslua_debugger_is_enabled() && debuggerPaused;
    ui->actionContinue->setEnabled(allowContinue);
    ui->actionStepOver->setEnabled(allowContinue);
    ui->actionStepIn->setEnabled(allowContinue);
    ui->actionStepOut->setEnabled(allowContinue);
    /* Run to this line additionally requires a focusable line in the editor,
     * i.e. an active code view tab. */
    ui->actionRunToLine->setEnabled(allowContinue && currentCodeView() != nullptr);
}

void LuaDebuggerDialog::updateWidgets()
{
#ifndef QT_NO_DEBUG
    if (wslua_debugger_is_paused())
    {
        Q_ASSERT(wslua_debugger_is_enabled());
    }
#endif
    syncDebuggerToggleWithCore();
    updateEnabledCheckboxIcon();
    updateStatusLabel();
    updateContinueActionState();
    updateEvalPanelState();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::ensureDebuggerEnabledForActiveBreakpoints()
{
    /* wslua_debugger owns enable *policy*; live capture gating is owned here
     * (s_captureSuppression*): epan has no knowledge of the capture path. */
    if (!wslua_debugger_may_auto_enable_for_breakpoints())
    {
        refreshDebuggerStateUi();
        return;
    }
    if (isSuppressedByLiveCapture())
    {
        /* A breakpoint was just (re)armed during a live capture.
         * Record the intent so the debugger comes back enabled when
         * the capture stops, but do not flip the core flag now —
         * pausing the dissector with the dumpcap pipe still feeding
         * us packets is exactly what the suppression exists to
         * prevent. */
        s_captureSuppressionPrevEnabled_ = true;
        refreshDebuggerStateUi();
        return;
    }
    if (!wslua_debugger_is_enabled())
    {
        wslua_debugger_set_enabled(true);
        refreshDebuggerStateUi();
    }
}

void LuaDebuggerDialog::onOpenFile()
{
    QString startDir = lastOpenDirectory;
    if (startDir.isEmpty())
    {
        startDir = QDir::homePath();
    }

    const QString filePath = WiresharkFileDialog::getOpenFileName(
        this, tr("Open Lua Script"), startDir,
        tr("Lua Scripts (*.lua);;All Files (*)"));

    if (filePath.isEmpty())
    {
        return;
    }

    lastOpenDirectory = QFileInfo(filePath).absolutePath();
    loadFile(filePath);
}

void LuaDebuggerDialog::onReloadLuaPlugins()
{
    reloadUiRequestWasEnabled_ = false;
    if (!ensureUnsavedChangesHandled(tr("Reload Lua Plugins")))
    {
        return;
    }

    // Confirmation dialog
    QMessageBox::StandardButton reply = QMessageBox::question(
        this, tr("Reload Lua Plugins"),
        tr("Are you sure you want to reload all Lua plugins?\n\nThis will "
           "restart all Lua "
           "scripts and may affect capture analysis."),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

    if (reply != QMessageBox::Yes)
    {
        return;
    }
    reloadUiRequestWasEnabled_ = wslua_debugger_is_enabled();

    /*
     * If the debugger is currently paused, disable it (which continues
     * execution), signal the event loop to exit, and let handlePause()
     * schedule a deferred reload after the Lua call stack unwinds.
     */
    if (debuggerPaused)
    {
        wslua_debugger_notify_reload();
        /* onLuaReloadCallback() has already set reloadDeferred,
         * cleared paused UI, and quit the event loop. */
        updateWidgets();
        return;
    }

    /*
     * Not paused — trigger the reload directly via the delayed
     * path so it runs after this dialog method returns.
     */
    if (mainApp)
    {
        mainApp->reloadLuaPluginsDelayed();
    }
}

void LuaDebuggerDialog::updateEvalPanelState()
{
    const bool canEvaluate = debuggerPaused && wslua_debugger_is_paused();
    evalInputEdit->setEnabled(canEvaluate);
    evalButton->setEnabled(canEvaluate);

    if (!canEvaluate)
    {
        evalInputEdit->setPlaceholderText(
            tr("Evaluation available when debugger is paused"));
    }
    else
    {
        evalInputEdit->setPlaceholderText(
            tr("Enter Lua expression (prefix with = to return value)"));
    }
}

void LuaDebuggerDialog::onEvaluate()
{
    if (!debuggerPaused || !wslua_debugger_is_paused())
    {
        return;
    }

    QString expression = evalInputEdit->toPlainText().trimmed();
    if (expression.isEmpty())
    {
        return;
    }

    char *error_msg = nullptr;
    char *result =
        wslua_debugger_evaluate(expression.toUtf8().constData(), &error_msg);

    QString output;
    if (result)
    {
        output = QString::fromUtf8(result);
        g_free(result);
    }
    else if (error_msg)
    {
        output = tr("Error: %1").arg(QString::fromUtf8(error_msg));
        g_free(error_msg);
    }
    else
    {
        output = tr("Error: Unknown error");
    }

    // Append to output with separator
    QString currentOutput = evalOutputEdit->toPlainText();
    if (!currentOutput.isEmpty())
    {
        currentOutput += QStringLiteral("\n");
    }
    currentOutput += QStringLiteral("> %1\n%2").arg(expression, output);
    evalOutputEdit->setPlainText(currentOutput);

    // Scroll to bottom
    QTextCursor cursor = evalOutputEdit->textCursor();
    cursor.movePosition(QTextCursor::End);
    evalOutputEdit->setTextCursor(cursor);

    // Update all views in case the expression modified state
    updateStack();
    if (variablesModel)
        {
            variablesModel->removeRows(0, variablesModel->rowCount());
        }
    updateVariables(nullptr, QString());
    restoreVariablesExpansionState();
    refreshAvailableScripts();
    refreshWatchDisplay();
}

void LuaDebuggerDialog::onEvalClear()
{
    evalInputEdit->clear();
    evalOutputEdit->clear();
}

void LuaDebuggerDialog::storeWatchList()
{
    if (!watchTree)
    {
        return;
    }
    /* On disk, "watches" is a flat array of canonical watch spec strings in
     * visual order. Per-row expansion, editor origin, and other runtime state
     * are tracked in QStandardItem data roles only and are not persisted. */
    QStringList specs;
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *it = watchModel->item(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(WatchSpecRole).toString();
        if (spec.isEmpty())
        {
            continue;
        }
        specs.append(spec);
    }
    settings_[SettingsKeys::Watches] = specs;
    /* The runtime expansion map is keyed by root spec; drop entries for
     * specs that no longer exist in the tree. `storeWatchList` only runs
     * when the dialog is closing, which is also the last chance to avoid
     * persisting stale expansion data for specs that have since been
     * deleted or renamed. */
    pruneWatchExpansionMap();
}

void LuaDebuggerDialog::storeBreakpointsList()
{
    QVariantList list;
    const unsigned count = wslua_debugger_get_breakpoint_count();
    for (unsigned i = 0; i < count; i++)
    {
        const char *file = nullptr;
        int64_t line = 0;
        bool active = false;
        if (wslua_debugger_get_breakpoint(i, &file, &line, &active))
        {
            QJsonObject bp;
            bp[QStringLiteral("file")] = QString::fromUtf8(file);
            bp[QStringLiteral("line")] = static_cast<qint64>(line);
            bp[QStringLiteral("active")] = active;
            list.append(bp.toVariantMap());
        }
    }
    settings_[SettingsKeys::Breakpoints] = list;
}

void LuaDebuggerDialog::rebuildWatchTreeFromSettings()
{
    if (!watchTree || !watchModel)
    {
        return;
    }
    watchModel->removeRows(0, watchModel->rowCount());
    /* The tree is being repopulated from settings; any stale baselines for
     * specs that end up in the tree will be rebuilt naturally on the next
     * refresh. Wipe everything so a fresh session starts with no "changed"
     * flags. Variables baselines are kept because they are not tied to
     * watch specs. */
    watchRootBaseline_.clear();
    watchRootCurrent_.clear();
    watchChildBaseline_.clear();
    watchChildCurrent_.clear();
    /* The watch list on disk is a flat array of canonical spec strings.
     * Values that are not a valid path watch, or that are not strings, are
     * silently dropped (see wslua_debugger_watch_spec_uses_path_resolution). */
    const QVariantList rawList =
        settings_.value(QString::fromUtf8(SettingsKeys::Watches)).toList();
    for (const QVariant &entry : rawList)
    {
        /* Container QVariants (QVariantMap / QVariantList) toString() to an
         * empty string and are dropped here. Scalar-like values (numbers,
         * booleans) convert to a non-empty string but are then rejected by
         * watchSpecUsesPathResolution below. */
        const QString spec = entry.toString();
        if (spec.isEmpty())
        {
            continue;
        }
        if (!watchSpecUsesPathResolution(spec))
        {
            continue;
        }
        auto *col0 = new QStandardItem();
        auto *col1 = new QStandardItem();
        setupWatchRootItemFromSpec(col0, col1, spec);
        watchModel->appendRow({col0, col1});
    }
    refreshWatchDisplay();
    restoreWatchExpansionState();
}

namespace
{
// NOLINTNEXTLINE(misc-no-recursion)
static QStandardItem *findVariableItemByPathRecursive(QStandardItem *node,
                                                        const QString &path)
{
    if (!node)
    {
        return nullptr;
    }
    if (node->data(VariablePathRole).toString() == path)
    {
        return node;
    }
    const int n = node->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *r =
            findVariableItemByPathRecursive(node->child(i), path);
        if (r)
        {
            return r;
        }
    }
    return nullptr;
}
} // namespace

void LuaDebuggerDialog::deleteWatchRows(const QList<QStandardItem *> &items)
{
    if (!watchModel || items.isEmpty())
    {
        return;
    }
    QVector<int> indices;
    indices.reserve(items.size());
    for (QStandardItem *it : items)
    {
        if (!it || it->parent() != nullptr)
        {
            continue;
        }
        indices.append(it->row());
    }
    if (indices.isEmpty())
    {
        return;
    }
    /* Delete highest-index first so earlier indices remain valid. */
    std::sort(indices.begin(), indices.end(), std::greater<int>());
    for (int idx : indices)
    {
        watchModel->removeRow(idx);
    }
    /* After deletion, drop baselines for specs that are no longer present
     * in the tree so a later "Add Watch" of the same spec starts clean. */
    pruneChangeBaselinesToLiveWatchSpecs();
    refreshWatchDisplay();
}

QList<QStandardItem *>
LuaDebuggerDialog::selectedWatchRootItemsForRemove() const
{
    QList<QStandardItem *> del;
    if (!watchModel || !watchTree || !watchTree->selectionModel())
    {
        return del;
    }
    for (const QModelIndex &six :
         watchTree->selectionModel()->selectedRows(0))
    {
        QStandardItem *it = watchModel->itemFromIndex(six);
        if (it && it->parent() == nullptr)
        {
            del.append(it);
        }
    }
    /* Intentionally no QTreeView::currentIndex fallback: after a remove the
     * selection can be empty while current still points at a row, which would
     * leave the header button enabled and the next click would remove the
     * wrong (non-selected) entry. The context menu and Del key have their
     * own item/current handling. */
    return del;
}

void LuaDebuggerDialog::updateWatchHeaderButtonState()
{
    if (watchRemoveButton_)
    {
        watchRemoveButton_->setEnabled(
            !selectedWatchRootItemsForRemove().isEmpty());
    }
    if (watchRemoveAllButton_)
    {
        watchRemoveAllButton_->setEnabled(
            watchModel && watchModel->rowCount() > 0);
    }
}

void LuaDebuggerDialog::toggleAllBreakpointsActiveFromHeader()
{
    const unsigned n = wslua_debugger_get_breakpoint_count();
    if (n == 0U)
    {
        return;
    }
    /* Activate all only when every BP is off; if any is on (all on or mix),
     * this control shows “deactivate” and turns all off. */
    bool allInactive = true;
    for (unsigned i = 0; i < n; ++i)
    {
        const char *file_path;
        int64_t line;
        bool active;
        if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active) &&
            active)
        {
            allInactive = false;
            break;
        }
    }
    const bool makeActive = allInactive;
    for (unsigned i = 0; i < n; ++i)
    {
        const char *file_path;
        int64_t line;
        bool active;
        if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active))
        {
            wslua_debugger_set_breakpoint_active(file_path, line, makeActive);
        }
    }
    updateBreakpoints();
    const qint32 tabCount = static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *const tabView = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (tabView)
        {
            tabView->updateBreakpointMarkers();
        }
    }
}

void LuaDebuggerDialog::updateBreakpointHeaderButtonState()
{
    if (breakpointHeaderToggleButton_)
    {
        const int side = std::max(breakpointHeaderToggleButton_->height(),
                                  breakpointHeaderToggleButton_->width());
        const qreal dpr = breakpointHeaderToggleButton_->devicePixelRatioF();
        LuaDebuggerCodeView *const cv = currentCodeView();
        const QFont *const editorFont =
            (cv && !cv->getFilename().isEmpty()) ? &cv->font() : nullptr;
        const unsigned n = wslua_debugger_get_breakpoint_count();
        bool allInactive = n > 0U;
        for (unsigned i = 0; allInactive && i < n; ++i)
        {
            const char *file_path;
            int64_t line;
            bool active;
            if (wslua_debugger_get_breakpoint(i, &file_path, &line, &active))
            {
                if (active)
                {
                    allInactive = false;
                }
            }
        }
        LuaDbgBpHeaderIconMode mode;
        const QString tglLineKeys =
            kCtxToggleBreakpoint.toString(QKeySequence::NativeText);
        if (n == 0U)
        {
            mode = LuaDbgBpHeaderIconMode::NoBreakpoints;
            breakpointHeaderToggleButton_->setEnabled(false);
            breakpointHeaderToggleButton_->setToolTip(
                tr("No breakpoints\n%1: add or remove breakpoint on the current "
                   "line in the editor")
                    .arg(tglLineKeys));
        }
        else if (allInactive)
        {
            /* All BPs off: dot is gray (mirrors gutter); click activates all. */
            mode = LuaDbgBpHeaderIconMode::ActivateAll;
            breakpointHeaderToggleButton_->setEnabled(true);
            breakpointHeaderToggleButton_->setToolTip(
                tr("All breakpoints are inactive — click to activate all\n"
                   "%1: add or remove on the current line in the editor")
                    .arg(tglLineKeys));
        }
        else
        {
            /* Any BP on (all-on or mix): dot is red (mirrors gutter); click
             * deactivates all. */
            mode = LuaDbgBpHeaderIconMode::DeactivateAll;
            breakpointHeaderToggleButton_->setEnabled(true);
            breakpointHeaderToggleButton_->setToolTip(
                tr("Click to deactivate all breakpoints\n"
                   "%1: add or remove on the current line in the editor")
                    .arg(tglLineKeys));
        }
        /* Cache the three icons keyed by (font, side, dpr); cursor moves
         * fire updateBreakpointHeaderButtonState() frequently and only the
         * mode actually varies on hot paths. */
        const QString cacheKey =
            QStringLiteral("%1/%2/%3")
                .arg(editorFont != nullptr ? editorFont->key()
                                           : QGuiApplication::font().key())
                .arg(side)
                .arg(dpr);
        if (cacheKey != bpHeaderIconCacheKey_)
        {
            bpHeaderIconCacheKey_ = cacheKey;
            for (QIcon &cached : bpHeaderIconCache_)
            {
                cached = QIcon();
            }
        }
        const int modeIdx = static_cast<int>(mode);
        if (bpHeaderIconCache_[modeIdx].isNull())
        {
            bpHeaderIconCache_[modeIdx] =
                luaDbgBreakpointHeaderIconForMode(editorFont, mode, side, dpr);
        }
        breakpointHeaderToggleButton_->setIcon(bpHeaderIconCache_[modeIdx]);
    }
    if (breakpointHeaderRemoveAllButton_)
    {
        const bool hasBreakpoints =
            breakpointsModel && breakpointsModel->rowCount() > 0;
        breakpointHeaderRemoveAllButton_->setEnabled(hasBreakpoints);
        if (actionRemoveAllBreakpoints_)
        {
            actionRemoveAllBreakpoints_->setEnabled(hasBreakpoints);
        }
    }
}

QStandardItem *
LuaDebuggerDialog::findVariablesItemByPath(const QString &path) const
{
    if (!variablesTree || path.isEmpty())
    {
        return nullptr;
    }
    const int top = variablesModel->rowCount();
    for (int i = 0; i < top; ++i)
    {
        QStandardItem *r =
            findVariableItemByPathRecursive(variablesModel->item(i, 0),
                                            path);
        if (r)
        {
            return r;
        }
    }
    return nullptr;
}

QStandardItem *
LuaDebuggerDialog::findWatchRootForVariablePath(const QString &path) const
{
    if (!watchTree || path.isEmpty())
    {
        return nullptr;
    }
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *w = watchModel->item(i, 0);
        const QString spec = w->data(WatchSpecRole).toString();
        QString vp = watchResolvedVariablePathForTooltip(spec);
        if (vp.isEmpty())
        {
            vp = watchVariablePathForSpec(spec);
        }
        if (!vp.isEmpty() && vp == path)
        {
            return w;
        }
        if (w->data(VariablePathRole).toString() == path)
        {
            return w;
        }
    }
    return nullptr;
}

void LuaDebuggerDialog::expandAncestorsOf(QTreeView *tree,
                                          QStandardItemModel *model,
                                          QStandardItem *item)
{
    if (!tree || !model || !item)
    {
        return;
    }
    QList<QStandardItem *> chain;
    for (QStandardItem *p = item->parent(); p; p = p->parent())
    {
        chain.prepend(p);
    }
    for (QStandardItem *a : chain)
    {
        const QModelIndex ix = model->indexFromItem(a);
        if (ix.isValid())
        {
            tree->setExpanded(ix, true);
        }
    }
}

void LuaDebuggerDialog::onVariablesCurrentItemChanged(
    const QModelIndex &current, const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (syncWatchVariablesSelection_ || !watchTree || !watchModel ||
        !variablesTree || !variablesModel || !current.isValid())
    {
        return;
    }
    QStandardItem *curItem =
        variablesModel->itemFromIndex(current.sibling(current.row(), 0));
    QStandardItem *watch = nullptr;
    if (curItem)
    {
        const QString path = curItem->data(VariablePathRole).toString();
        if (!path.isEmpty())
        {
            watch = findWatchRootForVariablePath(path);
        }
    }
    syncWatchVariablesSelection_ = true;
    if (watch)
    {
        const QModelIndex wix = watchModel->indexFromItem(watch);
        watchTree->setCurrentIndex(wix);
        watchTree->scrollTo(wix);
    }
    else if (QItemSelectionModel *sm = watchTree->selectionModel())
    {
        /* No matching watch for this Variables row — clear the stale
         * Watch selection so the two trees stay in sync. */
        sm->clearSelection();
        sm->setCurrentIndex(QModelIndex(), QItemSelectionModel::Clear);
    }
    syncWatchVariablesSelection_ = false;
}

void LuaDebuggerDialog::syncVariablesTreeToCurrentWatch()
{
    if (syncWatchVariablesSelection_ || !watchTree || !variablesTree)
    {
        return;
    }
    const QModelIndex curIx = watchTree->currentIndex();
    QStandardItem *const cur =
        watchModel
            ? watchModel->itemFromIndex(curIx.sibling(curIx.row(), 0))
            : nullptr;
    QStandardItem *v = nullptr;
    if (cur && cur->parent() == nullptr)
    {
        const QString spec = cur->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            QString path = cur->data(VariablePathRole).toString();
            if (path.isEmpty())
            {
                path = watchResolvedVariablePathForTooltip(spec);
                if (path.isEmpty())
                {
                    path = watchVariablePathForSpec(spec);
                }
            }
            if (!path.isEmpty())
            {
                v = findVariablesItemByPath(path);
            }
        }
    }
    syncWatchVariablesSelection_ = true;
    if (v)
    {
        expandAncestorsOf(variablesTree, variablesModel, v);
        const QModelIndex vix = variablesModel->indexFromItem(v);
        variablesTree->setCurrentIndex(vix);
        variablesTree->scrollTo(vix);
    }
    else if (QItemSelectionModel *sm = variablesTree->selectionModel())
    {
        /* No matching Variables row for the current watch — clear the
         * stale Variables selection so the two trees stay in sync. */
        sm->clearSelection();
        sm->setCurrentIndex(QModelIndex(), QItemSelectionModel::Clear);
    }
    syncWatchVariablesSelection_ = false;
}

void LuaDebuggerDialog::onWatchCurrentItemChanged(const QModelIndex &current,
                                                  const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (syncWatchVariablesSelection_ || !watchTree || !watchModel ||
        !variablesTree || !current.isValid())
    {
        return;
    }
    QStandardItem *rowItem =
        watchModel->itemFromIndex(current.sibling(current.row(), 0));
    const QString spec =
        (rowItem && rowItem->parent() == nullptr)
            ? rowItem->data(WatchSpecRole).toString()
            : QString();

    if (!spec.isEmpty())
    {
        const bool live = wslua_debugger_is_enabled() && debuggerPaused &&
                          wslua_debugger_is_paused();
        if (live)
        {
            const int32_t desired =
                wslua_debugger_find_stack_level_for_watch_spec(
                    spec.toUtf8().constData());
            if (desired >= 0 && desired != stackSelectionLevel)
            {
                stackSelectionLevel = static_cast<int>(desired);
                wslua_debugger_set_variable_stack_level(desired);
                refreshVariablesForCurrentStackFrame();
                updateStack();
            }
        }
    }

    /* Always sync: when the current watch has no resolvable path, the
     * helper clears the stale Variables selection. */
    syncVariablesTreeToCurrentWatch();
}

namespace
{
/**
 * Blend two RGB colors by @a alpha (0 = all @a base, 255 = all @a accent).
 * Used to build a theme-aware transient flash background that sits at a
 * low opacity over the view's base color so it does not overpower the
 * text or the selection highlight.
 */
static QColor blendRgb(const QColor &base, const QColor &accent, int alpha)
{
    const int a = std::max(0, std::min(255, alpha));
    const int inv = 255 - a;
    return QColor::fromRgb(
        (base.red() * inv + accent.red() * a) / 255,
        (base.green() * inv + accent.green() * a) / 255,
        (base.blue() * inv + accent.blue() * a) / 255);
}
} // namespace

void LuaDebuggerDialog::refreshChangedValueBrushes()
{
    /* Bold accent matches application link color (see ColorUtils::themeLinkBrush).
     * Flash still blends the watch tree Base + Highlight for row-local context. */
    QPalette pal = palette();
    if (watchTree)
    {
        pal = watchTree->palette();
    }

    QColor accent = ColorUtils::themeLinkBrush().color();
    if (!accent.isValid())
    {
        accent = QApplication::palette().color(QPalette::Highlight);
    }
    if (!accent.isValid())
    {
        accent = QColor(0x1F, 0x6F, 0xEB); // reasonable fallback
    }
    changedValueBrush_ = QBrush(accent);

    const QColor base = pal.color(QPalette::Base);
    const QColor hi = pal.color(QPalette::Highlight);
    /* ~20% opacity mix feels visible on light themes and doesn't wash out
     * text on dark themes. Pre-blend with Base so the resulting solid color
     * renders the same regardless of whether the style composites alpha. */
    changedFlashBrush_ = QBrush(blendRgb(base, hi, 50));
}

void LuaDebuggerDialog::snapshotBaselinesOnPauseEntry()
{
    /* Rotate Current → Baseline for every changed-tracking map, then clear
     * Current. The paint helpers will repopulate Current with this pause's
     * displayed values as they run. Missing keys mean "no baseline yet"
     * and deliberately do not light up as "changed" on the first sighting. */
    watchRootBaseline_ = std::move(watchRootCurrent_);
    watchRootCurrent_.clear();
    watchChildBaseline_ = std::move(watchChildCurrent_);
    watchChildCurrent_.clear();
    variablesBaseline_ = std::move(variablesCurrent_);
    variablesCurrent_.clear();
    /* Rotate the parent-visited sets in lockstep with the value maps;
     * the gate they feed (parent visited last pause?) is meaningful only
     * relative to the same rotation boundary. */
    variablesBaselineParents_ = std::move(variablesCurrentParents_);
    variablesCurrentParents_.clear();
    watchChildBaselineParents_ = std::move(watchChildCurrentParents_);
    watchChildCurrentParents_.clear();
}

void LuaDebuggerDialog::updatePauseEntryFrameIdentity()
{
    /* Compute "<source>:<linedefined>" for the function at frame 0 and
     * compare against the identity captured at the previous pause. The
     * baseline rotation just done in snapshotBaselinesOnPauseEntry() keys
     * Locals/Upvalues at numeric stack level 0 — that is meaningful only
     * if frame 0 is still the same Lua function. After a call or return
     * it is a different function whose locals never lived under those
     * keys, so changeHighlightAllowed() must report false for one pause
     * (Globals are unaffected; they are anchored to level=-1).
     *
     * Self-correcting: painting still runs, so the next pause's rotate
     * will leave Baseline holding values that match the new function. */
    int32_t frameCount = 0;
    wslua_stack_frame_t *stack = wslua_debugger_get_stack(&frameCount);

    QString newIdentity;
    if (stack && frameCount > 0)
    {
        const char *src = stack[0].source ? stack[0].source : "";
        newIdentity =
            QStringLiteral("%1:%2").arg(QString::fromUtf8(src)).arg(
                static_cast<qlonglong>(stack[0].linedefined));
    }
    if (stack)
    {
        wslua_debugger_free_stack(stack, frameCount);
    }

    /* Empty newIdentity (no frames at all — should not happen at a real
     * pause, but be defensive) is treated as "different from anything",
     * so the cue is suppressed. The match flag is also false on the very
     * first pause because pauseEntryFrame0Identity_ starts empty; that is
     * harmless because the baselines are empty too. */
    pauseEntryFrame0MatchesPrev_ =
        !newIdentity.isEmpty() && newIdentity == pauseEntryFrame0Identity_;
    pauseEntryFrame0Identity_ = newIdentity;
}

namespace
{
/**
 * Collect every column-cell in the same row as @p anchor (inclusive).
 * Works for both top-level rows (anchor->parent() == nullptr) and child
 * rows. Cells with different models, or missing columns, are skipped.
 */
static QVector<QStandardItem *> rowCellsFor(QStandardItem *anchor)
{
    QVector<QStandardItem *> out;
    if (!anchor)
    {
        return out;
    }
    auto *model = qobject_cast<QStandardItemModel *>(anchor->model());
    if (!model)
    {
        return out;
    }
    const int cols = model->columnCount();
    QStandardItem *parent = anchor->parent();
    const int row = anchor->row();
    for (int c = 0; c < cols; ++c)
    {
        QStandardItem *cell = parent ? parent->child(row, c)
                                     : model->item(row, c);
        if (cell)
        {
            out.append(cell);
        }
    }
    return out;
}

/**
 * Schedule a one-shot clear for @p cell tagged with @p serial. The clear
 * only runs if the cell's current serial still matches, so a newer flash
 * installed on the same cell is not wiped by a stale timer.
 */
static void scheduleFlashClear(QObject *owner, QStandardItem *cell,
                               qint32 serial, int delayMs)
{
    if (!cell || !cell->model())
    {
        return;
    }
    QPointer<QAbstractItemModel> modelGuard(cell->model());
    const QPersistentModelIndex pix(cell->index());
    QTimer::singleShot(delayMs, owner, [modelGuard, pix, serial]() {
        if (!modelGuard || !pix.isValid())
        {
            return;
        }
        auto *sim =
            qobject_cast<QStandardItemModel *>(modelGuard.data());
        if (!sim)
        {
            return;
        }
        QStandardItem *c = sim->itemFromIndex(pix);
        if (!c)
        {
            return;
        }
        if (c->data(ChangedFlashSerialRole).toInt() != serial)
        {
            return;
        }
        c->setBackground(QBrush());
        c->setData(QVariant(), ChangedFlashSerialRole);
    });
}
} // namespace

void LuaDebuggerDialog::applyChangedVisuals(QStandardItem *anchor,
                                            bool changed,
                                            bool isPauseEntryRefresh)
{
    if (!anchor)
    {
        return;
    }

    const QVector<QStandardItem *> cells = rowCellsFor(anchor);
    if (cells.isEmpty())
    {
        return;
    }

    if (changed)
    {
        /* One serial per row-flash; every cell in the row tags itself with
         * the same serial so a re-flash on this row cleanly supersedes the
         * previous row-flash's pending timers. */
        const qint32 serial =
            isPauseEntryRefresh ? ++flashSerial_ : 0;
        for (QStandardItem *cell : cells)
        {
            QFont f = cell->font();
            f.setBold(true);
            cell->setFont(f);
            cell->setForeground(changedValueBrush_);
            if (isPauseEntryRefresh)
            {
                cell->setData(serial, ChangedFlashSerialRole);
                cell->setBackground(changedFlashBrush_);
                scheduleFlashClear(this, cell, serial, CHANGED_FLASH_MS);
            }
        }
    }
    else
    {
        /* Clear ONLY the change-specific visuals (bold, and any flash this
         * helper installed). Leave the caller-managed foreground /
         * background untouched so error chrome (red) and the no-live-
         * context placeholder coloring survive. A pending flash timer is
         * cancelled by invalidating the serial. */
        for (QStandardItem *cell : cells)
        {
            QFont f = cell->font();
            f.setBold(false);
            cell->setFont(f);
            if (cell->data(ChangedFlashSerialRole).isValid())
            {
                cell->setData(QVariant(), ChangedFlashSerialRole);
                cell->setBackground(QBrush());
            }
        }
    }
}

void LuaDebuggerDialog::clearAllChangeBaselines()
{
    watchRootBaseline_.clear();
    watchRootCurrent_.clear();
    watchChildBaseline_.clear();
    watchChildCurrent_.clear();
    variablesBaseline_.clear();
    variablesCurrent_.clear();
    variablesBaselineParents_.clear();
    variablesCurrentParents_.clear();
    watchChildBaselineParents_.clear();
    watchChildCurrentParents_.clear();
    /* The frame-0 identity gate is part of the same "comparable across
     * pauses" contract: a debugger toggle or Lua reload also breaks that
     * contract, and starting the next session by comparing against a
     * stale identity would suppress the cue on the very first pause for
     * no reason. */
    pauseEntryFrame0Identity_.clear();
    pauseEntryFrame0MatchesPrev_ = false;
}

void LuaDebuggerDialog::clearChangeBaselinesForWatchSpec(const QString &spec)
{
    if (spec.isEmpty())
    {
        return;
    }
    const auto matches = [&spec](const QString &key)
    {
        return watchSpecFromChangeKey(key) == spec;
    };
    for (auto *m : {&watchRootBaseline_, &watchRootCurrent_})
    {
        for (auto it = m->begin(); it != m->end();)
        {
            if (matches(it.key()))
            {
                it = m->erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    for (auto *m : {&watchChildBaseline_, &watchChildCurrent_})
    {
        for (auto it = m->begin(); it != m->end();)
        {
            if (matches(it.key()))
            {
                it = m->erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    for (auto *m : {&watchChildBaselineParents_, &watchChildCurrentParents_})
    {
        for (auto it = m->begin(); it != m->end();)
        {
            if (matches(it.key()))
            {
                it = m->erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

void LuaDebuggerDialog::pruneChangeBaselinesToLiveWatchSpecs()
{
    if (!watchModel)
    {
        return;
    }
    QSet<QString> liveSpecs;
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        const QStandardItem *it = watchModel->item(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            liveSpecs.insert(spec);
        }
    }
    const auto pruneMap = [&](auto &m)
    {
        for (auto it = m.begin(); it != m.end();)
        {
            if (!liveSpecs.contains(watchSpecFromChangeKey(it.key())))
            {
                it = m.erase(it);
            }
            else
            {
                ++it;
            }
        }
    };
    pruneMap(watchRootBaseline_);
    pruneMap(watchRootCurrent_);
    pruneMap(watchChildBaseline_);
    pruneMap(watchChildCurrent_);
    pruneMap(watchChildBaselineParents_);
    pruneMap(watchChildCurrentParents_);
}

void LuaDebuggerDialog::refreshWatchDisplay()
{
    if (!watchTree)
    {
        return;
    }
    const bool liveContext = wslua_debugger_is_enabled() && debuggerPaused &&
                             wslua_debugger_is_paused();
    const QString muted = QStringLiteral("\u2014");
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        QStandardItem *root = watchModel->item(i);
        applyWatchItemState(root, liveContext, muted);
        if (liveContext && root &&
            LuaDebuggerItems::isExpanded(watchTree, watchModel, root))
        {
            refreshWatchBranch(root);
        }
    }
}

void LuaDebuggerDialog::applyWatchItemEmpty(QStandardItem *item,
                                            const QString &muted,
                                            const QString &watchTipExtra)
{
    if (!watchModel)
    {
        return;
    }
    clearWatchFilterErrorChrome(item, watchTree);
    setText(watchModel, item, 1, muted);
    item->setToolTip(watchTipExtra);
    /* Explain the muted em dash instead of leaving an empty tooltip: a blank
     * row has no variable path to evaluate, so there is nothing to show in
     * the Value column. */
    LuaDebuggerItems::setToolTip(
        watchModel, item, 1,
        capWatchTooltipText(
            tr("No watch path entered yet — enter a variable path in the "
               "Watch column to see a value here.")));
    applyChangedVisuals(item,
                        /*changed=*/false, /*isPauseEntryRefresh=*/false);
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }
}

void LuaDebuggerDialog::applyWatchItemNonPath(QStandardItem *item,
                                              const QString &watchTipExtra)
{
    if (!watchModel)
    {
        return;
    }
    /* Defensive: normal entry points reject non-path specs before a row is
     * created, but hand-edited lua_debugger.json could still supply one. */
    applyWatchFilterErrorChrome(item, watchTree);
    setText(watchModel, item, 1, tr("Not a variable path"));
    item->setToolTip(
        capWatchTooltipText(
            QStringLiteral("%1\n%2")
                .arg(item->text(),
                     tr("Use a Variables-style path (e.g. Locals.x, "
                        "Globals.t.k, t[1], t[\"k\"], or a single identifier).")) +
                watchTipExtra));
    LuaDebuggerItems::setToolTip(
        watchModel, item, 1,
        capWatchTooltipText(tr("Only variable paths can be watched.")));
    applyChangedVisuals(item,
                        /*changed=*/false, /*isPauseEntryRefresh=*/false);
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }
}

void LuaDebuggerDialog::applyWatchItemNoLiveContext(QStandardItem *item,
                                                    const QString &muted,
                                                    const QString &watchTipExtra)
{
    if (!watchModel || !watchTree)
    {
        return;
    }
    setText(watchModel, item, 1, muted);
    LuaDebuggerItems::setForeground(watchModel, item, 1,
                                 watchTree->palette().brush(
                                     QPalette::PlaceholderText));
    /* Replace the previous `muted \n Type: muted` tooltip (which just
     * repeated the em dash) with a short explanation so the user knows
     * *why* there is no value: watches are only evaluated while the
     * debugger is paused. */
    const QString mutedReason =
        wslua_debugger_is_enabled()
            ? tr("Value shown only while the debugger is paused.")
            : tr("Value shown only while the debugger is paused. "
                 "The debugger is currently disabled.");
    const QString ttSuf = tr("Type: %1").arg(muted);
    item->setToolTip(
        capWatchTooltipText(
            QStringLiteral("%1\n%2\n%3")
                .arg(item->text(), mutedReason, ttSuf) +
            watchTipExtra));
    LuaDebuggerItems::setToolTip(watchModel, item, 1,
                            capWatchTooltipText(mutedReason));
    /* Clear the accent/bold/flash but do NOT touch the baseline maps:
     * bold-on-change must survive resume → pause cycles so the next pause
     * can compare against the value displayed at the end of this pause.
     * applyChangedVisuals(false) only unbolds; it leaves the caller's
     * foreground / background intact, so the placeholder brush set above
     * and the normal column-0 text stay as the caller wants. */
    applyChangedVisuals(item,
                        /*changed=*/false, /*isPauseEntryRefresh=*/false);
    /* A previous pause may have left the Watch-column (col 0) foreground
     * set to the accent. Reset it to the default text color so the spec
     * looks normal while unpaused. */
    LuaDebuggerItems::setForeground(
        watchModel, item, 0,
        watchTree->palette().brush(QPalette::Text));
    if (item->parent() == nullptr)
    {
        while (item->rowCount() > 0)
        {
            item->removeRow(0);
        }
    }
}

void LuaDebuggerDialog::applyWatchItemError(QStandardItem *item,
                                            const QString &errStr,
                                            const QString &watchTipExtra)
{
    if (!watchModel)
    {
        return;
    }
    applyWatchFilterErrorChrome(item, watchTree);
    setText(watchModel, item, 1, errStr);
    const QString ttSuf = tr("Type: %1").arg(tr("error"));
    item->setToolTip(
        capWatchTooltipText(
            QStringLiteral("%1\n%2").arg(item->text(), ttSuf) + watchTipExtra));
    LuaDebuggerItems::setToolTip(
        watchModel, item, 1,
        capWatchTooltipText(
            QStringLiteral("%1\n%2\n%3")
                .arg(tr("Invalid watch path."), errStr, ttSuf)));
    applyChangedVisuals(item,
                        /*changed=*/false, /*isPauseEntryRefresh=*/false);
    /* An error invalidates the comparison: drop baselines for this root so
     * the next successful evaluation does not flag a change vs the pre-error
     * value. */
    if (item->parent() == nullptr)
    {
        const QString spec = item->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            clearChangeBaselinesForWatchSpec(spec);
        }
    }
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }
}

void LuaDebuggerDialog::applyWatchItemSuccess(QStandardItem *item,
                                              const QString &spec,
                                              const char *val, const char *typ,
                                              bool can_expand,
                                              const QString &watchTipExtra)
{
    if (item->parent() == nullptr)
    {
        watchRootSetVariablePathRoleFromSpec(item, spec);
    }
    if (!watchModel)
    {
        return;
    }
    const QString v = val ? QString::fromUtf8(val) : QString();
    const QString typStr = typ ? QString::fromUtf8(typ) : QString();
    setText(watchModel, item, 1, v);
    const QString ttSuf =
        typStr.isEmpty() ? QString() : tr("Type: %1").arg(typStr);
    item->setToolTip(
        capWatchTooltipText(
            (ttSuf.isEmpty()
                 ? item->text()
                 : QStringLiteral("%1\n%2").arg(item->text(), ttSuf)) +
            watchTipExtra));
    LuaDebuggerItems::setToolTip(
        watchModel, item, 1,
        capWatchTooltipText(
            ttSuf.isEmpty() ? v : QStringLiteral("%1\n%2").arg(v, ttSuf)));
    /* Only watch roots are routed through applyWatchItemSuccess; children go
     * through applyWatchChildRowTextAndTooltip + applyChangedVisuals inside
     * fillWatchPathChildren. The Globals branch is excluded from
     * changeHighlightAllowed() because it is anchored to level=-1 and
     * therefore stays comparable across stack-frame switches. */
    const bool isGlobal = watchSpecIsGlobalScoped(spec);
    const int level = isGlobal ? -1 : stackSelectionLevel;
    const QString rk = changeKey(level, spec);
    const bool changed = (isGlobal || changeHighlightAllowed()) &&
                         shouldMarkChanged(watchRootBaseline_, rk, v);
    applyChangedVisuals(item, changed, isPauseEntryRefresh_);
    watchRootCurrent_[rk] = v;

    if (can_expand)
    {
        if (item->rowCount() == 0)
        {
            QStandardItem *const ph0 = new QStandardItem();
            QStandardItem *const ph1 = new QStandardItem();
            ph0->setFlags(Qt::ItemIsEnabled);
            ph1->setFlags(Qt::ItemIsEnabled);
            item->appendRow({ph0, ph1});
        }
    }
    else
    {
        while (item->rowCount() > 0)
        {
            item->removeRow(0);
        }
    }
}

void LuaDebuggerDialog::applyWatchItemState(QStandardItem *item,
                                            bool liveContext,
                                            const QString &muted)
{
    if (!item || !watchModel || !watchTree)
    {
        return;
    }

    const QString spec = item->data(WatchSpecRole).toString();
    const QString watchTipExtra = watchPathOriginSuffix(item, spec);

    if (item->parent() == nullptr && spec.isEmpty())
    {
        applyWatchItemEmpty(item, muted, watchTipExtra);
        return;
    }

    if (!watchSpecUsesPathResolution(spec))
    {
        applyWatchItemNonPath(item, watchTipExtra);
        return;
    }

    clearWatchFilterErrorChrome(item, watchTree);
    LuaDebuggerItems::setForeground(watchModel, item, 1,
                               watchTree->palette().brush(QPalette::Text));

    if (!liveContext)
    {
        applyWatchItemNoLiveContext(item, muted, watchTipExtra);
        return;
    }

    char *val = nullptr;
    char *typ = nullptr;
    bool can_expand = false;
    char *err = nullptr;
    const bool ok = wslua_debugger_watch_read_root(
        spec.toUtf8().constData(), &val, &typ, &can_expand, &err);
    if (!ok)
    {
        const QString errStr = err ? QString::fromUtf8(err) : muted;
        applyWatchItemError(item, errStr, watchTipExtra);
        g_free(err);
        return;
    }

    applyWatchItemSuccess(item, spec, val, typ, can_expand, watchTipExtra);
    g_free(val);
    g_free(typ);
}

void LuaDebuggerDialog::fillWatchPathChildren(QStandardItem *parent,
                                              const QString &path)
{
    if (!watchModel || !watchTree)
    {
        return;
    }
    /* Path watches drill down with wslua_debugger_get_variables (same tree as
     * Variables); expression watches use wslua_debugger_watch_* elsewhere. */
    if (watchSubpathBoundaryCount(path) >= WSLUA_WATCH_MAX_PATH_SEGMENTS)
    {
        auto *sent0 = new QStandardItem(QStringLiteral("\u2026"));
        auto *sent1 = new QStandardItem(tr("Maximum watch depth reached"));
        sent0->setFlags(Qt::ItemIsEnabled);
        sent1->setFlags(Qt::ItemIsEnabled);
        LuaDebuggerItems::setForeground(
            watchModel, sent0, 1,
            watchTree->palette().brush(QPalette::PlaceholderText));
        LuaDebuggerItems::setToolTip(
            watchModel, sent0, 1,
            capWatchTooltipText(tr("Maximum watch depth reached.")));
        parent->appendRow({sent0, sent1});
        return;
    }

    int32_t variableCount = 0;
    wslua_variable_t *variables = wslua_debugger_get_variables(
        path.isEmpty() ? NULL : path.toUtf8().constData(), &variableCount);

    if (!variables)
    {
        return;
    }

    const QStandardItem *const rootWatch = watchRootItem(parent);
    const QString rootSpec =
        rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    const bool rootIsGlobal = watchSpecIsGlobalScoped(rootSpec);
    const int rootLevel = rootIsGlobal ? -1 : stackSelectionLevel;
    const QString rootKey = changeKey(rootLevel, rootSpec);
    auto &baseline = watchChildBaseline_[rootKey];
    auto &current = watchChildCurrent_[rootKey];
    /* Globals-scoped roots are anchored to level=-1 and stay comparable
     * across stack-frame switches; everything else is suppressed when the
     * user has navigated away from the pause-entry frame (see
     * changeHighlightAllowed()). */
    const bool highlightAllowed = rootIsGlobal || changeHighlightAllowed();
    /* "First-time expansion" guard, mirror of the one in updateVariables():
     * a child absent from baseline is only meaningfully "new" if the
     * parent @p path was painted at the previous pause. We record that
     * fact directly via the visited-parents companion set; scanning the
     * value baseline by prefix cannot tell "collapsed last pause" apart
     * from "expanded last pause with no children yet", so the FIRST
     * child to appear under a parent that has always been empty (an
     * empty table just got its first key) would otherwise never flash. */
    auto &baselineParents = watchChildBaselineParents_[rootKey];
    auto &currentParents = watchChildCurrentParents_[rootKey];
    const bool parentVisitedInBaseline = baselineParents.contains(path);
    currentParents.insert(path);

    for (int32_t variableIndex = 0; variableIndex < variableCount;
         ++variableIndex)
    {
        auto *nameItem = new QStandardItem();
        auto *valueItem = new QStandardItem();

        const VariableRowFields f =
            readVariableRowFields(variables[variableIndex], path);

        nameItem->setText(f.name);
        nameItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        nameItem->setData(f.type, VariableTypeRole);
        nameItem->setData(f.canExpand, VariableCanExpandRole);
        nameItem->setData(f.childPath, VariablePathRole);

        parent->appendRow({nameItem, valueItem});

        applyWatchChildRowTextAndTooltip(nameItem, f.value, f.type);

        /* flashNew=parentVisitedInBaseline: a child key that appeared
         * since the previous pause inside an already-visited watch path
         * is a legitimate change (e.g. a new key inserted into a table)
         * and gets the cue. But when the user expands a parent for the
         * first time, the parent itself was never painted at the previous
         * pause, so lighting up the whole subtree as "new" is misleading. The whole
         * comparison is also gated on highlightAllowed (see above) to
         * suppress the cue when the user is browsing a different stack
         * frame than the pause was entered at — Globals-scoped roots are
         * exempt and stay comparable. */
        const bool changed =
            highlightAllowed &&
            shouldMarkChanged(baseline, f.childPath, f.value,
                              /*flashNew=*/parentVisitedInBaseline);
        applyChangedVisuals(nameItem, changed, isPauseEntryRefresh_);
        current[f.childPath] = f.value;

        applyVariableExpansionIndicator(nameItem, f.canExpand,
                                        /*enabledOnlyPlaceholder=*/true,
                                        /*columnCount=*/2);
    }

    if (variableChildrenShouldSortByName(path))
    {
        parent->sortChildren(0, Qt::AscendingOrder);
    }

    wslua_debugger_free_variables(variables, variableCount);
}

namespace
{
/** Subpath / variable-path key used to address @p item inside a watch root. */
static QString watchItemExpansionKey(const QStandardItem *item)
{
    if (!item || !item->parent())
    {
        return QString();
    }
    const QString sp = item->data(WatchSubpathRole).toString();
    if (!sp.isEmpty())
    {
        return sp;
    }
    return item->data(VariablePathRole).toString();
}
} // namespace

void LuaDebuggerDialog::recordTreeSectionRootExpansion(
    QHash<QString, TreeSectionExpansionState> &map, const QString &rootKey,
    bool expanded)
{
    if (rootKey.isEmpty())
    {
        return;
    }
    if (!expanded && !map.contains(rootKey))
    {
        return;
    }
    TreeSectionExpansionState &e = map[rootKey];
    e.rootExpanded = expanded;
    if (!expanded && e.subpaths.isEmpty())
    {
        map.remove(rootKey);
    }
}

void LuaDebuggerDialog::recordTreeSectionSubpathExpansion(
    QHash<QString, TreeSectionExpansionState> &map, const QString &rootKey,
    const QString &key, bool expanded)
{
    if (rootKey.isEmpty() || key.isEmpty())
    {
        return;
    }
    if (expanded)
    {
        TreeSectionExpansionState &e = map[rootKey];
        if (!e.subpaths.contains(key))
        {
            e.subpaths.append(key);
        }
    }
    else
    {
        auto it = map.find(rootKey);
        if (it == map.end())
        {
            return;
        }
        it->subpaths.removeAll(key);
        if (!it->rootExpanded && it->subpaths.isEmpty())
        {
            map.erase(it);
        }
    }
}

QStringList LuaDebuggerDialog::treeSectionExpandedSubpaths(
    const QHash<QString, TreeSectionExpansionState> &map,
    const QString &rootKey) const
{
    if (rootKey.isEmpty())
    {
        return QStringList();
    }
    const auto it = map.constFind(rootKey);
    if (it == map.constEnd())
    {
        return QStringList();
    }
    return it->subpaths;
}

void LuaDebuggerDialog::recordWatchRootExpansion(const QString &rootSpec,
                                                 bool expanded)
{
    recordTreeSectionRootExpansion(watchExpansion_, rootSpec, expanded);
}

void LuaDebuggerDialog::recordWatchSubpathExpansion(const QString &rootSpec,
                                                    const QString &key,
                                                    bool expanded)
{
    recordTreeSectionSubpathExpansion(watchExpansion_, rootSpec, key, expanded);
}

QStringList
LuaDebuggerDialog::watchExpandedSubpathsForSpec(const QString &rootSpec) const
{
    return treeSectionExpandedSubpaths(watchExpansion_, rootSpec);
}

void LuaDebuggerDialog::pruneWatchExpansionMap()
{
    if (!watchTree || watchExpansion_.isEmpty())
    {
        return;
    }
    QSet<QString> liveSpecs;
    const int n = watchModel->rowCount();
    for (int i = 0; i < n; ++i)
    {
        const QStandardItem *it = watchModel->item(i);
        if (!it)
        {
            continue;
        }
        const QString spec = it->data(WatchSpecRole).toString();
        if (!spec.isEmpty())
        {
            liveSpecs.insert(spec);
        }
    }
    for (auto it = watchExpansion_.begin(); it != watchExpansion_.end();)
    {
        if (!liveSpecs.contains(it.key()))
        {
            it = watchExpansion_.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void LuaDebuggerDialog::onWatchItemExpanded(const QModelIndex &index)
{
    if (!watchModel || !index.isValid())
    {
        return;
    }
    QStandardItem *item =
        watchModel->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    /* Track expansion in the runtime map. This fires for both user-driven
     * expansion and the programmatic setExpanded(true) calls made by
     * reexpandWatchDescendantsByPathKeys; re-recording an already-tracked
     * key is idempotent. */
    const QStandardItem *const rootWatch = watchRootItem(item);
    const QString rootSpec =
        rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    if (!item->parent())
    {
        recordWatchRootExpansion(rootSpec, true);
    }
    else
    {
        recordWatchSubpathExpansion(rootSpec, watchItemExpansionKey(item),
                                    true);
    }

    if (item->rowCount() == 1)
    {
        const QModelIndex parentIx = watchModel->indexFromItem(item);
        const QModelIndex firstChildIx =
            watchModel->index(0, 0, parentIx);
        const QString t0 =
            LuaDebuggerItems::rowColumnDisplayText(firstChildIx, 0);
        const QString t1 =
            LuaDebuggerItems::rowColumnDisplayText(firstChildIx, 1);
        if (t0.isEmpty() && t1.isEmpty())
        {
            item->removeRow(0);
        }
        else
        {
            return;
        }
    }
    else if (item->rowCount() > 0)
    {
        return;
    }

    refillWatchChildren(item);
}

void LuaDebuggerDialog::onWatchItemCollapsed(const QModelIndex &index)
{
    if (!watchModel || !index.isValid())
    {
        return;
    }
    QStandardItem *item =
        watchModel->itemFromIndex(index.sibling(index.row(), 0));
    if (!item)
    {
        return;
    }
    const QStandardItem *const rootWatch = watchRootItem(item);
    const QString rootSpec =
        rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    if (!item->parent())
    {
        recordWatchRootExpansion(rootSpec, false);
    }
    else
    {
        recordWatchSubpathExpansion(rootSpec, watchItemExpansionKey(item),
                                    false);
    }
}

void LuaDebuggerDialog::refillWatchChildren(QStandardItem *item)
{
    if (!item)
    {
        return;
    }
    while (item->rowCount() > 0)
    {
        item->removeRow(0);
    }

    const QStandardItem *const rootWatch = watchRootItem(item);
    const QString rootSpec = rootWatch->data(WatchSpecRole).toString();
    QString path = item->data(VariablePathRole).toString();
    if (path.isEmpty())
    {
        path = watchResolvedVariablePathForTooltip(rootSpec);
        if (path.isEmpty())
        {
            path = watchVariablePathForSpec(rootSpec);
        }
    }
    fillWatchPathChildren(item, path);
}

void LuaDebuggerDialog::refreshWatchBranch(QStandardItem *item)
{
    if (!item || !watchTree || !watchModel ||
        !LuaDebuggerItems::isExpanded(watchTree, watchModel, item))
    {
        return;
    }
    /* refillWatchChildren deletes and re-creates every descendant, so the
     * tree alone cannot remember which sub-elements were expanded. Instead,
     * consult the dialog-level runtime expansion map (watchExpansion_),
     * which is kept up to date by onWatchItemExpanded / onWatchItemCollapsed
     * and survives both refills and the children-clearing that happens while
     * the debugger is not paused. This lets deep subtrees survive stepping,
     * pause / resume, and Variables tree refreshes without being tied to
     * transient QStandardItem lifetimes. */
    const QStandardItem *const rootWatch = watchRootItem(item);
    const QString rootSpec =
        rootWatch ? rootWatch->data(WatchSpecRole).toString() : QString();
    refillWatchChildren(item);
    reexpandWatchDescendantsByPathKeys(
        watchTree, watchModel, item, watchExpandedSubpathsForSpec(rootSpec));
}

namespace
{
/** Pointers into the context menu built by buildWatchContextMenu(). */
struct WatchContextMenuActions
{
    QAction *addWatch = nullptr;
    QAction *copyValue = nullptr;
    QAction *duplicate = nullptr;
    QAction *editWatch = nullptr;
    QAction *remove = nullptr;
    QAction *removeAllWatches = nullptr;
};
} /* namespace */

/**
 * Populate @a menu with the watch context-menu actions appropriate for
 * @a item (may be null / a child row), returning pointers to each action
 * so the caller can dispatch on the chosen QAction.
 *
 * Sub-element rows (descendants of a watch root) only expose `Add Watch`
 * and `Copy Value`. Watch roots also get duplicate, edit, copy value, remove
 * one, and remove all.
 */
static void buildWatchContextMenu(
    QMenu &menu, QStandardItem *item, WatchContextMenuActions *acts,
    const QStandardItemModel *watchModel, const QKeySequence &addWatchShortcut)
{
    acts->addWatch = menu.addAction(QObject::tr("Add Watch"));
    if (!addWatchShortcut.isEmpty())
    {
        acts->addWatch->setShortcut(addWatchShortcut);
    }
    if (!item)
    {
        if (watchModel && watchModel->rowCount() > 0)
        {
            menu.addSeparator();
            acts->removeAllWatches = menu.addAction(
                QObject::tr("Remove All Watches"));
            acts->removeAllWatches->setShortcut(kCtxWatchRemoveAll);
        }
        return;
    }

    if (item->parent() == nullptr)
    {
        /* Watch root: Add Watch, then duplicate / edit, then the rest. */
        acts->duplicate = menu.addAction(QObject::tr("Duplicate Watch"));
        acts->duplicate->setShortcut(kCtxWatchDuplicate);
        acts->editWatch = menu.addAction(QObject::tr("Edit Watch"));
        acts->editWatch->setShortcut(kCtxWatchEdit);
        menu.addSeparator();
    }

    acts->copyValue = menu.addAction(QObject::tr("Copy Value"));
    acts->copyValue->setShortcut(kCtxWatchCopyValue);

    if (item->parent() != nullptr)
    {
        return;
    }

    menu.addSeparator();
    acts->remove = menu.addAction(QObject::tr("Remove"));
    acts->remove->setShortcut(QKeySequence::Delete);
    if (watchModel->rowCount() > 0)
    {
        acts->removeAllWatches = menu.addAction(
            QObject::tr("Remove All Watches"));
        acts->removeAllWatches->setShortcut(kCtxWatchRemoveAll);
    }
}

void LuaDebuggerDialog::onWatchContextMenuRequested(const QPoint &pos)
{
    if (!watchTree || !watchModel)
    {
        return;
    }

    const QModelIndex ix = watchTree->indexAt(pos);
    QStandardItem *item = nullptr;
    if (ix.isValid())
    {
        item = watchModel->itemFromIndex(ix.sibling(ix.row(), 0));
    }

    QMenu menu(this);
    WatchContextMenuActions acts;
    buildWatchContextMenu(menu, item, &acts, watchModel,
                          ui->actionAddWatch->shortcut());

    QAction *chosen = menu.exec(watchTree->viewport()->mapToGlobal(pos));
    if (!chosen)
    {
        return;
    }

    if (chosen == acts.addWatch)
    {
        insertNewWatchRow(QString(), true);
        return;
    }
    if (chosen == acts.removeAllWatches)
    {
        removeAllWatchTopLevelItems();
        return;
    }
    if (!item)
    {
        return;
    }

    if (chosen == acts.copyValue)
    {
        copyWatchValueForItem(item, ix);
        return;
    }

    if (item->parent() != nullptr)
    {
        return;
    }

    if (chosen == acts.editWatch)
    {
        QTimer::singleShot(0, this, [this, item]()
                           {
                               if (!watchModel || !watchTree)
                               {
                                   return;
                               }
                               const QModelIndex editIx =
                                   watchModel->indexFromItem(item);
                               if (!editIx.isValid())
                               {
                                   return;
                               }
                               watchTree->scrollTo(editIx);
                               watchTree->setCurrentIndex(editIx);
                               watchTree->edit(editIx);
                           });
        return;
    }

    if (chosen == acts.remove)
    {
        QList<QStandardItem *> del;
        for (const QModelIndex &six :
             watchTree->selectionModel()->selectedRows(0))
        {
            QStandardItem *it = watchModel->itemFromIndex(six);
            if (it && it->parent() == nullptr)
            {
                del.append(it);
            }
        }
        if (del.isEmpty())
        {
            del.append(item);
        }
        deleteWatchRows(del);
        return;
    }

    if (chosen == acts.duplicate)
    {
        duplicateWatchRootItem(item);
        return;
    }
}

void LuaDebuggerDialog::copyWatchValueForItem(QStandardItem *item,
                                              const QModelIndex &ix)
{
    auto copyToClipboard = [](const QString &s)
    {
        if (QClipboard *c = QGuiApplication::clipboard())
        {
            c->setText(s);
        }
    };
    QString value;
    const QString varPath = item->data(VariablePathRole).toString();
    if (!varPath.isEmpty() && debuggerPaused && wslua_debugger_is_enabled() &&
        wslua_debugger_is_paused())
    {
        char *val = nullptr;
        char *err = nullptr;
        if (wslua_debugger_read_variable_value_full(
                varPath.toUtf8().constData(), &val, &err))
        {
            value = QString::fromUtf8(val ? val : "");
        }
        g_free(val);
        g_free(err);
    }
    if (value.isNull())
    {
        value = LuaDebuggerItems::rowColumnDisplayText(ix, 1);
    }
    copyToClipboard(value);
}

void LuaDebuggerDialog::duplicateWatchRootItem(QStandardItem *item)
{
    if (!watchModel || !item || item->parent() != nullptr)
    {
        return;
    }
    auto *copy0 = new QStandardItem();
    auto *copy1 = new QStandardItem();
    copy0->setFlags(copy0->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled |
                    Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    copy1->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    copy0->setText(item->text());
    {
        const QModelIndex srcRow0 = watchModel->indexFromItem(item);
        LuaDebuggerItems::setText(
            watchModel, copy0, 1,
            LuaDebuggerItems::rowColumnDisplayText(srcRow0, 1));
    }
    for (int r = WatchSpecRole; r <= WatchPendingNewRole; ++r)
    {
        copy0->setData(item->data(r), r);
    }
    copy0->setData(false, WatchPendingNewRole);
    copy0->setData(item->data(VariablePathRole), VariablePathRole);
    copy0->setData(item->data(VariableTypeRole), VariableTypeRole);
    copy0->setData(item->data(VariableCanExpandRole), VariableCanExpandRole);
    /* The duplicate is a brand-new row: it has no baseline yet, so the
     * first refresh will not show it as "changed". No per-item role data
     * to clear — baselines live on the dialog, keyed by spec+level, and
     * the copy shares the spec of its source. */
    {
        auto *ph0 = new QStandardItem();
        auto *ph1 = new QStandardItem();
        ph0->setFlags(Qt::ItemIsEnabled);
        ph1->setFlags(Qt::ItemIsEnabled);
        copy0->appendRow({ph0, ph1});
    }
    watchModel->insertRow(item->row() + 1, {copy0, copy1});
    refreshWatchDisplay();
}

void LuaDebuggerDialog::removeAllWatchTopLevelItems()
{
    if (!watchModel)
    {
        return;
    }
    QList<QStandardItem *> all;
    for (int i = 0; i < watchModel->rowCount(); ++i)
    {
        if (QStandardItem *r = watchModel->item(i, 0))
        {
            all.append(r);
        }
    }
    deleteWatchRows(all);
}

void LuaDebuggerDialog::toggleBreakpointOnCodeViewLine(
    LuaDebuggerCodeView *codeView, qint32 line)
{
    if (!codeView || line < 1)
    {
        return;
    }
    const QString file_path = codeView->getFilename();
    const int32_t state = wslua_debugger_get_breakpoint_state(
        file_path.toUtf8().constData(), line);
    if (state == -1)
    {
        wslua_debugger_add_breakpoint(file_path.toUtf8().constData(), line);
        ensureDebuggerEnabledForActiveBreakpoints();
    }
    else
    {
        wslua_debugger_remove_breakpoint(file_path.toUtf8().constData(), line);
        refreshDebuggerStateUi();
    }
    updateBreakpoints();
    const qint32 tabCount =
        static_cast<qint32>(ui->codeTabWidget->count());
    for (qint32 tabIndex = 0; tabIndex < tabCount; ++tabIndex)
    {
        LuaDebuggerCodeView *tabView = qobject_cast<LuaDebuggerCodeView *>(
            ui->codeTabWidget->widget(static_cast<int>(tabIndex)));
        if (tabView)
        {
            tabView->updateBreakpointMarkers();
        }
    }
}

void LuaDebuggerDialog::onRunToLine()
{
    LuaDebuggerCodeView *codeView = currentCodeView();
    if (!codeView || !eventLoop)
    {
        return;
    }
    const qint32 line =
        static_cast<qint32>(codeView->textCursor().blockNumber() + 1);
    runToCurrentLineInPausedEditor(codeView, line);
}

void LuaDebuggerDialog::runToCurrentLineInPausedEditor(
    LuaDebuggerCodeView *codeView, qint32 line)
{
    if (!codeView || !eventLoop || line < 1)
    {
        return;
    }
    ensureDebuggerEnabledForActiveBreakpoints();
    wslua_debugger_run_to_line(codeView->getFilename().toUtf8().constData(),
                              line);
    if (eventLoop)
    {
        eventLoop->quit();
    }
    debuggerPaused = false;
    updateWidgets();
    clearPausedStateUi();
}

void LuaDebuggerDialog::addWatchFromSpec(const QString &watchSpec)
{
    insertNewWatchRow(watchSpec, false);
}

void LuaDebuggerDialog::showPathOnlyVariablePathWatchMessage()
{
    QMessageBox::information(
        this, tr("Lua Debugger"),
        tr("Only variable paths can be watched (e.g. Locals.name, Globals.x, "
           "or a single identifier for Locals.name)."));
}

void LuaDebuggerDialog::commitWatchRootSpec(QStandardItem *item,
                                            const QString &text)
{
    if (!watchTree || !watchModel || !item || item->parent() != nullptr)
    {
        return;
    }

    const QString t = text.trimmed();
    if (t.isEmpty())
    {
        /* Clearing the text of a brand-new row discards it (no persisted
         * entry ever existed); clearing an existing row removes it. */
        if (item->data(WatchPendingNewRole).toBool())
        {
            watchModel->removeRow(item->row());
            refreshWatchDisplay();
        }
        else
        {
            deleteWatchRows({item});
        }
        return;
    }

    if (t.size() > WATCH_EXPR_MAX_CHARS)
    {
        QMessageBox::warning(
            this, tr("Lua Debugger"),
            tr("Watch path is too long (maximum %Ln characters).", "",
               static_cast<qlonglong>(WATCH_EXPR_MAX_CHARS)));
        return;
    }

    if (!watchSpecUsesPathResolution(t))
    {
        showPathOnlyVariablePathWatchMessage();
        return;
    }

    /* Editing a spec invalidates baselines for both old and new specs:
     * the old spec no longer applies to this row, and the new spec has
     * never been evaluated on this row before (so the first refresh must
     * not flag it as "changed" against an unrelated old value). */
    const QString oldSpec = item->data(WatchSpecRole).toString();
    if (!oldSpec.isEmpty() && oldSpec != t)
    {
        clearChangeBaselinesForWatchSpec(oldSpec);
    }
    clearChangeBaselinesForWatchSpec(t);

    item->setData(t, WatchSpecRole);
    item->setText(t);
    item->setData(false, WatchPendingNewRole);
    watchRootSetVariablePathRoleFromSpec(item, t);
    if (item->rowCount() == 0)
    {
        auto *ph0 = new QStandardItem();
        auto *ph1 = new QStandardItem();
        ph0->setFlags(Qt::ItemIsEnabled);
        ph1->setFlags(Qt::ItemIsEnabled);
        item->appendRow({ph0, ph1});
    }
    refreshWatchDisplay();
}

void LuaDebuggerDialog::insertNewWatchRow(const QString &initialSpec,
                                          bool openEditor)
{
    if (!watchTree || !watchModel)
    {
        return;
    }

    const QString init = initialSpec.trimmed();
    for (int i = 0; i < watchModel->rowCount(); ++i)
    {
        if (QStandardItem *r = watchModel->item(i, 0))
        {
            if (r->data(WatchSpecRole).toString() == init)
            {
                const QModelIndex wix = watchModel->indexFromItem(r);
                watchTree->scrollTo(wix);
                watchTree->setCurrentIndex(wix);
                return;
            }
        }
    }
    if (!init.isEmpty() && !watchSpecUsesPathResolution(init))
    {
        showPathOnlyVariablePathWatchMessage();
        return;
    }

    auto *row0 = new QStandardItem();
    auto *row1 = new QStandardItem();
    row0->setFlags(row0->flags() | Qt::ItemIsEditable | Qt::ItemIsEnabled |
                   Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    row1->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsDragEnabled);
    row0->setData(init, WatchSpecRole);
    row0->setText(init);
    row0->setData(QString(), WatchSubpathRole);
    row0->setData(QVariant(init.isEmpty()), WatchPendingNewRole);
    if (!init.isEmpty())
    {
        watchRootSetVariablePathRoleFromSpec(row0, init);
    }
    {
        auto *ph0 = new QStandardItem();
        auto *ph1 = new QStandardItem();
        ph0->setFlags(Qt::ItemIsEnabled);
        ph1->setFlags(Qt::ItemIsEnabled);
        row0->appendRow({ph0, ph1});
    }
    watchModel->appendRow({row0, row1});
    refreshWatchDisplay();

    if (openEditor)
    {
        QTimer::singleShot(0, this, [this, row0]()
                           {
                               const QModelIndex editIx =
                                   watchModel->indexFromItem(row0);
                               watchTree->scrollTo(editIx);
                               watchTree->setCurrentIndex(editIx);
                               watchTree->edit(editIx);
                           });
    }
}

void LuaDebuggerDialog::restoreWatchExpansionState()
{
    if (!watchTree)
    {
        return;
    }
    /* Re-apply each root's expansion from the runtime map. After a fresh load
     * from lua_debugger.json the map is empty (rows open collapsed). */
    for (int i = 0; i < watchModel->rowCount(); ++i)
    {
        QStandardItem *root = watchModel->item(i);
        const QString spec = root->data(WatchSpecRole).toString();
        bool rootExpanded = false;
        QStringList subpaths;
        const auto it = watchExpansion_.constFind(spec);
        if (it != watchExpansion_.cend())
        {
            rootExpanded = it->rootExpanded;
            subpaths = it->subpaths;
        }
        if (rootExpanded !=
            LuaDebuggerItems::isExpanded(watchTree, watchModel, root))
        {
            LuaDebuggerItems::setExpanded(watchTree, watchModel, root,
                                     rootExpanded);
        }
        if (rootExpanded)
        {
            reexpandTreeDescendantsByPathKeys(
                watchTree, watchModel, root, subpaths,
                findWatchItemBySubpathOrPathKey);
        }
    }
}

void LuaDebuggerDialog::restoreVariablesExpansionState()
{
    if (!variablesTree)
    {
        return;
    }
    for (int i = 0; i < variablesModel->rowCount(); ++i)
    {
        QStandardItem *root = variablesModel->item(i);
        const QString section = root->data(VariablePathRole).toString();
        if (section.isEmpty())
        {
            continue;
        }
        bool rootExpanded = false;
        QStringList subpaths;
        const auto it = variablesExpansion_.constFind(section);
        if (it == variablesExpansion_.cend())
        {
            if (section == QLatin1String("Locals"))
            {
                rootExpanded = true;
            }
        }
        else
        {
            rootExpanded = it->rootExpanded;
            subpaths = it->subpaths;
        }
        if (rootExpanded !=
            LuaDebuggerItems::isExpanded(variablesTree, variablesModel, root))
        {
            LuaDebuggerItems::setExpanded(variablesTree, variablesModel, root,
                                     rootExpanded);
        }
        if (rootExpanded)
        {
            reexpandTreeDescendantsByPathKeys(
                variablesTree, variablesModel, root, subpaths,
                findVariableTreeItemByPathKey);
        }
    }
}

// Qt-based JSON Settings Persistence
void LuaDebuggerDialog::loadSettingsFile()
{
    const QString path = luaDebuggerSettingsFilePath();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
    {
        return;
    }

    QFile loadFile(path);
    if (!loadFile.open(QIODevice::ReadOnly))
    {
        return;
    }

    QByteArray loadData = loadFile.readAll();
    if (loadData.startsWith("\xef\xbb\xbf"))
    {
        loadData = loadData.mid(3);
    }
    loadData = loadData.trimmed();

    QJsonParseError parseError;
    const QJsonDocument document =
        QJsonDocument::fromJson(loadData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
    {
        return;
    }
    settings_ = document.object().toVariantMap();
}

void LuaDebuggerDialog::saveSettingsFile()
{
    /*
     * Always merge live watch rows and engine breakpoints before writing so
     * callers that only touch theme/splitters (or watches alone) do not persist
     * stale or empty breakpoint/watch entries.
     */
    if (watchTree)
    {
        storeWatchList();
    }
    storeBreakpointsList();

    const QString savePath = luaDebuggerSettingsFilePath();
    QFileInfo fileInfo(savePath);

    QFile saveFile(savePath);
    if (fileInfo.exists() && !fileInfo.isFile())
    {
        return;
    }

    if (saveFile.open(QIODevice::WriteOnly))
    {
        QJsonDocument document(QJsonObject::fromVariantMap(settings_));
        QByteArray saveData = document.toJson(QJsonDocument::Indented);
        saveFile.write(saveData);
    }
}

void LuaDebuggerDialog::applyDialogSettings()
{
    loadSettingsFile();

    /*
     * Load JSON into the engine and watch tree. JSON is read only here (dialog
     * construction); it is written only from closeEvent() (see saveSettingsFile).
     * Apply breakpoints first so that list is never empty before rebuild.
     */
    QJsonArray breakpointsArray =
        jsonArrayFromSettingsMap(settings_, SettingsKeys::Breakpoints);
    for (const QJsonValue &val : breakpointsArray)
    {
        QJsonObject bp = val.toObject();
        QString file = bp.value("file").toString();
        int64_t line = bp.value("line").toVariant().toLongLong();
        bool active = bp.value("active").toBool(true);

        if (!file.isEmpty() && line > 0)
        {
            int32_t state = wslua_debugger_get_breakpoint_state(
                file.toUtf8().constData(), line);
            if (state < 0)
            {
                wslua_debugger_add_breakpoint(file.toUtf8().constData(), line);
            }
            wslua_debugger_set_breakpoint_active(file.toUtf8().constData(),
                                                 line, active);
        }
    }

    rebuildWatchTreeFromSettings();

    // Apply theme setting
    QString themeStr = settings_.value(SettingsKeys::Theme, "auto").toString();
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeStr == "dark")
        theme = WSLUA_DEBUGGER_THEME_DARK;
    else if (themeStr == "light")
        theme = WSLUA_DEBUGGER_THEME_LIGHT;
    currentTheme_ = theme;

    if (themeComboBox)
    {
        int idx = themeComboBox->findData(theme);
        if (idx >= 0)
            themeComboBox->setCurrentIndex(idx);
    }

    QString mainSplitterHex =
        settings_.value(SettingsKeys::MainSplitter).toString();
    QString leftSplitterHex =
        settings_.value(SettingsKeys::LeftSplitter).toString();

    bool splittersRestored = false;
    if (!mainSplitterHex.isEmpty() && ui->mainSplitter)
    {
        ui->mainSplitter->restoreState(
            QByteArray::fromHex(mainSplitterHex.toLatin1()));
        splittersRestored = true;
    }
    if (!leftSplitterHex.isEmpty() && ui->leftSplitter)
    {
        ui->leftSplitter->restoreState(
            QByteArray::fromHex(leftSplitterHex.toLatin1()));
        splittersRestored = true;
    }

    if (!splittersRestored && ui->mainSplitter)
    {
        ui->mainSplitter->setStretchFactor(0, 1);
        ui->mainSplitter->setStretchFactor(1, 2);
        QList<int> sizes;
        sizes << 300 << 600;
        ui->mainSplitter->setSizes(sizes);
    }

    if (variablesSection)
        variablesSection->setExpanded(
            settings_.value(SettingsKeys::SectionVariables, true).toBool());
    if (stackSection)
        stackSection->setExpanded(
            settings_.value(SettingsKeys::SectionStack, true).toBool());
    if (breakpointsSection)
        breakpointsSection->setExpanded(
            settings_.value(SettingsKeys::SectionBreakpoints, true).toBool());
    if (filesSection)
        filesSection->setExpanded(
            settings_.value(SettingsKeys::SectionFiles, false).toBool());
    if (evalSection)
        evalSection->setExpanded(
            settings_.value(SettingsKeys::SectionEval, false).toBool());
    if (settingsSection)
        settingsSection->setExpanded(
            settings_.value(SettingsKeys::SectionSettings, false).toBool());
    if (watchSection)
        watchSection->setExpanded(
            settings_.value(SettingsKeys::SectionWatch, true).toBool());
    /* The setExpanded() calls above each fire the section's toggled signal
     * which triggers updateLeftPanelStretch(). Call once more explicitly to
     * guarantee the splitter max-height and layout stretch factors reflect
     * the final restored expansion state regardless of signal-ordering. */
    updateLeftPanelStretch();
    /* Match Qt enable intent to C: persist active breakpoints, then
     * enable only if the user is not in "disabled" mode. */
    ensureDebuggerEnabledForActiveBreakpoints();
}

void LuaDebuggerDialog::storeDialogSettings()
{
    /*
     * Refresh settings_ from UI only (no disk I/O). JSON is written from
     * closeEvent() via saveSettingsFile().
     */
    // Store theme from combo box (or current C-side value)
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeComboBox)
    {
        theme = themeComboBox->itemData(themeComboBox->currentIndex()).toInt();
    }
    if (theme == WSLUA_DEBUGGER_THEME_DARK)
        settings_[SettingsKeys::Theme] = "dark";
    else if (theme == WSLUA_DEBUGGER_THEME_LIGHT)
        settings_[SettingsKeys::Theme] = "light";
    else
        settings_[SettingsKeys::Theme] = "auto";

    // Store splitter states as hex strings
    if (ui->mainSplitter)
    {
        settings_[SettingsKeys::MainSplitter] =
            QString::fromLatin1(ui->mainSplitter->saveState().toHex());
    }
    if (ui->leftSplitter)
    {
        settings_[SettingsKeys::LeftSplitter] =
            QString::fromLatin1(ui->leftSplitter->saveState().toHex());
    }

    // Store section expanded states
    settings_[SettingsKeys::SectionVariables] =
        variablesSection ? variablesSection->isExpanded() : true;
    settings_[SettingsKeys::SectionStack] =
        stackSection ? stackSection->isExpanded() : true;
    settings_[SettingsKeys::SectionBreakpoints] =
        breakpointsSection ? breakpointsSection->isExpanded() : true;
    settings_[SettingsKeys::SectionFiles] =
        filesSection ? filesSection->isExpanded() : false;
    settings_[SettingsKeys::SectionEval] =
        evalSection ? evalSection->isExpanded() : false;
    settings_[SettingsKeys::SectionSettings] =
        settingsSection ? settingsSection->isExpanded() : false;
    settings_[SettingsKeys::SectionWatch] =
        watchSection ? watchSection->isExpanded() : true;

    if (watchTree)
    {
        storeWatchList();
    }
}
