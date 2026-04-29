/* lua_debugger_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_DIALOG_H
#define LUA_DEBUGGER_DIALOG_H

#include "epan/wslua/wslua_debugger.h"
#include "geometry_state_dialog.h"

#include <QBrush>

class QToolButton;
#include <QCheckBox>
#include <QComboBox>
#include <QEventLoop>
#include <QFont>
#include <QHash>
#include <QIcon>
#include <QList>
#include <QPair>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QString>
#include <QStringList>
#include <QModelIndex>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QTreeView>
#include <QVariantMap>
#include <QVector>

struct _capture_session;

class AccordionFrame;
class CollapsibleSection;
class LuaDebuggerPauseOverlay;
class QAction;
class QEvent;
class QChildEvent;
class QCloseEvent;
class QShowEvent;

namespace Ui
{
class LuaDebuggerDialog;
}

class LuaDebuggerCodeView;

/**
 * @brief Top-level dialog hosting the Lua debugger UI components.
 */
class LuaDebuggerDialog : public GeometryStateDialog
{
    Q_OBJECT

  public:
    /**
     * @brief Construct the dialog and initialize all child widgets.
     * @param parent Optional parent widget used for ownership and stacking.
     */
    explicit LuaDebuggerDialog(QWidget *parent = nullptr);
    /**
     * @brief Destroy the dialog and disconnect debugger callbacks.
     */
    ~LuaDebuggerDialog();

    /**
     * @brief Get the current theme setting.
     * @return Theme enum value (WSLUA_DEBUGGER_THEME_AUTO, DARK, or LIGHT).
     */
    static int32_t currentTheme();

    /**
     * @brief Retrieve the singleton instance, creating it if needed.
     * @param parent Optional parent widget supplied when instantiating.
     * @return Pointer to the global dialog instance.
     */
    static LuaDebuggerDialog *instance(QWidget *parent = nullptr);

    /**
     * @brief True when a live capture is running and the debugger has
     *        been forcibly disabled by it.
     *
     * The pause path (handlePause()) is incompatible with live capture:
     * the dumpcap pipe keeps delivering packets while we sit in a
     * nested QEventLoop, and dissecting them would re-enter Lua on the
     * paused stack. Suspending the pipe source from outside is also
     * fragile (g_source_destroy frees the GIOChannel, breaking the
     * resume path). The least invasive policy is to simply turn the
     * debugger off for the duration of any live capture and restore
     * the user's prior on/off setting when capture finishes.
     */
    static bool isSuppressedByLiveCapture();

    /**
     * @brief Capture-session observer; force-disables the debugger
     *        while a live capture is running and restores the prior
     *        enabled state on capture stop.
     *
     * Registered from LuaDebuggerUiCallbackRegistrar so the policy is
     * in effect from process start, regardless of whether the dialog
     * has been opened. Always called on the GUI thread.
     */
    static void onCaptureSessionEvent(int event,
                                      struct _capture_session *cap_session,
                                      void *user_data);

    /**
     * @brief If the debugger is paused, reject the supplied close
     *        event, record the pending close so it can be re-delivered
     *        once the Lua C stack has unwound, raise/activate the
     *        debugger window, and return true. Otherwise return false
     *        and do nothing.
     *
     * Called from WiresharkMainWindow::closeEvent /
     * StratosharkMainWindow::closeEvent. Encapsulates the pause-close
     * interaction so the main window does not need to know about the
     * debugger's paused state or its re-delivery protocol. Paths like
     * macOS Dock-Quit (which fan a single close pulse out to every
     * top-level window and never retry) are handled correctly because
     * handlePause()'s post-loop cleanup re-issues the deferred close
     * once the Lua stack has unwound.
     */
    static bool handleMainCloseIfPaused(QCloseEvent *event);

    /**
     * @brief React to the debugger pausing execution at a breakpoint.
     * @param file_path Path of the Lua file that triggered the pause.
     * @param line Line number where execution stopped.
     */
    void handlePause(const char *file_path, int64_t line);

    /**
     * @brief Ensure the hierarchical file tree contains the supplied script
     * path.
     *
     * This is public because it is called from a C callback that iterates
     * loaded Lua scripts.
     *
     * @param file_path Path to split and insert.
     * @return True if a new leaf entry was added.
     */
    bool ensureFileTreeEntry(const QString &file_path);

    /**
     * @brief Apply inline edit for a root watch row (used by the item delegate).
     */
    void commitWatchRootSpec(QStandardItem *item, const QString &text);

    /**
     * @brief Re-apply monospace and header fonts to tree panels. Call after
     *        watch-list internal moves so styling matches the rest of the dialog.
     */
    void reapplyMonospacePanelFonts() { applyMonospacePanelFonts(); }

    /**
     * @brief Close from Esc or programmatic reject(); queues close() so
     *        closeEvent() runs (unsaved-scripts prompt matches the window
     *        close button). The base QDialog::reject() hides via done() and
     *        skips closeEvent(); synchronous close() from Esc can fail to close.
     */
    void reject() override;

  public slots:
    /**
     * @brief Escape: hide inline find/go accordions if shown, else close dialog.
     *        Invoked from the script editor because keys often go to the viewport,
     *        not the top-level dialog event filter.
     */
    void handleEscapeKey();

  protected:
    /**
     * @brief Flush state and resume execution when the dialog closes.
     * @param event Close request metadata from Qt.
     */
    void closeEvent(QCloseEvent *event) override;
    void showEvent(QShowEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *event) override;
    void childEvent(QChildEvent *event) override;

  private slots:
    /** @brief Resume Lua execution when the Continue action is triggered. */
    void onContinue();
    /** @brief Step over the current line. */
    void onStepOver();
    /** @brief Step into the next line (including callees). */
    void onStepIn();
    /** @brief Step out to the caller frame. */
    void onStepOut();
    /** @brief Run to the line under the cursor in the active code editor. */
    void onRunToLine();
    /** @brief Enable or disable the debugger when the toggle button is clicked.
     */
    void onDebuggerToggled(bool checked);
    /** @brief Remove every stored breakpoint. */
    void onClearBreakpoints();
    /** @brief Apply checkbox updates to a specific breakpoint row. */
    void onBreakpointItemChanged(QStandardItem *item);
    /** @brief Open the clicked breakpoint's file and focus the line. */
    void onBreakpointItemDoubleClicked(const QModelIndex &index);
    /** @brief Show the Breakpoints tree context menu (Open / Remove / Remove All). */
    void onBreakpointContextMenuRequested(const QPoint &pos);
    /** @brief Build and show the editor context menu. */
    void onCodeViewContextMenu(const QPoint &pos);
    /** @brief Populate child variable nodes when a tree item expands. */
    void onVariableItemExpanded(const QModelIndex &index);
    /** @brief Update the Variables expansion map when a row collapses. */
    void onVariableItemCollapsed(const QModelIndex &index);
    /** @brief Populate watch child rows when a watch item expands. */
    void onWatchItemExpanded(const QModelIndex &index);
    /** @brief Update the in-memory expansion map when a watch row collapses. */
    void onWatchItemCollapsed(const QModelIndex &index);
    /** @brief Context menu for the Watch tree. */
    void onWatchContextMenuRequested(const QPoint &pos);
    /** @brief Provide copy actions for a variable entry. */
    void onVariablesContextMenuRequested(const QPoint &pos);
    /** @brief Right-click menu on a Files-panel script leaf. */
    void onFileTreeContextMenuRequested(const QPoint &pos);
    /** @brief Right-click menu on a Stack-Trace row. */
    void onStackContextMenuRequested(const QPoint &pos);
    /** @brief Prompt the user to open a Lua file into a new tab. */
    void onOpenFile();
    /** @brief Save the active script tab to disk. */
    void onSaveFile();
    /** @brief Prompt before closing a tab that has unsaved edits. */
    void onCodeTabCloseRequested(int idx);
    /** @brief Trigger a reload of all Lua plugins. */
    void onReloadLuaPlugins();
    /** @brief Jump to the selected stack frame location. */
    void onStackItemDoubleClicked(const QModelIndex &index);
    /** @brief Show Locals/Upvalues for the selected stack frame. */
    void onStackCurrentItemChanged(const QModelIndex &current,
                                 const QModelIndex &previous);
    /** @brief Apply Wireshark text zoom to the script editor only. */
    void onMonospaceFontUpdated(const QFont &font);
    /** @brief Refresh fonts once the main application finishes initializing. */
    void onMainAppInitialized();
    /** @brief Update code view themes when preferences change. */
    void onPreferencesChanged();
    /** @brief Update code view themes when Wireshark's color scheme changes. */
    void onColorsChanged();
    /** @brief Evaluate the expression in the eval input field. */
    void onEvaluate();
    /** @brief Clear the eval input and output fields. */
    void onEvalClear();
    /** @brief Handle theme selection changes from the Settings section. */
    void onThemeChanged(int idx);
    /** @brief Show inline find/replace bar. */
    void onEditorFind();
    /** @brief Show inline go-to-line bar. */
    void onEditorGoToLine();
    /**
     * @brief Copy a Watch row's value (untruncated when paused); shared with
     *        context menu and keyboard shortcut.
     */
    void copyWatchValueForItem(QStandardItem *item, const QModelIndex &ix);
    /** @brief Duplicate a top-level watch row. */
    void duplicateWatchRootItem(QStandardItem *item);
    /** @brief Remove every top-level watch row. */
    void removeAllWatchTopLevelItems();
    void toggleBreakpointOnCodeViewLine(LuaDebuggerCodeView *codeView,
                                        qint32 line);
    void runToCurrentLineInPausedEditor(LuaDebuggerCodeView *codeView, qint32 line);
    /** @brief Sync Watch selection when Variables row selection changes. */
    void onVariablesCurrentItemChanged(const QModelIndex &current,
                                       const QModelIndex &previous);
    /** @brief Sync Variables selection when a path-style watch root is selected. */
    void onWatchCurrentItemChanged(const QModelIndex &current,
                                   const QModelIndex &previous);
    /**
     * @brief Adjust the left panel layout based on section expansion state.
     *
     * When at least one collapsible section is expanded, the splitter takes
     * all extra vertical space. When every section is collapsed, the
     * splitter is clamped to its content height (sum of section header
     * heights plus inter-section handles) and a trailing stretch in
     * leftPanelLayout absorbs the leftover, keeping the toolbar and section
     * headers pinned to the top of the panel.
     */
    void updateLeftPanelStretch();

  private:
    Ui::LuaDebuggerDialog *ui;
    static LuaDebuggerDialog *_instance;
    static int32_t currentTheme_;

    /* Live-capture suppression. See isSuppressedByLiveCapture(). */
    static bool s_captureSuppressionActive_;
    /* User's enabled-state at the moment the live capture started;
     * restored when capture finishes. Meaningful only while
     * s_captureSuppressionActive_ is true. */
    static bool s_captureSuppressionPrevEnabled_;

    /* Enter / exit the "live capture is suppressing the debugger"
     * state. Idempotent; each returns true iff the call actually
     * transitioned the static state (and therefore whoever called
     * needs to refresh widgets). Shared between the capture-callback
     * path (onCaptureSessionEvent) and the dialog-startup
     * reconciliation path so both follow exactly the same protocol. */
    static bool enterLiveCaptureSuppression();
    static bool exitLiveCaptureSuppression();

    /* Re-apply live-capture suppression at dialog startup so any
     * core-enable that leaked through constructor-time init paths
     * (e.g. ensureDebuggerEnabledForActiveBreakpoints after applying
     * saved breakpoints) is forced back off without disturbing the
     * previously captured "user intent" used to restore state on
     * capture stop. */
    void reconcileWithLiveCaptureOnStartup();

    /* True when a main-window close has been requested while the Lua
     * debugger must arbitrate first (paused-stack safety or unsaved
     * script prompt). Consumed by deliverDeferredMainCloseIfPending(). */
    static bool s_mainCloseDeferredByPause_;

    /* Re-deliver a main-window close that was deferred while paused.
     * Idempotent. Called from handlePause()'s post-loop cleanup so
     * the queued close runs after the Lua C stack has unwound. */
    static void deliverDeferredMainCloseIfPending();

    /**
     * @brief Static callback invoked before Lua plugins are reloaded.
     *
     * This is registered with wslua_debugger_register_reload_callback()
     * and forwards to the instance method reloadAllScriptFiles().
     */
    static void onLuaReloadCallback();

    /**
     * @brief Static callback invoked after Lua plugins are reloaded.
     *
     * This is registered with wslua_debugger_register_post_reload_callback()
     * and refreshes the file tree with newly loaded scripts.
     */
    static void onLuaPostReloadCallback();

    /**
     * @brief Static callback invoked when a Lua script is loaded.
     *
     * This is registered with wslua_debugger_register_script_loaded_callback()
     * and adds the script to the file tree.
     */
    static void onScriptLoadedCallback(const char *file_path);

    QEventLoop *eventLoop;
    QCheckBox *enabledCheckBox;
    QString lastOpenDirectory;
    bool breakpointTabsPrimed;
    QIcon folderIcon;
    QIcon fileIcon;
    /* True when this dialog is in a pause entry / nested event-loop UI
     * (Continue/step, freeze, chrome). The C side reports an actual
     * breakpoint with wslua_debugger_is_paused(); the two are usually
     * aligned but are updated on different call paths. */
    bool debuggerPaused;
    bool reloadDeferred;
    /* True while "Reload Lua Plugins" forces temporary reload chrome. */
    bool reloadUiActive_ = false;
    /* Snapshot checkbox state so we can restore prior chrome after reload. */
    bool reloadUiSavedCheckboxChecked_ = false;
    bool reloadUiSavedCheckboxEnabled_ = true;
    /* Debugger enabled-state when reload was requested from this dialog. */
    bool reloadUiRequestWasEnabled_ = false;

    /* Pause-freeze state: populated on outermost-frame pause entry,
     * consumed on outermost-frame resume. */
    QList<QPointer<QWidget>> frozenTopLevels;
    /* Every QAction outside the debugger dialog disabled across the
     * pause: menu items, toolbar buttons, and keyboard shortcuts.
     * Needed because macOS native NSMenuItems bypass the QApplication
     * event filter and trigger QAction::triggered() directly, and
     * because Qt::ApplicationShortcut actions on background dialogs
     * could fire even though those dialogs are setEnabled(false). A
     * disabled QAction propagates to all of its UI representations,
     * which gives the user an unambiguous "everything outside the
     * debugger is inert" cue. */
    QList<QPointer<QAction>> frozenActions;
    /* QMainWindow::centralWidget() disabled across the pause. The
     * QApplication-level PauseInputFilter is meant to drop mouse and
     * key events for any window other than this dialog, but it is not
     * a reliable single point of truth — native menu-equivalent paths
     * on macOS and other edge cases can still drive selection changes
     * in the packet list. setEnabled(false) on centralWidget is a
     * guaranteed cut: Qt refuses to deliver user input to the widget
     * or any of its descendants, and the tree grays to match the
     * overlay's "paused" visual language. The dialog itself is
     * parented to the QMainWindow (not to its central widget) so this
     * does NOT disable the debugger UI. On resume, setEnabled(true)
     * triggers Qt's update() cascade over centralWidget and its
     * descendants, which is what restores the packet list from the
     * frozen-looking state it would otherwise be stuck in — the
     * QEvent::UpdateRequest filter swallowed every main-window paint
     * during the pause, so some child viewports have a stale backing
     * store until something forces a real paint pass. */
    QPointer<QWidget> frozenCentralWidget;
    /* Pause overlay is a plain child widget of the main window (like
     * SplashOverlay on the welcome page). Created on pause entry and
     * destroyed on resume; being a child widget means it has no
     * platform-window identity of its own, so it cannot surface as an
     * independent entry in Mission Control or Alt-Tab and follows the
     * main window for free. */
    QPointer<LuaDebuggerPauseOverlay> pauseOverlay;
    QObject *pauseInputFilter;
    /* One-shot guard for endPauseFreeze(): set to false at outer pause
     * entry, flipped to true on first unfreeze so the second call site
     * (handlePause post-loop vs. closeEvent) becomes a no-op. */
    bool pauseUnfrozen_ = true;
    /** @brief lua_getstack level for variables; kept in sync with stack list. */
    int stackSelectionLevel;

    // Collapsible sections (created programmatically)
    CollapsibleSection *variablesSection;
    CollapsibleSection *watchSection;
    CollapsibleSection *stackSection;
    CollapsibleSection *breakpointsSection;
    CollapsibleSection *filesSection;
    CollapsibleSection *evalSection;
    CollapsibleSection *settingsSection;

    // Tree views and item models (created programmatically)
    QTreeView *variablesTree;
    QStandardItemModel *variablesModel;
    QTreeView *watchTree;
    QStandardItemModel *watchModel;
    QTreeView *stackTree;
    QStandardItemModel *stackModel;
    QTreeView *fileTree;
    QStandardItemModel *fileModel;
    QTreeView *breakpointsTree;
    QStandardItemModel *breakpointsModel;

    // Eval panel widgets (created programmatically)
    QPlainTextEdit *evalInputEdit;
    QPlainTextEdit *evalOutputEdit;
    QPushButton *evalButton;
    QPushButton *evalClearButton;

    // Settings panel widgets (created programmatically)
    QComboBox *themeComboBox;
    /** @brief Watch section header: remove selected root watch row(s). */
    QToolButton *watchRemoveButton_ = nullptr;
    /** @brief Watch section header: remove all top-level watch rows. */
    QToolButton *watchRemoveAllButton_ = nullptr;
    /** @brief Breakpoints section header: toggle at caret, clear all. */
    QToolButton *breakpointHeaderToggleButton_ = nullptr;
    QToolButton *breakpointHeaderRemoveAllButton_ = nullptr;
    /** @brief Dialog-wide QAction backing the Ctrl+Shift+F9 shortcut. */
    QAction *actionRemoveAllBreakpoints_ = nullptr;
    /**
     * @brief Cached breakpoint header dot icons, indexed by
     *        @c LuaDbgBpHeaderIconMode (0..2). Recomputed lazily when the
     *        cache key (editor font + side + DPR) changes; without this the
     *        icon would be regenerated on every cursor move.
     */
    QIcon bpHeaderIconCache_[3];
    QString bpHeaderIconCacheKey_;

    /** @brief Refresh the call stack tree from the debugger back-end. */
    void updateStack();
    /**
     * @brief Rebuild the variables tree after the stack frame for inspection
     *        changed (same as clearing the tree and calling updateVariables at
     *        the root).
     */
    void refreshVariablesForCurrentStackFrame();
    /**
     * @brief Populate the variables tree with locals, globals, or nested
     * tables.
     * @param parent Optional parent tree item receiving the children.
     * @param path Resolved variable path used for debugger queries.
     */
    void updateVariables(QStandardItem *parent = nullptr,
                         const QString &path = QString());
    /** @brief Rebuild the breakpoint list widget from persisted data. */
    void updateBreakpoints();
    /**
     * @brief Remove the breakpoints corresponding to the given model rows.
     *
     * Snapshots (file, line) pairs first, then calls the debugger core,
     * refreshes the breakpoint list, and repaints markers in any code tab
     * whose file was touched. Duplicate row indices are ignored.
     *
     * @param rows Model rows in @c breakpointsModel to remove.
     * @return True if at least one breakpoint was removed.
     */
    bool removeBreakpointRows(const QList<int> &rows);
    /**
     * @brief Remove every currently selected breakpoint row.
     *
     * Thin wrapper around removeBreakpointRows() used by the Del/Backspace
     * shortcut and the "Remove" context-menu action.
     *
     * @return True if at least one breakpoint was removed.
     */
    bool removeSelectedBreakpoints();
    /**
     * @brief Load a file into a code tab, creating the tab if necessary.
     * @param file_path Absolute or relative file path to open.
     * @return Pointer to the code view widget that now hosts the file.
     */
    LuaDebuggerCodeView *loadFile(const QString &file_path);
    /** @brief The code editor in the active tab, or nullptr. */
    LuaDebuggerCodeView *currentCodeView() const;
    /** @brief True if any open tab has unsaved edits. */
    bool hasUnsavedChanges() const;
    /** @brief How many open code tabs currently have unsaved edits. */
    qint32 unsavedOpenScriptTabCount() const;
    /**
     * @brief If any tab is modified, prompt to save or discard.
     * @param title Window title for the prompt.
     * @return False if the user cancelled; true if there is nothing to do,
     *         changes were saved, or the user chose to discard.
     */
    bool ensureUnsavedChangesHandled(const QString &title);
    /** @brief Mark every open document as unmodified without saving. */
    void clearAllDocumentModified();
    /** @brief Persist one editor buffer to its file path. */
    bool saveCodeView(LuaDebuggerCodeView *view);
    /** @brief Save every tab that has unsaved edits. */
    bool saveAllModified();
    /** @brief Update tab label (e.g. trailing *) for one editor. */
    void updateTabTextForCodeView(LuaDebuggerCodeView *view);
    /** @brief Enable Save when the current tab can be written. */
    void updateSaveActionState();
    /** @brief Reflect unsaved scripts in the window (e.g. close-button hint). */
    void updateWindowModifiedState();
    /** @brief Hide other accordion bars then show one (matches main window). */
    void showAccordionFrame(AccordionFrame *frame, bool toggle = false);
    /** @brief Point find/goto bars at the active code tab. */
    void updateLuaEditorAuxFrames();
    /** @brief Install this dialog as an event filter on all descendant widgets
     *  so conflicting shortcuts are handled here before the main window.
     */
    void installDescendantShortcutFilters();
    /** @brief Apply monospace to each open code tab (and line number area). */
    void applyCodeEditorFonts(const QFont &monoFont);
    /** @brief Base monospace for panel bodies; normal font for tree headers. */
    void applyMonospacePanelFonts();
    /** @brief Re-sync each @c QStandardItem font in the watch model to
     *        the panel monospace (keeps @c QStandardItem::font in line with
     *        the tree’s @c setFont, e.g. after DnD). Preserves @c QFont::bold. */
    void reapplyMonospaceToWatchItemFonts();
    /** @brief Index all Lua scripts from standard plugin directories. */
    void refreshAvailableScripts();
    /**
     * @brief Scan a specific directory for Lua scripts and add them to the file
     * tree.
     * @param dir_path Directory to scan recursively.
     */
    void scanScriptDirectory(const QString &dir_path);
    /**
     * @brief Normalize a path by trimming prefixes and resolving symbolic
     * components.
     * @param file_path Input path that may be relative or prefixed with '@'.
     * @return Canonical or cleaned absolute path string.
     */
    QString normalizedFilePath(const QString &file_path) const;
    /** @brief Sync only the checkbox checked/enabled state from core flags. */
    void syncDebuggerToggleWithCore();
    /** @brief Refresh checkbox sync + all debugger state chrome/widgets. */
    void refreshDebuggerStateUi();
    /** @brief Enter transient "reload in progress" chrome when applicable. */
    void enterReloadUiStateIfEnabled();
    /** @brief Exit transient reload chrome and restore normal widget syncing. */
    void exitReloadUiState();
    /** @brief One combined status for window title and toolbar dot (single source
     *        of truth for chrome, derived from the core and Qt members). */
    enum class DebuggerUiStatus
    {
        Paused,
        DisabledLiveCapture,
        Disabled,
        Running
    };
    DebuggerUiStatus currentDebuggerUiStatus() const;
    /** @brief Update the checkbox icon based on the enabled state. */
    void updateEnabledCheckboxIcon();
    /** @brief Enable the debugger if any active breakpoint requires it. */
    void ensureDebuggerEnabledForActiveBreakpoints();
    /**
     * @brief Locate a child item by absolute path beneath a parent node.
     * @param parent Parent item or nullptr for top-level search.
     * @param path Fully qualified path from the role data.
     * @return Matching tree item pointer or nullptr.
     */
    QStandardItem *findChildItemByPath(QStandardItem *parent,
                                       const QString &path) const;
    /**
     * @brief Break a path into display + absolute segments for the Files tree.
     * @param file_path Absolute path to split.
     * @param components Output vector receiving ordered components.
     * @return True when at least one path segment was produced.
     */
    bool
    appendPathComponents(const QString &file_path,
                         QVector<QPair<QString, QString>> &components) const;
    /**
     * @brief Open each initial breakpoint file once tabs are ready.
     * @param files Ordered list of canonical script paths to open.
     */
    void openInitialBreakpointFiles(const QVector<QString> &files);
    /** @brief Update the status label to show current debugger state. */
    void updateStatusLabel();
    /** @brief Enable or disable the Continue action based on debugger state. */
    void updateContinueActionState();
    /** @brief Configure the variables tree column sizing rules. */
    void configureVariablesTreeColumns();
    /** @brief Configure the watch tree column sizing rules. */
    void configureWatchTreeColumns();
    /** @brief Configure the stack tree header layout. */
    void configureStackTreeColumns();
    /** @brief Remove paused-state UI artifacts like stacks and highlights. */
    void clearPausedStateUi();
    /** @brief Remove highlights from every open code view. */
    void clearAllCodeHighlights();
    /** @brief Zoomed monospace for the editor; base monospace + normal headers for panels. */
    void applyMonospaceFonts();
    /** @brief Apply the current theme preference to all code views. */
    void applyCodeViewThemes();
    /** @brief Reload all script files from disk (e.g., after Lua plugin
     * reload). */
    void reloadAllScriptFiles();
    /** @brief Monospace for panels and the script editor. */
    QFont effectiveMonospaceFont(bool zoomed) const;
    /** @brief Standard Wireshark UI font for tree column headers. */
    QFont effectiveRegularFont() const;
    /** @brief Resume the debugger (if paused) and exit any nested event loop.
     */
    void resumeDebuggerAndExitLoop();
    /**
     * @brief Undo the pause-entry UI freeze synchronously.
     *
     * Idempotent: safe to call from both handlePause()'s post-loop
     * (normal Continue/Step resume) and from closeEvent() (so the
     * rest of WiresharkMainWindow::closeEvent runs with a fully
     * interactive UI when the user closes the app while the
     * debugger is paused). Gated by pauseUnfrozen_.
     */
    void endPauseFreeze();
    /**
     * @brief Resume execution with a stepping mode; shared by step over/in/out.
     * @param step_fn Core step function (e.g. wslua_debugger_step_over).
     */
    void runDebuggerStep(void (*step_fn)(void));
    /** @brief Update the enabled state of the eval panel based on debugger
     * state. */
    void updateEvalPanelState();
    /** @brief Update all widgets based on the current debugger state. */
    void updateWidgets();
    /** @brief Create the collapsible sections and their content widgets. */
    void createCollapsibleSections();

    // ---- Qt-based JSON settings persistence (like import_hexdump) ----
    /** @brief In-memory settings store, persisted to JSON file. */
    QVariantMap settings_;
    /** @brief True after lua_debugger.json was written from closeEvent (destructor fallback if false). */
    bool luaDebuggerJsonSaved_{false};
    /** @brief Load settings from lua_debugger.json (global personal config, not per-profile).
     */
    void loadSettingsFile();
    /** @brief Save settings to lua_debugger.json (global personal config, not per-profile).
     */
    void saveSettingsFile();
    /** @brief Apply loaded settings to UI widgets. */
    void applyDialogSettings();
    /** @brief Store current UI widget state into settings map. */
    void storeDialogSettings();

    /** @brief Serialize breakpoint list from the engine into settings_. */
    void storeBreakpointsList();
    /** @brief Serialize watch entries from the watch tree into settings_. */
    void storeWatchList();
    /** @brief Rebuild the watch tree from settings_. */
    void rebuildWatchTreeFromSettings();
    /** @brief Refresh value/type (and expansion affordances) for all watch roots. */
    void refreshWatchDisplay();
    /** @brief Add a watch from an expression/path spec without opening the editor. */
    void addWatchFromSpec(const QString &watchSpec);
    /**
     * @brief Insert a top-level watch row; optionally open the inline editor.
     *        The spec must be a Variables-style path (see
     *        wslua_debugger_watch_spec_uses_path_resolution).
     */
    void insertNewWatchRow(const QString &initialSpec = QString(),
                           bool openEditor = true);
    /** @brief Apply one root or nested watch row from the debugger back-end. */
    void applyWatchItemState(QStandardItem *item, bool liveContext,
                             const QString &muted);
    void applyWatchItemEmpty(QStandardItem *item, const QString &muted,
                             const QString &watchTipExtra);
    void applyWatchItemNonPath(QStandardItem *item,
                               const QString &watchTipExtra);
    void applyWatchItemNoLiveContext(QStandardItem *item,
                                     const QString &muted,
                                     const QString &watchTipExtra);
    void applyWatchItemError(QStandardItem *item, const QString &errStr,
                             const QString &watchTipExtra);
    void applyWatchItemSuccess(QStandardItem *item, const QString &spec,
                               const char *val, const char *typ,
                               bool can_expand,
                               const QString &watchTipExtra);
    /** @brief Fill children for a path-based watch using get_variables. */
    void fillWatchPathChildren(QStandardItem *parent,
                               const QString &variablePath);
    /** @brief Re-query children after clearing (used on expand and on refresh). */
    void refillWatchChildren(QStandardItem *item);
    /** @brief Refresh expanded watch rows depth-first (values after pause/step). */
    void refreshWatchBranch(QStandardItem *item);
    /** @brief Re-expand persisted subpaths after loading settings or refresh. */
    void restoreWatchExpansionState();
    /** @brief Re-expand Variables sections from the runtime expansion map. */
    void restoreVariablesExpansionState();

    /** @brief Delete the given top-level watch rows from the tree. */
    void deleteWatchRows(const QList<QStandardItem *> &items);
    /**
     * @brief Top-level watch rows in the current selection (column 0) only;
     *        used by the header Remove control. No currentIndex fallback, so
     *        the button does not act on a non-selected row.
     */
    QList<QStandardItem *> selectedWatchRootItemsForRemove() const;
    /** @brief Enable the Watch section header + / − / remove-all controls. */
    void updateWatchHeaderButtonState();
    /** @brief Enable the Breakpoints section header toggle / remove-all. */
    void updateBreakpointHeaderButtonState();
    /** @brief Activate all or deactivate all breakpoints (header control). */
    void toggleAllBreakpointsActiveFromHeader();
    QStandardItem *findVariablesItemByPath(const QString &path) const;
    QStandardItem *findWatchRootForVariablePath(const QString &path) const;
    static void expandAncestorsOf(QTreeView *tree, QStandardItemModel *model,
                                  QStandardItem *item);
    /** @brief Select the Variables row matching the current watch (if any). */
    void syncVariablesTreeToCurrentWatch();
    /** @brief Shared wording when the user enters a non-path watch spec. */
    void showPathOnlyVariablePathWatchMessage();

    bool syncWatchVariablesSelection_ = false;

    /**
     * @brief Runtime-only expansion state for one tree root (watch row or
     * Variables Locals/Globals/Upvalues section).
     *
     * Tracks which roots are expanded and which descendant path keys are
     * expanded. Updated on every QTreeView::expanded / collapsed signal so
     * the state survives child-item destruction during pause →
     * resume → pause cycles, lazy refills, and tree refreshes.
     *
     * **Not** persisted to `lua_debugger.json`.
     */
    struct TreeSectionExpansionState
    {
        bool rootExpanded = false;
        QStringList subpaths;
    };
    QHash<QString, TreeSectionExpansionState> watchExpansion_;
    /**
     * @brief Runtime-only expansion for Variables top-level sections
     * (`Locals`, `Globals`, `Upvalues`). Same lifecycle as `watchExpansion_`.
     */
    QHash<QString, TreeSectionExpansionState> variablesExpansion_;

    void recordTreeSectionRootExpansion(
        QHash<QString, TreeSectionExpansionState> &map, const QString &rootKey,
        bool expanded);
    void recordTreeSectionSubpathExpansion(
        QHash<QString, TreeSectionExpansionState> &map, const QString &rootKey,
        const QString &key, bool expanded);
    QStringList treeSectionExpandedSubpaths(
        const QHash<QString, TreeSectionExpansionState> &map,
        const QString &rootKey) const;

    /** @brief Merge one root's expansion state into `watchExpansion_`. */
    void recordWatchRootExpansion(const QString &rootSpec, bool expanded);
    /** @brief Add / remove one descendant key in `watchExpansion_`. */
    void recordWatchSubpathExpansion(const QString &rootSpec,
                                     const QString &key, bool expanded);
    /** @brief Look up expanded descendant keys for @p rootSpec (may be empty). */
    QStringList watchExpandedSubpathsForSpec(const QString &rootSpec) const;
    /** @brief Drop map entries for watch specs no longer in the tree. */
    void pruneWatchExpansionMap();

    // -----------------------------------------------------------------------
    // Changed-value (bold + accent + transient flash) bookkeeping.
    //
    // Semantics: a Value cell is marked "changed" when its value at this
    // pause differs from the value it had at the previous pause entry.
    //
    // Baselines rotate only on pause entry (`snapshotBaselinesOnPauseEntry`),
    // so intra-pause refreshes (stack-frame switch, theme change, watch
    // edit, eval, ...) leave the cue stable. Current-value maps are written
    // by the paint helpers on every refresh and become the next pause's
    // baselines at that pause's entry.
    //
    // Keys encode the stack level so `Locals.x` / `Upvalues.x` at different
    // frames are tracked independently; `Globals.*` uses level = -1 so
    // frame switches do not invalidate it. See `changeKey()` in the .cpp.
    // -----------------------------------------------------------------------
    QHash<QString /* rootKey */, QString> watchRootBaseline_;
    QHash<QString /* rootKey */, QString> watchRootCurrent_;
    QHash<QString /* rootKey */, QHash<QString /* childPath */, QString>>
        watchChildBaseline_;
    QHash<QString /* rootKey */, QHash<QString /* childPath */, QString>>
        watchChildCurrent_;
    QHash<QString /* variablesKey */, QString> variablesBaseline_;
    QHash<QString /* variablesKey */, QString> variablesCurrent_;

    // -----------------------------------------------------------------------
    // Companion "visited parents" sets. Every paint of a parent's children
    // records the parent's own change-key (variables) or path (watch) here,
    // and the sets rotate on pause entry just like the value maps. Used as
    // the flashNew gate so we only treat an absent child as "new" when the
    // parent was actually expanded at the previous pause; without this a
    // first-time expansion in the current pause would flash every child,
    // and conversely a parent that was expanded last pause but had no
    // children to show (function with no locals yet, empty table) could
    // not light up the FIRST child that appears now (because no per-child
    // baseline keys exist to prove "the parent existed in baseline"). The
    // sets give the unambiguous per-parent expansion signal that scanning
    // value-map prefixes cannot.
    // -----------------------------------------------------------------------
    QSet<QString /* variablesKey of parent */> variablesBaselineParents_;
    QSet<QString /* variablesKey of parent */> variablesCurrentParents_;
    QHash<QString /* rootKey */, QSet<QString /* parentPath */>>
        watchChildBaselineParents_;
    QHash<QString /* rootKey */, QSet<QString /* parentPath */>>
        watchChildCurrentParents_;

    /** Accent foreground used for changed values; resolved from palette. */
    QBrush changedValueBrush_;
    /** Transient flash background for the moment of change. */
    QBrush changedFlashBrush_;
    /**
     * True only during the pause-entry refresh (handlePause). Paint helpers
     * use this to decide whether to schedule the one-shot background flash.
     */
    bool isPauseEntryRefresh_ = false;
    /**
     * Monotonic counter that identifies one flash installation per cell.
     * The scheduled clear-timer only clears if the cell's recorded serial
     * still matches, so a re-flashed cell doesn't lose its new flash when
     * an earlier clear fires.
     */
    qint32 flashSerial_ = 0;
    /**
     * Monotonic epoch for the deferred "Watch column shows —" placeholder
     * application after a step resume. runDebuggerStep() captures the value
     * at schedule-time; handlePause() bumps it on every pause entry so a
     * synchronous re-pause invalidates the still-pending timer and the user
     * never sees the value briefly flip to "—" and back. Without this the
     * typical fast single-step produced a visible value→—→value blink in
     * every Watch row even when the value did not change.
     */
    qint32 watchPlaceholderEpoch_ = 0;
    /**
     * The stack selection level that was active when the pause entered.
     * handlePause() resets stackSelectionLevel to 0, so this is normally 0;
     * keeping it as an explicit member documents the invariant and makes
     * changeHighlightAllowed() read naturally. Walking a different frame
     * inside the same pause yields a fundamentally different scope (often
     * different locals entirely), so the "changed since last pause" cue
     * stops being meaningful and is suppressed.
     */
    int pauseEntryStackLevel_ = 0;
    /**
     * Stable identity of frame 0 at pause entry, formatted as
     * "<source>:<linedefined>". Empty before the first pause and after a
     * debugger-off / Lua reload. Compared at every subsequent pause entry
     * to decide whether the previous pause's Locals/Upvalues baseline
     * still refers to the same Lua function — it does not after a call or
     * a return, so the cue must be suppressed for that one pause.
     */
    QString pauseEntryFrame0Identity_;
    /**
     * True when the just-captured frame-0 identity equals the identity
     * captured at the previous pause. False on the very first pause (no
     * previous identity to compare against; baselines are empty there
     * anyway, so suppression is harmless), and false for one pause after
     * any call/return that changes the function at frame 0.
     */
    bool pauseEntryFrame0MatchesPrev_ = false;

    /**
     * @brief True when the changed-value visual cue (bold accent, optional
     * transient flash) is meaningful for the currently displayed values.
     *
     * The cue requires both:
     *   - The user is viewing the stack level that was active at pause
     *     entry. Walking a different frame inside the same pause shows
     *     variables from an unrelated scope; the per-(level, path)
     *     baseline comparison would spuriously light up "new" locals or
     *     compare against an unrelated previous-pause snapshot at the same
     *     numeric level.
     *   - The function at frame 0 is the same as at the previous pause
     *     entry. Across a call or return, frame 0 is a different Lua
     *     function entirely, and the previous pause's baseline keyed at
     *     numeric level 0 belongs to a different scope; comparing against
     *     it would flash every local as "changed" or "new".
     *
     * Globals and Globals-scoped watches are exempt from both checks at
     * the call sites because they are anchored to level = -1 in the
     * baseline keys and stay comparable regardless of the call stack.
     */
    bool changeHighlightAllowed() const
    {
        return stackSelectionLevel == pauseEntryStackLevel_ &&
               pauseEntryFrame0MatchesPrev_;
    }

    /** @brief Recompute `changedValueBrush_` / `changedFlashBrush_` from the
     *  current palette; call whenever the theme / palette changes. */
    void refreshChangedValueBrushes();
    /** @brief Rotate watch/variables Current → Baseline and clear Current. */
    void snapshotBaselinesOnPauseEntry();
    /** @brief Apply (or clear) the accent + bold on @p valueCell, and if
     *  @p isPauseEntryRefresh and @p changed also install the one-shot
     *  background flash. Safe to call with @p valueCell == nullptr. */
    void applyChangedVisuals(QStandardItem *valueCell, bool changed,
                             bool isPauseEntryRefresh);
    /** @brief Drop all change-tracking baselines and current-value maps. */
    void clearAllChangeBaselines();
    /** @brief Drop baseline + current entries whose watch spec is @p spec. */
    void clearChangeBaselinesForWatchSpec(const QString &spec);
    /** @brief Prune baseline + current maps down to the watch specs still in
     *  the tree; mirror of pruneWatchExpansionMap. */
    void pruneChangeBaselinesToLiveWatchSpecs();
    /** @brief Capture the identity of frame 0 ("<source>:<linedefined>")
     *  and update @ref pauseEntryFrame0MatchesPrev_. Call once per pause
     *  entry, before painting begins; see changeHighlightAllowed(). */
    void updatePauseEntryFrameIdentity();
};

#endif // LUA_DEBUGGER_DIALOG_H
