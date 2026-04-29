/* lua_debugger_code_view.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_CODE_VIEW_H
#define LUA_DEBUGGER_CODE_VIEW_H

#include <QFont>
#include <QObject>
#include <QPlainTextEdit>
#include <QtGlobal>

class QSyntaxHighlighter;
class QEvent;

/**
 * @brief Editable code editor supporting gutter breakpoints and highlighting.
 */
class LuaDebuggerCodeView : public QPlainTextEdit
{
    Q_OBJECT

  public:
    /**
     * @brief Create the code view and configure the line number gutter.
     * @param parent Optional parent widget for ownership.
     */
    LuaDebuggerCodeView(QWidget *parent = nullptr);

    /**
     * @brief Paint the custom gutter that hosts line numbers and breakpoints.
     * @param event Exposes the area to repaint.
     */
    void lineNumberAreaPaintEvent(QPaintEvent *event);
    /**
     * @brief Compute the width required for the gutter, including icons.
     * @return Width in device-independent pixels.
     */
    qint32 lineNumberAreaWidth();

    void setFilename(const QString &f) { filename = f; }
    QString getFilename() const { return filename; }
    /**
     * @brief Set the debugger "execution paused" line (amber bar) and move the
     *        caret to that line. Pass @<= 0 to clear only the paused-line bar.
     */
    void setCurrentLine(qint32 line);
    /** @brief Clear the debugger paused-line highlight (caret stripe unchanged). */
    void clearCurrentLineHighlight();
    /**
     * @brief Move the caret to the start of a line without changing the paused
     *        line (e.g. go-to-line).
     */
    void moveCaretToLineStart(qint32 line);
    /** @brief Apply a monospace font to both editor text and gutter. */
    void setEditorFont(const QFont &font);
    /** @brief Refresh breakpoint markers in the gutter area. */
    void updateBreakpointMarkers();
    /** @brief Re-apply theme colors from the current preference. */
    void applyTheme();

  signals:
    /**
     * @brief Emitted when a breakpoint icon is clicked within the gutter
     *        (right margin).
     * @param toggleActive If true, the click should enable/disable the
     *        breakpoint without removing it (currently mapped to Shift+click);
     *        otherwise add or remove on plain click.
     */
    void breakpointToggled(const QString &filename, qint32 line,
                           bool toggleActive);

  protected:
    /** @brief Update margins whenever Qt reports a size change. */
    void resizeEvent(QResizeEvent *event) override;
    /** @brief Forward Esc to LuaDebuggerDialog (keys go to viewport, not the dialog). */
    bool eventFilter(QObject *watched, QEvent *event) override;

  private slots:
    /** @brief Update margins to accommodate new block digits. */
    void updateLineNumberAreaWidth(int newBlockCount);
    /** @brief Rebuild debugger + caret line extra selections. */
    void rebuildLineHighlights();
    /** @brief Repaint the gutter when Qt issues update requests. */
    void updateLineNumberArea(const QRect &rect, int dy);

  private:
    QWidget *lineNumberArea;
    QSyntaxHighlighter *syntaxHighlighter;
    /** 1-based line where the debugger is paused, or -1 if none. */
    qint32 pausedExecutionLine_ = -1;

    friend class LineNumberArea;
    QString filename;
    /** @brief Apply a VS Code inspired dark palette to the editor. */
    void applyEditorPalette();
};

class LineNumberArea : public QWidget
{
  public:
    /**
     * @brief Construct the helper widget bound to a specific code view.
     * @param editor Owning code editor responsible for painting content.
     */
    LineNumberArea(LuaDebuggerCodeView *editor)
        : QWidget(editor), codeEditor(editor)
    {
    }

    /** @brief Size the gutter according to the editor's width requirements. */
    QSize sizeHint() const override
    {
        return QSize(codeEditor->lineNumberAreaWidth(), 0);
    }

  protected:
    /** @brief Delegate painting back to the code view. */
    void paintEvent(QPaintEvent *event) override
    {
        codeEditor->lineNumberAreaPaintEvent(event);
    }

    /** @brief Toggle breakpoints when the gutter is clicked. */
    void mousePressEvent(QMouseEvent *event) override;

  private:
    LuaDebuggerCodeView *codeEditor;
};

#endif // LUA_DEBUGGER_CODE_VIEW_H
