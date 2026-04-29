/* lua_debugger_goto_line_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_GOTO_LINE_FRAME_H
#define LUA_DEBUGGER_GOTO_LINE_FRAME_H

#include "accordion_frame.h"

#include <QPointer>

class QKeyEvent;
class QPlainTextEdit;

namespace Ui {
class LuaDebuggerGoToLineFrame;
}

/**
 * @brief Inline "go to line" bar for the Lua debugger code editor (AccordionFrame).
 */
class LuaDebuggerGoToLineFrame : public AccordionFrame
{
    Q_OBJECT

  public:
    explicit LuaDebuggerGoToLineFrame(QWidget *parent = nullptr);
    ~LuaDebuggerGoToLineFrame() override;

    void setTargetEditor(QPlainTextEdit *editor);

    /** @brief Set the line field from the current editor cursor (before animatedShow). */
    void syncLineFieldFromEditor();
    /** @brief After animatedShow(), move focus to the line field (call from dialog). */
    void scheduleLineFieldFocus();

  protected:
    void keyPressEvent(QKeyEvent *event) override;

  private:
    Ui::LuaDebuggerGoToLineFrame *ui_;
    QPointer<QPlainTextEdit> editor_;

    void focusLineField();

  private slots:
    void on_goButton_clicked();
    void on_cancelButton_clicked();
};

#endif // LUA_DEBUGGER_GOTO_LINE_FRAME_H
