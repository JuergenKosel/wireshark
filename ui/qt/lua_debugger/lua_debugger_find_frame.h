/* lua_debugger_find_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_FIND_FRAME_H
#define LUA_DEBUGGER_FIND_FRAME_H

#include "accordion_frame.h"

#include <QPointer>

class QEvent;
class QKeyEvent;
class QPlainTextEdit;

namespace Ui {
class LuaDebuggerFindFrame;
}

/**
 * @brief Inline find/replace bar for the Lua debugger code editor (AccordionFrame).
 */
class LuaDebuggerFindFrame : public AccordionFrame
{
    Q_OBJECT

  public:
    explicit LuaDebuggerFindFrame(QWidget *parent = nullptr);
    ~LuaDebuggerFindFrame() override;

    void setTargetEditor(QPlainTextEdit *editor);

    /** @brief After animatedShow(), move focus to the find field (call from dialog). */
    void scheduleFindFieldFocus();

  protected:
    bool eventFilter(QObject *watched, QEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

  private:
    Ui::LuaDebuggerFindFrame *ui_;
    QPointer<QPlainTextEdit> editor_;

    void focusFindField();

    void findNext(bool backward);
    bool selectionMatchesFind() const;
    void replaceAll();

  private slots:
    void on_findNextButton_clicked();
    void on_findPreviousButton_clicked();
    void on_replaceButton_clicked();
    void on_replaceAllButton_clicked();
    void on_closeButton_clicked();
};

#endif // LUA_DEBUGGER_FIND_FRAME_H
