/* lua_debugger_item_utils.h
 *
 * Helpers for QTreeView + QStandardItemModel rows (multi-column items).
 *
 * These follow Qt’s model/view split: the view owns expansion state; use
 * isExpanded/setExpanded here rather than QStandardItem APIs. Prefer
 * QModelIndex and model data (e.g. rowColumnDisplayText) at view boundaries
 * so a future QSortFilterProxyModel can sit in front of the model without
 * rewriting call sites. QStandardItem navigation remains appropriate for
 * lazy tree construction (appendRow, child lookup).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LUA_DEBUGGER_ITEM_UTILS_H
#define LUA_DEBUGGER_ITEM_UTILS_H

#include <QBrush>
#include <QFont>
#include <QIcon>
#include <QModelIndex>
#include <QStandardItem>
#include <QStandardItemModel>
#include <QString>
#include <QTreeView>
#include <QVariant>

namespace LuaDebuggerItems
{

/** Qt::DisplayRole text for column @p col in the same row as @p indexInRow. */
inline QString
rowColumnDisplayText(const QModelIndex &indexInRow, int col)
{
    if (!indexInRow.isValid())
    {
        return QString();
    }
    return indexInRow.sibling(indexInRow.row(), col).data(Qt::DisplayRole).toString();
}

/** Column-0 item for the same row as @p cell. */
inline QStandardItem *
rowCol0(QStandardItemModel *model, QStandardItem *cell)
{
    if (!model || !cell)
    {
        return nullptr;
    }
    const QModelIndex ix = model->indexFromItem(cell);
    if (!ix.isValid())
    {
        return nullptr;
    }
    return model->itemFromIndex(ix.sibling(ix.row(), 0));
}

/** Cell in column @p col for a row whose column-0 anchor is @p col0. */
inline QStandardItem *
cellAt(QStandardItemModel *model, QStandardItem *col0, int col)
{
    if (!model || !col0 || col0->column() != 0)
    {
        return nullptr;
    }
    QStandardItem *par = col0->parent();
    if (!par)
    {
        return model->item(col0->row(), col);
    }
    return par->child(col0->row(), col);
}

inline QString
text(QStandardItemModel *model, QStandardItem *col0, int col)
{
    QStandardItem *c = cellAt(model, col0, col);
    return c ? c->text() : QString();
}

inline void
setText(QStandardItemModel *model, QStandardItem *col0, int col, const QString &t)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setText(t);
    }
}

inline void
setToolTip(QStandardItemModel *model, QStandardItem *col0, int col, const QString &tip)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setToolTip(tip);
    }
}

inline void
setFont(QStandardItemModel *model, QStandardItem *col0, int col, const QFont &font)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setFont(font);
    }
}

inline void
setForeground(QStandardItemModel *model, QStandardItem *col0, int col,
                const QBrush &brush)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setForeground(brush);
    }
}

inline void
setBackground(QStandardItemModel *model, QStandardItem *col0, int col,
              const QBrush &brush)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setBackground(brush);
    }
}

inline void
setIcon(QStandardItemModel *model, QStandardItem *col0, int col, const QIcon &icon)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setIcon(icon);
    }
}

inline void
setTextAlignment(QStandardItemModel *model, QStandardItem *col0, int col,
                 Qt::Alignment align)
{
    QStandardItem *c = cellAt(model, col0, col);
    if (c)
    {
        c->setTextAlignment(align);
    }
}

inline QModelIndex
indexCol0(QStandardItemModel *model, QStandardItem *col0)
{
    if (!model || !col0 || col0->column() != 0)
    {
        return QModelIndex();
    }
    return model->indexFromItem(col0);
}

inline bool
isExpanded(QTreeView *tree, QStandardItemModel *model, QStandardItem *col0)
{
    const QModelIndex ix = indexCol0(model, col0);
    return ix.isValid() && tree->isExpanded(ix);
}

inline void
setExpanded(QTreeView *tree, QStandardItemModel *model, QStandardItem *col0,
            bool expanded)
{
    const QModelIndex ix = indexCol0(model, col0);
    if (ix.isValid())
    {
        tree->setExpanded(ix, expanded);
    }
}

} // namespace LuaDebuggerItems

#endif /* LUA_DEBUGGER_ITEM_UTILS_H */
