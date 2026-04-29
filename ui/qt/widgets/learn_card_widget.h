/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LEARN_CARD_WIDGET_H
#define LEARN_CARD_WIDGET_H

#include <QWidget>
#include <QFrame>
#include <QColor>

class QPushButton;

namespace Ui {
class LearnCardWidget;
}

class LearnCardWidget : public QFrame {
    Q_OBJECT
public:
    explicit LearnCardWidget(QWidget *parent = nullptr);
    ~LearnCardWidget();
    void setLinksCollapsed(bool collapsed);
    bool isLinksCollapsed() const;

protected:
    bool event(QEvent *event) override;

private:

    enum ValidityType {
        AllVersions,
        ReleaseOnly,
        DevOnly
    };

    struct LinkType {
        QString url;
        QString label;
        QString short_label;
        QString tooltip;
        ValidityType validity;
    };

    struct ButtonType {
        QString url;
        QString label;
        QString tooltip;
        QColor color;
        QColor hover_color;
        ValidityType validity;
    };

    Ui::LearnCardWidget *ui_;
    QList<LinkType> links_;
    QList<ButtonType> buttons_;
    bool links_collapsed_;

    void loadLinksFromRessource();

    void setupLinks();
    void setupActionButtons();
    void updateStyleSheet();
};

#endif //LEARN_CARD_WIDGET_H
