/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WELCOME_HEADER_WIDGET_H
#define WELCOME_HEADER_WIDGET_H

#include <QWidget>

class QPropertyAnimation;

namespace Ui {
class WelcomeHeaderWidget;
}

class WelcomeHeaderWidget : public QWidget {
    Q_OBJECT
public:
    explicit WelcomeHeaderWidget(QWidget *parent = nullptr);
    ~WelcomeHeaderWidget();
    void updateStyleSheets();

protected:
    virtual bool event(QEvent *event);

private:
    Ui::WelcomeHeaderWidget *header_ui_;
    QPropertyAnimation *pulseAnimation_;
    QString new_version_;
    QString release_notes_;
    QStringList skipped_versions_;

    void updateSoftwareUpdateInfo();
    void updateStyleSheet();
    void skipThisVersion();

private slots:
    void setAvailableUpdateVersion(QString newVersion, QString releaseNotes);
    void clearAvailableUpdateVersion();

};

#endif // WELCOME_HEADER_WIDGET_H
