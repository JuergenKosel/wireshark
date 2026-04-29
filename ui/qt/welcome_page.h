/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WELCOME_PAGE_H
#define WELCOME_PAGE_H

#include <QFrame>

class QListWidget;
class QListWidgetItem;
class QMenu;
class CaptureCardWidget;
class InterfaceFrame;

#include <ui/qt/widgets/splash_overlay.h>

namespace Ui {
    class WelcomePage;
}

class WelcomePage : public QFrame
{
    Q_OBJECT
public:
    explicit WelcomePage(QWidget *parent = 0);
    virtual ~WelcomePage();
    InterfaceFrame *getInterfaceFrame();
    CaptureCardWidget *captureCard();
    const QString captureFilter();
    void setCaptureFilter(const QString capture_filter);
    void updateStyleSheets();

public slots:
    void interfaceSelected();
    void setCaptureFilterText(const QString capture_filter);

protected:
    virtual bool event(QEvent *event);
    virtual void resizeEvent(QResizeEvent *event);
    virtual void showEvent(QShowEvent *event);

protected slots:
    void on_openFileSectionLabel_clicked();

private:
    Ui::WelcomePage *welcome_ui_;
    QString show_in_str_;

    SplashOverlay *splash_overlay_;

    void updateSidebarLayout();

signals:
    void recentFileActivated(QString cfile);

private slots:
    void appInitialized();
    void showCaptureFilesContextMenu(QPoint pos);
    void applySidebarPreferences();
};

#endif // WELCOME_PAGE_H
