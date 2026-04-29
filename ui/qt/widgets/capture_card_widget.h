/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_CARD_WIDGET_H
#define CAPTURE_CARD_WIDGET_H

#include <QFrame>

class InterfaceFrame;

namespace Ui {
class CaptureCardWidget;
}

class CaptureCardWidget : public QFrame {
    Q_OBJECT
public:
    explicit CaptureCardWidget(QWidget *parent = nullptr);
    ~CaptureCardWidget();

    InterfaceFrame *interfaceFrame();
    const QString captureFilter();
    void setCaptureFilter(const QString &filter);
    void setCaptureFilterText(const QString &filter);

public slots:
    void interfaceSelected();

signals:
    void startCapture(QStringList ifaces);
    void captureFilterSyntaxChanged(bool valid);
    void showExtcapOptions(QString device_name, bool startCaptureOnClose);
    void interfacesChanged();

protected:
    bool event(QEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

private:
    Ui::CaptureCardWidget *ui_;

    void updateStyleSheet();
    void updateFilterRowVisibility();

private slots:
    void appInitialized();
    void interfaceListChanged();
    void captureFilterTextEdited(const QString &filter);
    void captureStarting();
};

#endif // CAPTURE_CARD_WIDGET_H
