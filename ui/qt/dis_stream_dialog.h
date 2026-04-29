/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIS_STREAM_DIALOG_H
#define DIS_STREAM_DIALOG_H

#include <mutex>

#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#ifdef QT_MULTIMEDIA_LIB
#include <QAudio>
#endif

#include "capture_file.h"
#include "wireshark_dialog.h"

#include "ui/tap-dis-common.h"

#include "dis_stream_analysis_dialog.h"

class DisStreamDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    static DisStreamDialog *openDisStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

    DisStreamDialog(DisStreamDialog &other) = delete;
    void operator=(const DisStreamDialog &) = delete;

signals:
    void updateFilter(QString filter, bool force = false);
    void goToPacket(int packet_num);

protected:
    explicit DisStreamDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);
    ~DisStreamDialog();

    void captureFileClosing() override;
    void captureFileClosed() override;

private:
    class DisStreamTreeWidgetItem : public QTreeWidgetItem {
    public:
        using QTreeWidgetItem::QTreeWidgetItem;
        bool operator<(const QTreeWidgetItem &other) const override;
    };

    static DisStreamDialog *pinstance_;
    static std::mutex mutex_;

    QTreeWidget *stream_tree_;
    QDialogButtonBox *button_box_;
    QPushButton *filter_button_;
    QPushButton *play_button_;
    QPushButton *stop_button_;
    QPushButton *analyze_button_;
    bool need_redraw_;
    QObject *packet_list_;

#ifdef QT_MULTIMEDIA_LIB
    class DisAudioStream *audio_stream_;
#endif

    disstream_tapinfo_t tapinfo_;

    static void tapReset(disstream_tapinfo_t *tapinfo);
    static void tapDraw(disstream_tapinfo_t *tapinfo);

    disstream_info_t *selectedStream() const;
    void updateStreams();
    void updateWidgets() override;

private slots:
    void onStreamSelectionChanged();
    void onStreamItemDoubleClicked(QTreeWidgetItem *item, int column);
    void onPrepareFilter();
    void onAnalyzeStream();
#ifdef QT_MULTIMEDIA_LIB
    void onPlayStream();
    void onStopStream();
    void onPlaybackStateChanged(QAudio::State state _U_);
#endif
    void onCaptureEvent(CaptureEvent e);
};

#endif /* DIS_STREAM_DIALOG_H */
