/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIS_STREAM_ANALYSIS_DIALOG_H
#define DIS_STREAM_ANALYSIS_DIALOG_H

#include <mutex>

#include <QDialogButtonBox>
#include <QTreeWidget>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>

#ifdef QT_MULTIMEDIA_LIB
#include <QAudio>
#endif

#include "capture_file.h"
#include "wireshark_dialog.h"

#include "ui/tap-dis-common.h"

class QComboBox;
class QCustomPlot;

class DisStreamAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    static DisStreamAnalysisDialog *openDisStreamAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);

        void selectStream(disstream_info_t *stream_info);

    DisStreamAnalysisDialog(DisStreamAnalysisDialog &other) = delete;
    void operator=(const DisStreamAnalysisDialog &) = delete;

signals:
    void goToPacket(int packet_num);

protected:
    explicit DisStreamAnalysisDialog(QWidget &parent, CaptureFile &cf, QObject *packet_list);
    ~DisStreamAnalysisDialog();

    void captureFileClosing() override;
    void captureFileClosed() override;

private:
    static DisStreamAnalysisDialog *pinstance_;
    static std::mutex mutex_;

    QComboBox *stream_combo_;
    QCustomPlot *audio_plot_;
    QTreeWidget *packet_tree_;
    QLabel *duration_label_;
    QLabel *packets_label_;
    QLabel *signal_label_;
    QLabel *tx_label_;
    QLabel *lost_label_;
    QLabel *jitter_label_;
    QLabel *delta_label_;
    QLabel *codec_label_;
    QProgressBar *playback_progress_;
    QLabel *playback_time_label_;
    QDialogButtonBox *button_box_;
    QPushButton *play_button_;
    QPushButton *stop_button_;
    QPushButton *goto_button_;
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
    void updateAnalysis();
    void updatePacketRows();
    void updatePlot();

private slots:
    void onStreamChanged(int index);
    void onGoToPacket();
    void onPacketRowActivated(QTreeWidgetItem *item, int column);
#ifdef QT_MULTIMEDIA_LIB
    void onPlayPauseStream();
    void onStopStream();
    void onPlaybackProgress(double position_secs, double duration_secs);
    void onPlaybackStateChanged(QAudio::State state _U_);
#endif
    void onCaptureEvent(CaptureEvent e);
};

#endif /* DIS_STREAM_ANALYSIS_DIALOG_H */
