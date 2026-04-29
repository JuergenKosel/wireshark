/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SOFTWARE_UPDATE_H
#define SOFTWARE_UPDATE_H

#include <QObject>
#include <QUrl>
#include <QMutex>
#include <QTimer>
#include <QVersionNumber>

class QNetworkAccessManager;
class QNetworkReply;

class ShutdownEvent {
public:
    void accept();
    void reject(const QString& reason = {});

    bool isAccepted() const;
    QString reason() const;

private:
    bool accepted_ = false;
    bool rejected_ = false;
    QString reason_;
};

struct AppcastItem {
    QString title;
    QVersionNumber version;
    QVersionNumber shortVersion;
    QUrl downloadUrl;
    QUrl releaseNotesUrl;
    QString os;           // "windows", "macos", or empty (= all)
    qint64 length = 0;
    QString edSignature;
};

/**
 * @brief The SoftwareUpdate class provides an interface for checking for software
 * updates and engaging the update process.
 *
 * This class is implemented as a singleton and can be accessed through the static
 * instance() method. It provides methods for initializing and cleaning up the update
 * framework, as well as for starting and stopping automatic update checks. The class
 * also emits signals when updates are available, when update checks fail, when the
 * update process is engaged, and when the application requests a shutdown for
 * performing an update.
 */
class SoftwareUpdate : public QObject
{
        Q_OBJECT
public:
    SoftwareUpdate(const SoftwareUpdate&) = delete;
    SoftwareUpdate& operator=(const SoftwareUpdate&) = delete;

    static SoftwareUpdate* instance();

    /**
     * This method will be called by the main application after it has initialized
     * far enough that the update frameworks can be initialized. Together with that
     * the automatic update check will also be started, if the user has enabled it
     * in the preferences. The interval used will be the one set in the preferences as well.
     *
     * @param runWithoutSilentCheck If true, the update check will be performed as it had
     * been before the silent check was implemented, by using the API versions of the silent
     * checks.
     */
    void init(bool runWithoutSilentCheck = false);

    /**
     * Cleans up the update framework and stops the automatic update check.
     */
    void cleanup();

    /**
     * This will initiate the UI update process. It is assumed, that if the periodic
     * update check is enabled, this will be called by the user by interacting with the
     * update notification. It will also be called when clicking on the "Check for updates"
     * action in the "Help" menu.
     *
     * The "normal" flow is, that we periodically check for updates in the background and
     * notify the user if an update is available. It is then up to the user to decide if
     * they want to update or not.
     */
    static void performUIUpdate();

    /**
     * Returns a string with the information about which software update framework is being used.
     */
    static QString info();

    /**
     * A runtime "wrapper" for HAVE_SOFTWARE_UPDATE and including platform checks. This can be
     * used by the UI to check if an update is currently supported and possible or not.
     *
     * @return true The platform is supported
     * @return false The platform is not supported
     */
    static bool plattformSupported();

    /**** Utility functions if the automatic update check needs to be manipulated through the UI ****/

    void startAutoCheck(int intervalSeconds = 0);
    void stopAutoCheck();
    bool isAutoCheckEnabled() const;

signals:
    /** Emitted when a new software update is available. */
    void updateAvailable(QString newVersion, QString releaseNotes);
    /** Emitted when the update check fails. */
    void updateCheckFailed(const QString& errorString);
    /** Emitted when the update process is engaged.
     * This will be emitted in either of the following cases:
     * 1. The user has accepted to update after being notified about an available update.
     * 2. The user has accepted to update after manually checking for updates through the UI
     * 3. The user has been presented with the update dialog but dismissed it
     * 4. The user has been presented with the update dialog but cancelled it
     * 5. The update process has failed
     */
    void updateEngaged();
    /** Emitted when the application requests a shutdown (because it will perform an update). */
    void appShutdownRequested(ShutdownEvent* shutdownEvent);

private:
    static SoftwareUpdate* instance_;
    static QMutex mutex_;
    static QMutex updateMutex_;

    QTimer* updateCheckTimer_;
    QNetworkAccessManager* networkAccessManager_;

    QUrl updateUrl() const;
    QList<AppcastItem> parseAppcast(const QByteArray &data) const;

#if defined(_WIN32)
    static int __cdecl softwareUpdateCanShutdownCallback();
    static void __cdecl shutdownRequestCallback();
    static void __cdecl softwareUpdateEngaged();
#elif defined(__APPLE__)
    static void onPostponeRelaunch(void (*proceed)(void *ctx), void *ctx);
#endif /* if */

private slots:
    void onNetworkReplyFinished(QNetworkReply* reply);
    void checkForUpdates();

protected:
    explicit SoftwareUpdate(QObject *parent = nullptr);
    ~SoftwareUpdate();
};

#endif /* SOFTWARE_UPDATE_H */
