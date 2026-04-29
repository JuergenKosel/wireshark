/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROFILE_MODEL_H
#define PROFILE_MODEL_H

#include "config.h"

#include <ui/profile.h>

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QLoggingCategory>
#include <QFileInfoList>

Q_DECLARE_LOGGING_CATEGORY(profileLogger)

class ProfileItem
{
public:
    enum StatusType {
        New = 0,
        Existing,
        Changed,
        Copy
    };

    ProfileItem(profile_def* profile);
    ProfileItem(QString name, QString reference, StatusType status, bool isGlobal, bool fromGlobal, bool isImport);

    const QString& getName() const { return name_; }
    const QString getType() const;
    const QString& getAutoSwitchFilter() const { return autoSwitchFilter_; }
    StatusType getStatus() const { return status_; }
    bool isGlobal() const { return isGlobal_; }
    bool isFromGlobal() const { return fromGlobal_; }
    bool isChanged() const { return isChanged_; }
    bool isDefault() const;
    bool isImport() const { return isImport_; }
    bool isDeleted() const { return setForDeletion_; }

    const QString& getReference() const { return reference_; }

    //Provide the profile's path
    //
    //profileName Name to append to profile path. If profileName is empty, current profile name is used
    QString getProfilePath(QString profileName = "") const;

    void setName(QString value);
    void setStatus(StatusType status) {status_ = status; }
    void setAutoSwitchFilter(QString value);
    void setForDeletion() { setForDeletion_ = true; }

private:
    QString name_;
    StatusType status_;

    QString autoSwitchFilter_ = "";
    bool      isGlobal_;
    bool      fromGlobal_ = false;
    bool      isImport_ = false;
    bool      setForDeletion_ = false;

    //Original name when created
    QString reference_;

    bool isChanged_ = false;
};


class ProfileSortModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    ProfileSortModel(QObject *parent = Q_NULLPTR);

    enum FilterType {
        AllProfiles = 0,
        PersonalProfiles,
        GlobalProfiles
    };

    void setFilterType(FilterType ft);
    void setFilterString(QString txt = QString());

    static QStringList filterTypes();

protected:
    virtual bool lessThan(const QModelIndex &source_left, const QModelIndex &source_right) const;
    virtual bool filterAcceptsRow(int source_row, const QModelIndex &source_parent) const;

private:
    FilterType ft_;
    QString ftext_;
};

class ProfileModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit ProfileModel(QObject * parent = Q_NULLPTR);
    virtual ~ProfileModel();

    enum {
        COL_NAME,
        COL_TYPE,
        COL_AUTO_SWITCH_FILTER,
        _LAST_ENTRY
    } columns_;

    enum {
        DATA_IS_DEFAULT = Qt::UserRole,
        DATA_IS_GLOBAL,
    } data_values_;

    void fillTable();

    // QAbstractItemModel interface
    virtual int rowCount(const QModelIndex & parent = QModelIndex()) const;
    virtual int columnCount(const QModelIndex & parent = QModelIndex()) const;
    virtual QVariant data(const QModelIndex & idx, int role = Qt::DisplayRole) const;
    virtual bool setData(const QModelIndex &index, const QVariant &value, int role);
    virtual QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const;
    virtual Qt::ItemFlags flags(const QModelIndex &index) const;

    void deleteEntries(QModelIndexList idcs);
    bool restoreEntries(QModelIndexList idcs);

    int findByName(const QString& name);
    QModelIndex addNewProfile(QString name);
    QModelIndex duplicateEntry(QModelIndex idx, ProfileItem::StatusType status = ProfileItem::StatusType::Copy);

    QModelIndex activeProfile() const;

    bool userProfilesExist() const;

    bool isDataValid(QString& err);

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    bool exportProfiles(QString filename, QModelIndexList items, QString& err);
    void importProfilesFromZip(QString filename, int& skippedCnt, QStringList& importList);
#endif
    void importProfilesFromDir(QString filename, int& skippedCnt, QStringList& importList, bool fromZip = false);

    static bool checkNameValidity(QString name, QString& msg);
    QList<int> findAllByNameAndVisibility(const QString& name, bool isGlobal = false, bool searchReference = false) const;

    bool checkDuplicate(const QModelIndex &index, bool isOriginalToDuplicate = false) const;

    void applyChanges();

    const ProfileItem* getCurrentProfile() const { return current_profile_; }
    const ProfileItem* getProfile(int index) const { return profile_items_[index]; }
    const ProfileItem* getPersonalProfile(const QString& name);

    QVariant dataPath(const QModelIndex& idx, QString& profilePath) const;

protected:
    static QString illegalCharacters();

    QModelIndex addNewProfile(QString name, QString reference, bool isGlobal = false, bool fromGlobal = false, bool isImport = false);

private:
    QList<ProfileItem*> profile_items_;
    QStringList profile_files_;
    ProfileItem* current_profile_ = Q_NULLPTR;

    int findByNameAndVisibility(const QString& name, bool isGlobal = false, bool searchReference = false) const;

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    static bool acceptFile(QString fileName, int fileSize);
    static QString cleanName(QString fileName);
#endif

    QVariant dataDisplay(const QModelIndex & idx) const;
    QVariant dataFontRole(const QModelIndex & idx) const;
    QVariant dataBackgroundRole(const QModelIndex & idx) const;
    QVariant dataForegroundRole(const QModelIndex & idx) const;
    QVariant dataToolTipRole(const QModelIndex & idx) const;

#if defined(HAVE_MINIZIP) || defined(HAVE_MINIZIPNG)
    QStringList exportFileList(QModelIndexList items);
#endif
    bool copyTempToProfile(QString tempPath, QString profilePath, bool& wasEmpty);
    QFileInfoList filterProfilePath(QString, QFileInfoList ent, bool fromZip);
    QFileInfoList uniquePaths(QFileInfoList lst);

};

#endif
