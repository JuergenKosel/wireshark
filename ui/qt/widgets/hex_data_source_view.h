/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <config.h>

#include "ui/recent.h"

#include <QAbstractScrollArea>
#include <QFont>
#include <QColor>
#include <QVector>
#include <QMenu>
#include <QSize>
#include <QString>
#include <QTextLayout>
#include <QVector>

#include <limits>

#include "base_data_source_view.h"

#include <ui/qt/utils/data_printer.h>
#include <ui/qt/utils/idata_printable.h>

// XXX - Is there any reason we shouldn't add ImageDataSourceView, etc?

class HexDataSourceView : public BaseDataSourceView, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:
    struct ByteViewAnnotation {
        int start;
        int length;
        QColor color;
        QString comment;
    };

    explicit HexDataSourceView(const QByteArray &data, packet_char_enc encoding = PACKET_CHAR_ENC_CHAR_ASCII, QWidget *parent = nullptr);
    ~HexDataSourceView();

    void setFormat(bytes_view_type format);
    void setAnnotations(const QVector<ByteViewAnnotation> &annotations);

    bool selectionRange(int *start, int *length) const;
    int selectionAnchor() const;
    int selectionEnd() const;
    int contextByteOffset() const;
    int dataSize() const {
        Q_ASSERT(data_.size() <= std::numeric_limits<int>::max());
        return static_cast<int>(data_.size());
    }
    int offsetStart() const { return offset_start_byte_; }
    int offsetEnd() const { return offset_end_byte_; }
    int selectedFieldStart() const { return field_start_; }
    int selectedFieldLength() const { return field_len_; }
    int selectedProtocolStart() const { return proto_start_; }
    int selectedProtocolLength() const { return proto_len_; }
    bool selectedFieldIsProtocol() const { return selected_field_is_protocol_; }
    bool selectedFieldUsesOwnRange() const { return selected_field_use_own_range_; }
    void setOffsetStart(int byte);
    void setOffsetEnd(int byte);
    void clearOffsetMarkers();
    void setSelectedFieldIsProtocol(bool is_protocol) { selected_field_is_protocol_ = is_protocol; }
    void setSelectedFieldUsesOwnRange(bool use_own_range) { selected_field_use_own_range_ = use_own_range; }

signals:
    void byteViewSettingsChanged();
    void addAnnotationRequested();
    void editAnnotationRequested();
    void removeAnnotationRequested();
    void offsetStartRequested(int byte);
    void offsetEndRequested(int byte);
    void offsetMarkersCleared();

public slots:
    void setMonospaceFont(const QFont &mono_font);
    void updateByteViewSettings();

    void markProtocol(int start, int length);
    void markField(int start, int length, bool scroll_to = true, bool hover = false);
    void markAppendix(int start, int length);
    void unmarkField();

protected:
    virtual void paintEvent(QPaintEvent *);
    virtual void resizeEvent(QResizeEvent *);
    virtual void showEvent(QShowEvent *);
    virtual void mousePressEvent (QMouseEvent * event);
    virtual void mouseMoveEvent (QMouseEvent * event);
    virtual void mouseReleaseEvent(QMouseEvent *event);
    virtual void leaveEvent(QEvent *event);
    virtual void contextMenuEvent(QContextMenuEvent *event);
    virtual void keyPressEvent(QKeyEvent *event);

private:
    // Text highlight modes.
    typedef enum {
        ModeNormal,
        ModeField,
        ModeProtocol,
        ModeOffsetNormal,
        ModeOffsetField,
        ModeNonPrintable,
        ModeHover
    } HighlightMode;

    QTextLayout *layout_;

    void updateLayoutMetrics();
    int stringWidth(const QString &line);
    void drawLine(QPainter *painter, const int offset, const int row_y);
    bool addFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int start, int length, HighlightMode mode);
    bool addHexFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HighlightMode mode);
    bool addAsciiFormatRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, HighlightMode mode);
    bool addHexCustomRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, const QColor &bg, const QColor &fg);
    bool addAsciiCustomRange(QList<QTextLayout::FormatRange> &fmt_list, int mark_start, int mark_length, int tvb_offset, int max_tvb_pos, const QColor &bg, const QColor &fg);
    int annotationIndexAt(int byte_offset) const;
    int annotationIndexIntersecting(int start, int length) const;
    void updateSelection(int byte_offset, bool extend, bool emit_signal);
    void updateAnnotationToolTip(int byte_offset, const QPoint &global_pos);
    void scrollToByte(int byte);
    void updateScrollbars();
    int byteOffsetAtPixel(QPoint pos, bool allow_fuzzy = false);

    void createContextMenu();
    void updateContextMenu();

    int offsetChars(bool include_pad = true);
    int offsetPixels();
    int hexPixels();
    int asciiPixels();
    int totalPixels();
    const QByteArray printableData() { return data_; }

    static const int separator_interval_;

    bool layout_dirty_;

    // Colors
    QColor offset_normal_fg_;
    QColor offset_field_fg_;

    // Data
    packet_char_enc encoding_;  // ASCII or EBCDIC
    QMenu ctx_menu_;

    // Data highlight
    int hovered_byte_offset_;
    int proto_start_;
    int proto_len_;
    int field_start_;
    int field_len_;
    int field_a_start_;
    int field_a_len_;
    int field_hover_start_;
    int field_hover_len_;

    bool show_offset_;          // Should we show the byte offset?
    bool show_hex_;             // Should we show the hex display?
    bool show_ascii_;           // Should we show the ASCII display?
    int row_width_;             // Number of bytes per line
    int em_width_;              // Single character width and text margin. NOTE: Use fontMetrics::width for multiple characters.
    int line_height_;           // Font line spacing
    QList<QRect> hover_outlines_; // Hovered byte outlines.

    bool allow_hover_selection_;

    QVector<ByteViewAnnotation> annotations_;

    int selection_anchor_;
    int selection_start_;
    int selection_end_;
    bool selecting_;
    int context_byte_offset_;
    int cursor_byte_;
    int hovered_annotation_index_;
    int offset_start_byte_;
    int offset_end_byte_;
    bool selected_field_is_protocol_;
    bool selected_field_use_own_range_;

    // Data selection
    QVector<int> x_pos_to_column_;

    // Context menu actions
    QAction *action_allow_hover_selection_;
    QAction *action_add_annotation_;
    QAction *action_edit_annotation_;
    QAction *action_remove_annotation_;
    QAction *action_set_offset_start_;
    QAction *action_set_offset_end_;
    QAction *action_clear_offset_markers_;
    QAction *action_bytes_hex_;
    QAction *action_bytes_dec_;
    QAction *action_bytes_oct_;
    QAction *action_bytes_bits_;
    QAction *action_bytes_enc_from_packet_;
    QAction *action_bytes_enc_ascii_;
    QAction *action_bytes_enc_ebcdic_;

private slots:
    void copyBytes(bool);
    void setHexDisplayFormat(QAction *action);
    void setCharacterEncoding(QAction *action);
    void toggleHoverAllowed(bool);
    void requestAddAnnotation();
    void requestEditAnnotation();
    void requestRemoveAnnotation();
    void requestSetOffsetStart();
    void requestSetOffsetEnd();
    void requestClearOffsetMarkers();

};
