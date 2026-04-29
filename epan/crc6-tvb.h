/** @file
 * Declaration of CRC-6 tvbuff routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CRC6_TVB_H__
#define __CRC6_TVB_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Compute CRC-6 checksum for a given tvbuff.
 *
 * @param tvb Pointer to the tvbuff containing the data.
 * @param len Length of the data in the tvbuff.
 * @return uint16_t Computed CRC-6 checksum.
 */
WS_DLL_PUBLIC uint16_t crc6_compute_tvb(tvbuff_t *tvb, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* crc6-tvb.h */
