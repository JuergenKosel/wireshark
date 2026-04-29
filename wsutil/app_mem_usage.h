/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __APP_MEM_USAGE_H__
#define __APP_MEM_USAGE_H__

#include "ws_symbol_export.h"

typedef struct {
	const char *name;
	size_t (*fetch)(void);
	void (*gc)(void);

} ws_mem_usage_t;

/**
 * @brief Registers a memory usage component.
 *
 * @param component Pointer to the memory usage component to register.
 */
WS_DLL_PUBLIC void memory_usage_component_register(const ws_mem_usage_t *component);

/**
 * @brief Perform garbage collection on memory components.
 *
 * This function iterates through all registered memory components and calls their
 * garbage collection functions if available.
 */
WS_DLL_PUBLIC void memory_usage_gc(void);

/**
 * @brief Retrieves the name of a memory usage component.
 *
 * @param idx Index of the memory usage component to retrieve.
 * @param value Pointer to store the fetched value if not NULL.
 * @return const char* Name of the memory usage component, or NULL if invalid index.
 */
WS_DLL_PUBLIC const char *memory_usage_get(unsigned idx, size_t *value);

#endif /* APP_MEM_USAGE_H */
