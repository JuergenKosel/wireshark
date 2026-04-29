/** @file
 *
 * Definitions for routines to get information about capture interfaces
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __CAPTURE_IFINFO_H__
#define __CAPTURE_IFINFO_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Explicitly set the interface_type enum values as these values are exposed
 * in the preferences gui.interfaces_hidden_types string.
 */
typedef enum {
	IF_WIRED	= 0,
	IF_AIRPCAP	= 1,
	IF_PIPE		= 2,
	IF_STDIN	= 3,
	IF_BLUETOOTH	= 4,
	IF_WIRELESS	= 5,
	IF_DIALUP	= 6,
	IF_USB		= 7,
	IF_EXTCAP	= 8,
	IF_VIRTUAL	= 9,
        IF_LOOPBACK	= 10,
        IF_TUNNEL	= 11,
} interface_type;

/*
 * "get_if_capabilities()" and "capture_if_capabilities()" return a pointer
 * to an allocated instance of this structure.  "free_if_capabilities()"
 * frees the returned instance.
 */
typedef struct {
	bool	can_set_rfmon;	/* true if can be put into monitor mode */
	GList		*data_link_types;	/* GList of data_link_info_t's */
	GList		*data_link_types_rfmon; /* GList of data_link_info_t's */
	GList		*timestamp_types;   /* GList of timestamp_info_t's */
	int status;
	char *primary_msg;   /* If non-NULL, the query failed, and a message explaining why */
	const char *secondary_msg; /* An optional supplementary message */
} if_capabilities_t;

/*
 * The list of interfaces returned by "get_interface_list()" is
 * a list of these structures.
 */
typedef struct {
	char	*name;          /* e.g. "eth0" */
	char	*friendly_name; /* from OS, e.g. "Local Area Connection", or
				   NULL if not available */
	char	*vendor_description;
				/* vendor description from pcap_findalldevs()
				   on Windows, e.g. "Realtek PCIe GBE Family Controller",
				   or NULL if not available */
	GSList  *addrs;         /* containing address values of if_addr_t */
	interface_type type;    /* type of interface */
	bool loopback;      /* true if loopback, false otherwise */
	char	*extcap;		/* extcap arguments, which present the data to call the extcap interface */
	if_capabilities_t *caps;
} if_info_t;

/**
 * @brief Enumeration of supported interface address types.
 *
 * Used to indicate whether an address is IPv4 or IPv6.
 */
typedef enum {
	IF_AT_IPv4, /**< IPv4 address (4 bytes). */
	IF_AT_IPv6  /**< IPv6 address (16 bytes). */
} if_address_type;

/**
 * @brief Represents an IP address in an interface address list.
 *
 * This structure holds either an IPv4 or IPv6 address, along with a type indicator.
 * It is typically used to store addresses associated with network interfaces.
 */
typedef struct {
	if_address_type ifat_type; /**< Type of address (IPv4 or IPv6). */
	union {
		uint32_t ip4_addr;     /**< IPv4 address in network byte order. */
		uint8_t ip6_addr[16];  /**< IPv6 address in network byte order. */
	} addr;
} if_addr_t;

extern GList *deserialize_interface_list(char *data, int *err, char **err_str);

/**
 * @brief Get the list of capture interfaces.
 *
 * This function retrieves the list of available capture interfaces, including local,
 * remote, and extcap interfaces. It uses dumpcap to fetch local interfaces and appends
 * remote and extcap interfaces to the list.
 *
 * @param app_name The name of the application requesting the interface list.
 * @param err Pointer to an integer that will receive an error code if an error occurs.
 * @param err_str Pointer to a string that will receive an error message if an error occurs.
 * @param update_cb Callback function to update the UI during the process.
 * @return A GList containing if_info_t structs if successful, or NULL on failure.
 */
extern GList *capture_interface_list(const char* app_name, int *err, char **err_str, void (*update_cb)(void));

/* Error values from "get_interface_list()/capture_interface_list()". */
#define	CANT_GET_INTERFACE_LIST	1	/* error getting list */
#define	DONT_HAVE_PCAP		2	/* couldn't load WinPcap/Npcap */

/**
 * @brief Free an interface list.
 *
 * @param if_list The interface list to free.
 */
void free_interface_list(GList *if_list);

/**
 * @brief Deep copy an interface list
 * @param if_list The interface list to copy.
 * @return A new GList containing copies of the interface information.
 */
GList * interface_list_copy(GList *if_list);

/**
 * @brief Get an if_info_t for a particular interface.
 * @param name The name of the interface to retrieve information for.
 * @return An allocated if_info_t structure containing information about the interface, or NULL if the interface is not found or an error occurs.
 * @note May require privilege, so should only be used by dumpcap.
 */
extern if_info_t *if_info_get(const char *name);

/**
 * @brief Free an if_info_t.
 * @param if_info The if_info_t structure to free.
 */
void if_info_free(if_info_t *if_info);

/**
 * @brief Deep copy an if_info_t.
 * @param if_info The if_info_t structure to copy.
 * @return A new if_info_t structure containing a copy of the original information.
 */
if_info_t *if_info_copy(const if_info_t *if_info);

/**
 * @brief Deep copy an if_addr_t.
 * @param if_addr The if_addr_t structure to copy.
 * @return A new if_addr_t structure containing a copy of the original information.
 */
if_addr_t *if_addr_copy(const if_addr_t *if_addr);

typedef struct {
        const char *name;
        bool monitor_mode;
        const char *auth_username;
        const char *auth_password;
} if_cap_query_t;

/*
 * Information about data link types.
 */
typedef struct {
	int	dlt;            /* e.g. DLT_EN10MB (which is 1) */
	char	*name;          /* e.g. "EN10MB" or "DLT 1" */
	char	*description;   /* descriptive name from wiretap e.g. "Ethernet", NULL if unknown */
} data_link_info_t;

/*
 * Information about timestamp types.
 */
typedef struct {
	char	*name;          /* e.g. "adapter_unsynced" */
	char	*description;   /* description from libpcap e.g. "Adapter, not synced with system time" */
} timestamp_info_t;

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern if_capabilities_t *
capture_get_if_capabilities(const char* app_name, const char *devname, bool monitor_mode,
                            const char *auth_string,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void));

/**
 * Fetch the linktype list for the specified interface from a child process.
 */
extern GHashTable *
capture_get_if_list_capabilities(const char* app_name, GList *if_cap_queries,
                            char **err_primary_msg, char **err_secondary_msg,
                            void (*update_cb)(void));

/**
 * @brief Frees the memory allocated for interface capabilities.
 *
 * @param caps Pointer to the if_capabilities_t structure to be freed.
 */
void free_if_capabilities(if_capabilities_t *caps);

#ifdef HAVE_PCAP_REMOTE
void add_interface_to_remote_list(if_info_t *if_info);

GList* append_remote_list(GList *iflist);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CAPTURE_IFINFO_H__ */
