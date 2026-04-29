/* wslua_debugger.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "init_wslua.h"
#include "wslua.h"
#include "wslua_debugger.h"
#include <glib.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/ws_assert.h>

typedef enum
{
    WSLUA_STEP_KIND_NONE = 0,
    WSLUA_STEP_KIND_IN,   /**< Next line hook anywhere (step into calls) */
    WSLUA_STEP_KIND_OVER, /**< Next line at same or outer stack depth */
    WSLUA_STEP_KIND_OUT   /**< Pause when returning to an outer frame */
} wslua_step_kind_t;

/* debugger context */
typedef struct
{
    wslua_debugger_state_t state;
    bool enabled;
    wslua_debugger_ui_update_cb_t ui_update_callback;
    lua_State *L;
    lua_State *paused_L;
    GMutex mutex;
    bool mutex_initialized;
    wslua_breakpoint_t temporary_breakpoint;
    wslua_step_kind_t step_kind;
    int step_stack_depth; /**< Frame count captured when OVER/OUT begins */
    int32_t variable_stack_level; /**< lua_getstack index for Locals/Upvalues */
    /*
     * Set only in wslua_debugger_notify_reload() to copy debugger.enabled
     * before the reload path forces enabled false and clears L. Used by
     * wslua_debugger_restore_after_reload() to turn the debugger back on after
     * cf_reload / redissect (not by wslua_debugger_init, which is suppressed
     * while this sequence runs). Cleared on consume, on renounce, or when the
     * user sets user_explicitly_disabled (uncheck) so a pending restore does
     * not fight that intent.
     */
    bool was_enabled_before_reload;
    /*
     * True between wslua_debugger_notify_reload() and
     * wslua_debugger_notify_post_reload(). While set, wslua_debugger_init()
     * returns without auto-enabling for active breakpoints, so the line hook
     * does not run inside the reload / re-dissection stack and re-enter the
     * event loop.
     */
    bool reload_in_progress;
    /*
     * Set from the UI main enable checkbox via
     * wslua_debugger_set_user_explicitly_disabled(). When true, the user has
     * left the core debugger "off" on purpose. Gates wslua_debugger_init
     * breakpoint auto-enable, wslua_debugger_may_auto_enable_for_breakpoints,
     * wslua_debugger_run_to_line, and a secondary check in
     * wslua_debugger_restore_after_reload. Not equivalent to !enabled — the
     * core can be off for other reasons (e.g. live capture) without this bit
     * being set, and it persists across operations that do not touch
     * was_enabled_before_reload.
     */
    bool user_explicitly_disabled;
} wslua_debugger_t;

static wslua_debugger_t debugger = {
    WSLUA_DEBUGGER_OFF,
    false,
    NULL,
    NULL,
    NULL,
    {0}, /* mutex */
    false,
    {NULL, 0, false}, /* temporary_breakpoint */
    WSLUA_STEP_KIND_NONE, /* step_kind */
    0,                    /* step_stack_depth */
    0,                    /* variable_stack_level */
    false,                /* was_enabled_before_reload */
    false,                /* reload_in_progress */
    false,                /* user_explicitly_disabled */
};

/* Breakpoints (in-memory, persisted by Qt side) */
static GArray *breakpoints_array = NULL;

static GHashTable *canonical_path_cache = NULL;
static GRWLock canonical_path_cache_lock;

/**
 * @brief Ensure the canonical path cache is initialized exactly once.
 */
static void ensure_canonical_path_cache_initialized(void)
{
    static size_t canonical_cache_once = 0;
    if (g_once_init_enter(&canonical_cache_once))
    {
        g_rw_lock_init(&canonical_path_cache_lock);
        canonical_path_cache =
            g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        g_once_init_leave(&canonical_cache_once, 1);
    }
}

/**
 * @brief Canonicalize a file path while caching results for reuse.
 * @param file_path Path in any user-provided form.
 * @return Pointer to cached canonical path; ownership stays with the cache.
 */
static const char *
wslua_debugger_get_cached_canonical_path(const char *file_path)
{
    if (!file_path || !*file_path)
    {
        return NULL;
    }

    ensure_canonical_path_cache_initialized();

    g_rw_lock_reader_lock(&canonical_path_cache_lock);
    const char *cached_path =
        canonical_path_cache
            ? (const char *)g_hash_table_lookup(canonical_path_cache, file_path)
            : NULL;
    if (cached_path)
    {
        g_rw_lock_reader_unlock(&canonical_path_cache_lock);
        return cached_path;
    }
    g_rw_lock_reader_unlock(&canonical_path_cache_lock);

    char *canonicalized_path = g_canonicalize_filename(file_path, NULL);
    if (!canonicalized_path)
    {
        return NULL;
    }

    g_rw_lock_writer_lock(&canonical_path_cache_lock);
    const char *existing_path =
        canonical_path_cache
            ? (const char *)g_hash_table_lookup(canonical_path_cache, file_path)
            : NULL;
    if (existing_path)
    {
        g_rw_lock_writer_unlock(&canonical_path_cache_lock);
        g_free(canonicalized_path);
        return existing_path;
    }

    char *key_copy = g_strdup(file_path);
    g_hash_table_insert(canonical_path_cache, key_copy, canonicalized_path);
    g_rw_lock_writer_unlock(&canonical_path_cache_lock);
    return canonicalized_path;
}

/**
 * @brief Return a newly allocated canonical path copy for caller ownership.
 */
static char *wslua_debugger_dup_canonical_path(const char *file_path)
{
    const char *cached_path =
        wslua_debugger_get_cached_canonical_path(file_path);
    return cached_path ? g_strdup(cached_path) : NULL;
}

/**
 * @brief Determine if a breakpoint matches a canonical path + line pair.
 */
static bool
wslua_debugger_breakpoint_matches(const wslua_breakpoint_t *breakpoint,
                                  const char *canonical_path, int64_t line)
{
    if (!breakpoint || !canonical_path)
    {
        return false;
    }
    if (breakpoint->line != line)
    {
        return false;
    }

    return g_strcmp0(breakpoint->file_path, canonical_path) == 0;
}

/* Forward declarations */
static void wslua_debug_hook(lua_State *L, lua_Debug *debug_info);
static void wslua_debugger_update_hook(void);
static int wslua_debugger_count_stack_frames(lua_State *L);
static void remove_breakpoint_at(unsigned idx);
static bool wslua_debugger_entry_is_hidden(lua_State *L);
static int64_t wslua_debugger_count_visible_table_entries(lua_State *L, int idx);
static char *wslua_debugger_describe_value(lua_State *L, int idx);
static bool wslua_debugger_push_getters(lua_State *L, int idx);
static int64_t wslua_debugger_count_userdata_getters(lua_State *L, int idx);
static bool wslua_debugger_push_pairs_iterator(lua_State *L, int idx);
static bool wslua_debugger_pairs_next(lua_State *L);
static bool wslua_debugger_userdata_has_visible_pairs(lua_State *L, int idx);

/**
 * @brief Ensure breakpoints array is initialized.
 */
static void ensure_breakpoints_initialized(void)
{
    if (!breakpoints_array)
    {
        breakpoints_array =
            g_array_new(FALSE, TRUE, sizeof(wslua_breakpoint_t));
    }
}

/**
 * @brief Free a breakpoint's allocated memory.
 */
static void free_breakpoint(wslua_breakpoint_t *bp)
{
    if (bp)
    {
        g_free(bp->file_path);
        bp->file_path = NULL;
    }
}

/**
 * @brief Remove a breakpoint at the specified index.
 */
static void remove_breakpoint_at(unsigned idx)
{
    ensure_breakpoints_initialized();

    if (idx >= breakpoints_array->len)
        return;

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    free_breakpoint(bp);
    g_array_remove_index(breakpoints_array, idx);
}

/**
 * @brief Initialize the debugger subsystem.
 * @param L The Lua state.
 */
void wslua_debugger_init(lua_State *L)
{
    debugger.L = L;
    static bool initialized = false;

    if (!debugger.mutex_initialized)
    {
        g_mutex_init(&debugger.mutex);
        debugger.mutex_initialized = true;
    }

    if (!initialized)
    {
        /* Initialize breakpoints array */
        ensure_breakpoints_initialized();

        /* Note: JSON settings are loaded by the Qt UI (lua_debugger_dialog.cpp)
         * when the dialog is first opened. The C side only maintains in-memory
         * state. */

        initialized = true;
    }

    /*
     * During a reload, do NOT auto-enable the debugger here.
     * The hook would fire inside cf_reload → cf_read → dissectIdle,
     * potentially entering a nested event loop while deep in the
     * reload call stack.  The callers will call
     * wslua_debugger_notify_post_reload() after cf_reload completes.
     */
    if (debugger.reload_in_progress)
    {
        /* Don't auto-enable: the hook would fire during
         * cf_reload / redissect and re-enter the event loop.
         * wslua_debugger_restore_after_reload() handles this. */
        return;
    }

    /* Check if we should auto-enable based on active breakpoints */
    bool has_active = false;
    ensure_breakpoints_initialized();
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (bp->active)
        {
            has_active = true;
            break;
        }
    }
    g_mutex_unlock(&debugger.mutex);

    bool user_wants_debugger_off = false;
    g_mutex_lock(&debugger.mutex);
    user_wants_debugger_off = debugger.user_explicitly_disabled;
    g_mutex_unlock(&debugger.mutex);

    if (has_active && !user_wants_debugger_off)
    {
        wslua_debugger_set_enabled(true);
    }
    else
    {
        /* Ensure hook is updated for new L */
        wslua_debugger_update_hook();
    }
}

/**
 * @brief Check if debugger is enabled.
 * @return true if enabled, false otherwise.
 */
bool wslua_debugger_is_enabled(void)
{
    g_mutex_lock(&debugger.mutex);
    bool enabled = debugger.enabled;
    g_mutex_unlock(&debugger.mutex);
    return enabled;
}

/**
 * @brief Update the Lua debug hook based on state.
 */
static void wslua_debugger_update_hook(void)
{
    if (!debugger.L)
        return;

    bool should_hook = false;
    g_mutex_lock(&debugger.mutex);
    if (debugger.enabled)
    {
        if (breakpoints_array)
        {
            for (unsigned i = 0; i < breakpoints_array->len; i++)
            {
                wslua_breakpoint_t *bp =
                    &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
                if (bp->active)
                {
                    should_hook = true;
                    break;
                }
            }
        }

        if (!should_hook && debugger.temporary_breakpoint.active)
        {
            should_hook = true;
        }

        if (!should_hook && debugger.step_kind != WSLUA_STEP_KIND_NONE)
        {
            should_hook = true;
        }
    }
    g_mutex_unlock(&debugger.mutex);

    if (should_hook)
    {
        lua_sethook(debugger.L, wslua_debug_hook, LUA_MASKLINE, 0);
    }
    else
    {
        lua_sethook(debugger.L, NULL, 0, 0);
    }
}

/**
 * @brief Set the enabled state of the debugger.
 * @param enabled true to enable, false to disable.
 */
void wslua_debugger_set_enabled(bool enabled)
{
    g_mutex_lock(&debugger.mutex);
    if (!enabled && debugger.state == WSLUA_DEBUGGER_PAUSED)
    {
        g_mutex_unlock(&debugger.mutex);
        wslua_debugger_continue();
        g_mutex_lock(&debugger.mutex);
    }
    debugger.enabled = enabled;
    if (enabled)
    {
        debugger.state = WSLUA_DEBUGGER_RUNNING;
    }
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

void wslua_debugger_set_user_explicitly_disabled(
    bool user_wants_debugger_stay_off)
{
    g_mutex_lock(&debugger.mutex);
    debugger.user_explicitly_disabled = user_wants_debugger_stay_off;
    if (user_wants_debugger_stay_off)
    {
        debugger.was_enabled_before_reload = false;
    }
    g_mutex_unlock(&debugger.mutex);
}

bool wslua_debugger_may_auto_enable_for_breakpoints(void)
{
    g_mutex_lock(&debugger.mutex);
    const bool may = !debugger.user_explicitly_disabled;
    g_mutex_unlock(&debugger.mutex);
    return may;
}

void wslua_debugger_renounce_restore_after_reload(void)
{
    g_mutex_lock(&debugger.mutex);
    debugger.was_enabled_before_reload = false;
    g_mutex_unlock(&debugger.mutex);
}

/**
 * @brief Register the UI callback.
 * @param cb The callback function.
 */
void wslua_debugger_register_ui_callback(wslua_debugger_ui_update_cb_t cb)
{
    debugger.ui_update_callback = cb;
}

/**
 * @brief Continue execution.
 */
void wslua_debugger_continue(void)
{
    g_mutex_lock(&debugger.mutex);
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    debugger.step_kind = WSLUA_STEP_KIND_NONE;
    /* Clear temp breakpoint */
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
        debugger.temporary_breakpoint.file_path = NULL;
    }
    debugger.temporary_breakpoint.active = false;
    debugger.paused_L = NULL;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Run to a specific line.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_run_to_line(const char *file_path, int64_t line)
{
    char *canonical_copy = wslua_debugger_dup_canonical_path(file_path);
    if (!canonical_copy)
    {
        return;
    }
    g_mutex_lock(&debugger.mutex);
    if (debugger.user_explicitly_disabled)
    {
        g_mutex_unlock(&debugger.mutex);
        g_free(canonical_copy);
        return;
    }
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
    }
    debugger.temporary_breakpoint.file_path = canonical_copy;
    debugger.temporary_breakpoint.line = line;
    debugger.temporary_breakpoint.active = true;

    debugger.step_kind = WSLUA_STEP_KIND_NONE;
    debugger.paused_L = NULL;
    debugger.enabled = true;
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Count Lua stack frames (0 = innermost).
 */
static int
wslua_debugger_count_stack_frames(lua_State *L)
{
    lua_Debug ar;
    int level = 0;

    while (lua_getstack(L, level, &ar))
    {
        level++;
    }
    return level;
}

/**
 * @brief Shared setup when resuming from a paused state into a step mode.
 */
static void
wslua_debugger_begin_step(wslua_step_kind_t kind, int stack_depth_for_over_out)
{
    g_mutex_lock(&debugger.mutex);
    /* Clear temp breakpoint since we're stepping */
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
        debugger.temporary_breakpoint.file_path = NULL;
    }
    debugger.temporary_breakpoint.active = false;
    debugger.paused_L = NULL;

    debugger.step_kind = kind;
    if (kind == WSLUA_STEP_KIND_OVER || kind == WSLUA_STEP_KIND_OUT)
    {
        debugger.step_stack_depth = stack_depth_for_over_out;
    }
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

void wslua_debugger_step_in(void)
{
    wslua_debugger_begin_step(WSLUA_STEP_KIND_IN, 0);
}

void wslua_debugger_step_over(void)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        return;
    }
    const int depth = wslua_debugger_count_stack_frames(target_L);
    wslua_debugger_begin_step(WSLUA_STEP_KIND_OVER, depth);
}

void wslua_debugger_step_out(void)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        return;
    }
    const int depth = wslua_debugger_count_stack_frames(target_L);
    /*
     * Only one Lua frame: "step out" of the chunk is ordinary continuation —
     * there will be no further line hooks in this activation.
     */
    if (depth <= 1)
    {
        wslua_debugger_continue();
        return;
    }
    wslua_debugger_begin_step(WSLUA_STEP_KIND_OUT, depth);
}

void wslua_debugger_set_variable_stack_level(int32_t level)
{
    g_mutex_lock(&debugger.mutex);
    debugger.variable_stack_level = level < 0 ? 0 : level;
    g_mutex_unlock(&debugger.mutex);
}

int32_t wslua_debugger_get_variable_stack_level(void)
{
    g_mutex_lock(&debugger.mutex);
    const int32_t level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);
    return level;
}

/**
 * @brief Add a breakpoint.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_add_breakpoint(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    /* Check if exists */
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            return; /* Already exists */
        }
    }

    wslua_breakpoint_t breakpoint;
    breakpoint.file_path = g_strdup(norm_file_path);
    breakpoint.line = line;
    breakpoint.active = true;

    g_array_append_val(breakpoints_array, breakpoint);
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
    wslua_debugger_update_hook();
}

/**
 * @brief Remove a breakpoint.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_remove_breakpoint(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    bool removed = false;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            remove_breakpoint_at(i);
            removed = true;
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            if (removed)
            {
                wslua_debugger_update_hook();
            }
            return;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * @brief Set breakpoint active state.
 * @param file_path The file path.
 * @param line The line number.
 * @param active The new state.
 */
void wslua_debugger_set_breakpoint_active(const char *file_path, int64_t line,
                                          bool active)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            if (bp->active == active)
            {
                g_mutex_unlock(&debugger.mutex);
                g_free(norm_file_path);
                return;
            }
            bp->active = active;
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            /* Toggling a breakpoint's active state must never change the
             * debugger's enabled flag (especially during a live capture,
             * where debugging is suppressed entirely). Just re-arm the
             * Lua line hook so the change takes effect on the next tick. */
            wslua_debugger_update_hook();
            return;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * @brief Clear all breakpoints.
 */
void wslua_debugger_clear_breakpoints(void)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    /* Free all breakpoint data */
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        free_breakpoint(bp);
    }
    g_array_set_size(breakpoints_array, 0);
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Internal: check breakpoint state using an already-canonical path.
 */
static int32_t
get_breakpoint_state_for_canonical(const char *canonical_path, int64_t line)
{
    if (!canonical_path)
    {
        return -1;
    }

    ensure_breakpoints_initialized();

    int32_t result = -1;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, canonical_path, line))
        {
            result = bp->active ? 1 : 0;
            break;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    return result;
}

int32_t wslua_debugger_get_breakpoint_state(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return -1;
    }
    const int32_t result =
        get_breakpoint_state_for_canonical(norm_file_path, line);
    g_free(norm_file_path);
    return result;
}

int32_t wslua_debugger_get_breakpoint_state_canonical(const char *canonical_path,
                                                      int64_t line)
{
    return get_breakpoint_state_for_canonical(canonical_path, line);
}

char *wslua_debugger_canonical_path(const char *file_path)
{
    return wslua_debugger_dup_canonical_path(file_path);
}

/**
 * @brief The Lua debug hook.
 * @param L The Lua state.
 * @param debug_info The debug info.
 */
static void wslua_debug_hook(lua_State *L, lua_Debug *debug_info)
{
    g_mutex_lock(&debugger.mutex);
    bool hook_active = debugger.enabled;
    g_mutex_unlock(&debugger.mutex);
    if (!hook_active)
        return;

    /* Get info */
    if (lua_getinfo(L, "Sl", debug_info) == 0)
        return;

    /* Check if we are in a C function */
    if (debug_info->currentline < 0)
        return;

    const char *source = debug_info->source;
    if (source && source[0] == '@')
    {
        source++; /* Skip '@' */
    }
    else
    {
        /* Not a file */
        return;
    }

    const char *norm_source = wslua_debugger_get_cached_canonical_path(source);
    if (!norm_source)
    {
        return;
    }

    bool hit = false;

    /* Single-step modes (step in / over / out) */
    wslua_step_kind_t step_kind;
    int step_stack_depth_snapshot;
    g_mutex_lock(&debugger.mutex);
    step_kind = debugger.step_kind;
    step_stack_depth_snapshot = debugger.step_stack_depth;
    g_mutex_unlock(&debugger.mutex);

    if (step_kind != WSLUA_STEP_KIND_NONE)
    {
        bool step_done = false;
        switch (step_kind)
        {
        case WSLUA_STEP_KIND_IN:
            step_done = true;
            break;
        case WSLUA_STEP_KIND_OVER: {
            const int d = wslua_debugger_count_stack_frames(L);
            if (d <= step_stack_depth_snapshot)
            {
                step_done = true;
            }
            break;
        }
        case WSLUA_STEP_KIND_OUT: {
            const int d = wslua_debugger_count_stack_frames(L);
            if (d < step_stack_depth_snapshot)
            {
                step_done = true;
            }
            break;
        }
        default:
            break;
        }
        if (step_done)
        {
            hit = true;
            g_mutex_lock(&debugger.mutex);
            debugger.step_kind = WSLUA_STEP_KIND_NONE;
            g_mutex_unlock(&debugger.mutex);
        }
    }

    /* Check regular breakpoints */
    if (!hit)
    {
        g_mutex_lock(&debugger.mutex);
        if (breakpoints_array)
        {
            for (unsigned i = 0; i < breakpoints_array->len; i++)
            {
                wslua_breakpoint_t *bp =
                    &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
                if (bp->active &&
                    wslua_debugger_breakpoint_matches(
                        bp, norm_source, (int64_t)debug_info->currentline))
                {
                    hit = true;
                    break;
                }
            }
        }
        g_mutex_unlock(&debugger.mutex);
    }

    /* Check temp breakpoint */
    if (!hit)
    {
        g_mutex_lock(&debugger.mutex);
        if (debugger.temporary_breakpoint.active &&
            wslua_debugger_breakpoint_matches(&debugger.temporary_breakpoint,
                                              norm_source,
                                              (int64_t)debug_info->currentline))
        {
            hit = true;
            /* Temp breakpoint is one-shot */
            debugger.temporary_breakpoint.active = false;
        }
        g_mutex_unlock(&debugger.mutex);
    }

    if (hit)
    {
        g_mutex_lock(&debugger.mutex);
        debugger.state = WSLUA_DEBUGGER_PAUSED;
        debugger.paused_L = L;
        g_mutex_unlock(&debugger.mutex);

        if (debugger.ui_update_callback)
        {
            /*
             * Disable the hook while paused.
             *
             * The UI callback runs a nested Qt event loop and may trigger
             * additional Lua activity. Keeping the line hook installed during
             * that time can lead to re-entrancy and crashes.
             */
            lua_sethook(L, NULL, 0, 0);
            debugger.ui_update_callback(source,
                                        (int64_t)debug_info->currentline);
        }

        /*
         * After the UI callback returns (nested event loop exited),
         * execution resumes normally. If a reload was requested while
         * we were paused, the reload was deferred — the UI quit the
         * event loop and scheduled a delayed reload. The hook simply
         * returns here, allowing the Lua script to finish its current
         * execution naturally. The deferred reload will run once the
         * Lua call stack has fully unwound.
         */

        /*
         * Re-install the hook on this thread (L) so that stepping
         * and breakpoints can fire on subsequent lines within the
         * same dissector call.  The hook was disabled on L above to
         * prevent re-entrancy during the nested event loop; now that
         * the event loop has exited we need it back.  Note: L may be
         * a coroutine thread created by lua_newthread(), which is
         * distinct from debugger.L (the main state).
         */
        g_mutex_lock(&debugger.mutex);
        bool reinstall_hook = debugger.enabled;
        g_mutex_unlock(&debugger.mutex);
        if (reinstall_hook)
        {
            lua_sethook(L, wslua_debug_hook, LUA_MASKLINE, 0);
        }
    }
}

/**
 * @brief Get stack trace.
 * @param frame_count Output pointer for frame count.
 * @return Array of stack frames.
 */
wslua_stack_frame_t *wslua_debugger_get_stack(int32_t *frame_count)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        *frame_count = 0;
        return NULL;
    }

    lua_Debug debug_info;
    int32_t level = 0;
    GArray *stack_array =
        g_array_new(false, false, sizeof(wslua_stack_frame_t));

    while (lua_getstack(target_L, level, &debug_info))
    {
        lua_getinfo(target_L, "nSl", &debug_info);
        wslua_stack_frame_t frame;
        frame.source = g_strdup(debug_info.source ? debug_info.source : "?");
        frame.line = (int64_t)debug_info.currentline;
        frame.linedefined = (int64_t)debug_info.linedefined;
        frame.name = g_strdup(debug_info.name ? debug_info.name : "?");
        g_array_append_val(stack_array, frame);
        level++;
    }

    *frame_count = level;
    return (wslua_stack_frame_t *)g_array_free(stack_array, false);
}

/**
 * @brief Free stack trace.
 * @param stack The stack array.
 * @param frame_count The number of frames.
 */
void wslua_debugger_free_stack(wslua_stack_frame_t *stack, int32_t frame_count)
{
    for (int32_t frame_index = 0; frame_index < frame_count; frame_index++)
    {
        g_free(stack[frame_index].source);
        g_free(stack[frame_index].name);
    }
    g_free(stack);
}

/**
 * @brief Fill @a ar for lua_getlocal / lua_getinfo for stack frame @a level.
 */
static bool
wslua_debugger_fill_activation(lua_State *L, int32_t level, lua_Debug *ar)
{
    return lua_getstack(L, level, ar);
}

/**
 * @brief After @a ar describes an activation, push the running closure so
 *        lua_getupvalue can enumerate upvalues (Lua debug library pattern).
 */
static bool wslua_debugger_push_function_for_ar(lua_State *L, lua_Debug *ar)
{
    const int base = lua_gettop(L);
    if (!lua_getinfo(L, "f", ar))
    {
        lua_settop(L, base);
        return false;
    }
    if (!lua_isfunction(L, -1))
    {
        lua_settop(L, base);
        return false;
    }
    return true;
}

/**
 * @brief Index the value at the stack top by a string key.
 *
 * Consumes the parent from the stack and pushes the resulting value on
 * success (returns true). Supports regular tables (via lua_getfield),
 * wslua userdata with attribute getters (via __getters), and any value
 * exposing the standard Lua __pairs protocol as a last resort. Returns
 * false with the parent popped if traversal fails.
 */
static bool wslua_debugger_index_by_string(lua_State *L, const char *key)
{
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, key);
        lua_remove(L, -2);
        return true;
    }
    if (lua_isuserdata(L, -1))
    {
        const int userdata_abs = lua_gettop(L);
        /* A class registered via WSLUA_REGISTER_META always ends up with
         * a __getters field on its metatable (wslua_register_classinstance_meta
         * installs one unconditionally when introspection is enabled), even
         * when the class declares no attributes. Only take the getter branch
         * when the table actually contains a visible getter so classes like
         * Prefs fall through to the __pairs fallback instead of being
         * silently swallowed by an empty getters table. */
        if (wslua_debugger_count_userdata_getters(L, userdata_abs) > 0 &&
            wslua_debugger_push_getters(L, userdata_abs))
        {
            /* Stack: ..., userdata, __getters */
            lua_pushstring(L, key);
            lua_rawget(L, -2);
            /* Stack: ..., userdata, __getters, getter_or_nil */
            if (!lua_iscfunction(L, -1))
            {
                lua_pop(L, 3); /* getter_or_nil, __getters, userdata */
                return false;
            }
            lua_pushvalue(L, userdata_abs); /* self */
            /* Stack: ..., userdata, __getters, getter, userdata */
            if (lua_pcall(L, 1, 1, 0) != 0)
            {
                lua_pop(L, 3); /* error, __getters, userdata */
                return false;
            }
            /* Stack: ..., userdata, __getters, result */
            lua_remove(L, -2); /* __getters */
            lua_remove(L, -2); /* userdata */
            return true;
        }
        if (wslua_debugger_push_pairs_iterator(L, userdata_abs))
        {
            /* Stack: ..., userdata, iter, state, initial_key.
             * Walk the iterator linearly until the requested key is
             * found. The iterator contract matches the enumeration
             * used when the userdata is expanded, so paths built from
             * expansion round-trip reliably. */
            while (wslua_debugger_pairs_next(L))
            {
                /* Stack: ..., userdata, iter, state, key, value */
                if (lua_type(L, -2) == LUA_TSTRING &&
                    g_strcmp0(lua_tostring(L, -2), key) == 0)
                {
                    /* Match: reduce stack to just the value. */
                    lua_remove(L, -2); /* key */
                    lua_remove(L, -2); /* state */
                    lua_remove(L, -2); /* iter */
                    lua_remove(L, -2); /* userdata */
                    return true;
                }
                lua_pop(L, 1); /* value; pairs_next keeps the key */
            }
            /* pairs_next cleaned up the iterator triple on exhaustion. */
            lua_pop(L, 1); /* userdata */
            return false;
        }
        lua_pop(L, 1); /* userdata */
        return false;
    }
    lua_pop(L, 1);
    return false;
}

/**
 * Resolve a global-like name: try the registry global table first, then the
 * current stack frame's _ENV upvalue (Lua 5.2+). Wireshark loads scripts with
 * a file environment that stores top-level bindings in _ENV while
 * lua_getglobal() only sees raw _G, so Globals.foo paths must fall back to
 * _ENV to match what Lua code actually resolves.
 * On success leaves one value on the stack; on failure leaves the stack clean.
 */
static bool
wslua_debugger_get_global_or_env_field(lua_State *L, int32_t stack_level,
                                       const char *name)
{
    if (!name || !*name)
    {
        return false;
    }

    lua_getglobal(L, name);
    if (!lua_isnil(L, -1))
    {
        return true;
    }
    lua_pop(L, 1);

#if LUA_VERSION_NUM >= 502
    {
        lua_Debug ar;
        if (!wslua_debugger_fill_activation(L, stack_level, &ar))
        {
            return false;
        }
        if (!wslua_debugger_push_function_for_ar(L, &ar))
        {
            return false;
        }
        int uv = 1;
        const char *nm;
        while ((nm = lua_getupvalue(L, -1, uv++)))
        {
            if (g_strcmp0(nm, "_ENV") == 0)
            {
                lua_remove(L, -2); /* function */
                lua_getfield(L, -1, name);
                lua_remove(L, -2); /* _ENV table */
                if (!lua_isnil(L, -1))
                {
                    return true;
                }
                lua_pop(L, 1);
                return false;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1); /* function */
    }
#endif
    return false;
}

/** How to resolve the first path segment (after optional Locals./Upvalues./Globals. strip). */
typedef enum
{
    /** Locals, then upvalues, then globals (unqualified / bare watch specs). */
    WSLUA_LOOKUP_FIRST_AUTO = 0,
    /** Path was written as Locals.… — first name is a local only. */
    WSLUA_LOOKUP_FIRST_LOCAL_ONLY = 1,
    /** Path was written as Upvalues.… */
    WSLUA_LOOKUP_FIRST_UPVALUE_ONLY = 2,
    /** Path was written as Globals.… — first name is _G[name] only. */
    WSLUA_LOOKUP_FIRST_GLOBAL_ONLY = 3,
} wslua_lookup_first_kind_t;

/* Forward declaration — defined with the path-grammar scanners below. */
static bool wslua_debugger_spec_scan_bracket_key(const char **pp, lua_State *L);

/**
 * @brief Lookup a variable path in Lua state.
 * @param L The Lua state.
 * @param path The path to lookup (e.g. "a.b"), without Locals./Upvalues./Globals. prefix.
 * @param first_kind Where the first segment must be resolved (AUTO = legacy order).
 * @return true if found (value on stack), false otherwise.
 */
static bool wslua_debugger_lookup_path(lua_State *L, const char *path,
                                       int32_t stack_level,
                                       wslua_lookup_first_kind_t first_kind)
{
    if (!path || !*path)
        return false;

    /* Parse first component */
    const char *path_ptr = path;
    const char *end_ptr = path_ptr;
    while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
        end_ptr++;

    char *first_component = g_strndup(path_ptr, end_ptr - path_ptr);
    path_ptr = end_ptr;

    if (first_kind == WSLUA_LOOKUP_FIRST_GLOBAL_ONLY)
    {
        if (!wslua_debugger_get_global_or_env_field(L, stack_level,
                                                    first_component))
        {
            g_free(first_component);
            return false;
        }
        g_free(first_component);
        goto traverse_rest;
    }

    lua_Debug debug_info;
    if (!wslua_debugger_fill_activation(L, stack_level, &debug_info))
    {
        g_free(first_component);
        return false;
    }

    if (first_kind == WSLUA_LOOKUP_FIRST_LOCAL_ONLY)
    {
        int32_t local_index = 1;
        const char *name;
        bool found = false;
        while ((name = lua_getlocal(L, &debug_info, local_index++)))
        {
            if (g_strcmp0(name, first_component) == 0)
            {
                found = true;
                break;
            }
            lua_pop(L, 1);
        }
        g_free(first_component);
        if (!found)
        {
            return false;
        }
        goto traverse_rest;
    }

    if (first_kind == WSLUA_LOOKUP_FIRST_UPVALUE_ONLY)
    {
        bool found = false;
        if (wslua_debugger_push_function_for_ar(L, &debug_info))
        {
            int32_t uv = 1;
            const char *nm;
            while ((nm = lua_getupvalue(L, -1, uv++)))
            {
                if (g_strcmp0(nm, first_component) == 0)
                {
                    found = true;
                    lua_remove(L, -2); /* function */
                    break;
                }
                lua_pop(L, 1);
            }
            if (!found)
            {
                lua_pop(L, 1); /* function */
            }
        }
        g_free(first_component);
        if (!found)
        {
            return false;
        }
        goto traverse_rest;
    }

    /* WSLUA_LOOKUP_FIRST_AUTO — locals, then upvalues, then globals */
    {
        int32_t local_index = 1;
        const char *name;
        bool found = false;
        while ((name = lua_getlocal(L, &debug_info, local_index++)))
        {
            if (g_strcmp0(name, first_component) == 0)
            {
                found = true;
                break;
            }
            lua_pop(L, 1);
        }

        if (!found)
        {
            /* Look in upvalues */
            if (wslua_debugger_push_function_for_ar(L, &debug_info))
            {
                local_index = 1;
                while ((name = lua_getupvalue(L, -1, local_index++)))
                {
                    if (g_strcmp0(name, first_component) == 0)
                    {
                        found = true;
                        lua_remove(L, -2); /* Remove function */
                        break;
                    }
                    lua_pop(L, 1);
                }
                if (!found)
                    lua_pop(L, 1); /* Remove function */
            }

            if (!found)
            {
                /* Globals (raw _G) or chunk _ENV (Wireshark file sandbox). */
                if (!wslua_debugger_get_global_or_env_field(L, stack_level,
                                                            first_component))
                {
                    g_free(first_component);
                    return false;
                }
            }
        }
        g_free(first_component);
    }

traverse_rest:
    /* Traverse rest */
    while (*path_ptr)
    {
        if (*path_ptr == '.')
        {
            path_ptr++;
            end_ptr = path_ptr;
            while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
                end_ptr++;
            char *key = g_strndup(path_ptr, end_ptr - path_ptr);
            const bool ok = wslua_debugger_index_by_string(L, key);
            g_free(key);
            if (!ok)
            {
                return false;
            }
            path_ptr = end_ptr;
        }
        else if (*path_ptr == '[')
        {
            path_ptr++;
            const bool is_table = lua_istable(L, -1);
            const bool is_userdata = !is_table && lua_isuserdata(L, -1);
            if (!is_table && !is_userdata)
            {
                lua_pop(L, 1);
                return false;
            }

            /* Decode the bracket key and push it on the stack (above the
             * parent). */
            if (!wslua_debugger_spec_scan_bracket_key(&path_ptr, L))
            {
                lua_pop(L, 1); /* parent */
                return false;
            }

            if (is_table)
            {
                /* stack: parent, key → parent[key] */
                lua_gettable(L, -2);
                lua_remove(L, -2); /* parent */
            }
            else
            {
                /* Userdata indexing only makes sense with a string key. */
                if (lua_type(L, -1) != LUA_TSTRING)
                {
                    lua_pop(L, 2); /* key + parent */
                    return false;
                }
                size_t key_len = 0;
                const char *key_lua = lua_tolstring(L, -1, &key_len);
                char *key_copy = g_strndup(key_lua, key_len);
                lua_pop(L, 1); /* key */
                const bool ok =
                    wslua_debugger_index_by_string(L, key_copy);
                g_free(key_copy);
                if (!ok)
                {
                    return false;
                }
            }
        }
        else
        {
            break;
        }
    }

    return true;
}

static int wslua_debugger_abs_index(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 502
    return lua_absindex(L, idx);
#else
    if (idx > 0 || idx <= LUA_REGISTRYINDEX)
    {
        return idx;
    }
    return lua_gettop(L) + idx + 1;
#endif
}

/**
 * @brief Basic (non-recursive) entry filter for the Variables view.
 *
 * Hides function/method entries and the wslua __typeof marker that
 * wslua_register_class stores on class tables. Operates on the
 * (key, value) pair at stack positions (-2, -1).
 */
static bool wslua_debugger_basic_entry_is_hidden(lua_State *L)
{
    if (lua_type(L, -1) == LUA_TFUNCTION)
    {
        return true;
    }
    if (lua_type(L, -2) == LUA_TSTRING)
    {
        const char *key = lua_tostring(L, -2);
        if (g_strcmp0(key, WSLUA_TYPEOF_FIELD) == 0)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Count raw and visible entries of a table in a single pass.
 *
 * "Visible" uses the basic (non-recursive) filter so the cost stays O(n)
 * and deep nesting does not blow up.
 */
static void wslua_debugger_basic_table_counts(lua_State *L, int idx,
                                              int64_t *total,
                                              int64_t *visible)
{
    const int tableIndex = wslua_debugger_abs_index(L, idx);
    int64_t total_count = 0;
    int64_t visible_count = 0;
    lua_pushnil(L);
    while (lua_next(L, tableIndex) != 0)
    {
        ++total_count;
        if (!wslua_debugger_basic_entry_is_hidden(L))
        {
            ++visible_count;
        }
        lua_pop(L, 1);
    }
    if (total)
    {
        *total = total_count;
    }
    if (visible)
    {
        *visible = visible_count;
    }
}

/**
 * @brief Returns true if the (key, value) pair at stack positions
 *        (-2, -1) should be hidden from the Variables view.
 *
 * Extends the basic filter by also hiding "namespace" tables whose
 * contents are entirely functions/methods or wslua internals (for
 * example Lua stdlib tables like @c string / @c table and wslua class
 * tables such as @c Proto). An empty user-defined table is preserved
 * because the raw count distinguishes it from a collapsed namespace.
 */
static bool wslua_debugger_entry_is_hidden(lua_State *L)
{
    if (wslua_debugger_basic_entry_is_hidden(L))
    {
        return true;
    }
    if (lua_type(L, -1) == LUA_TTABLE)
    {
        int64_t total = 0;
        int64_t visible = 0;
        wslua_debugger_basic_table_counts(L, -1, &total, &visible);
        if (total > 0 && visible == 0)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Count only visible entries in a table (skipping functions,
 *        wslua internals, and namespace tables that collapse to empty).
 *
 * The Variables view filters out functions and methods, so the displayed
 * size and expandability should reflect the visible entries rather than
 * the raw table length.
 */
static int64_t wslua_debugger_count_visible_table_entries(lua_State *L, int idx)
{
    const int tableIndex = wslua_debugger_abs_index(L, idx);
    int64_t count = 0;
    lua_pushnil(L);
    while (lua_next(L, tableIndex) != 0)
    {
        if (!wslua_debugger_entry_is_hidden(L))
        {
            ++count;
        }
        lua_pop(L, 1);
    }
    return count;
}

/**
 * @brief Push the wslua __getters table for a userdata value onto the stack.
 *
 * Returns true with the __getters table at the top of the stack (the stack
 * otherwise unchanged). Returns false with the stack unchanged when the
 * value at @a idx is not a wslua userdata or has no getters table.
 */
static bool wslua_debugger_push_getters(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (lua_type(L, absIndex) != LUA_TUSERDATA)
    {
        return false;
    }
    if (!lua_getmetatable(L, absIndex))
    {
        return false;
    }
    lua_pushstring(L, "__getters");
    lua_rawget(L, -2);
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 2);
        return false;
    }
    lua_remove(L, -2); /* Drop metatable, leave __getters on top */
    return true;
}

/**
 * @brief Push the Lua __pairs iterator triple for the value at @a idx.
 *
 * On success leaves [iterator, state, initial_key] on the stack (three
 * extra items) and returns true. On failure the stack is unchanged.
 *
 * The iterator is driven by @ref wslua_debugger_pairs_next, which wraps
 * the standard Lua generic-for protocol so the debugger can enumerate
 * any value that opts in via a __pairs metamethod — independently of
 * whether it is a wslua userdata with attribute getters.
 */
static bool wslua_debugger_push_pairs_iterator(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (!luaL_getmetafield(L, absIndex, "__pairs"))
    {
        return false;
    }
    /* Stack: ..., __pairs */
    lua_pushvalue(L, absIndex);
    if (lua_pcall(L, 1, 3, 0) != 0)
    {
        lua_pop(L, 1); /* error */
        return false;
    }
    /* Stack: ..., iterator, state, initial_key */
    return true;
}

/**
 * @brief Drive a __pairs iterator by one step.
 *
 * The top of the stack must hold [iterator, state, last_key] when called.
 * On success the stack holds [iterator, state, new_key, value] and the
 * function returns true. On exhaustion or error the three iterator slots
 * are popped and the function returns false.
 */
static bool wslua_debugger_pairs_next(lua_State *L)
{
    lua_pushvalue(L, -3); /* iterator */
    lua_pushvalue(L, -3); /* state */
    lua_pushvalue(L, -3); /* last key */
    if (lua_pcall(L, 2, 2, 0) != 0)
    {
        lua_pop(L, 1); /* error */
        lua_pop(L, 3); /* iterator, state, last key */
        return false;
    }
    /* Stack: ..., iterator, state, last_key, new_key, value */
    if (lua_isnil(L, -2))
    {
        lua_pop(L, 2); /* new_key (nil), value */
        lua_pop(L, 3); /* iterator, state, last key */
        return false;
    }
    /* Drop the previous key so the caller sees [iter, state, key, value]. */
    lua_remove(L, -3);
    return true;
}

/**
 * @brief Whether a userdata has at least one non-function entry when
 *        iterated via __pairs.
 *
 * Used as a cheap "is it worth offering an expand arrow" check when the
 * value does not expose wslua-style attribute getters. Short-circuits as
 * soon as a displayable entry is found so the cost stays bounded even
 * for large collections.
 */
static bool wslua_debugger_userdata_has_visible_pairs(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (!wslua_debugger_push_pairs_iterator(L, absIndex))
    {
        return false;
    }
    /* Stack: ..., iterator, state, initial_key */
    bool found = false;
    while (wslua_debugger_pairs_next(L))
    {
        /* Stack: ..., iterator, state, key, value */
        if (lua_type(L, -1) != LUA_TFUNCTION)
        {
            found = true;
            lua_pop(L, 2); /* value, key */
            lua_pop(L, 2); /* iterator, state */
            return found;
        }
        lua_pop(L, 1); /* value; pairs_next keeps new key for next step */
    }
    /* pairs_next cleaned up the iterator triple on exhaustion. */
    return found;
}

/**
 * @brief Count userdata attribute getters that are safe to display.
 *
 * Skips the sentinel __typeof entry and anything that is not a C function.
 */
static int64_t wslua_debugger_count_userdata_getters(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (!wslua_debugger_push_getters(L, absIndex))
    {
        return 0;
    }
    int64_t count = 0;
    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        if (lua_type(L, -2) == LUA_TSTRING && lua_iscfunction(L, -1))
        {
            const char *key = lua_tostring(L, -2);
            if (g_strcmp0(key, WSLUA_TYPEOF_FIELD) != 0)
            {
                ++count;
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1); /* __getters */
    return count;
}

/*
 * Cap preview strings at a modest length so one oversized leaf cannot
 * freeze the Variables view. Tvb's __tostring dumps the full packet as
 * hex; a 1500-byte frame becomes a ~4500 character preview. The raw,
 * untruncated value is reachable via
 * @ref wslua_debugger_read_variable_value_full (used by "Copy value"
 * in the Watch panel) and via the Evaluate pane.
 */
#define WSLUA_DEBUGGER_PREVIEW_MAX_BYTES 256

/*
 * Stringify the Lua value at @p idx. When @p truncate is true the result
 * is capped at WSLUA_DEBUGGER_PREVIEW_MAX_BYTES for display surfaces
 * (Variables tree, watch root/child preview). When false the full
 * luaL_tolstring output is returned so callers such as "Copy value" can
 * deliver the complete text to the clipboard.
 */
static char *wslua_debugger_describe_value_ex(lua_State *L, int idx,
                                              bool truncate)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    const int valueType = lua_type(L, absIndex);
    if (valueType == LUA_TFUNCTION)
    {
        /*
         * Functions are filtered out of the Variables view; the empty
         * string is kept for defensive callers that still reach here.
         *
         * Note: some userdata classes deliberately return "" from
         * __tostring when no meaningful text is available (for example
         * Column when pinfo->cinfo is NULL during details-pane
         * dissection — see wslua_column.c). An empty preview therefore
         * is not necessarily a bug in describe_value; check the class's
         * __tostring before assuming the debugger is dropping data.
         */
        return g_strdup("");
    }
    if (valueType == LUA_TTABLE)
    {
        const int64_t entryCount =
            wslua_debugger_count_visible_table_entries(L, absIndex);
        return g_strdup_printf("table[%" PRId64 "]", entryCount);
    }
    size_t length = 0;
    const char *stringValue = luaL_tolstring(L, absIndex, &length);
    char *result;
    if (truncate && stringValue && length > WSLUA_DEBUGGER_PREVIEW_MAX_BYTES)
    {
        /* Use an ASCII ellipsis ("...") to avoid UTF-8 truncation concerns
         * when the raw preview is binary. */
        result = g_strdup_printf("%.*s...",
                                 WSLUA_DEBUGGER_PREVIEW_MAX_BYTES,
                                 stringValue);
    }
    else if (!truncate && stringValue)
    {
        /* Copy exactly @p length bytes so full values containing embedded
         * NULs (binary data produced by Tvb / ByteArray __tostring)
         * round-trip intact to the clipboard. g_strdup would stop at the
         * first NUL. */
        result = g_strndup(stringValue, length);
    }
    else
    {
        result = g_strdup(stringValue ? stringValue : "");
    }
    lua_pop(L, 1);
    return result;
}

static char *wslua_debugger_describe_value(lua_State *L, int idx)
{
    return wslua_debugger_describe_value_ex(L, idx, true);
}

static bool wslua_debugger_value_can_expand(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    const int valueType = lua_type(L, absIndex);
    if (valueType == LUA_TTABLE)
    {
        return wslua_debugger_count_visible_table_entries(L, absIndex) > 0;
    }
    if (valueType == LUA_TUSERDATA)
    {
        /* Prefer wslua attribute getters; fall back to the standard
         * Lua __pairs protocol so any iterable userdata can be drilled
         * into without the debugger knowing about the class. */
        if (wslua_debugger_count_userdata_getters(L, absIndex) > 0)
        {
            return true;
        }
        return wslua_debugger_userdata_has_visible_pairs(L, absIndex);
    }
    return false;
}

/**
 * @brief Lua typename, or "userdata (ClassName)" when metatable.__name is a string.
 */
static char *
wslua_debugger_format_value_type(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 502
    const int absidx = lua_absindex(L, idx);
#else
    const int absidx =
        (idx > 0 || idx <= LUA_REGISTRYINDEX) ? idx : lua_gettop(L) + idx + 1;
#endif
    const int t = lua_type(L, absidx);
    if (t != LUA_TUSERDATA)
    {
        return g_strdup(lua_typename(L, t));
    }
    if (!lua_getmetatable(L, absidx))
    {
        return g_strdup("userdata");
    }
    const char *cls = NULL;
    if (lua_getfield(L, -1, "__name") && lua_type(L, -1) == LUA_TSTRING)
    {
        cls = lua_tostring(L, -1);
    }
    lua_pop(L, 1); /* __name or nil */
    lua_pop(L, 1); /* metatable */
    if (cls)
    {
        return g_strdup_printf("userdata (%s)", cls);
    }
    return g_strdup("userdata");
}

/**
 * Append child variable rows for the value at stack top (table or userdata).
 * Pops that value.
 * @param globals_subtree When true (Variables path "Globals."…), do not hide
 *        whole "namespace" tables whose entries are only functions — same as
 *        the top-level Globals list — so class/proto tables remain navigable.
 */
static void
wslua_debugger_append_children_of_value(lua_State *target_L,
                                        GArray *variables_array,
                                        bool globals_subtree)
{
    if (lua_istable(target_L, -1))
    {
        lua_pushnil(target_L);
        while (lua_next(target_L, -2) != 0)
        {
            /* key at -2, value at -1 */

            /* Hide functions/methods and wslua internal markers. */
            if (globals_subtree
                    ? wslua_debugger_basic_entry_is_hidden(target_L)
                    : wslua_debugger_entry_is_hidden(target_L))
            {
                lua_pop(target_L, 1);
                continue;
            }

            wslua_variable_t variable;

            /* Key */
            if (lua_type(target_L, -2) == LUA_TSTRING)
            {
                variable.name = g_strdup(lua_tostring(target_L, -2));
            }
            else if (lua_type(target_L, -2) == LUA_TNUMBER)
            {
                /* Use lua_tonumber instead of lua_tostring to avoid
                 * modifying the key on the stack, which would break
                 * lua_next() iteration */
                lua_Number num_key = lua_tonumber(target_L, -2);
                variable.name =
                    g_strdup_printf("[%g]", (double)num_key);
            }
            else
            {
                variable.name = g_strdup(
                    lua_typename(target_L, lua_type(target_L, -2)));
            }

            /* Value */
            variable.type = wslua_debugger_format_value_type(target_L, -1);
            variable.value =
                wslua_debugger_describe_value(target_L, -1);
            if (globals_subtree && lua_istable(target_L, -1))
            {
                /* Stay navigable even when all children are functions. */
                int64_t total = 0;
                wslua_debugger_basic_table_counts(target_L, -1, &total, NULL);
                variable.can_expand = total > 0;
            }
            else
            {
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);
            }
            g_array_append_val(variables_array, variable);
            lua_pop(target_L, 1);
        }
    }
    else if (lua_isuserdata(target_L, -1))
    {
        /* Two introspection protocols are supported, in order:
         *   1. wslua attribute getters (via __getters), which
         *      expose a class's declared properties.
         *   2. the standard Lua __pairs metamethod, for any
         *      iterable userdata (for example a wslua class
         *      backed by a C-side collection).
         *
         * Classes registered with WSLUA_REGISTER_META get an
         * empty __getters table installed by wslua_register_
         * classinstance_meta even when they declare no
         * attributes, so gate the first branch on an actual
         * visible entry rather than the table's existence. */
        const int userdata_abs = lua_gettop(target_L);
        if (wslua_debugger_count_userdata_getters(target_L,
                                                  userdata_abs) > 0 &&
            wslua_debugger_push_getters(target_L, userdata_abs))
        {
            lua_pushnil(target_L);
            while (lua_next(target_L, -2) != 0)
            {
                /* __getters stores: [name] = cfunction. Anything
                 * else (notably the __typeof marker) is ignored. */
                if (lua_type(target_L, -2) != LUA_TSTRING ||
                    !lua_iscfunction(target_L, -1))
                {
                    lua_pop(target_L, 1);
                    continue;
                }

                const char *attr_name = lua_tostring(target_L, -2);
                if (g_strcmp0(attr_name, WSLUA_TYPEOF_FIELD) == 0)
                {
                    lua_pop(target_L, 1);
                    continue;
                }

                /* Protected call: getter(userdata). Errors are
                 * surfaced as the value so traversal keeps working
                 * even if a single attribute raises. */
                lua_pushvalue(target_L, -1);           /* getter */
                lua_pushvalue(target_L, userdata_abs); /* self */
                const int call_status =
                    lua_pcall(target_L, 1, 1, 0);
                if (call_status != 0)
                {
                    wslua_variable_t variable;
                    variable.name = g_strdup(attr_name);
                    variable.type = g_strdup("error");
                    const char *err = lua_tostring(target_L, -1);
                    variable.value =
                        g_strdup(err ? err : "<getter error>");
                    variable.can_expand = false;
                    g_array_append_val(variables_array, variable);
                    lua_pop(target_L, 2); /* error + getter */
                    continue;
                }

                /* Skip attributes that resolve to a callable; the
                 * Variables view never shows functions/methods. */
                if (lua_type(target_L, -1) == LUA_TFUNCTION)
                {
                    lua_pop(target_L, 2); /* result + getter */
                    continue;
                }

                /* Skip attributes that evaluated to nil. A getter
                 * returning nil typically signals "not applicable
                 * for this object variant" (e.g. PseudoHeader
                 * fields that only make sense for a subset of
                 * encapsulations, or a Dumper that has been
                 * closed). Hiding these keeps the view focused on
                 * data that is actually present. */
                if (lua_type(target_L, -1) == LUA_TNIL)
                {
                    lua_pop(target_L, 2); /* result + getter */
                    continue;
                }

                wslua_variable_t variable;
                variable.name = g_strdup(attr_name);
                /*
                 * Tag attribute-backed rows so the UI tooltip makes
                 * the kind obvious: an "attribute" comes from a
                 * wslua __getters entry (class-declared property),
                 * while ordinary locals/upvalues/globals carry the
                 * raw Lua typename.
                 */
                {
                    char *inner =
                        wslua_debugger_format_value_type(target_L, -1);
                    variable.type =
                        g_strdup_printf("attribute (%s)", inner);
                    g_free(inner);
                }
                variable.value =
                    wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 2); /* result + getter */
            }
            lua_pop(target_L, 1); /* __getters */
        }
        else if (wslua_debugger_push_pairs_iterator(target_L,
                                                    userdata_abs))
        {
            /* Stack: ..., userdata, iterator, state, key */
            while (wslua_debugger_pairs_next(target_L))
            {
                /* Stack: ..., userdata, iterator, state, key,
                 *        value */
                if (lua_type(target_L, -1) == LUA_TFUNCTION)
                {
                    lua_pop(target_L, 1); /* value; keep key */
                    continue;
                }
                /* Hide nil entries for the same reason as in the
                 * attribute path: nil typically marks a slot that
                 * is not meaningful for the current instance. */
                if (lua_type(target_L, -1) == LUA_TNIL)
                {
                    lua_pop(target_L, 1); /* value; keep key */
                    continue;
                }

                wslua_variable_t variable;
                if (lua_type(target_L, -2) == LUA_TSTRING)
                {
                    variable.name =
                        g_strdup(lua_tostring(target_L, -2));
                }
                else if (lua_type(target_L, -2) == LUA_TNUMBER)
                {
                    lua_Number num_key =
                        lua_tonumber(target_L, -2);
                    variable.name =
                        g_strdup_printf("[%g]", (double)num_key);
                }
                else
                {
                    variable.name = g_strdup(lua_typename(
                        target_L, lua_type(target_L, -2)));
                }

                /*
                 * Tag __pairs-sourced rows as "pair" so the UI can
                 * distinguish them from attribute-backed rows and
                 * regular locals in the tooltip.
                 */
                {
                    char *inner =
                        wslua_debugger_format_value_type(target_L, -1);
                    variable.type = g_strdup_printf("pair (%s)", inner);
                    g_free(inner);
                }
                variable.value =
                    wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 1); /* value; keep key */
            }
            /* pairs_next cleaned up the iterator triple. */
        }
    }
    lua_pop(target_L, 1); /* Pop result */
}

/**
 * @brief Get variables for a path.
 * @param path The path (NULL for root).
 * @param variable_count Output pointer for variable count.
 * @return Array of variables.
 */
wslua_variable_t *wslua_debugger_get_variables(const char *path,
                                               int32_t *variable_count)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        *variable_count = 0;
        return NULL;
    }

    GArray *variables_array =
        g_array_new(false, false, sizeof(wslua_variable_t));

    if (!path || !*path)
    {
        /* Root: Locals, Upvalues, Globals */
        wslua_variable_t variable;

        variable.name = g_strdup("Locals");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);

        variable.name = g_strdup("Upvalues");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);

        variable.name = g_strdup("Globals");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);
    }
    else if (g_strcmp0(path, "Locals") == 0)
    {
        /* Locals */
        lua_Debug debug_info;
        if (wslua_debugger_fill_activation(target_L, variable_stack_level,
                                           &debug_info))
        {
            int32_t local_index = 1;
            const char *name;
            while ((name = lua_getlocal(target_L, &debug_info, local_index++)))
            {
                if (g_str_has_prefix(name, "("))
                {
                    lua_pop(target_L, 1);
                    continue;
                }
                /* The Variables view intentionally hides functions/methods. */
                if (lua_type(target_L, -1) == LUA_TFUNCTION)
                {
                    lua_pop(target_L, 1);
                    continue;
                }

                wslua_variable_t variable;
                variable.name = g_strdup(name);
                variable.type =
                    wslua_debugger_format_value_type(target_L, -1);
                variable.value = wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 1);
            }
        }
    }
    else if (g_strcmp0(path, "Upvalues") == 0)
    {
        /* Upvalues */
        lua_Debug debug_info;
        if (wslua_debugger_fill_activation(target_L, variable_stack_level,
                                           &debug_info) &&
            wslua_debugger_push_function_for_ar(target_L, &debug_info))
        {
            int32_t upvalue_index = 1;
            const char *name;
            while ((name = lua_getupvalue(target_L, -1, upvalue_index)))
            {
                /* The Variables view intentionally hides functions/methods. */
                if (lua_type(target_L, -1) == LUA_TFUNCTION)
                {
                    lua_pop(target_L, 1);
                    upvalue_index++;
                    continue;
                }

                wslua_variable_t variable;
                /* C closures use "" as the name for each slot; use a label so
                 * the UI path is valid for expansion. */
                if (name[0] == '\0')
                {
                    variable.name =
                        g_strdup_printf("(closure #%d)", upvalue_index);
                }
                else
                {
                    variable.name = g_strdup(name);
                }
                variable.type =
                    wslua_debugger_format_value_type(target_L, -1);
                variable.value = wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 1);
                upvalue_index++;
            }
            lua_pop(target_L, 1); /* Function */
        }
    }
    else if (g_strcmp0(path, "Globals") == 0)
    {
        /* Globals (_G) — limit to avoid freezing the UI */
#define WSLUA_GLOBALS_DISPLAY_LIMIT 500
        unsigned globals_count = 0;
        lua_pushglobaltable(target_L);
        /* Iterate table */
        lua_pushnil(target_L);
        while (lua_next(target_L, -2) != 0)
        {
            if (globals_count >= WSLUA_GLOBALS_DISPLAY_LIMIT)
            {
                lua_pop(target_L, 2); /* key + value */
                /* Add a sentinel entry so the user knows the list is truncated */
                wslua_variable_t truncated;
                truncated.name = g_strdup_printf(
                    "... (%u+ globals, showing first %u)",
                    WSLUA_GLOBALS_DISPLAY_LIMIT, WSLUA_GLOBALS_DISPLAY_LIMIT);
                truncated.type = g_strdup("");
                truncated.value = g_strdup("");
                truncated.can_expand = false;
                g_array_append_val(variables_array, truncated);
                break;
            }

            /* Hide functions and __typeof keys only — not "namespace" tables
             * whose children are all functions. entry_is_hidden() would drop
             * class/proto tables like Proto entirely, so a global like a Proto
             * or wslua class table would never appear at this level. */
            if (wslua_debugger_basic_entry_is_hidden(target_L))
            {
                lua_pop(target_L, 1);
                continue;
            }

            wslua_variable_t variable;

            if (lua_type(target_L, -2) == LUA_TSTRING)
            {
                variable.name = g_strdup(lua_tostring(target_L, -2));
            }
            else
            {
                /* Skip non-string globals for now or format them */
                lua_pop(target_L, 1);
                continue;
            }

            variable.type =
                wslua_debugger_format_value_type(target_L, -1);
            variable.value = wslua_debugger_describe_value(target_L, -1);
            /* value_can_expand() uses the "visible" filter and would hide
             * namespace tables we just listed; use raw count so they stay
             * navigable. */
            if (lua_istable(target_L, -1))
            {
                int64_t total = 0;
                wslua_debugger_basic_table_counts(target_L, -1, &total, NULL);
                variable.can_expand = total > 0;
            }
            else
            {
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);
            }

            g_array_append_val(variables_array, variable);
            lua_pop(target_L, 1);
            globals_count++;
        }
        lua_pop(target_L, 1); /* Table */
    }
    else
    {
        /* Lookup path */
        /* Strip prefix if present; honor explicit section (no shadowing). */
        const char *lookup_path = path;
        wslua_lookup_first_kind_t lk_first = WSLUA_LOOKUP_FIRST_AUTO;
        if (g_str_has_prefix(path, "Locals."))
        {
            lookup_path = path + 7;
            lk_first = WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
        }
        else if (g_str_has_prefix(path, "Upvalues."))
        {
            lookup_path = path + 9;
            lk_first = WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
        }
        else if (g_str_has_prefix(path, "Globals."))
        {
            lookup_path = path + 8;
            lk_first = WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
        }

        if (wslua_debugger_lookup_path(target_L, lookup_path,
                                       variable_stack_level, lk_first))
        {
            const bool globals_subtree =
                path && g_str_has_prefix(path, "Globals.");
            wslua_debugger_append_children_of_value(target_L, variables_array,
                                                    globals_subtree);
        }
    }

    *variable_count = (int32_t)variables_array->len;
    return (wslua_variable_t *)g_array_free(variables_array, false);
}

/**
 * @brief Free variables array.
 * @param variables The array.
 * @param variable_count The count.
 */
void wslua_debugger_free_variables(wslua_variable_t *variables,
                                   int32_t variable_count)
{
    for (int32_t variable_index = 0; variable_index < variable_count;
         variable_index++)
    {
        g_free(variables[variable_index].name);
        g_free(variables[variable_index].value);
        g_free(variables[variable_index].type);
    }
    g_free(variables);
}

/**
 * @brief Get breakpoint count.
 * @return The number of breakpoints.
 */
unsigned wslua_debugger_get_breakpoint_count(void)
{
    ensure_breakpoints_initialized();
    return breakpoints_array->len;
}

/**
 * @brief Get breakpoint at index.
 * @param idx The index.
 * @param file_path Output file path.
 * @param line Output line.
 * @param active Output active state.
 * @return true if found.
 */
bool wslua_debugger_get_breakpoint(unsigned idx, const char **file_path,
                                   int64_t *line, bool *active)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    if (idx >= breakpoints_array->len)
    {
        g_mutex_unlock(&debugger.mutex);
        return false;
    }

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    *file_path = bp->file_path;
    *line = bp->line;
    *active = bp->active;
    g_mutex_unlock(&debugger.mutex);
    return true;
}

/* Reload callback */
static wslua_debugger_reload_callback_t reload_callback = NULL;

/**
 * @brief Register a callback to be notified before Lua plugins are reloaded.
 *
 * The debugger UI uses this to reload script files from disk before
 * Lua executes them, ensuring breakpoints show current code.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_reload_callback(
    wslua_debugger_reload_callback_t callback)
{
    reload_callback = callback;
}

/**
 * @brief Notify the debugger that a reload is about to happen.
 *
 * Saves the debugger enabled state, disables the debugger, detaches
 * from the current Lua state, and calls the reload callback so the
 * UI can refresh script files from disk.
 *
 * If the debugger is paused, it is disabled (which continues execution)
 * and the reload callback is invoked so the UI can exit its nested
 * event loop and schedule a deferred reload.
 *
 * @return true if the caller should proceed with the reload immediately;
 *         false if the reload was deferred (debugger was paused).
 */
bool wslua_debugger_notify_reload(void)
{
    bool should_disable = false;

    g_mutex_lock(&debugger.mutex);
    if (!debugger.reload_in_progress)
    {
        debugger.reload_in_progress = true;
        debugger.was_enabled_before_reload = debugger.enabled;
    }
    should_disable = debugger.enabled;
    g_mutex_unlock(&debugger.mutex);

    if (should_disable)
    {
        wslua_debugger_set_enabled(false);
    }

    debugger.L = NULL;

    if (reload_callback)
    {
        reload_callback();
    }

    return !wslua_debugger_is_paused();
}

/**
 * @brief Post-reload callback storage.
 */
static wslua_debugger_post_reload_callback_t post_reload_callback = NULL;

/**
 * @brief Register a callback to be notified after Lua plugins are reloaded.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_post_reload_callback(
    wslua_debugger_post_reload_callback_t callback)
{
    post_reload_callback = callback;
}

/**
 * @brief Notify listeners that reload has completed.
 *
 * Called by wslua_reload_plugins() AFTER wslua_init() completes.
 * Clears the reload_in_progress flag and fires the post-reload UI
 * callback so the file tree is refreshed with newly loaded scripts.
 *
 * The debugger is NOT re-enabled here.  The UI must call
 * wslua_debugger_restore_after_reload() once cf_reload / redissect
 * has finished, to avoid the debug hook firing while packets are
 * still being re-read.
 */
void wslua_debugger_notify_post_reload(void)
{
    debugger.reload_in_progress = false;

    if (post_reload_callback)
    {
        post_reload_callback();
    }
}

/**
 * @brief Re-enable the debugger after a reload + cf_reload cycle.
 *
 * If the debugger was enabled before the reload, re-enable it now
 * that the file has been fully re-read.  This must be called AFTER
 * cf_reload / redissectPackets completes.
 */
void wslua_debugger_restore_after_reload(void)
{
    bool need_enable = false;

    g_mutex_lock(&debugger.mutex);
    if (!debugger.was_enabled_before_reload)
    {
        g_mutex_unlock(&debugger.mutex);
        return;
    }
    debugger.was_enabled_before_reload = false;
    if (debugger.user_explicitly_disabled)
    {
        g_mutex_unlock(&debugger.mutex);
        return;
    }
    need_enable = !debugger.enabled && debugger.L != NULL;
    g_mutex_unlock(&debugger.mutex);

    if (need_enable)
    {
        wslua_debugger_set_enabled(true);
    }
}

/**
 * @brief Script-loaded callback storage.
 */
static wslua_debugger_script_loaded_callback_t script_loaded_callback = NULL;

/**
 * @brief Register a callback to be notified when a Lua script is loaded.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_script_loaded_callback(
    wslua_debugger_script_loaded_callback_t callback)
{
    script_loaded_callback = callback;
}

/**
 * @brief Notify the debugger that a Lua script has been loaded.
 *
 * Called by the Lua loader when a script is successfully loaded.
 *
 * @param file_path The full path to the loaded script file.
 */
void wslua_debugger_notify_script_loaded(const char *file_path)
{
    if (script_loaded_callback && file_path)
    {
        script_loaded_callback(file_path);
    }
}

/**
 * @brief Check if the debugger is currently paused.
 * @return true if paused at a breakpoint, false otherwise.
 */
bool wslua_debugger_is_paused(void)
{
    g_mutex_lock(&debugger.mutex);
    bool paused = debugger.state == WSLUA_DEBUGGER_PAUSED &&
                  debugger.paused_L != NULL;
    g_mutex_unlock(&debugger.mutex);
    return paused;
}

/**
 * @brief Maximum number of Lua instructions allowed during evaluation.
 *
 * This prevents infinite loops from hanging Wireshark.  The limit is
 * generous enough for any reasonable inspection expression but will
 * abort runaway code within a fraction of a second.
 */
#define WSLUA_EVAL_INSTRUCTION_LIMIT 1000000

/**
 * @brief Maximum call depth allowed during evaluation.
 *
 * This catches deep recursion that could overflow the C stack before
 * the instruction-count limit triggers.
 */
#define WSLUA_EVAL_MAX_CALL_DEPTH 100

/** @brief Current call depth during expression evaluation. */
static int eval_call_depth;

/**
 * @brief Hook that aborts evaluation on instruction limit or deep recursion.
 */
static void wslua_eval_timeout_hook(lua_State *L, lua_Debug *ar)
{
    if (ar->event == LUA_HOOKCALL || ar->event == LUA_HOOKTAILCALL)
    {
        eval_call_depth++;
        if (eval_call_depth > WSLUA_EVAL_MAX_CALL_DEPTH)
        {
            luaL_error(L, "Evaluation aborted: call depth limit (%d) exceeded "
                       "(possible infinite recursion)",
                       WSLUA_EVAL_MAX_CALL_DEPTH);
        }
        return;
    }
    if (ar->event == LUA_HOOKRET)
    {
        if (eval_call_depth > 0)
        {
            eval_call_depth--;
        }
        return;
    }
    /* LUA_HOOKCOUNT — instruction limit reached */
    luaL_error(L, "Evaluation aborted: instruction limit (%d) exceeded "
               "(possible infinite loop)",
               WSLUA_EVAL_INSTRUCTION_LIMIT);
}

/**
 * Build a compilable Lua chunk from a user expression. A leading '=' means
 * "return …". If the text does not compile as a chunk, retry as
 * "return (expr)" so bare identifiers (e.g. a local name) work like the
 * Evaluate pane's '=' shorthand.
 *
 * @return Newly allocated source for luaL_loadstring(), or NULL on failure.
 */
static char *
wslua_debugger_expression_compilable_chunk(lua_State *L,
                                             const char *expression,
                                             char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }

    char *trimmed = g_strdup(expression);
    g_strstrip(trimmed);
    if (!*trimmed)
    {
        g_free(trimmed);
        if (error_msg)
        {
            *error_msg = g_strdup("Empty expression");
        }
        return NULL;
    }

    if (trimmed[0] == '=')
    {
        char *chunk = g_strdup_printf("return %s", trimmed + 1);
        g_free(trimmed);
        if (luaL_loadstring(L, chunk) != LUA_OK)
        {
            if (error_msg)
            {
                *error_msg =
                    g_strdup(lua_tostring(L, -1) ? lua_tostring(L, -1)
                                                : "Syntax error");
            }
            lua_pop(L, 1);
            g_free(chunk);
            return NULL;
        }
        lua_pop(L, 1);
        return chunk;
    }

    char *chunk = g_strdup(trimmed);
    if (luaL_loadstring(L, chunk) == LUA_OK)
    {
        lua_pop(L, 1);
        g_free(trimmed);
        return chunk;
    }
    lua_pop(L, 1);
    g_free(chunk);

    chunk = g_strdup_printf("return (%s)", trimmed);
    g_free(trimmed);
    if (luaL_loadstring(L, chunk) != LUA_OK)
    {
        if (error_msg)
        {
            *error_msg =
                g_strdup(lua_tostring(L, -1) ? lua_tostring(L, -1)
                                              : "Syntax error");
        }
        lua_pop(L, 1);
        g_free(chunk);
        return NULL;
    }
    lua_pop(L, 1);
    return chunk;
}

/**
 * Scan one [A-Za-z_][A-Za-z0-9_]*; advance *pp past it on success.
 */
static bool
wslua_debugger_spec_scan_identifier(const char **pp)
{
    const char *p = *pp;
    if (!p || (!g_ascii_isalpha((guchar)*p) && *p != '_'))
        return false;
    p++;
    while (g_ascii_isalnum((guchar)*p) || *p == '_')
        p++;
    *pp = p;
    return true;
}

/**
 * @brief Consume one Lua string escape starting at **pp (which must point at
 * '\\'). If @a out is non-NULL, append the decoded bytes.
 *
 * Accepted escapes match the Lua 5.x reference manual:
 *   \\a \\b \\f \\n \\r \\t \\v   C-style control bytes
 *   \\\\ \\" \\' \\?              literal punctuation
 *   \\NNN                         decimal byte, 1..3 digits, value <= 255
 *   \\xHH                         hex byte, exactly 2 hex digits
 *   \\u{H..}                      Unicode codepoint (1..8 hex digits,
 *                                 <= 0x7FFFFFFF), encoded as UTF-8
 *   \\z                           skip following whitespace (no bytes emitted)
 *
 * Returns false on a malformed escape.
 */
static bool
wslua_debugger_spec_consume_escape(const char **pp, GString *out)
{
    const char *p = *pp;
    if (*p != '\\' || !p[1])
        return false;
    p++;
    char c = *p;
    switch (c)
    {
    case 'a':  if (out) g_string_append_c(out, '\a'); p++; break;
    case 'b':  if (out) g_string_append_c(out, '\b'); p++; break;
    case 'f':  if (out) g_string_append_c(out, '\f'); p++; break;
    case 'n':  if (out) g_string_append_c(out, '\n'); p++; break;
    case 'r':  if (out) g_string_append_c(out, '\r'); p++; break;
    case 't':  if (out) g_string_append_c(out, '\t'); p++; break;
    case 'v':  if (out) g_string_append_c(out, '\v'); p++; break;
    case '\\': if (out) g_string_append_c(out, '\\'); p++; break;
    case '"':  if (out) g_string_append_c(out, '"'); p++; break;
    case '\'': if (out) g_string_append_c(out, '\''); p++; break;
    case '?':  if (out) g_string_append_c(out, '?'); p++; break;
    case 'z':
        p++;
        while (*p && g_ascii_isspace((guchar)*p))
            p++;
        break;
    case 'x':
    {
        p++;
        if (!g_ascii_isxdigit((guchar)p[0]) ||
            !g_ascii_isxdigit((guchar)p[1]))
            return false;
        if (out)
        {
            unsigned v = ((unsigned)g_ascii_xdigit_value(p[0]) << 4) |
                         (unsigned)g_ascii_xdigit_value(p[1]);
            g_string_append_c(out, (char)v);
        }
        p += 2;
        break;
    }
    case 'u':
    {
        p++;
        if (*p != '{')
            return false;
        p++;
        guint64 v = 0;
        int hexcount = 0;
        while (g_ascii_isxdigit((guchar)*p) && hexcount < 8)
        {
            v = (v << 4) | (guint64)g_ascii_xdigit_value(*p);
            p++;
            hexcount++;
        }
        if (hexcount == 0 || *p != '}' || v > 0x7FFFFFFFu)
            return false;
        p++;
        if (out)
            g_string_append_unichar(out, (gunichar)v);
        break;
    }
    default:
        if (g_ascii_isdigit((guchar)c))
        {
            unsigned v = 0;
            int digits = 0;
            while (g_ascii_isdigit((guchar)*p) && digits < 3)
            {
                v = v * 10 + (unsigned)(*p - '0');
                p++;
                digits++;
            }
            if (v > 255)
                return false;
            if (out)
                g_string_append_c(out, (char)v);
        }
        else
        {
            return false;
        }
        break;
    }
    *pp = p;
    return true;
}

/**
 * @brief Scan a Lua short literal string (double- or single-quoted) starting
 * at **pp. If @a out is non-NULL, decode the contents into it (without the
 * surrounding quotes). Advances *pp past the closing quote on success.
 */
static bool
wslua_debugger_spec_scan_quoted(const char **pp, GString *out)
{
    const char *p = *pp;
    char quote = *p;
    if (quote != '"' && quote != '\'')
        return false;
    p++;
    while (*p && *p != quote)
    {
        if (*p == '\\')
        {
            if (!wslua_debugger_spec_consume_escape(&p, out))
                return false;
            continue;
        }
        if (*p == '\n' || *p == '\r')
            return false;
        if (out)
            g_string_append_c(out, *p);
        p++;
    }
    if (*p != quote)
        return false;
    p++;
    *pp = p;
    return true;
}

/**
 * @brief Scan an integer literal at **pp with optional leading '-' and
 * decimal or hex ("0x" / "0X") digits. Advances *pp past the literal.
 * If @a out_value is non-NULL, stores the parsed value.
 */
static bool
wslua_debugger_spec_scan_integer(const char **pp, int64_t *out_value)
{
    const char *p = *pp;
    bool neg = false;
    if (*p == '-')
    {
        neg = true;
        p++;
    }
    if (!g_ascii_isdigit((guchar)*p))
        return false;

    char *endp = NULL;
    guint64 mag;
    if (*p == '0' && (p[1] == 'x' || p[1] == 'X') &&
        g_ascii_isxdigit((guchar)p[2]))
    {
        mag = g_ascii_strtoull(p + 2, &endp, 16);
    }
    else
    {
        mag = g_ascii_strtoull(p, &endp, 10);
    }
    if (!endp || endp == p)
        return false;

    if (out_value)
        *out_value = neg ? -(int64_t)mag : (int64_t)mag;
    *pp = endp;
    return true;
}

/**
 * @brief Scan a bracket key starting at **pp (after the opening '[' has been
 * consumed). Advances *pp past the closing ']'. Whitespace around the key is
 * tolerated. If @a L is non-NULL, pushes the decoded Lua value on top of @a L.
 *
 * Accepts:
 *   integer                 decimal or hex, optional leading '-'
 *   true / false            Lua boolean literals
 *   "string" / 'string'     Lua short literal string with full escape set
 */
static bool
wslua_debugger_spec_scan_bracket_key(const char **pp, lua_State *L)
{
    const char *p = *pp;
    while (*p && g_ascii_isspace((guchar)*p))
        p++;
    if (!*p)
        return false;

    bool pushed = false;
    if (strncmp(p, "true", 4) == 0 &&
        !(g_ascii_isalnum((guchar)p[4]) || p[4] == '_'))
    {
        if (L)
        {
            lua_pushboolean(L, 1);
            pushed = true;
        }
        p += 4;
    }
    else if (strncmp(p, "false", 5) == 0 &&
             !(g_ascii_isalnum((guchar)p[5]) || p[5] == '_'))
    {
        if (L)
        {
            lua_pushboolean(L, 0);
            pushed = true;
        }
        p += 5;
    }
    else if (*p == '-' || g_ascii_isdigit((guchar)*p))
    {
        int64_t v;
        if (!wslua_debugger_spec_scan_integer(&p, &v))
            return false;
        if (L)
        {
            lua_pushinteger(L, (lua_Integer)v);
            pushed = true;
        }
    }
    else if (*p == '"' || *p == '\'')
    {
        GString *decoded = L ? g_string_new(NULL) : NULL;
        if (!wslua_debugger_spec_scan_quoted(&p, decoded))
        {
            if (decoded)
                g_string_free(decoded, true);
            return false;
        }
        if (L)
        {
            lua_pushlstring(L, decoded->str, decoded->len);
            pushed = true;
            g_string_free(decoded, true);
        }
    }
    else
    {
        return false;
    }

    while (*p && g_ascii_isspace((guchar)*p))
        p++;
    if (*p != ']')
    {
        if (pushed)
            lua_pop(L, 1);
        return false;
    }
    p++;
    *pp = p;
    return true;
}

/**
 * @brief Validate a path body.
 *
 * Grammar (after any section prefix has already been stripped):
 *   body        := ident ( '.' ident | '[' bracket-key ']' )*
 *   ident       := [A-Za-z_] [A-Za-z0-9_]*
 *   bracket-key := ws? ( integer | 'true' | 'false' | string ) ws?
 *   integer     := '-'? ( decimal-digits | '0x' hex-digits | '0X' hex-digits )
 *   string      := '"' ( char-except-"\\\\\" | escape )* '"'
 *                | '\'' ( char-except-'\\\\\' | escape )* '\''
 *   escape      — see wslua_debugger_spec_consume_escape()
 *
 * Same surface syntax as wslua_debugger_lookup_path after the first segment.
 */
static bool
wslua_debugger_spec_validate_path_body(const char *body)
{
    const char *p = body;

    if (!body || !*body)
        return false;
    if (!wslua_debugger_spec_scan_identifier(&p))
        return false;
    while (*p)
    {
        if (*p == '.')
        {
            p++;
            if (!wslua_debugger_spec_scan_identifier(&p))
                return false;
        }
        else if (*p == '[')
        {
            p++;
            if (!wslua_debugger_spec_scan_bracket_key(&p, NULL))
                return false;
        }
        else
        {
            return false;
        }
    }
    return true;
}

/**
 * Remove spaces and tabs adjacent to '.' outside of bracket [...] string
 * literals. Modifies @a s in place.
 */
static void
wslua_debugger_watch_collapse_ws_around_dots(char *s)
{
    if (!s || !*s)
        return;

    GString *o = g_string_sized_new(strlen(s) + 4);
    const char *p = s;
    bool in_bracket = false;
    bool in_dq = false;
    bool in_sq = false;

    while (*p)
    {
        unsigned char c = (unsigned char)*p;

        if (!in_bracket)
        {
            if (c == '[')
            {
                in_bracket = true;
                g_string_append_c(o, (char)c);
                p++;
                continue;
            }
            if (g_ascii_isspace(c))
            {
                const char *q = p;
                while (*q && g_ascii_isspace((unsigned char)*q))
                    q++;
                if (*q == '.' && o->len > 0 && o->str[o->len - 1] != '.')
                {
                    p = q;
                    continue;
                }
                if (o->len > 0 && o->str[o->len - 1] == '.' &&
                    (*q == '_' || g_ascii_isalpha((guchar)*q) || *q == '['))
                {
                    p = q;
                    continue;
                }
            }
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }

        /* in_bracket */
        if ((in_dq || in_sq) && c == '\\' && p[1])
        {
            /* Keep the backslash and the escaped byte together so that
             * \" / \' inside a bracket string literal do not toggle the
             * in-string state. */
            g_string_append_c(o, (char)c);
            g_string_append_c(o, p[1]);
            p += 2;
            continue;
        }
        if (!in_dq && !in_sq && c == ']')
        {
            in_bracket = false;
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }
        if (!in_sq && c == '"')
        {
            in_dq = !in_dq;
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }
        if (!in_dq && c == '\'')
        {
            in_sq = !in_sq;
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }
        g_string_append_c(o, (char)c);
        p++;
    }

    /* o is built by copying/skipping bytes from s, so o->len <= strlen(s)
     * and writing o->len + 1 bytes back into s is safe.
     */
    memcpy(s, o->str, o->len + 1);
    g_string_free(o, true);
}

/**
 * Count of '.' and '[' in @a path — the same metric as the Qt Watch panel
 * (watchSubpathBoundaryCount) and @ref WSLUA_WATCH_MAX_PATH_SEGMENTS.
 */
static unsigned
wslua_debugger_watch_path_boundary_count(const char *path)
{
    unsigned n = 0;

    if (!path)
    {
        return 0;
    }
    for (const char *p = path; *p; p++)
    {
        if (*p == '.' || *p == '[')
        {
            n++;
        }
    }
    return n;
}

/**
 * @return Heap-allocated canonical variable-tree path, or NULL if @a spec is
 *         not a valid path-shaped watch. Applies trim, @c _G / @c _G. alias
 *         to @c Globals / @c Globals., whitespace collapse around dots, and
 *         path-body validation. Caller must @c g_free when non-NULL.
 */
static char *
wslua_debugger_watch_canonical_path(const char *spec)
{
    if (!spec || !*spec)
        return NULL;

    char *work = g_strdup(spec);
    g_strstrip(work);
    if (!*work)
    {
        g_free(work);
        return NULL;
    }

    if (g_strcmp0(work, "_G") == 0)
    {
        g_free(work);
        return g_strdup("Globals");
    }
    if (g_str_has_prefix(work, "_G."))
    {
        char *t = g_strdup_printf("Globals.%s", work + 3);
        g_free(work);
        work = t;
    }

    wslua_debugger_watch_collapse_ws_around_dots(work);

    if (g_str_has_prefix(work, "Locals."))
    {
        if (!wslua_debugger_spec_validate_path_body(work + 7))
            goto fail;
        goto canon_ok;
    }
    if (g_str_has_prefix(work, "Upvalues."))
    {
        if (!wslua_debugger_spec_validate_path_body(work + 9))
            goto fail;
        goto canon_ok;
    }
    if (g_str_has_prefix(work, "Globals."))
    {
        if (!wslua_debugger_spec_validate_path_body(work + 8))
            goto fail;
        goto canon_ok;
    }
    if (g_strcmp0(work, "Locals") == 0 || g_strcmp0(work, "Upvalues") == 0 ||
        g_strcmp0(work, "Globals") == 0)
    {
        goto canon_ok;
    }
    if (!wslua_debugger_spec_validate_path_body(work))
        goto fail;
    /* Bare path body: caller decides whether to prepend Locals. */
canon_ok:
    if (wslua_debugger_watch_path_boundary_count(work) >=
        WSLUA_WATCH_MAX_PATH_SEGMENTS)
    {
        goto fail;
    }
    return work;

fail:
    g_free(work);
    return NULL;
}

bool
wslua_debugger_watch_spec_uses_path_resolution(const char *spec)
{
    char *c = wslua_debugger_watch_canonical_path(spec);
    if (!c)
        return false;
    g_free(c);
    return true;
}

char *
wslua_debugger_watch_variable_path_for_spec(const char *spec)
{
    char *canon = wslua_debugger_watch_canonical_path(spec);
    if (!canon)
        return NULL;

    if (g_str_has_prefix(canon, "Locals.") ||
        g_str_has_prefix(canon, "Upvalues.") ||
        g_str_has_prefix(canon, "Globals.") ||
        g_strcmp0(canon, "Locals") == 0 ||
        g_strcmp0(canon, "Upvalues") == 0 ||
        g_strcmp0(canon, "Globals") == 0)
    {
        return canon;
    }

    char *out = g_strdup_printf("Locals.%s", canon);
    g_free(canon);
    return out;
}

/**
 * @return 0 if @a first_component matches a local, 1 upvalue, 2 global, -1 not found.
 *         Clears transient values from the Lua stack.
 */
static int
wslua_debugger_first_segment_binding_kind(lua_State *L, int32_t stack_level,
                                          const char *first_component)
{
    if (!first_component || !*first_component)
    {
        return -1;
    }

    lua_Debug debug_info;
    if (!wslua_debugger_fill_activation(L, stack_level, &debug_info))
    {
        return -1;
    }

    int32_t local_index = 1;
    const char *name;
    while ((name = lua_getlocal(L, &debug_info, local_index++)))
    {
        if (g_strcmp0(name, first_component) == 0)
        {
            lua_pop(L, 1);
            return 0;
        }
        lua_pop(L, 1);
    }

    if (wslua_debugger_push_function_for_ar(L, &debug_info))
    {
        local_index = 1;
        while ((name = lua_getupvalue(L, -1, local_index++)))
        {
            if (g_strcmp0(name, first_component) == 0)
            {
                lua_remove(L, -2); /* function */
                lua_pop(L, 1);     /* value */
                return 1;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1); /* function */
    }

    if (wslua_debugger_get_global_or_env_field(L, stack_level,
                                               first_component))
    {
        lua_pop(L, 1);
        return 2;
    }
    return -1;
}

char *
wslua_debugger_watch_resolved_variable_path_for_spec(const char *spec)
{
    char *canon = wslua_debugger_watch_canonical_path(spec);
    if (!canon)
        return NULL;

    /* Already qualified or a section-only spec → done. */
    if (g_str_has_prefix(canon, "Locals.") ||
        g_str_has_prefix(canon, "Upvalues.") ||
        g_str_has_prefix(canon, "Globals.") ||
        g_strcmp0(canon, "Locals") == 0 ||
        g_strcmp0(canon, "Upvalues") == 0 ||
        g_strcmp0(canon, "Globals") == 0)
    {
        return canon;
    }

    /* Bare path body: if we have a paused frame, classify by first segment
     * binding, otherwise fall back to "Locals.<body>". */
    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;

    if (!paused || !L)
    {
        g_mutex_unlock(&debugger.mutex);
        char *out = g_strdup_printf("Locals.%s", canon);
        g_free(canon);
        return out;
    }

    const char *end_ptr = canon;
    while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
        end_ptr++;

    char *first_component = g_strndup(canon, (size_t)(end_ptr - canon));
    if (!first_component || !*first_component)
    {
        g_mutex_unlock(&debugger.mutex);
        g_free(first_component);
        return canon;
    }

    const int kind = wslua_debugger_first_segment_binding_kind(
        L, variable_stack_level, first_component);
    g_mutex_unlock(&debugger.mutex);
    g_free(first_component);

    const char *section = "Locals";
    if (kind == 1)
        section = "Upvalues";
    else if (kind == 2)
        section = "Globals";
    /* kind < 0 falls back to Locals (matches variable_path_for_spec). */

    char *out = g_strdup_printf("%s.%s", section, canon);
    g_free(canon);
    return out;
}

/** @return level or -1 */
static int32_t
wslua_debugger_find_frame_with_local(lua_State *L, const char *name)
{
    if (!name || !*name)
    {
        return -1;
    }
    for (int32_t level = 0;; level++)
    {
        lua_Debug ar;
        if (!lua_getstack(L, level, &ar))
        {
            break;
        }
        int32_t i = 1;
        const char *ln;
        while ((ln = lua_getlocal(L, &ar, i++)))
        {
            if (ln[0] == '(')
            {
                lua_pop(L, 1);
                continue;
            }
            if (g_strcmp0(ln, name) == 0)
            {
                lua_pop(L, 1);
                return level;
            }
            lua_pop(L, 1);
        }
    }
    return -1;
}

/** @return level or -1 */
static int32_t
wslua_debugger_find_frame_with_upvalue(lua_State *L, const char *name)
{
    if (!name || !*name)
    {
        return -1;
    }
    for (int32_t level = 0;; level++)
    {
        lua_Debug ar;
        if (!lua_getstack(L, level, &ar))
        {
            break;
        }
        if (!wslua_debugger_push_function_for_ar(L, &ar))
        {
            continue;
        }
        int32_t uv = 1;
        const char *un;
        while ((un = lua_getupvalue(L, -1, uv++)))
        {
            if (g_strcmp0(un, name) == 0)
            {
                lua_pop(L, 2); /* upvalue + function */
                return level;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1); /* function */
    }
    return -1;
}

int32_t
wslua_debugger_find_stack_level_for_watch_spec(const char *spec)
{
    char *canon = wslua_debugger_watch_canonical_path(spec);
    if (!canon)
        return -1;

    if (g_strcmp0(canon, "Locals") == 0 || g_strcmp0(canon, "Upvalues") == 0 ||
        g_strcmp0(canon, "Globals") == 0 ||
        g_str_has_prefix(canon, "Globals."))
    {
        g_free(canon);
        return -1;
    }

    enum
    {
        WATCH_STACK_LOCAL,
        WATCH_STACK_UPVALUE,
        WATCH_STACK_UNQUAL
    } mode = WATCH_STACK_UNQUAL;

    const char *walk = canon;
    if (g_str_has_prefix(canon, "Locals."))
    {
        mode = WATCH_STACK_LOCAL;
        walk = canon + 7;
    }
    else if (g_str_has_prefix(canon, "Upvalues."))
    {
        mode = WATCH_STACK_UPVALUE;
        walk = canon + 9;
    }

    const char *end = walk;
    while (*end && *end != '.' && *end != '[')
        end++;
    if (end == walk)
    {
        g_free(canon);
        return -1;
    }

    char *first_seg = g_strndup(walk, (size_t)(end - walk));

    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    if (!paused || !L)
    {
        g_mutex_unlock(&debugger.mutex);
        g_free(first_seg);
        g_free(canon);
        return -1;
    }

    int32_t found = -1;
    if (mode == WATCH_STACK_LOCAL)
    {
        found = wslua_debugger_find_frame_with_local(L, first_seg);
    }
    else if (mode == WATCH_STACK_UPVALUE)
    {
        found = wslua_debugger_find_frame_with_upvalue(L, first_seg);
    }
    else
    {
        found = wslua_debugger_find_frame_with_local(L, first_seg);
        if (found < 0)
            found = wslua_debugger_find_frame_with_upvalue(L, first_seg);
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(first_seg);
    g_free(canon);
    return found;
}

bool wslua_debugger_watch_read_root(const char *spec,
                                    char **value_out, char **type_out,
                                    bool *can_expand_out, char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }
    if (type_out)
    {
        *type_out = NULL;
    }
    if (can_expand_out)
    {
        *can_expand_out = false;
    }
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!spec || !*spec)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty watch specification");
        }
        return false;
    }

    if (!wslua_debugger_watch_spec_uses_path_resolution(spec))
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Invalid watch path");
        }
        return false;
    }

    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);

    if (!paused || !L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return false;
    }

    char *varpath = wslua_debugger_watch_resolved_variable_path_for_spec(spec);
    if (!varpath)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Invalid watch path");
        }
        return false;
    }

    /* Section-only specs ("Locals" / "Upvalues" / "Globals") have no root
     * value to look up: they are purely container rows whose children are
     * produced by wslua_debugger_get_variables(section). Report them as an
     * empty, expandable "section" entry so the Qt layer shows the expansion
     * indicator and lazy-fills children on demand. */
    if (g_strcmp0(varpath, "Locals") == 0 ||
        g_strcmp0(varpath, "Upvalues") == 0 ||
        g_strcmp0(varpath, "Globals") == 0)
    {
        if (type_out)
        {
            *type_out = g_strdup("section");
        }
        if (value_out)
        {
            *value_out = g_strdup("");
        }
        if (can_expand_out)
        {
            *can_expand_out = true;
        }
        g_free(varpath);
        return true;
    }

    /* Strip Locals./Upvalues./Globals. prefix and pick first-segment resolver. */
    const char *lookup_path = varpath;
    wslua_lookup_first_kind_t lk_first = WSLUA_LOOKUP_FIRST_AUTO;
    if (g_str_has_prefix(varpath, "Locals."))
    {
        lookup_path = varpath + 7;
        lk_first = WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
    }
    else if (g_str_has_prefix(varpath, "Upvalues."))
    {
        lookup_path = varpath + 9;
        lk_first = WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
    }
    else if (g_str_has_prefix(varpath, "Globals."))
    {
        lookup_path = varpath + 8;
        lk_first = WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
    }

    if (!wslua_debugger_lookup_path(L, lookup_path, variable_stack_level,
                                    lk_first))
    {
        g_free(varpath);
        if (error_msg)
        {
            *error_msg = g_strdup("Path not found");
        }
        return false;
    }

    const bool globals_subtree = g_str_has_prefix(varpath, "Globals.") ||
                                 g_strcmp0(varpath, "Globals") == 0;
    g_free(varpath);

    if (type_out)
    {
        *type_out = wslua_debugger_format_value_type(L, -1);
    }
    if (value_out)
    {
        if (lua_type(L, -1) == LUA_TNIL)
        {
            *value_out = g_strdup("nil");
        }
        else
        {
            *value_out = wslua_debugger_describe_value(L, -1);
        }
    }
    if (can_expand_out)
    {
        /* Under Globals.*, namespace tables full of functions still expand so
         * class/proto tables stay navigable (same rule as get_variables). */
        if (globals_subtree && lua_istable(L, -1))
        {
            int64_t total = 0;
            wslua_debugger_basic_table_counts(L, -1, &total, NULL);
            *can_expand_out = total > 0;
        }
        else
        {
            *can_expand_out = wslua_debugger_value_can_expand(L, -1);
        }
    }
    lua_pop(L, 1);
    return true;
}

bool wslua_debugger_read_variable_value_full(const char *variable_path,
                                             char **value_out,
                                             char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!variable_path || !*variable_path)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty variable path");
        }
        return false;
    }

    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);

    if (!paused || !L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return false;
    }

    /* Mirror wslua_debugger_watch_read_root's first-segment resolver so
     * "Locals.x", "Upvalues.y" and "Globals.z" resolve from the intended
     * section even when a local shadows a global. */
    const char *lookup_path = variable_path;
    wslua_lookup_first_kind_t lk_first = WSLUA_LOOKUP_FIRST_AUTO;
    if (g_str_has_prefix(variable_path, "Locals."))
    {
        lookup_path = variable_path + 7;
        lk_first = WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
    }
    else if (g_str_has_prefix(variable_path, "Upvalues."))
    {
        lookup_path = variable_path + 9;
        lk_first = WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
    }
    else if (g_str_has_prefix(variable_path, "Globals."))
    {
        lookup_path = variable_path + 8;
        lk_first = WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
    }

    if (!wslua_debugger_lookup_path(L, lookup_path, variable_stack_level,
                                    lk_first))
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Path not found");
        }
        return false;
    }

    if (value_out)
    {
        if (lua_type(L, -1) == LUA_TNIL)
        {
            *value_out = g_strdup("nil");
        }
        else
        {
            *value_out = wslua_debugger_describe_value_ex(L, -1,
                                                          /*truncate=*/false);
        }
    }
    lua_pop(L, 1);
    return true;
}

/**
 * @brief Evaluate a Lua expression in the context of the paused debugger.
 *
 * This function evaluates the given expression using the paused Lua state.
 * It supports the '=' prefix shorthand: "=expr" becomes "return expr".
 *
 * An instruction-count hook is installed for the duration of the call so
 * that infinite loops are caught instead of hanging Wireshark.
 *
 * WARNING: The expression runs in the live dissector Lua state.  Modifying
 * globals (e.g. _G.some_proto = nil) can corrupt ongoing analysis.
 *
 * @param expression The Lua expression to evaluate.
 * @param error_msg Output pointer for error message (caller frees).
 * @return Result string (caller frees), or NULL on error.
 */
char *wslua_debugger_evaluate(const char *expression, char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!expression || !*expression)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty expression");
        }
        return NULL;
    }

    g_mutex_lock(&debugger.mutex);
    lua_State *L = debugger.paused_L;
    g_mutex_unlock(&debugger.mutex);
    if (!L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return NULL;
    }

    /* Save stack top to detect return values */
    int top_before = lua_gettop(L);

    char *code_to_eval =
        wslua_debugger_expression_compilable_chunk(L, expression, error_msg);
    if (!code_to_eval)
    {
        return NULL;
    }

    /* Load the string as a chunk */
    int load_result = luaL_loadstring(L, code_to_eval);
    g_free(code_to_eval);

    if (load_result != LUA_OK)
    {
        const char *lua_err = lua_tostring(L, -1);
        if (error_msg)
        {
            *error_msg = g_strdup(lua_err ? lua_err : "Syntax error");
        }
        lua_pop(L, 1); /* Pop error message */
        return NULL;
    }

    /*
     * Install hooks to abort runaway code:
     * - LUA_MASKCOUNT: fires after WSLUA_EVAL_INSTRUCTION_LIMIT instructions
     * - LUA_MASKCALL / LUA_MASKRET: tracks call depth to catch deep recursion
     *   that could overflow the C stack before the instruction limit fires
     */
    eval_call_depth = 0;
    lua_sethook(L, wslua_eval_timeout_hook,
                LUA_MASKCOUNT | LUA_MASKCALL | LUA_MASKRET,
                WSLUA_EVAL_INSTRUCTION_LIMIT);

    /* Execute the chunk */
    int call_result = lua_pcall(L, 0, LUA_MULTRET, 0);

    /* Remove the timeout hook regardless of outcome */
    lua_sethook(L, NULL, 0, 0);

    if (call_result != LUA_OK)
    {
        const char *lua_err = lua_tostring(L, -1);
        if (error_msg)
        {
            *error_msg = g_strdup(lua_err ? lua_err : "Runtime error");
        }
        lua_pop(L, 1); /* Pop error message */
        return NULL;
    }

    /* Check if there are return values */
    int top_after = lua_gettop(L);
    int num_results = top_after - top_before;

    if (num_results == 0)
    {
        return g_strdup(""); /* No return value */
    }

    /* Build result string from all return values */
    GString *result = g_string_new(NULL);
    for (int i = 0; i < num_results; i++)
    {
        int idx = top_before + 1 + i;
        if (i > 0)
        {
            g_string_append(result, "\t");
        }

        /* Use our existing describe_value function */
        char *value_str = wslua_debugger_describe_value(L, idx);
        if (value_str)
        {
            g_string_append(result, value_str);
            g_free(value_str);
        }
        else
        {
            g_string_append(result, "nil");
        }
    }

    /* Pop all return values */
    lua_pop(L, num_results);

    return g_string_free(result, FALSE);
}

/**
 * @brief Helper callback for wslua_debugger_foreach_loaded_script.
 *
 * This callback receives plugin descriptions from
 * wslua_plugins_get_descriptions and forwards only the filename to the user's
 * callback.
 */
static void loaded_script_description_callback(const char *name _U_,
                                               const char *version _U_,
                                               const char *description _U_,
                                               const char *filename,
                                               void *user_data)
{
    /* user_data is a two-element array: [0] = user callback, [1] = user data */
    void **context = (void **)user_data;
    wslua_debugger_loaded_script_callback_t user_callback =
        (wslua_debugger_loaded_script_callback_t)context[0];
    void *user_context = context[1];

    if (user_callback && filename)
    {
        user_callback(filename, user_context);
    }
}

/**
 * @brief Iterate over all currently loaded Lua plugin scripts.
 *
 * This function calls the provided callback once for each Lua script
 * that has been loaded by the Wireshark Lua subsystem.
 *
 * @param callback Function to call for each loaded script.
 * @param user_data Context pointer passed to the callback.
 */
void wslua_debugger_foreach_loaded_script(
    wslua_debugger_loaded_script_callback_t callback, void *user_data)
{
    if (!callback)
    {
        return;
    }

    /* Pack callback and user_data into array for inner callback */
    void *context[2] = {(void *)callback, user_data};
    wslua_plugins_get_descriptions(loaded_script_description_callback, context);
}
