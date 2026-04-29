/* wslua_debugger.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSLUA_DEBUGGER_H__
#define __WSLUA_DEBUGGER_H__

#include "ws_symbol_export.h"
#include <glib.h>
#include <stdbool.h>

typedef struct lua_State lua_State;

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Debugger state enum.
     */
    typedef enum
    {
        WSLUA_DEBUGGER_OFF,     /**< Debugger is off */
        WSLUA_DEBUGGER_RUNNING, /**< Debugger is running (enabled but not
                                   paused) */
        WSLUA_DEBUGGER_PAUSED   /**< Debugger is paused at a breakpoint */
    } wslua_debugger_state_t;

    /**
     * @brief Code view theme enum.
     */
    typedef enum
    {
        WSLUA_DEBUGGER_THEME_AUTO = 0, /**< Follow Wireshark theme (default) */
        WSLUA_DEBUGGER_THEME_DARK = 1, /**< Dark theme */
        WSLUA_DEBUGGER_THEME_LIGHT = 2 /**< Light theme */
    } wslua_debugger_theme_t;

    /**
     * @brief Breakpoint structure for in-memory storage.
     *
     * Breakpoints are persisted via the Qt UI's JSON settings file,
     * not via Wireshark's UAT system.
     */
    typedef struct _wslua_breakpoint_t
    {
        char *file_path; /**< File path of the script */
        int64_t line;    /**< Line number */
        bool active;     /**< Whether the breakpoint is active */
    } wslua_breakpoint_t;

    /**
     * @brief Initialize the debugger subsystem.
     * @param L The Lua state.
     */
    WS_DLL_PUBLIC void wslua_debugger_init(lua_State *L);

    /**
     * @brief Check if debugger is enabled.
     * @return true if enabled, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_is_enabled(void);

    /**
     * @brief Enable or disable the debugger.
     * @param enabled true to enable, false to disable.
     */
    WS_DLL_PUBLIC void wslua_debugger_set_enabled(bool enabled);

    /**
     * @brief Set whether the user asked to keep the debugger off.
     *
     * When @a user_wants_debugger_stay_off is true, also invalidates
     * @c was_enabled_before_reload so a pending
     * wslua_debugger_restore_after_reload() will not re-enable. When false,
     * the user has explicitly enabled the debugger in the UI again; auto-enable
     * and restore logic may then apply.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_user_explicitly_disabled(bool user_wants_debugger_stay_off);

    /**
     * @brief True if the UI may enable the debugger for active breakpoints
     *        and similar (false when the user has asked the debugger to stay
     *        off). Does not consider capture; the UI may combine this with
     *        e.g. live-capture gating.
     */
    WS_DLL_PUBLIC bool
    wslua_debugger_may_auto_enable_for_breakpoints(void);

    /**
     * @brief Clear state saved for wslua_debugger_restore_after_reload() so
     *        a pending call will not re-enable. Call e.g. when the debugger
     *        dialog is closed and no delayed restore is desired.
     */
    WS_DLL_PUBLIC void wslua_debugger_renounce_restore_after_reload(void);

    /**
     * @brief Callback type for UI update when paused.
     * @param file_path The file path where execution is paused.
     * @param line The line number where execution is paused.
     */
    typedef void (*wslua_debugger_ui_update_cb_t)(const char *file_path,
                                                  int64_t line);

    /**
     * @brief Register the UI callback.
     * @param cb The callback function.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_register_ui_callback(wslua_debugger_ui_update_cb_t cb);

    /**
     * @brief Continue execution from a paused state.
     */
    WS_DLL_PUBLIC void wslua_debugger_continue(void);

    /**
     * @brief Step into the next executed line (enters called functions).
     *
     * Resumes execution and pauses at the very next line hook,
     * regardless of breakpoints.
     */
    WS_DLL_PUBLIC void wslua_debugger_step_in(void);

    /**
     * @brief Step over the current line (skips line hooks inside callees).
     *
     * Resumes execution and pauses at the next line hook that runs in the
     * current stack frame or an outer frame (after returns).
     */
    WS_DLL_PUBLIC void wslua_debugger_step_over(void);

    /**
     * @brief Step out of the current function (pause in the caller).
     *
     * If there is only one Lua stack frame, behaves like
     * wslua_debugger_continue().
     */
    WS_DLL_PUBLIC void wslua_debugger_step_out(void);

    /**
     * @brief Set which call stack frame supplies Locals and Upvalues in the
     *        variables view.
     *
     * @a level is the index passed to @c lua_getstack (0 = innermost Lua/C
     * activation). Globals are unaffected. If the debugger is not paused, the
     * value is still stored for the next pause.
     */
    WS_DLL_PUBLIC void wslua_debugger_set_variable_stack_level(int32_t level);

    /**
     * @brief Current variable-inspection stack level (see
     *        wslua_debugger_set_variable_stack_level()).
     */
    WS_DLL_PUBLIC int32_t wslua_debugger_get_variable_stack_level(void);

    /**
     * @brief Suggest a stack frame index for a path-style watch (same indices as
     *        wslua_debugger_set_variable_stack_level / lua_getstack: 0 = innermost).
     *
     * @c Globals.… and section-only specs return -1. @c Locals.… searches locals
     * only; @c Upvalues.… searches upvalues only; unqualified specs try locals
     * (innermost first) then upvalues. Returns -1 when not paused or no match.
     */
    WS_DLL_PUBLIC int32_t wslua_debugger_find_stack_level_for_watch_spec(
        const char *spec);

    /**
     * @brief Run execution until a specific line is reached.
     * @param file_path The file path.
     * @param line The line number.
     */
    WS_DLL_PUBLIC void wslua_debugger_run_to_line(const char *file_path,
                                                  int64_t line);

    /**
     * @brief Add a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     */
    WS_DLL_PUBLIC void wslua_debugger_add_breakpoint(const char *file_path,
                                                     int64_t line);

    /**
     * @brief Remove a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     */
    WS_DLL_PUBLIC void wslua_debugger_remove_breakpoint(const char *file_path,
                                                        int64_t line);

    /**
     * @brief Set the active state of a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     * @param active The new active state.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_active(const char *file_path, int64_t line,
                                         bool active);

    /**
     * @brief Clear all breakpoints.
     */
    WS_DLL_PUBLIC void wslua_debugger_clear_breakpoints(void);

    /**
     * @brief Get the state of a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     * @return 1 if active, 0 if inactive, -1 if not found.
     */
    WS_DLL_PUBLIC int32_t
    wslua_debugger_get_breakpoint_state(const char *file_path, int64_t line);

    /**
     * @brief Get breakpoint state using an already-canonical path.
     *
     * Like wslua_debugger_get_breakpoint_state() but skips path
     * canonicalization. Use with wslua_debugger_canonical_path() to
     * avoid repeated allocations when checking many lines in one file.
     *
     * @param canonical_path A canonical file path.
     * @param line The line number.
     * @return 1 if active, 0 if inactive, -1 if not found.
     */
    WS_DLL_PUBLIC int32_t
    wslua_debugger_get_breakpoint_state_canonical(
        const char *canonical_path, int64_t line);

    /**
     * @brief Return a newly allocated canonical path.
     * @param file_path The raw file path.
     * @return Canonical path (caller must g_free), or NULL on failure.
     */
    WS_DLL_PUBLIC char *wslua_debugger_canonical_path(const char *file_path);

    /**
     * @brief Variable structure for inspection.
     */
    typedef struct
    {
        char *name;  /**< Variable name */
        char *value; /**< Variable value as string */
        char *type;  /**< Variable type (e.g. "string", "number", "table") */
        bool can_expand; /**< true when the debugger can drill into children */
    } wslua_variable_t;

    /**
     * @brief Stack frame structure.
     */
    typedef struct
    {
        char *source;        /**< Source filename */
        int64_t line;        /**< Currently-executing line */
        int64_t linedefined; /**< First line of the function's definition; together
                                  with @c source forms a stable identity for this
                                  Lua activation (used by the Qt dialog to decide
                                  whether the previous-pause Locals/Upvalues
                                  baseline still refers to the same function). */
        char *name;          /**< Function name */
    } wslua_stack_frame_t;

    /**
     * @brief Get the current stack trace.
     * @param frame_count Output pointer for the number of frames.
     * @return Array of stack frames. Caller must free using
     * wslua_debugger_free_stack.
     */
    WS_DLL_PUBLIC wslua_stack_frame_t *
    wslua_debugger_get_stack(int32_t *frame_count);

    /**
     * @brief Free the stack trace array.
     * @param stack The stack array.
     * @param frame_count The number of frames.
     */
    WS_DLL_PUBLIC void wslua_debugger_free_stack(wslua_stack_frame_t *stack,
                                                 int32_t frame_count);

    /**
     * @brief Get variables for a specific path.
     * @param path The path to the variable (e.g. "a.b[1]"). NULL or empty for
     * root (Locals, Upvalues, Globals).
     * @param variable_count Output pointer for the number of variables.
     * @return Array of variables. Caller must free using
     * wslua_debugger_free_variables.
     */
    WS_DLL_PUBLIC wslua_variable_t *
    wslua_debugger_get_variables(const char *path, int32_t *variable_count);

    /**
     * @brief Free the variables array.
     * @param vars The variables array.
     * @param variable_count The number of variables.
     */
    WS_DLL_PUBLIC void wslua_debugger_free_variables(wslua_variable_t *vars,
                                                     int32_t variable_count);

    /**
     * @brief Get the total number of breakpoints.
     * @return The number of breakpoints.
     */
    WS_DLL_PUBLIC unsigned wslua_debugger_get_breakpoint_count(void);

    /**
     * @brief Get breakpoint details by index.
     * @param idx The index of the breakpoint.
     * @param file_path Output pointer for the file path.
     * @param line Output pointer for the line number.
     * @param active Output pointer for the active state.
     * @return true if found, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_get_breakpoint(unsigned idx,
                                                     const char **file_path,
                                                     int64_t *line,
                                                     bool *active);

    /**
     * @brief Callback type for reload notification.
     *
     * This callback is invoked BEFORE Lua plugins are reloaded, allowing
     * the UI to reload script files from disk before they are executed.
     */
    typedef void (*wslua_debugger_reload_callback_t)(void);

    /**
     * @brief Register a callback to be notified before Lua plugins are
     * reloaded.
     *
     * The callback is invoked by wslua_reload_plugins() BEFORE any Lua scripts
     * are unloaded or reloaded. This allows the debugger UI to:
     * - Reload script files from disk (user may have edited them)
     * - Prepare for potential breakpoints during reload
     *
     * @param callback The callback function, or NULL to unregister.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_reload_callback(
        wslua_debugger_reload_callback_t callback);

    /**
     * @brief Notify the debugger that a reload is about to happen.
     *
     * Saves the debugger enabled state, disables the debugger, detaches
     * from the current Lua state, and calls the reload callback so the
     * UI can refresh script files from disk.
     *
     * If the debugger is paused, it is disabled (which continues
     * execution) and the reload callback is invoked so the UI can exit
     * its nested event loop and schedule a deferred reload.
     *
     * @return true if the caller should proceed with the reload;
     *         false if the reload was deferred (debugger was paused).
     */
    WS_DLL_PUBLIC bool wslua_debugger_notify_reload(void);

    /**
     * @brief Callback type for post-reload notification.
     *
     * This callback is invoked AFTER Lua plugins have been reloaded,
     * allowing the UI to refresh the file tree with newly loaded scripts.
     */
    typedef void (*wslua_debugger_post_reload_callback_t)(void);

    /**
     * @brief Register a callback to be notified after Lua plugins are
     * reloaded.
     *
     * The callback is invoked by wslua_reload_plugins() AFTER all Lua scripts
     * have been loaded. This allows the debugger UI to refresh the file tree
     * with the newly loaded scripts.
     *
     * @param callback The callback function, or NULL to unregister.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_post_reload_callback(
        wslua_debugger_post_reload_callback_t callback);

    /**
     * @brief Notify registered listeners that a reload has completed.
     *
     * Called internally by wslua_reload_plugins() after reloading.
     * Clears the reload_in_progress flag and invokes the registered
     * post-reload callback.  Does NOT re-enable the debugger.
     */
    WS_DLL_PUBLIC void wslua_debugger_notify_post_reload(void);

    /**
     * @brief Re-enable the debugger after a reload + cf_reload cycle.
     *
     * If the debugger was enabled before the reload, re-enable it.
     * Must be called AFTER cf_reload / redissectPackets completes.
     */
    WS_DLL_PUBLIC void wslua_debugger_restore_after_reload(void);

    /**
     * @brief Evaluate a Lua expression in the context of the paused debugger.
     *
     * This function evaluates the given expression using the paused Lua state.
     * It can only be called when the debugger is paused at a breakpoint.
     *
     * If the expression starts with '=', it is treated as a return statement
     * (e.g., "=x" becomes "return x"). This allows easy inspection of values.
     *
     * @param expression The Lua expression to evaluate.
     * @param error_msg Output pointer for error message if evaluation fails.
     *                  Caller must free with g_free() if non-NULL.
     * @return The result as a string (caller must free with g_free()),
     *         or NULL if evaluation failed (check error_msg).
     */
    WS_DLL_PUBLIC char *wslua_debugger_evaluate(const char *expression,
                                                char **error_msg);

    /**
     * @brief Check if the debugger is currently paused.
     * @return true if paused at a breakpoint, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_is_paused(void);

    /**
     * @brief Callback type for script-loaded notification.
     *
     * This callback is invoked each time a Lua script file is loaded
     * by the Wireshark Lua subsystem. It provides the full path to the
     * script file, allowing the debugger UI to update its file tree.
     *
     * @param file_path The full path to the loaded Lua script file.
     */
    typedef void (*wslua_debugger_script_loaded_callback_t)(
        const char *file_path);

    /**
     * @brief Register a callback to be notified when a Lua script is loaded.
     *
     * The callback is invoked each time a Lua plugin script is loaded,
     * allowing the debugger UI to add the file to its file tree immediately.
     *
     * @param callback The callback function, or NULL to unregister.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_script_loaded_callback(
        wslua_debugger_script_loaded_callback_t callback);

    /**
     * @brief Notify the debugger that a Lua script has been loaded.
     *
     * Called internally by the Lua loader (init_wslua.c) when a script
     * is successfully loaded. This triggers the registered callback.
     *
     * @param file_path The full path to the loaded script file.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_notify_script_loaded(const char *file_path);

    /**
     * @brief Callback type for iterating over loaded Lua scripts.
     *
     * @param file_path The full path to the loaded Lua script file.
     * @param user_data User-provided context pointer.
     */
    typedef void (*wslua_debugger_loaded_script_callback_t)(
        const char *file_path, void *user_data);

    /**
     * @brief Iterate over all currently loaded Lua plugin scripts.
     *
     * This function calls the provided callback once for each Lua script
     * that has been loaded by the Wireshark Lua subsystem. This includes
     * scripts from both the global and personal plugin directories.
     *
     * Use this to populate the debugger's file tree with actually loaded
     * scripts rather than scanning directories.
     *
     * @param callback Function to call for each loaded script.
     * @param user_data Context pointer passed to the callback.
     */
    WS_DLL_PUBLIC void wslua_debugger_foreach_loaded_script(
        wslua_debugger_loaded_script_callback_t callback, void *user_data);

    /*
     * Watch path APIs (below) take @c debugger.mutex when they touch the
     * paused Lua state. Call them from the same execution context as the Lua
     * debugger UI (typically the Qt GUI thread), matching
     * @ref wslua_debugger_get_variables and other variable accessors. Do not
     * interleave them with code that resumes the debugger or replaces
     * @c paused_L from another thread.
     */

    /** Maximum count of '.' and '[' in a canonical watch path (same metric as the Qt Watch panel; enforced in wslua_debugger_watch_canonical_path()). */
#define WSLUA_WATCH_MAX_PATH_SEGMENTS 32

    /**
     * @brief True when @a spec resolves like a Variables path: @c Locals./
     *        @c Upvalues./ @c Globals. prefix, a section root name, or a
     *        single identifier (meaning @c Locals.name).
     *
     * The parser tolerates leading/trailing whitespace, the @c _G / @c _G.
     * alias for @c Globals / @c Globals., whitespace around @c "." outside
     * bracket string literals, and @c \\" / @c \\\\ escapes inside @c "..."
     * / @c '...' bracket keys.
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_spec_uses_path_resolution(
        const char *spec);

    /**
     * @brief Full variable-tree path for path-style specs (e.g. @c Locals.foo
     *        for @c "foo"). Caller must @c g_free when non-NULL.
     * @return NULL for non-path specs (operators, calls, invalid paths).
     */
    WS_DLL_PUBLIC char *wslua_debugger_watch_variable_path_for_spec(
        const char *spec);

    /**
     * @brief Full variable-tree path for UI (e.g. tooltips) matching Variables resolution.
     *
     * For unqualified specs, the first path segment is resolved in the same order as
     * variable lookup (locals, then upvalues, then globals), so a global-only name
     * maps to @c Globals.name rather than @c Locals.name.
     *
     * When the debugger is not paused, falls back to
     * wslua_debugger_watch_variable_path_for_spec(). Caller must @c g_free when non-NULL.
     */
    WS_DLL_PUBLIC char *wslua_debugger_watch_resolved_variable_path_for_spec(
        const char *spec);

    /**
     * @brief Read root Value/Type/expand for one watch while paused.
     *
     * @a spec must validate as a path under
     * wslua_debugger_watch_spec_uses_path_resolution(); otherwise the call
     * fails with an "Invalid watch path" error.
     *
     * Children (if any) are fetched with wslua_debugger_get_variables() on
     * the path returned by
     * wslua_debugger_watch_resolved_variable_path_for_spec().
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_read_root(
        const char *spec, char **value_out, char **type_out,
        bool *can_expand_out, char **error_msg);

    /**
     * @brief Read the full, untruncated value of a resolved variable path
     *        while the debugger is paused.
     *
     * Unlike the preview returned by @ref wslua_debugger_watch_read_root
     * or @ref wslua_debugger_get_variables — which cap the stringified
     * value at an internal display limit — this variant returns the
     * complete @c luaL_tolstring() output so the UI can offer a true
     * "Copy value" action for both watch roots and nested sub-elements.
     *
     * @p variable_path uses the same surface syntax as the Variables tree
     * (e.g. @c Locals.foo, @c Globals.bar[1].baz); the leading
     * @c Locals./Upvalues./Globals. prefix selects the resolution
     * section exactly as in @ref wslua_debugger_watch_read_root.
     *
     * Tables are still summarised as @c "table[N]" since a table has no
     * meaningful full-text form; binary string values (e.g. @c Tvb
     * @c __tostring output) are preserved verbatim including embedded
     * NULs.
     *
     * @param variable_path Resolved variable path.
     * @param value_out Output pointer; caller frees with g_free().
     * @param error_msg Optional error description; caller frees with g_free().
     * @return true on success, false on error.
     */
    WS_DLL_PUBLIC bool wslua_debugger_read_variable_value_full(
        const char *variable_path, char **value_out, char **error_msg);

#ifdef __cplusplus
}
#endif

#endif /* __WSLUA_DEBUGGER_H__ */
