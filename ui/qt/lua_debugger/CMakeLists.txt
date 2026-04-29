# CMakeLists.txt
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

set(WIRESHARK_LUA_DEBUGGER_HEADERS
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_code_view.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_item_utils.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_dialog.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_find_frame.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_goto_line_frame.h
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_pause_overlay.h
)

set(WIRESHARK_LUA_DEBUGGER_SRCS
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_code_view.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_dialog.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_find_frame.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_goto_line_frame.cpp
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_pause_overlay.cpp
)

set(WIRESHARK_LUA_DEBUGGER_UI
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_dialog.ui
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_find_frame.ui
	${CMAKE_CURRENT_LIST_DIR}/lua_debugger_goto_line_frame.ui
)
