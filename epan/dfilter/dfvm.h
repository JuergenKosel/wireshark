/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DFVM_H
#define DFVM_H

#include <wsutil/regex.h>
#include "dfilter-int.h"
#include "syntax-tree.h"
#include "drange.h"
#include "dfunctions.h"

#define ASSERT_DFVM_OP_NOT_REACHED(op) \
	ws_error("Invalid dfvm opcode '%s'.", dfvm_opcode_tostr(op))

typedef enum {
	EMPTY,
	FVALUE,
	HFINFO,
	RAW_HFINFO,
	HFINFO_VS,
	INSN_NUMBER,
	REGISTER,
	INTEGER,
	DRANGE,
	FUNCTION_DEF,
	PCRE,
} dfvm_value_type_t;

/**
 * @brief Represents a typed value used in display filter virtual machine (DFVM) operations.
 *
 * This structure encapsulates a single value of a specific type, used during
 * display filter evaluation. The value may be numeric, a range, a field reference,
 * a function definition, or a compiled regular expression.
 */
typedef struct {
	dfvm_value_type_t type; /**< Type of the value (e.g., numeric, range, regex). */

	union {
		GPtrArray *fvalue_p;           /**< Pointer to a array of fvalue. */
		uint32_t numeric;              /**< Numeric value. */
		drange_t *drange;              /**< Pointer to a display range. */
		header_field_info *hfinfo;     /**< Pointer to header field metadata. */
		df_func_def_t *funcdef;        /**< Pointer to a display filter function definition. */
		ws_regex_t *pcre;              /**< Pointer to a compiled regular expression. */
	} value;

	int ref_count; /**< Reference count for memory management. */
} dfvm_value_t;

#define dfvm_value_get_fvalue(val) ((val)->value.fvalue_p->pdata[0])

typedef enum {
	DFVM_NULL,	/* Null/invalid opcode */
	DFVM_IF_TRUE_GOTO,
	DFVM_IF_FALSE_GOTO,
	DFVM_CHECK_EXISTS,
	DFVM_CHECK_EXISTS_R,
	DFVM_NOT,
	DFVM_RETURN,
	DFVM_READ_TREE,
	DFVM_READ_TREE_R,
	DFVM_READ_REFERENCE,
	DFVM_READ_REFERENCE_R,
	DFVM_PUT_FVALUE,
	DFVM_ALL_EQ,
	DFVM_ANY_EQ,
	DFVM_ALL_NE,
	DFVM_ANY_NE,
	DFVM_ALL_GT,
	DFVM_ANY_GT,
	DFVM_ALL_GE,
	DFVM_ANY_GE,
	DFVM_ALL_LT,
	DFVM_ANY_LT,
	DFVM_ALL_LE,
	DFVM_ANY_LE,
	DFVM_ALL_CONTAINS,
	DFVM_ANY_CONTAINS,
	DFVM_ALL_MATCHES,
	DFVM_ANY_MATCHES,
	DFVM_SET_ALL_IN,
	DFVM_SET_ANY_IN,
	DFVM_SET_ALL_NOT_IN,
	DFVM_SET_ANY_NOT_IN,
	DFVM_SET_ADD,
	DFVM_SET_ADD_RANGE,
	DFVM_SET_CLEAR,
	DFVM_SLICE,
	DFVM_LENGTH,
	DFVM_BITWISE_AND,
	DFVM_UNARY_MINUS,
	DFVM_ADD,
	DFVM_SUBTRACT,
	DFVM_MULTIPLY,
	DFVM_DIVIDE,
	DFVM_MODULO,
	DFVM_CALL_FUNCTION,
	DFVM_STACK_PUSH,
	DFVM_STACK_POP,
	DFVM_NOT_ALL_ZERO,
	DFVM_NO_OP,
} dfvm_opcode_t;

/**
 * @brief Converts a DFVM opcode to its string representation.
 *
 * @param code The DFVM opcode to convert.
 * @return const char* A string representing the opcode.
 */
const char *
dfvm_opcode_tostr(dfvm_opcode_t code);

typedef struct {
	int		id;
	dfvm_opcode_t	op;
	dfvm_value_t	*arg1;
	dfvm_value_t	*arg2;
	dfvm_value_t	*arg3;
} dfvm_insn_t;

/**
 * @brief Creates a new DFVM instruction with the specified opcode.
 *
 * @param op The operation code for the new instruction.
 * @return A pointer to the newly created dfvm_insn_t structure.
 */
dfvm_insn_t*
dfvm_insn_new(dfvm_opcode_t op);

/**
 * @brief Replaces an instruction with a no-op.
 *
 * This function replaces the given instruction with a no-op (no operation) instruction.
 * It unrefs any arguments associated with the original instruction before setting it to no-op.
 *
 * @param insn Pointer to the instruction to be replaced.
 */
void
dfvm_insn_replace_no_op(dfvm_insn_t *insn);

/**
 * @brief Free a DFVM instruction.
 *
 * This function frees a DFVM instruction and unrefs any arguments it may have.
 *
 * @param insn The DFVM instruction to free.
 */
void
dfvm_insn_free(dfvm_insn_t *insn);

/**
 * @brief Create a new DFVM value.
 *
 * @param type The type of the value to create.
 * @return A pointer to the newly created dfvm_value_t.
 */
dfvm_value_t*
dfvm_value_new(dfvm_value_type_t type);

/**
 * @brief Increment the reference count of a dfvm_value_t.
 *
 * @param v Pointer to the dfvm_value_t whose reference count is to be incremented.
 * @return The same pointer to the dfvm_value_t.
 */
dfvm_value_t*
dfvm_value_ref(dfvm_value_t *v);

/**
 * @brief Decrements the reference count of a dfvm_value_t object and frees it if the reference count reaches zero.
 *
 * @param v Pointer to the dfvm_value_t object to be unreferenced.
 */
void
dfvm_value_unref(dfvm_value_t *v);

/**
 * @brief Creates a new DFVM value of type FVALUE.
 *
 * @param fv Pointer to the fvalue_t structure.
 * @return dfvm_value_t* Pointer to the newly created DFVM value.
 */
dfvm_value_t*
dfvm_value_new_fvalue(fvalue_t *fv);

/**
 * @brief Create a new dfvm_value_t with header field information.
 *
 * @param hfinfo Pointer to the header field information.
 * @param raw Flag indicating if the value is in raw format.
 * @param val_str Flag indicating if the value is a string.
 * @return dfvm_value_t* Pointer to the newly created dfvm_value_t.
 */
dfvm_value_t*
dfvm_value_new_hfinfo(header_field_info *hfinfo, bool raw, bool val_str);

/**
 * @brief Creates a new dfvm_value_t representing a register.
 *
 * @param reg The register value to be stored in the dfvm_value_t.
 * @return A pointer to the newly created dfvm_value_t.
 */
dfvm_value_t*
dfvm_value_new_register(int reg);

/**
 * @brief Creates a new dfvm_value_t with type DRANGE.
 *
 * @param dr Pointer to the drange_t structure.
 * @return A pointer to the newly created dfvm_value_t.
 */
dfvm_value_t*
dfvm_value_new_drange(drange_t *dr);

/**
 * @brief Create a new DFVM value of type FUNCTION_DEF.
 *
 * @param funcdef Pointer to the function definition.
 * @return dfvm_value_t* Pointer to the newly created DFVM value.
 */
dfvm_value_t*
dfvm_value_new_funcdef(df_func_def_t *funcdef);

/**
 * @brief Creates a new PCRE value.
 *
 * @param re The PCRE regular expression to be stored in the value.
 * @return A pointer to the newly created PCRE value.
 */
dfvm_value_t*
dfvm_value_new_pcre(ws_regex_t *re);

/**
 * @brief Create a new DFVM value with an unsigned integer.
 *
 * @param num The unsigned integer value to store in the new DFVM value.
 * @return dfvm_value_t* A pointer to the newly created DFVM value.
 */
dfvm_value_t*
dfvm_value_new_uint(unsigned num);

/**
 * @brief Dumps the bytecode of a dfilter_t to a file.
 *
 * @param f The file pointer where the bytecode will be written.
 * @param df The dfilter_t whose bytecode is to be dumped.
 * @param flags Flags that control the dumping process.
 */
void
dfvm_dump(FILE *f, dfilter_t *df, uint16_t flags);

/**
 * @brief Dumps a string representation of a dfilter.
 *
 * @param alloc Memory allocator for the buffer.
 * @param df The dfilter to dump.
 * @param flags Flags controlling what information is included in the dump.
 * @return A wmem_strbuf_t containing the dumped string.
 */
char *
dfvm_dump_str(wmem_allocator_t *alloc, dfilter_t *df,  uint16_t flags);

/**
 * @brief Applies a display filter to a protocol tree.
 *
 * @param df The display filter to apply.
 * @param tree The protocol tree to which the filter will be applied.
 * @return true if the filter was successfully applied, false otherwise.
 */
bool
dfvm_apply(dfilter_t *df, proto_tree *tree);

/**
 * @brief Apply a full Dissector Filter VM (DFVM) to a protocol tree.
 *
 * This function executes all instructions in the DFVM on the given protocol tree,
 * updating the filter values accordingly.
 *
 * @param df The Dissector Filter VM to apply.
 * @param tree The protocol tree to process.
 * @param fvals Pointer to an array of filter values, or NULL if not needed.
 */
bool
dfvm_apply_full(dfilter_t *df, proto_tree *tree, GPtrArray **fvals);

/**
 * @brief Retrieves the raw value of a field as a GByteArray.
 *
 * @param fi Pointer to the field_info structure containing the field information.
 * @return A GByteArray containing the raw value of the field, or NULL if an error occurs.
 */
fvalue_t *
dfvm_get_raw_fvalue(const field_info *fi);

#endif
