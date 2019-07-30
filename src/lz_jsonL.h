#ifndef __LZ_JSONL_H__
#define __LZ_JSONL_H__

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <stdbool.h>


/**
 * @brief converts a lz_json context to the native LUA datatype
 *
 * @param json
 * @param L
 *
 * @return
 */
LZ_EXPORT int lz_json_to_lua(lz_json * json, lua_State * L);


/**
 * @brief converts data from the LUA stack to a lz_json context
 *
 * @param L
 *
 * @return
 */
LZ_EXPORT lz_json * lz_json_from_lua(lua_State * L);

#endif

