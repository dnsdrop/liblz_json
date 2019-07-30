#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <ctype.h>

#include <liblz.h>
#include <liblz/lzapi.h>

#include "lz_json.h"
#include "lz_jsonL.h"

static int
js_number_to_lua_(lz_json * json, lua_State * L)
{
    lz_assert(L != NULL);

    if (lz_json_get_type(json) != lz_json_vtype_number)
    {
        return -1;
    }

    lua_pushnumber(L, lz_json_get_number(json));

    return 0;
}

static int
js_array_to_lua_(lz_json * json, lua_State * L)
{
    int             index;
    lz_tailq      * array;
    lz_tailq_elem * elem;
    lz_tailq_elem * temp;

    lz_assert(L != NULL);

    if (!(array = lz_json_get_array(json)))
    {
        return -1;
    }

    index = 1;

    lua_createtable(L, lz_tailq_size(array), 0);

    for (elem = lz_tailq_first(array); elem; elem = temp)
    {
        lz_json * val;

        val = (lz_json *)lz_tailq_elem_data(elem);

        if (val)
        {
            lua_pushnumber(L, index++);
            lz_json_to_lua(val, L);
            lua_settable(L, -3);
        }

        temp = lz_tailq_next(elem);
    }

    return 0;
}

static int
js_object_to_lua_(lz_json * json, lua_State * L)
{
    lz_kvmap     * object;
    lz_kvmap_ent * ent;
    lz_kvmap_ent * temp;

    lz_assert(L != NULL);

    if (!(object = lz_json_get_object(json)))
    {
        return -1;
    }

    lua_createtable(L, 0, lz_kvmap_get_size(object));


    for (ent = lz_kvmap_first(object); ent; ent = temp)
    {
        const char * key;
        lz_json    * val;

        key = lz_kvmap_ent_key(ent);
        val = lz_kvmap_ent_val(ent);

        if (val)
        {
            lua_pushlstring(L, key, lz_kvmap_ent_get_klen(ent));
            lz_json_to_lua(val, L);
            lua_settable(L, -3);
        }

        temp = lz_kvmap_next(ent);
    }

    return 0;
}

static int
js_string_to_lua_(lz_json * json, lua_State * L)
{
    const char * str;

    lz_assert(L != NULL);

    if (!(str = lz_json_get_string(json)))
    {
        return -1;
    }

    lua_pushlstring(L, str, (size_t)lz_json_get_size(json));

    return 0;
}

static lz_json *
js_from_lua_idx_(lua_State * L, int idx)
{
    lz_json * parent = NULL;

    /* T X, let idx = -2 */

    /* T X NIL */
    lua_pushnil(L);

    while (lua_next(L, /* -2 */ idx - 1))
    {
        lz_json    * ent;
        int          key_type;
        int          val_type;
        const char * key = NULL;

        key_type = lua_type(L, -2);
        val_type = lua_type(L, -1);

        if (parent == NULL)
        {
            switch (key_type) {
                case LUA_TNUMBER:
                    parent = lz_json_array_new();
                    break;
                case LUA_TSTRING:
                    parent = lz_json_object_new();
                    break;
                default:
                    return NULL;
            }
        }

        switch (val_type) {
            case LUA_TNUMBER:
                ent = lz_json_number_new(lua_tointeger(L, -1));
                break;
            case LUA_TSTRING:
                ent = lz_json_string_new(lua_tostring(L, -1));
                break;
            case LUA_TTABLE:
                ent = js_from_lua_idx_(L, -1);
                break;
            default:
                ent = NULL;
                break;
        }

        lua_pop(L, 1);

        if (ent == NULL)
        {
            continue;
        }

        val_type = lua_type(L, -1);

        if (val_type == LUA_TSTRING)
        {
            key = lua_tostring(L, -1);
        }

        lz_json_add(parent, key, ent);
    }

    return parent;
} /* js_from_lua_idx_ */

static lz_json *
_lz_j_from_lua(lua_State * L)
{
    if (L == NULL)
    {
        return NULL;
    }

    if (lua_type(L, -1) != LUA_TTABLE)
    {
        return NULL;
    }

    return js_from_lua_idx_(L, -1);
}

int
lz_json_to_lua(lz_json * json, lua_State * L)
{
    if (!json || !L)
    {
        return -1;
    }

    switch (lz_json_get_type(json)) {
        case lz_json_vtype_number:
            return js_number_to_lua_(json, L);
        case lz_json_vtype_array:
            return js_array_to_lua_(json, L);
        case lz_json_vtype_object:
            return js_object_to_lua_(json, L);
        case lz_json_vtype_string:
            return js_string_to_lua_(json, L);
        default:
            lua_pushnil(L);
            return -1;
    }

    return 0;
}

lz_json *
lz_json_from_lua(lua_State * L)
{
    return _lz_j_from_lua(L);
}

