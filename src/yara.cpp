
extern "C" {
    #include <yara.h>

    #include <lua.h>
    #include <lualib.h>
    #include <lauxlib.h>
}


static size_t read(void* ptr, size_t size, size_t count, void* p)
{
    memcpy(ptr, p, size * count);
    return count;
}

static size_t write(const void* ptr, size_t size, size_t count, void* p)
{
    memcpy(p, ptr, size * count);
    return count;
}

static YR_STREAM memory_stream(void* ptr, size_t size)
{
    return YR_STREAM { ptr, read, write };
}

static void init_yara()
{
    static bool inited = false;
    if (!inited)
    {
        yr_initialize();
        inited = true;
    }
}

static int rules_call(lua_State *L)
{
    auto rules = *((YR_RULES**)lua_touserdata(L, 1));
    const uint8_t *ptr = nullptr;
    size_t size = 0;
    if (lua_type(L, 2) == LUA_TSTRING)
    {
        ptr = (const uint8_t*)lua_tolstring(L, 2, &size);
        lua_pushvalue(L, 3);
        luaL_checktype(L, 3, LUA_TFUNCTION);
    }
    else
    {
        ptr = (const uint8_t*)luaL_checkinteger(L, 2);
        size = luaL_checkinteger(L, 3);
    }
    luaL_checktype(L, 4, LUA_TFUNCTION);

    if (!ptr) luaL_argerror(L, 2, "string or integer");
    auto r = yr_rules_scan_mem(rules, ptr, size, 0, [](YR_SCAN_CONTEXT* c, int msg, void* data, void* user)
    {
        auto L = (lua_State*)user;
        int result = CALLBACK_CONTINUE;
        switch (msg)
        {
        case CALLBACK_MSG_RULE_MATCHING:
        {
            YR_MATCH *match;
            auto r = (YR_RULE*)data;
            if (r->strings)
            {
                yr_string_matches_foreach(c, r->strings, match)
                {
                    lua_pushvalue(L, 4);
                    lua_pushstring(L, r->identifier);
                    lua_pushinteger(L, match->offset);
                    lua_pushinteger(L, match->match_length);
                    if (lua_pcall(L, 3, 1, 0) != 0)
                    {
                        return CALLBACK_ERROR;
                    }
                    auto abort = lua_isboolean(L, -1) && lua_toboolean(L, -1) == 0;
                    lua_pop(L, 1);
                    if (abort) return CALLBACK_ABORT;
                }
            }
            else
            {
                lua_pushvalue(L, 4);
                lua_pushstring(L, r->identifier);
                if (lua_pcall(L, 1, 1, 0) != 0)
                {
                    return CALLBACK_ERROR;
                }
                auto abort = lua_isboolean(L, -1) && lua_toboolean(L, -1) == 0;
                lua_pop(L, 1);
                if (abort) return CALLBACK_ABORT;
            }
            break;
        }
        }
        return result;
    }, L, 3000);

    if (r)
    {
        lua_pushinteger(L, r);
        if (r == ERROR_CALLBACK_ERROR)
            lua_pushvalue(L, -2);
        else
            lua_pushnil(L);
        return 2;
    }
    return 0;
}

static int rules_gc(lua_State *L)
{
    yr_rules_destroy(*(YR_RULES**)lua_touserdata(L, 1));
    return 0;
}

static void lua_push_yararules(lua_State *L, YR_RULES *rules)
{
    static int refmeta = 0;

    assert(rules != nullptr);
    *(YR_RULES**)lua_newuserdata(L, sizeof(rules)) = rules;

    if (!refmeta)
    {
        lua_createtable(L, 0, 2);
        lua_pushcfunction(L, rules_call);
        lua_setfield(L, -2, "__call");
        lua_pushcfunction(L, rules_gc);
        lua_setfield(L, -2, "__gc");
        refmeta = luaL_ref(L, LUA_REGISTRYINDEX);
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, refmeta);
    lua_setmetatable(L, -2);
}

#define CHK_YARA_ERROR(stat) if (int _err_ = stat) { \
    lua_pushnil(L); lua_pushinteger(L, _err_); return 2; \
}

int loadYara(lua_State *L)
{
    init_yara();

    size_t size = 0;
    auto rule = lua_tolstring(L, 3, &size);
    YR_STREAM s = memory_stream((void*)rule, size);
    YR_RULES *rules = nullptr;
    CHK_YARA_ERROR(yr_rules_load_stream(&s, &rules));
    lua_push_yararules(L, rules);
    return 1;
}

int compile_yara(lua_State *L)
{
    init_yara();

    YR_COMPILER *cl = nullptr;
    CHK_YARA_ERROR(yr_compiler_create(&cl));
    CHK_YARA_ERROR(yr_compiler_add_string(cl, luaL_checkstring(L, 1), nullptr));

    YR_RULES *rules = nullptr;
    CHK_YARA_ERROR(yr_compiler_get_rules(cl, &rules));
    yr_compiler_destroy(cl);

    lua_push_yararules(L, rules);
    return 1;
}

extern "C" __declspec(dllexport) int luaopen_yara(lua_State *L)
{
    lua_createtable(L, 0, 2);
    lua_pushcfunction(L, compile_yara);
    lua_setfield(L, -2, "compile");
    return 1;
}