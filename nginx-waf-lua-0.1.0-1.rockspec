package = "nginx-waf-lua"
version = "0.1.0-1"
source = {
    url = "git://github.com/RumenDamyanov/nginx-waf-lua",
    tag = "v0.1.0",
}
description = {
    summary = "OpenResty/Lua integration for nginx-waf",
    detailed = [[
        Lua library for OpenResty that reads nginx-waf IP list files
        and provides fast IP lookups, custom block responses, and
        runtime list management.
    ]],
    homepage = "https://github.com/RumenDamyanov/nginx-waf-lua",
    license = "BSD-3-Clause",
    maintainer = "Rumen Damyanov <contact@rumenx.com>",
}
dependencies = {
    "lua >= 5.1",
}
build = {
    type = "builtin",
    modules = {
        ["resty.waf.init"] = "lib/resty/waf/init.lua",
        ["resty.waf.parser"] = "lib/resty/waf/parser.lua",
        ["resty.waf.ip"] = "lib/resty/waf/ip.lua",
    },
}
