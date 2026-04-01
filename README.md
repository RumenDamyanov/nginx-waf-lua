# nginx-waf-lua

OpenResty/Lua integration library for nginx-waf.

## Overview

nginx-waf-lua provides a Lua library for OpenResty that reads nginx-waf IP list
files, provides fast IP lookups, custom block responses, and runtime list management.

## Features

- Read nginx-waf IP list files
- Fast IP matching (IPv4/IPv6 + CIDR)
- Shared dict caching for performance
- Custom block response handling
- Runtime block/unblock with TTL
- Drop-in access phase handler

## Quick Start

```lua
-- In OpenResty nginx.conf
lua_shared_dict waf_cache 10m;

init_by_lua_block {
    local waf = require("resty.waf")
    waf.init({
        lists_dir = "/etc/nginx/waf-lists",
        shared_dict = "waf_cache",
    })
}

access_by_lua_block {
    local waf = require("resty.waf")
    waf.check_request()
}
```

## API

```lua
local waf = require("resty.waf")

waf.init(opts)                  -- Initialize with options
waf.is_blocked(ip)              -- Check if IP is blocked
waf.is_allowed(ip)              -- Check if IP is allowed
waf.check_request()             -- Full access phase handler
waf.block(ip, opts)             -- Block IP at runtime
waf.unblock(ip)                 -- Unblock IP
```

## Installation

### From OBS packages

Available for Fedora, openSUSE, Debian, and Ubuntu via
[OBS](https://build.opensuse.org/package/show/home:rumenx/nginx-waf-lua).

### From source

```bash
make install PREFIX=/usr/local/openresty
```

### From LuaRocks (future)

```bash
luarocks install nginx-waf-lua
```

## Related Projects

### nginx-waf Ecosystem

- [nginx-waf](https://github.com/RumenDamyanov/nginx-waf) - Core nginx module (required)
- [nginx-waf-api](https://github.com/RumenDamyanov/nginx-waf-api) - REST API for list management
- [nginx-waf-feeds](https://github.com/RumenDamyanov/nginx-waf-feeds) - Threat feed updater
- [nginx-waf-ui](https://github.com/RumenDamyanov/nginx-waf-ui) - Web management interface

### Other Nginx Modules

- [nginx-torblocker](https://github.com/RumenDamyanov/nginx-torblocker) - Control access from Tor exit nodes
- [nginx-cf-realip](https://github.com/RumenDamyanov/nginx-cf-realip) - Automatic Cloudflare IP list fetcher for real client IP restoration
- [nginx-gone](https://github.com/RumenDamyanov/nginx-gone) - Return HTTP 410 Gone for permanently removed URIs

## License

BSD 3-Clause License - see [LICENSE.md](LICENSE.md) for details.
