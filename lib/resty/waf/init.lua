-- nginx-waf-lua: OpenResty integration for nginx-waf
-- Copyright (c) 2025-2026 Rumen Damyanov
-- BSD 3-Clause License

local parser = require("resty.waf.parser")
local ip_mod = require("resty.waf.ip")

local ngx = ngx
local shared = ngx and ngx.shared

local _M = {
    _VERSION = "0.1.0",
}

local _opts = {}
local _dict = nil
local _lists = {}     -- fallback: in-memory table when no shared dict
local _initialized = false

local LIST_PREFIX = "waf:list:"
local DYN_PREFIX = "waf:dyn:"
local META_KEY = "waf:meta:loaded_at"

--- Initialize the WAF module.
-- Must be called from init_by_lua or init_worker_by_lua.
-- @param opts table with:
--   lists_dir (string, required): path to nginx-waf list files
--   shared_dict (string, optional): name of lua_shared_dict for caching
--   reload_interval (number, optional): seconds between file re-reads (default 60)
--   allow_lists (table, optional): list names to use as allowlists
--   block_status (number, optional): HTTP status for blocked requests (default 403)
--   block_message (string, optional): response body for blocked requests
function _M.init(opts)
    if not opts or not opts.lists_dir then
        return nil, "lists_dir is required"
    end

    _opts = {
        lists_dir = opts.lists_dir,
        shared_dict = opts.shared_dict,
        reload_interval = opts.reload_interval or 60,
        allow_lists = opts.allow_lists or {},
        block_status = opts.block_status or 403,
        block_message = opts.block_message or "Forbidden\n",
    }

    -- Set up shared dict if available
    if _opts.shared_dict and shared then
        _dict = shared[_opts.shared_dict]
        if not _dict then
            return nil, "shared dict not found: " .. _opts.shared_dict
        end
    end

    -- Initial load
    local ok, err = _M.reload()
    if not ok then
        return nil, "initial load failed: " .. (err or "unknown")
    end

    _initialized = true
    return true
end

--- Reload all IP list files from disk.
-- Can be called from init_by_lua, init_worker_by_lua, or timer callbacks.
-- @return boolean, string|nil
function _M.reload()
    local lists, err = parser.parse_dir(_opts.lists_dir)
    if not lists then
        return nil, err
    end

    if _dict then
        -- Store each entry in shared dict for cross-worker access
        -- Format: "waf:list:<listname>:<ip>" = true
        -- First flush old list entries
        _dict:flush_all()
        _dict:flush_expired()

        for name, entries in pairs(lists) do
            for _, entry in ipairs(entries) do
                local key = LIST_PREFIX .. name .. ":" .. entry
                _dict:set(key, true)
            end
        end
        _dict:set(META_KEY, ngx.now())
    else
        -- In-memory fallback (single worker only)
        _lists = lists
    end

    return true
end

--- Build an allow set for quick lookup.
local function is_allow_list(name)
    for _, n in ipairs(_opts.allow_lists) do
        if n == name then
            return true
        end
    end
    return false
end

--- Check if an IP is blocked by any blocklist.
-- @param check_ip string: IP address to check
-- @return boolean: true if blocked
-- @return string|nil: name of the list that matched
function _M.is_blocked(check_ip)
    if not _initialized then
        return false, "not initialized"
    end

    if _dict then
        return _M._check_dict_blocked(check_ip)
    end
    return _M._check_mem_blocked(check_ip)
end

--- Check if an IP is in any allowlist.
-- @param check_ip string
-- @return boolean
function _M.is_allowed(check_ip)
    if not _initialized then
        return false
    end

    if _dict then
        return _M._check_dict_allowed(check_ip)
    end
    return _M._check_mem_allowed(check_ip)
end

--- Full access phase handler.
-- Call from access_by_lua_block. Returns 403 (or configured status) for blocked IPs.
function _M.check_request()
    if not _initialized then
        ngx.log(ngx.WARN, "nginx-waf-lua: not initialized, allowing request")
        return
    end

    local remote_ip = ngx.var.remote_addr
    if not remote_ip then
        return
    end

    -- Check allowlist first
    if _M.is_allowed(remote_ip) then
        return
    end

    -- Check dynamic blocks
    if _M._check_dynamic(remote_ip) then
        ngx.log(ngx.WARN, "nginx-waf-lua: dynamic block: ", remote_ip)
        ngx.exit(_opts.block_status)
        return
    end

    -- Check blocklists
    local blocked, list_name = _M.is_blocked(remote_ip)
    if blocked then
        ngx.log(ngx.WARN, "nginx-waf-lua: blocked ", remote_ip, " by list: ", list_name)
        ngx.exit(_opts.block_status)
        return
    end
end

--- Block an IP at runtime (stored in shared dict with optional TTL).
-- @param block_ip string: IP to block
-- @param opts table|nil: { ttl = seconds, reason = string }
-- @return boolean, string|nil
function _M.block(block_ip, opts)
    if not _dict then
        return nil, "shared dict required for dynamic blocks"
    end
    opts = opts or {}
    local key = DYN_PREFIX .. block_ip
    local ttl = opts.ttl or 0  -- 0 means no expiry
    local ok, err = _dict:set(key, opts.reason or "blocked", ttl)
    if not ok then
        return nil, "failed to set dynamic block: " .. (err or "unknown")
    end
    return true
end

--- Unblock a dynamically blocked IP.
-- @param unblock_ip string
-- @return boolean
function _M.unblock(unblock_ip)
    if not _dict then
        return nil, "shared dict required for dynamic blocks"
    end
    _dict:delete(DYN_PREFIX .. unblock_ip)
    return true
end

-- Internal: check dynamic blocks via shared dict
function _M._check_dynamic(check_ip)
    if not _dict then
        return false
    end
    local val = _dict:get(DYN_PREFIX .. check_ip)
    return val ~= nil
end

-- Internal: check blocklists via shared dict
function _M._check_dict_blocked(check_ip)
    -- For exact match, check directly
    local keys = _dict:get_keys(0)
    for _, key in ipairs(keys) do
        local list_name, entry = key:match("^" .. LIST_PREFIX .. "([^:]+):(.+)$")
        if list_name and not is_allow_list(list_name) then
            if ip_mod.match(check_ip, entry) then
                return true, list_name
            end
        end
    end
    return false
end

-- Internal: check allowlists via shared dict
function _M._check_dict_allowed(check_ip)
    local keys = _dict:get_keys(0)
    for _, key in ipairs(keys) do
        local list_name, entry = key:match("^" .. LIST_PREFIX .. "([^:]+):(.+)$")
        if list_name and is_allow_list(list_name) then
            if ip_mod.match(check_ip, entry) then
                return true
            end
        end
    end
    return false
end

-- Internal: check blocklists in memory
function _M._check_mem_blocked(check_ip)
    for name, entries in pairs(_lists) do
        if not is_allow_list(name) then
            for _, entry in ipairs(entries) do
                if ip_mod.match(check_ip, entry) then
                    return true, name
                end
            end
        end
    end
    return false
end

-- Internal: check allowlists in memory
function _M._check_mem_allowed(check_ip)
    for name, entries in pairs(_lists) do
        if is_allow_list(name) then
            for _, entry in ipairs(entries) do
                if ip_mod.match(check_ip, entry) then
                    return true
                end
            end
        end
    end
    return false
end

return _M
