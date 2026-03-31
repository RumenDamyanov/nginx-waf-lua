-- nginx-waf-lua: IP matching utilities
-- Supports IPv4, IPv6 and CIDR notation
-- Compatible with LuaJIT (bit) and Lua 5.3+ (native operators)

local band, bor, lshift, rshift

local ok, bit = pcall(require, "bit")
if ok then
    -- LuaJIT / luabitop
    band = bit.band
    bor = bit.bor
    lshift = bit.lshift
    rshift = bit.rshift
else
    -- Lua 5.3+ native bitwise ops via load()
    local band2 = load("return function(a,b) return a & b end")()
    local bor2 = load("return function(a,b) return a | b end")()
    lshift = load("return function(a,n) return (a << n) & 0xFFFFFFFF end")()
    rshift = load("return function(a,n) return (a >> n) & 0xFFFFFFFF end")()
    -- Variadic wrappers (bit.band/bor accept multiple args)
    band = function(a, b, ...)
        local r = band2(a, b)
        for _, v in ipairs({...}) do r = band2(r, v) end
        return r
    end
    bor = function(a, b, ...)
        local r = bor2(a, b)
        for _, v in ipairs({...}) do r = bor2(r, v) end
        return r
    end
end

local _M = {}

local ipv4_pattern = "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
local cidr_v4_pattern = "^(%d+%.%d+%.%d+%.%d+)/(%d+)$"
local cidr_v6_pattern = "^([%x:]+)/(%d+)$"

--- Parse an IPv4 address to a 32-bit integer.
-- @param ip string
-- @return number|nil
function _M.parse_ipv4(ip)
    local a, b, c, d = ip:match(ipv4_pattern)
    if not a then
        return nil
    end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then
        return nil
    end
    return bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
end

--- Expand an IPv6 address to 8 groups of 16-bit integers.
-- @param ip string
-- @return table|nil: array of 8 numbers (16-bit each)
function _M.parse_ipv6(ip)
    -- Handle IPv4-mapped IPv6 (::ffff:1.2.3.4)
    local v4_suffix = ip:match("::ffff:(%d+%.%d+%.%d+%.%d+)$")
    if v4_suffix then
        local v4 = _M.parse_ipv4(v4_suffix)
        if not v4 then return nil end
        local hi = band(rshift(v4, 16), 0xFFFF)
        local lo = band(v4, 0xFFFF)
        return { 0, 0, 0, 0, 0, 0xFFFF, hi, lo }
    end

    -- Split on :: first
    local head, tail = ip:match("^(.-)::(.*)$")
    local groups = {}

    if head then
        local head_groups = {}
        if head ~= "" then
            for g in head:gmatch("[%x]+") do
                head_groups[#head_groups + 1] = tonumber(g, 16)
                if head_groups[#head_groups] > 0xFFFF then return nil end
            end
        end
        local tail_groups = {}
        if tail ~= "" then
            for g in tail:gmatch("[%x]+") do
                tail_groups[#tail_groups + 1] = tonumber(g, 16)
                if tail_groups[#tail_groups] > 0xFFFF then return nil end
            end
        end
        local missing = 8 - #head_groups - #tail_groups
        if missing < 0 then return nil end

        for i = 1, #head_groups do
            groups[#groups + 1] = head_groups[i]
        end
        for _ = 1, missing do
            groups[#groups + 1] = 0
        end
        for i = 1, #tail_groups do
            groups[#groups + 1] = tail_groups[i]
        end
    else
        for g in ip:gmatch("[%x]+") do
            groups[#groups + 1] = tonumber(g, 16)
            if groups[#groups] > 0xFFFF then return nil end
        end
    end

    if #groups ~= 8 then
        return nil
    end
    return groups
end

--- Check if an IP (string) matches an entry (IP or CIDR string).
-- @param ip string: the IP to check
-- @param entry string: the entry (plain IP or CIDR)
-- @return boolean
function _M.match(ip, entry)
    -- Try IPv4 CIDR
    local net, prefix = entry:match(cidr_v4_pattern)
    if net then
        local ip_num = _M.parse_ipv4(ip)
        local net_num = _M.parse_ipv4(net)
        if not ip_num or not net_num then
            return false
        end
        prefix = tonumber(prefix)
        if prefix < 0 or prefix > 32 then
            return false
        end
        if prefix == 0 then
            return true
        end
        local mask = lshift(0xFFFFFFFF, 32 - prefix)
        mask = band(mask, 0xFFFFFFFF)
        return band(ip_num, mask) == band(net_num, mask)
    end

    -- Try IPv6 CIDR
    local net6, prefix6 = entry:match(cidr_v6_pattern)
    if net6 then
        return _M.match_ipv6_cidr(ip, net6, tonumber(prefix6))
    end

    -- Plain IP comparison
    local ip4 = _M.parse_ipv4(ip)
    local entry4 = _M.parse_ipv4(entry)
    if ip4 and entry4 then
        return ip4 == entry4
    end

    local ip6 = _M.parse_ipv6(ip)
    local entry6 = _M.parse_ipv6(entry)
    if ip6 and entry6 then
        for i = 1, 8 do
            if ip6[i] ~= entry6[i] then
                return false
            end
        end
        return true
    end

    return false
end

--- Check if an IPv6 address matches a CIDR.
function _M.match_ipv6_cidr(ip, net, prefix)
    local ip_groups = _M.parse_ipv6(ip)
    local net_groups = _M.parse_ipv6(net)
    if not ip_groups or not net_groups then
        return false
    end
    if prefix < 0 or prefix > 128 then
        return false
    end
    if prefix == 0 then
        return true
    end

    local full_groups = math.floor(prefix / 16)
    local remaining = prefix % 16

    for i = 1, full_groups do
        if ip_groups[i] ~= net_groups[i] then
            return false
        end
    end

    if remaining > 0 and full_groups < 8 then
        local mask = lshift(0xFFFF, 16 - remaining)
        mask = band(mask, 0xFFFF)
        local idx = full_groups + 1
        if band(ip_groups[idx], mask) ~= band(net_groups[idx], mask) then
            return false
        end
    end

    return true
end

return _M
