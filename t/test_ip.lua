-- Standalone unit tests for resty.waf.ip
-- Run with: lua t/test_ip.lua (from project root)

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local ip = require("resty.waf.ip")

local pass_count = 0
local fail_count = 0

local function assert_eq(name, got, expected)
    if got == expected then
        pass_count = pass_count + 1
        io.write("  PASS: " .. name .. "\n")
    else
        fail_count = fail_count + 1
        io.write("  FAIL: " .. name .. " (got: " .. tostring(got) .. ", expected: " .. tostring(expected) .. ")\n")
    end
end

local function assert_true(name, val)
    assert_eq(name, val, true)
end

local function assert_false(name, val)
    assert_eq(name, not not val, false)
end

local function assert_nil(name, val)
    if val == nil then
        pass_count = pass_count + 1
        io.write("  PASS: " .. name .. "\n")
    else
        fail_count = fail_count + 1
        io.write("  FAIL: " .. name .. " (got: " .. tostring(val) .. ", expected: nil)\n")
    end
end

print("=== IPv4 Parsing ===")
assert_true("parse 127.0.0.1", ip.parse_ipv4("127.0.0.1") ~= nil)
assert_true("parse 0.0.0.0", ip.parse_ipv4("0.0.0.0") ~= nil)
assert_true("parse 255.255.255.255", ip.parse_ipv4("255.255.255.255") ~= nil)
assert_nil("invalid: 256.0.0.1", ip.parse_ipv4("256.0.0.1"))
assert_nil("invalid: not-an-ip", ip.parse_ipv4("not-an-ip"))
assert_nil("invalid: empty", ip.parse_ipv4(""))

print("\n=== IPv6 Parsing ===")
assert_true("parse ::1", ip.parse_ipv6("::1") ~= nil)
assert_true("parse fe80::1", ip.parse_ipv6("fe80::1") ~= nil)
assert_true("parse 2001:db8::1", ip.parse_ipv6("2001:db8::1") ~= nil)
assert_true("parse full", ip.parse_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") ~= nil)
assert_true("parse ::ffff:192.168.1.1", ip.parse_ipv6("::ffff:192.168.1.1") ~= nil)
assert_nil("invalid: too many groups", ip.parse_ipv6("1:2:3:4:5:6:7:8:9"))
assert_nil("invalid: empty", ip.parse_ipv6(""))

print("\n=== IPv4 Matching ===")
assert_true("exact match", ip.match("192.168.1.1", "192.168.1.1"))
assert_false("exact no match", ip.match("192.168.1.1", "192.168.1.2"))
assert_true("CIDR /24 match", ip.match("10.0.0.55", "10.0.0.0/24"))
assert_false("CIDR /24 no match", ip.match("10.0.1.55", "10.0.0.0/24"))
assert_true("CIDR /8 match", ip.match("10.255.255.255", "10.0.0.0/8"))
assert_false("CIDR /8 no match", ip.match("11.0.0.1", "10.0.0.0/8"))
assert_true("CIDR /32 match", ip.match("192.168.1.1", "192.168.1.1/32"))
assert_true("CIDR /0 matches all", ip.match("1.2.3.4", "0.0.0.0/0"))
assert_true("CIDR /16 match", ip.match("172.16.5.10", "172.16.0.0/16"))

print("\n=== IPv6 Matching ===")
assert_true("v6 exact", ip.match("2001:db8::1", "2001:db8::1"))
assert_false("v6 no match", ip.match("2001:db8::1", "2001:db8::2"))
assert_true("v6 CIDR /48", ip.match("2001:db8:1::99", "2001:db8:1::/48"))
assert_false("v6 CIDR /48 no match", ip.match("2001:db8:2::1", "2001:db8:1::/48"))
assert_true("v6 CIDR /128", ip.match("::1", "::1/128"))
assert_true("v6 CIDR /0 all", ip.match("fe80::1", "::/0"))

print("\n=== Cross-type ===")
assert_false("v4 vs v6", ip.match("192.168.1.1", "::1"))
assert_false("v6 vs v4", ip.match("::1", "192.168.1.1"))

print("\n=== Results ===")
print(string.format("Passed: %d  Failed: %d  Total: %d", pass_count, fail_count, pass_count + fail_count))
if fail_count > 0 then
    os.exit(1)
end
