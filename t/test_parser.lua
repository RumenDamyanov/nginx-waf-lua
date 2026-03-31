-- Standalone unit tests for resty.waf.parser
-- Run with: lua t/test_parser.lua (from project root)

package.path = "lib/?.lua;lib/?/init.lua;" .. package.path

local parser = require("resty.waf.parser")

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

-- Create temp files for testing
local tmpdir = os.tmpname()
os.remove(tmpdir)
os.execute("mkdir -p " .. tmpdir)

-- Write a test list file
local f = io.open(tmpdir .. "/blocklist.txt", "w")
f:write("# Block list\n")
f:write("192.168.1.1\n")
f:write("10.0.0.0/8\n")
f:write("\n")
f:write("# Another comment\n")
f:write("2001:db8::1\n")
f:close()

-- Write a second list
f = io.open(tmpdir .. "/allowlist.txt", "w")
f:write("172.16.0.0/12\n")
f:close()

-- Write a non-txt file (should be ignored)
f = io.open(tmpdir .. "/readme.md", "w")
f:write("ignore me\n")
f:close()

print("=== parse_file ===")
local entries, err = parser.parse_file(tmpdir .. "/blocklist.txt")
assert_eq("no error", err, nil)
assert_eq("entry count", #entries, 3)
assert_eq("first entry", entries[1], "192.168.1.1")
assert_eq("second entry", entries[2], "10.0.0.0/8")
assert_eq("third entry", entries[3], "2001:db8::1")

print("\n=== parse_file missing ===")
local entries2, err2 = parser.parse_file(tmpdir .. "/nonexistent.txt")
assert_eq("returns nil", entries2, nil)
assert_eq("has error", err2 ~= nil, true)

print("\n=== parse_dir ===")
local lists, derr = parser.parse_dir(tmpdir)
assert_eq("blocklist exists", lists["blocklist"] ~= nil, true)
assert_eq("allowlist exists", lists["allowlist"] ~= nil, true)
assert_eq("readme ignored", lists["readme"] == nil, true)
if lists["blocklist"] then
    assert_eq("blocklist count", #lists["blocklist"], 3)
end
if lists["allowlist"] then
    assert_eq("allowlist count", #lists["allowlist"], 1)
end

-- Cleanup
os.execute("rm -rf " .. tmpdir)

print("\n=== Results ===")
print(string.format("Passed: %d  Failed: %d  Total: %d", pass_count, fail_count, pass_count + fail_count))
if fail_count > 0 then
    os.exit(1)
end
