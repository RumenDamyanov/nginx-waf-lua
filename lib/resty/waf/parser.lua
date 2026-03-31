-- nginx-waf-lua: IP list file parser
-- Reads plain-text IP list files compatible with nginx-waf

local _M = {}

--- Parse an IP list file and return a table of IP/CIDR entries.
-- Skips blank lines and lines starting with #.
-- @param path string: absolute path to the list file
-- @return table|nil: array of IP/CIDR strings, or nil on error
-- @return string|nil: error message
function _M.parse_file(path)
    local fh, err = io.open(path, "r")
    if not fh then
        return nil, "failed to open file: " .. (err or path)
    end

    local entries = {}
    local n = 0

    for line in fh:lines() do
        line = line:match("^%s*(.-)%s*$")  -- trim
        if line ~= "" and line:sub(1, 1) ~= "#" then
            n = n + 1
            entries[n] = line
        end
    end

    fh:close()
    return entries
end

--- Parse all .txt files in a directory.
-- @param dir string: directory containing IP list files
-- @return table: map of list_name => { entries }
-- @return string|nil: error message (first error encountered)
function _M.parse_dir(dir)
    local lfs_ok, lfs = pcall(require, "lfs")
    local lists = {}
    local first_err

    if lfs_ok then
        for fname in lfs.dir(dir) do
            if fname:match("%.txt$") then
                local name = fname:gsub("%.txt$", "")
                local path = dir .. "/" .. fname
                local entries, err = _M.parse_file(path)
                if entries then
                    lists[name] = entries
                elseif not first_err then
                    first_err = err
                end
            end
        end
    else
        -- Fallback: use os.execute + io.popen to list directory
        local cmd = "ls -1 " .. dir .. "/*.txt 2>/dev/null"
        local pipe = io.popen(cmd)
        if pipe then
            for fpath in pipe:lines() do
                local fname = fpath:match("([^/]+)$")
                if fname then
                    local name = fname:gsub("%.txt$", "")
                    local entries, err = _M.parse_file(fpath)
                    if entries then
                        lists[name] = entries
                    elseif not first_err then
                        first_err = err
                    end
                end
            end
            pipe:close()
        end
    end

    return lists, first_err
end

return _M
