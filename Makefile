PREFIX ?= /usr/local/openresty
LUA_LIB_DIR ?= $(PREFIX)/lualib

.PHONY: install test clean

install:
	mkdir -p $(DESTDIR)$(LUA_LIB_DIR)/resty/waf
	cp lib/resty/waf/*.lua $(DESTDIR)$(LUA_LIB_DIR)/resty/waf/

test:
	@echo "Running unit tests..."
	lua t/test_ip.lua
	lua t/test_parser.lua
	@echo "All unit tests passed."

clean:
	rm -rf t/servroot/
