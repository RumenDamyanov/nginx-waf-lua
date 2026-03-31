# vim:set ft= ts=4 sw=4 et:

use Test::Nginx::Socket 'no_plan';

no_long_string();
run_tests();

__DATA__

=== TEST 1: load module
--- config
    location /t {
        content_by_lua_block {
            local waf = require("resty.waf")
            ngx.say(waf._VERSION)
        }
    }
--- request
GET /t
--- response_body
0.1.0
--- no_error_log
[error]
