# openresty-config
For Microsoft Exchange Proxy

`load_module /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so;`

```
    proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

    # lua-resty-upstream-healthcheck
    lua_shared_dict healthcheck 1m;
    lua_socket_log_errors off;

    # cache for discovery metadata documents
    lua_shared_dict discovery 1m;

    # cache for JWKs
    lua_shared_dict jwks 1m;

    # cache for JWT verification results
    lua_shared_dict jwt_verification 100m;
    lua_shared_dict introspection 100m;

    lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

    lua_package_path "$prefix/conf/lua/?.lua;;";
```

## Dependencies

[lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc/tree/master)

Using `luarocks` execute the following:
```
luarocks install lua-resty-openidc
```

[upstream-ntlm-nginx-module](https://github.com/BotoX/upstream-ntlm-nginx-module)  
[OpenResty prerequisites](https://openresty.org/en/installation.html#prerequisites)

```
tar -xvf openresty-VERSION.tar.gz
cd openresty-VERSION/

./configure --prefix=/usr/local/openresty/nginx --with-cc-opt='-O2 -DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/zlib/include -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include' --with-ld-opt='-Wl,-rpath,/usr/local/openresty/luajit/lib -L/usr/local/openresty/zlib/lib -L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/zlib/lib:/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib' --with-pcre-jit --with-stream --without-mail_pop3_module --without-mail_imap_module --without-mail_smtp_module --with-threads --with-compat --with-http_v2_module --with-http_ssl_module --add-dynamic-module=../upstream-ntlm-nginx-module -j8

make -j

cp ./build/nginx-*/objs/ngx_http_upstream_ntlm_module.so /usr/local/openresty/modules
```
