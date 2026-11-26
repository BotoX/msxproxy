FROM openresty/openresty:bookworm-fat AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates git \
        libssl-dev libpcre2-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Install required Lua rocks into /usr/local/openresty/luajit
RUN luarocks install lua-resty-openidc \
    && luarocks install lua-resty-openssl

# Build context is ngx_http_upstream_ntlm_module
COPY config ngx_http_upstream_ntlm_module.c /usr/local/src/ngx_http_upstream_ntlm_module/

# Build ngx_http_upstream_ntlm_module.so against the exact OpenResty version in this image
RUN set -eu; \
    OPENRESTY_VER="$(/usr/local/openresty/bin/openresty -v 2>&1 | sed -n 's|.*openresty/\([0-9.]*\).*|\1|p')"; \
    echo "Building ngx_http_upstream_ntlm_module for OpenResty ${OPENRESTY_VER}"; \
    cd /usr/local/src; \
    curl -fsSLO "https://openresty.org/download/openresty-${OPENRESTY_VER}.tar.gz"; \
    tar -xzf "openresty-${OPENRESTY_VER}.tar.gz"; \
    cd "openresty-${OPENRESTY_VER}"; \
    CC_OPT='-O2 -DNGX_LUA_ABORT_AT_PANIC'; \
    LD_OPT='-Wl,-rpath,/usr/local/openresty/luajit/lib'; \
    if [ -d /usr/local/openresty/openssl3/include ]; then \
        CC_OPT="${CC_OPT} -I/usr/local/openresty/zlib/include -I/usr/local/openresty/pcre2/include -I/usr/local/openresty/openssl3/include"; \
        LD_OPT="${LD_OPT} -L/usr/local/openresty/zlib/lib -L/usr/local/openresty/pcre2/lib -L/usr/local/openresty/openssl3/lib -Wl,-rpath,/usr/local/openresty/zlib/lib:/usr/local/openresty/pcre2/lib:/usr/local/openresty/openssl3/lib"; \
    fi; \
    ./configure \
        --prefix=/usr/local/openresty/nginx \
        --with-cc-opt="${CC_OPT}" \
        --with-ld-opt="${LD_OPT}" \
        --with-pcre-jit \
        --with-stream \
        --without-mail_pop3_module \
        --without-mail_imap_module \
        --without-mail_smtp_module \
        --with-threads \
        --with-compat \
        --with-http_v2_module \
        --with-http_ssl_module \
        --add-dynamic-module=/usr/local/src/ngx_http_upstream_ntlm_module \
        -j"$(nproc)"; \
    make -j"$(nproc)"; \
    mkdir -p /usr/local/openresty/modules; \
    cp build/nginx-*/objs/ngx_http_upstream_ntlm_module.so /usr/local/openresty/modules/

FROM openresty/openresty:bookworm

COPY --from=builder /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so
COPY --from=builder /usr/local/openresty/luajit/share/lua/5.1 /usr/local/openresty/luajit/share/lua/5.1
COPY --from=builder /usr/local/openresty/luajit/lib/lua/5.1 /usr/local/openresty/luajit/lib/lua/5.1

RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
