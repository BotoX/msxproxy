-- Test-environment OpenResty configuration (loaded from /etc/msxproxy/config.lua)

return {
    hosts = {
        webmail      = "webmail.localhost:18443",
        exchange     = "exchange.test.local",
        autodiscover = "autodiscover.localhost:18443",
    },

    oidc = {
        msx_tenant_id = "00000000-0000-0000-0000-000000000000",

        local_issuer = "https://keycloak.localhost:18444/realms/TestRealm",
        audience     = "https_webmail.localhost",

        direct_grant = {
            client_id     = "https_webmail.localhost_DirectGrant",
            client_secret = "test-direct-grant-secret-0002",
            timeout       = 5000,
        },

        owa = {
            client_id      = "https_webmail.localhost",
            client_secret  = "test-owa-client-secret-0001",
            redirect_uri   = "/owa/redirect_uri",
            logout_path    = "/owa/logout",
            session_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        },
    },

    -- Deterministic 32-byte test MAC/AES key (base64 of 32 bytes)
    mac_key_b64 = "bXN4cHJveHktdGVzdC1tYWMta2V5LTMyLWJ5dGVzISE=",

    s4u2api = {
        host    = "s4u2api",
        port    = 7777,
        spn     = "http",
        timeout = 5000,
    },

    ratelimit = {
        base_bantime = 60,
        findtime     = 12 * 3600,
        maxretry     = 50,
        max_bantime  = 15 * 60,
    },

    activesync_enroll = {
        enabled   = true,
        -- Short cache TTL so E2E enrollment tests observe newly enrolled devices immediately
        cache_ttl = 1,
    },
}
