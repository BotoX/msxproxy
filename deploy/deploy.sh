#!/usr/bin/env bash
# deploy/deploy.sh — Install, check, reload, or safely upgrade msxproxy from git.
#
# Usage:
#   sudo ./deploy/deploy.sh install           # First-time Ubuntu setup (idempotent)
#   sudo ./deploy/deploy.sh update [git-ref]  # Pull/checkout, test, nginx -t, reload/restart
#   sudo ./deploy/deploy.sh reload            # Zero-downtime reload of OpenResty & mailproxy (certs/config)
#   sudo ./deploy/deploy.sh check             # Verify symlinks, /etc/msxproxy configs, tests & nginx -t
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ETC_DIR="${MSXPROXY_ETC_DIR:-/etc/msxproxy}"
OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty/nginx}"
OPENRESTY_BIN="${OPENRESTY_BIN:-${OPENRESTY_PREFIX}/sbin/nginx}"
OPENRESTY_SERVICE="${OPENRESTY_SERVICE:-openresty}"
OPENRESTY_GROUP="${OPENRESTY_GROUP:-nogroup}"

log()  { printf '[msxproxy] %s\n' "$*"; }
warn() { printf '[msxproxy] WARNING: %s\n' "$*" >&2; }
die()  { printf '[msxproxy] ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "Please run as root (sudo $0 $*)."
    fi
}

ensure_user() {
    local user="$1" home="$2"
    if ! id -u "${user}" >/dev/null 2>&1; then
        log "Creating system user '${user}'..."
        useradd -r -m -d "${home}" -s /usr/sbin/nologin -K UMASK=0077 "${user}"
    fi
}

link_file() {
    local src="$1" dst="$2"
    mkdir -p "$(dirname "${dst}")"
    ln -sfn "${src}" "${dst}"
    log "Linked ${dst} -> ${src}"
}

install_config_template() {
    local src="$1" dst="$2" group="$3"
    if [[ ! -f "${dst}" ]]; then
        cp "${src}" "${dst}"
        chmod 0640 "${dst}"
        if getent group "${group}" >/dev/null 2>&1; then
            chgrp "${group}" "${dst}"
        fi
        log "Created ${dst} from $(basename "${src}") — edit before starting services!"
    else
        log "Keeping existing ${dst}"
    fi
}

run_tests() {
    log "Running offline test suite..."
    if python3 -m pytest --version >/dev/null 2>&1; then
        (cd "${REPO_DIR}" && python3 -m pytest -q)
    elif command -v luajit >/dev/null 2>&1; then
        warn "pytest not installed; running LuaJIT tests only."
        luajit "${REPO_DIR}/tests/test_openresty.lua"
        luajit "${REPO_DIR}/tests/test_openresty_e2e.lua"
    else
        warn "Neither pytest nor luajit found; skipping automated tests."
    fi
}

check_nginx() {
    if [[ -x "${OPENRESTY_BIN}" ]]; then
        log "Testing OpenResty configuration (${OPENRESTY_BIN} -t)..."
        "${OPENRESTY_BIN}" -t
    else
        warn "OpenResty binary not found at ${OPENRESTY_BIN}; skipping nginx -t."
    fi
}

cmd_install() {
    require_root "$@"

    if [[ "${REPO_DIR}" != "/opt/msxproxy" ]]; then
        warn "Repo is at ${REPO_DIR} (systemd units and msxproxy-http.conf expect /opt/msxproxy)."
    fi

    # 1. System users
    ensure_user s4u2api /var/lib/s4u2api
    ensure_user mailproxy /var/lib/mailproxy
    if getent group valkey >/dev/null 2>&1; then
        usermod -aG valkey s4u2api
    fi

    # 2. /etc/msxproxy configs (directory 0755 so each service user can read only its own 0640 file)
    mkdir -p "${ETC_DIR}"
    chmod 0755 "${ETC_DIR}"

    install_config_template "${REPO_DIR}/deploy/etc/config.lua.example"     "${ETC_DIR}/config.lua"     "${OPENRESTY_GROUP}"
    install_config_template "${REPO_DIR}/deploy/etc/mailproxy.toml.example" "${ETC_DIR}/mailproxy.toml" mailproxy
    install_config_template "${REPO_DIR}/deploy/etc/s4u2api.toml.example"   "${ETC_DIR}/s4u2api.toml"   s4u2api

    # 3. Symlink systemd units and tmpfiles.d rule
    link_file "${REPO_DIR}/deploy/systemd/s4u2api.service" /etc/systemd/system/s4u2api.service
    link_file "${REPO_DIR}/deploy/systemd/mailproxy.service" /etc/systemd/system/mailproxy.service
    link_file "${REPO_DIR}/deploy/tmpfiles.d/s4u2api.conf" /etc/tmpfiles.d/s4u2api.conf

    systemd-tmpfiles --create /etc/tmpfiles.d/s4u2api.conf
    systemctl daemon-reload

    cat <<EOF

[msxproxy] Install complete! Next steps:
  1. Edit configs in ${ETC_DIR}/:
       - ${ETC_DIR}/config.lua      (OpenResty hosts, OIDC secrets, MAC/session keys)
       - ${ETC_DIR}/mailproxy.toml  (IMAP/SMTP backends, OIDC client_secret, cert paths)
       - ${ETC_DIR}/s4u2api.toml    (OIDC, Valkey socket, Kerberos principal & SPNs)
  2. Place the Kerberos keytab (chmod 0600, owned by root:root):
       - ${ETC_DIR}/krb5_keytab
  3. Ensure /usr/local/openresty/nginx/conf/nginx.conf contains:
       load_module /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so;
     and inside http {}:
       include /opt/msxproxy/deploy/openresty/msxproxy-http.conf;
  4. Verify with: sudo ${REPO_DIR}/deploy/deploy.sh check
  5. Enable & start services:
       systemctl enable --now s4u2api mailproxy ${OPENRESTY_SERVICE}
EOF
}

cmd_check() {
    log "Checking deployment state..."
    for f in config.lua mailproxy.toml s4u2api.toml; do
        [[ -f "${ETC_DIR}/${f}" ]] || die "Missing ${ETC_DIR}/${f}"
        if grep -q "CHANGE_ME" "${ETC_DIR}/${f}" 2>/dev/null; then
            warn "${ETC_DIR}/${f} still contains CHANGE_ME placeholders!"
        fi
    done
    [[ -f "${ETC_DIR}/krb5_keytab" ]] || warn "Missing ${ETC_DIR}/krb5_keytab"

    run_tests
    check_nginx
    log "All checks passed."
}

cmd_reload() {
    require_root "$@"
    check_nginx

    if systemctl is-active --quiet "${OPENRESTY_SERVICE}"; then
        log "Gracefully reloading ${OPENRESTY_SERVICE}..."
        systemctl reload "${OPENRESTY_SERVICE}"
    fi
    if systemctl is-active --quiet mailproxy; then
        log "Hot-reloading mailproxy (SIGHUP: config, TLS certs, JWKS)..."
        systemctl reload mailproxy
    fi
}

cmd_update() {
    require_root "$@"
    local target_ref="${1:-}"

    cd "${REPO_DIR}"
    if [[ -n "${target_ref}" ]]; then
        log "Fetching and checking out '${target_ref}'..."
        git fetch --tags origin
        git checkout "${target_ref}"
    else
        log "Pulling latest commits (fast-forward only)..."
        git pull --ff-only
    fi

    # Verify tests & nginx config BEFORE touching live services
    run_tests
    systemd-tmpfiles --create /etc/tmpfiles.d/s4u2api.conf
    systemctl daemon-reload
    check_nginx

    if systemctl is-active --quiet "${OPENRESTY_SERVICE}"; then
        log "Gracefully reloading ${OPENRESTY_SERVICE}..."
        systemctl reload "${OPENRESTY_SERVICE}"
    fi

    for svc in s4u2api mailproxy; do
        if systemctl is-active --quiet "${svc}"; then
            log "Restarting ${svc}..."
            systemctl restart "${svc}"
        fi
    done

    log "Update complete ($(git rev-parse --short HEAD))."
    systemctl --no-pager --lines=0 status "${OPENRESTY_SERVICE}" s4u2api mailproxy || true
}

case "${1:-}" in
    install) shift; cmd_install "$@" ;;
    update)  shift; cmd_update "$@" ;;
    reload)  shift; cmd_reload "$@" ;;
    check)   shift; cmd_check "$@" ;;
    *)
        echo "Usage: $0 {install|update [git-ref]|reload|check}" >&2
        exit 1
        ;;
esac
