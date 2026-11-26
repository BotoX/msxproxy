#!/usr/bin/env bash
# deploy/deploy.sh — Install, check, reload, or safely upgrade msxproxy from git.
#
# Usage:
#   sudo ./deploy/deploy.sh install            # First-time Ubuntu setup (idempotent)
#   sudo ./deploy/deploy.sh up [service...]    # Start core (+ enabled activesync-enroll) or named services
#   sudo ./deploy/deploy.sh down               # Stop msxproxy services
#   sudo ./deploy/deploy.sh reload [service...]        # Zero-downtime reload (all active or named services)
#   sudo ./deploy/deploy.sh restart [service...]       # Restart services (all active or named services)
#   sudo ./deploy/deploy.sh update [git-ref]           # Pull/checkout, test, nginx -t, reload/restart
#   ./deploy/deploy.sh status [service...]             # Show systemd service status
#   ./deploy/deploy.sh check                           # Verify symlinks, /etc/msxproxy configs, offline tests & nginx -t
#   ./deploy/deploy.sh test [args...]                  # Run live smoke test (tests/smoke_test.py)
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ETC_DIR="${MSXPROXY_ETC_DIR:-/etc/msxproxy}"
OPENRESTY_PREFIX="${OPENRESTY_PREFIX:-/usr/local/openresty/nginx}"
OPENRESTY_BIN="${OPENRESTY_BIN:-${OPENRESTY_PREFIX}/sbin/nginx}"
OPENRESTY_SERVICE="${OPENRESTY_SERVICE:-openresty}"
OPENRESTY_GROUP="${OPENRESTY_GROUP:-nogroup}"

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[1;31m'
    C_GREEN=$'\033[1;32m'
    C_YELLOW=$'\033[1;33m'
    C_CYAN=$'\033[1;36m'
else
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN=""
fi

log()  { printf '%s[msxproxy]%s %s\n' "${C_CYAN}" "${C_RESET}" "$*"; }
ok()   { printf '%s[msxproxy] ✓%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn() { printf '%s[msxproxy] WARNING:%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
die()  { printf '%s[msxproxy] ERROR:%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; exit 1; }

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
    local src="$1" dst="$2" group="$3" mode="${4:-0640}"
    if [[ ! -f "${dst}" ]]; then
        cp "${src}" "${dst}"
        chmod "${mode}" "${dst}"
        if [[ -n "${group}" ]] && getent group "${group}" >/dev/null 2>&1; then
            chgrp "${group}" "${dst}"
        fi
        ok "Created ${dst} from $(basename "${src}") — edit before starting services!"
    else
        log "${C_DIM}Keeping existing ${dst}${C_RESET}"
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

check_deps() {
    log "Checking system and Python dependencies..."
    local missing_py=()
    for mod in uvloop gssapi jwt httpx redis filelock cryptography; do
        if ! python3 -c "import ${mod}" >/dev/null 2>&1; then
            missing_py+=("${mod}")
        fi
    done

    if (( ${#missing_py[@]} > 0 )); then
        warn "Missing core Python modules: ${missing_py[*]}"
        warn "Install on Ubuntu with:"
        warn "  apt install python3-uvloop python3-gssapi python3-jwt python3-httpx python3-redis python3-filelock python3-cryptography"
    fi

    if ! command -v kinit >/dev/null 2>&1; then
        warn "Missing Kerberos tools (kinit). Install with: apt install krb5-user"
    fi
    if ! command -v valkey-server >/dev/null 2>&1; then
        warn "Missing valkey-server. Install with: apt install valkey-server"
    fi
    if [[ ! -x "${OPENRESTY_BIN}" ]]; then
        warn "OpenResty binary not found at ${OPENRESTY_BIN}. See INSTALL.md."
    fi
    if [[ ! -f /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so ]]; then
        warn "Missing /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so. See INSTALL.md."
    fi
    if ! find /usr/local/openresty /usr/local/share/lua /usr/share/lua -name 'openidc.lua' 2>/dev/null | grep -q .; then
        warn "lua-resty-openidc not found. Install with: luarocks install lua-resty-openidc"
    fi

    # Optional activesync-enroll dependencies
    local missing_as=()
    for mod in fastapi uvicorn jwt wbxml; do
        if ! python3 -c "import ${mod}" >/dev/null 2>&1; then
            missing_as+=("${mod}")
        fi
    done
    if (( ${#missing_as[@]} > 0 )); then
        if systemctl is-enabled --quiet activesync-enroll 2>/dev/null || systemctl is-active --quiet activesync-enroll 2>/dev/null; then
            warn "activesync-enroll is enabled/active but missing Python modules: ${missing_as[*]}"
            warn "Install on Ubuntu 26.04 with:"
            warn "  apt install python3-fastapi python3-uvicorn python3-jwt python3-pip python3-dev libwbxml2-dev"
            warn "  C_INCLUDE_PATH=\"\$(dirname \"\$(dpkg -L libwbxml2-dev | grep '/wbxml\\.h\$' | head -n1)\")\" pip install git+https://github.com/BotoX/python-wbxml.git --break-system-packages"
        else
            log "Optional activesync-enroll modules not installed (${missing_as[*]}) — only needed if enabling ActiveSync DeviceID enrollment."
        fi
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

ensure_repo_readable() {
    # Ensure service users (including systemd DynamicUser) can traverse and read repo code
    # even when `git clone` / `git pull` was run with a restrictive root umask (e.g. 0077).
    chmod a+rx "${REPO_DIR}"
    chmod -R a+rX "${REPO_DIR}/openresty" "${REPO_DIR}/s4u2api" "${REPO_DIR}/mailproxy" "${REPO_DIR}/activesync-enroll"
}

cmd_install() {
    require_root "$@"

    if [[ "${REPO_DIR}" != "/opt/msxproxy" ]]; then
        warn "Repo is at ${REPO_DIR} (systemd units and msxproxy-http.conf expect /opt/msxproxy)."
    fi

    ensure_repo_readable
    check_deps

    # 1. System users
    ensure_user s4u2api /var/lib/s4u2api
    ensure_user mailproxy /var/lib/mailproxy
    if getent group valkey >/dev/null 2>&1; then
        usermod -aG valkey s4u2api
    fi

    # 2. /etc/msxproxy configs (directory 0755 so each service user can read only its own 0640 file)
    mkdir -p "${ETC_DIR}/ssl"
    chmod 0755 "${ETC_DIR}" "${ETC_DIR}/ssl"

    install_config_template "${REPO_DIR}/deploy/etc/config.lua.example"            "${ETC_DIR}/config.lua"            "${OPENRESTY_GROUP}" 0640
    install_config_template "${REPO_DIR}/deploy/etc/mailproxy.toml.example"        "${ETC_DIR}/mailproxy.toml"        mailproxy            0640
    install_config_template "${REPO_DIR}/deploy/etc/s4u2api.toml.example"          "${ETC_DIR}/s4u2api.toml"          s4u2api              0640
    install_config_template "${REPO_DIR}/deploy/etc/activesync-enroll.toml.example" "${ETC_DIR}/activesync-enroll.toml" root                0600
    install_config_template "${REPO_DIR}/deploy/etc/smoke_test.toml.example"       "${ETC_DIR}/smoke_test.toml"       root                 0600

    # 3. Symlink systemd units
    link_file "${REPO_DIR}/deploy/systemd/s4u2api.service"           /etc/systemd/system/s4u2api.service
    link_file "${REPO_DIR}/deploy/systemd/mailproxy.service"         /etc/systemd/system/mailproxy.service
    link_file "${REPO_DIR}/deploy/systemd/activesync-enroll.service" /etc/systemd/system/activesync-enroll.service

    systemctl daemon-reload

    cat <<EOF

${C_GREEN}${C_BOLD}[msxproxy] Install complete!${C_RESET} ${C_BOLD}Next steps:${C_RESET}
  ${C_BOLD}1.${C_RESET} Edit configs in ${C_CYAN}${ETC_DIR}/${C_RESET}:
       - ${ETC_DIR}/config.lua             ${C_DIM}(OpenResty hosts, OIDC secrets, MAC/session keys)${C_RESET}
       - ${ETC_DIR}/mailproxy.toml         ${C_DIM}(IMAP/SMTP backends, OIDC client_secret, cert paths)${C_RESET}
       - ${ETC_DIR}/s4u2api.toml           ${C_DIM}(listener, OIDC, Valkey socket, Kerberos principal & SPNs)${C_RESET}
       - ${ETC_DIR}/activesync-enroll.toml ${C_YELLOW}(OPTIONAL: only needed for ActiveSync DeviceID enrollment)${C_RESET}
       - ${ETC_DIR}/smoke_test.toml        ${C_YELLOW}(OPTIONAL: test credentials for tests/smoke_test.py)${C_RESET}
  ${C_BOLD}2.${C_RESET} Place the Kerberos keytab (chmod 0600, owned by root:root):
       - ${ETC_DIR}/krb5_keytab
  ${C_BOLD}3.${C_RESET} Ensure /usr/local/openresty/nginx/conf/nginx.conf contains:
       ${C_CYAN}load_module /usr/local/openresty/modules/ngx_http_upstream_ntlm_module.so;${C_RESET}
     and inside http {}:
       ${C_CYAN}include /opt/msxproxy/deploy/openresty/msxproxy-http.conf;${C_RESET}
  ${C_BOLD}4.${C_RESET} Verify with: ${C_CYAN}sudo ${REPO_DIR}/deploy/deploy.sh check${C_RESET}
  ${C_BOLD}5.${C_RESET} Enable & start core services:
       ${C_CYAN}systemctl enable --now s4u2api mailproxy ${OPENRESTY_SERVICE}${C_RESET}
  ${C_BOLD}6.${C_RESET} ${C_YELLOW}(Optional)${C_RESET} To enable the ActiveSync DeviceID enrollment server, set
     activesync_enroll.enabled = true in ${ETC_DIR}/config.lua, configure
     ${ETC_DIR}/activesync-enroll.toml, and run:
       ${C_CYAN}systemctl enable --now activesync-enroll${C_RESET}
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
    if systemctl is-enabled --quiet activesync-enroll 2>/dev/null || systemctl is-active --quiet activesync-enroll 2>/dev/null; then
        [[ -f "${ETC_DIR}/activesync-enroll.toml" ]] || die "activesync-enroll is enabled/active but missing ${ETC_DIR}/activesync-enroll.toml"
        if grep -q "CHANGE_ME" "${ETC_DIR}/activesync-enroll.toml" 2>/dev/null; then
            warn "${ETC_DIR}/activesync-enroll.toml still contains CHANGE_ME placeholders!"
        fi
    fi
    [[ -f "${ETC_DIR}/krb5_keytab" ]] || warn "Missing ${ETC_DIR}/krb5_keytab"

    check_deps
    run_tests
    check_nginx
    ok "All checks passed."
}

resolve_service() {
    case "$1" in
        openresty|"${OPENRESTY_SERVICE}") echo "${OPENRESTY_SERVICE}" ;;
        s4u2api|mailproxy|activesync-enroll) echo "$1" ;;
        valkey|valkey-server) echo "valkey-server" ;;
        *) die "Unknown service '$1'. Valid services: openresty, mailproxy, s4u2api, activesync-enroll, valkey-server" ;;
    esac
}

cmd_up() {
    require_root up "$@"
    local svcs=()
    if (( $# > 0 )); then
        for arg in "$@"; do
            svcs+=("$(resolve_service "${arg}")")
        done
    else
        if systemctl list-unit-files valkey-server.service >/dev/null 2>&1; then
            svcs+=(valkey-server)
        fi
        svcs+=(s4u2api mailproxy "${OPENRESTY_SERVICE}")
        if systemctl is-enabled --quiet activesync-enroll 2>/dev/null; then
            svcs+=(activesync-enroll)
        fi
    fi

    for svc in "${svcs[@]}"; do
        if [[ "${svc}" == "${OPENRESTY_SERVICE}" ]]; then
            check_nginx
            break
        fi
    done

    log "Starting services: ${svcs[*]}..."
    systemctl start "${svcs[@]}"
    ok "Services started: ${svcs[*]}."
    cmd_status "${svcs[@]}"
}

cmd_down() {
    require_root down "$@"
    local svcs=()
    for svc in "${OPENRESTY_SERVICE}" mailproxy activesync-enroll s4u2api; do
        if systemctl is-active --quiet "${svc}"; then
            svcs+=("${svc}")
        fi
    done
    if (( ${#svcs[@]} == 0 )); then
        log "No running msxproxy services to stop."
        return 0
    fi
    log "Stopping services: ${svcs[*]}..."
    systemctl stop "${svcs[@]}"
    ok "Services stopped: ${svcs[*]}."
}

reload_one() {
    local svc
    svc="$(resolve_service "$1")"
    case "${svc}" in
        "${OPENRESTY_SERVICE}")
            systemctl is-active --quiet "${OPENRESTY_SERVICE}" || die "Service '${OPENRESTY_SERVICE}' is not active."
            check_nginx
            log "Gracefully reloading ${OPENRESTY_SERVICE}..."
            systemctl reload "${OPENRESTY_SERVICE}"
            ok "Reloaded ${OPENRESTY_SERVICE}."
            ;;
        mailproxy)
            systemctl is-active --quiet mailproxy || die "Service 'mailproxy' is not active."
            log "Hot-reloading mailproxy (SIGHUP: config, TLS certs, JWKS, backends, ratelimit)..."
            systemctl reload mailproxy
            ok "Reloaded mailproxy."
            ;;
        s4u2api)
            systemctl is-active --quiet s4u2api || die "Service 's4u2api' is not active."
            log "Hot-reloading s4u2api (SIGHUP: config, valid_spns, JWKS, keytab)..."
            systemctl reload s4u2api
            ok "Reloaded s4u2api."
            ;;
        activesync-enroll)
            systemctl is-active --quiet activesync-enroll || die "Service 'activesync-enroll' is not active."
            log "Hot-reloading activesync-enroll (SIGHUP: config, templates, secrets)..."
            systemctl reload activesync-enroll
            ok "Reloaded activesync-enroll."
            ;;
        *)
            die "Service '${svc}' does not support reload."
            ;;
    esac
}

cmd_reload() {
    require_root reload "$@"
    if (( $# > 0 )); then
        for svc in "$@"; do
            reload_one "${svc}"
        done
        return 0
    fi

    local reloaded=0
    for svc in "${OPENRESTY_SERVICE}" mailproxy s4u2api activesync-enroll; do
        if systemctl is-active --quiet "${svc}"; then
            reload_one "${svc}"
            reloaded=1
        fi
    done
    if [[ "${reloaded}" -eq 0 ]]; then
        warn "No active msxproxy services found to reload."
    fi
}

cmd_restart() {
    require_root restart "$@"
    local svcs=()
    if (( $# > 0 )); then
        for arg in "$@"; do
            svcs+=("$(resolve_service "${arg}")")
        done
    else
        for svc in s4u2api mailproxy "${OPENRESTY_SERVICE}" activesync-enroll; do
            if systemctl is-active --quiet "${svc}"; then
                svcs+=("${svc}")
            fi
        done
        if (( ${#svcs[@]} == 0 )); then
            warn "No active msxproxy services found to restart."
            return 0
        fi
    fi

    for svc in "${svcs[@]}"; do
        if [[ "${svc}" == "${OPENRESTY_SERVICE}" ]]; then
            check_nginx
            break
        fi
    done

    log "Restarting services: ${svcs[*]}..."
    systemctl restart "${svcs[@]}"
    ok "Services restarted: ${svcs[*]}."
    cmd_status "${svcs[@]}"
}

cmd_status() {
    local svcs=()
    if (( $# > 0 )); then
        for arg in "$@"; do
            svcs+=("$(resolve_service "${arg}")")
        done
    else
        if systemctl list-unit-files valkey-server.service >/dev/null 2>&1; then
            svcs+=(valkey-server)
        fi
        svcs+=(s4u2api mailproxy "${OPENRESTY_SERVICE}")
        if systemctl is-enabled --quiet activesync-enroll 2>/dev/null || systemctl is-active --quiet activesync-enroll 2>/dev/null; then
            svcs+=(activesync-enroll)
        fi
    fi
    systemctl --no-pager --lines=0 status "${svcs[@]}" || true
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
    ensure_repo_readable
    check_deps
    run_tests
    systemctl daemon-reload
    check_nginx

    if systemctl is-active --quiet "${OPENRESTY_SERVICE}"; then
        log "Gracefully reloading ${OPENRESTY_SERVICE}..."
        systemctl reload "${OPENRESTY_SERVICE}"
    fi

    for svc in s4u2api mailproxy activesync-enroll; do
        if systemctl is-active --quiet "${svc}"; then
            log "Restarting ${svc}..."
            systemctl restart "${svc}"
        fi
    done

    ok "Update complete ($(git rev-parse --short HEAD))."
    cmd_status
}

cmd_test() {
    log "Running live smoke test (tests/smoke_test.py)..."
    python3 "${REPO_DIR}/tests/smoke_test.py" "$@"
}

case "${1:-}" in
    install) shift; cmd_install "$@" ;;
    up)      shift; cmd_up "$@" ;;
    down)    shift; cmd_down "$@" ;;
    reload)  shift; cmd_reload "$@" ;;
    restart) shift; cmd_restart "$@" ;;
    update)  shift; cmd_update "$@" ;;
    status)  shift; cmd_status "$@" ;;
    check)   shift; cmd_check "$@" ;;
    test)    shift; cmd_test "$@" ;;
    *)
        echo "Usage: $0 {install|up [service...]|down|reload [service...]|restart [service...]|update [git-ref]|status [service...]|check|test [args...]}" >&2
        exit 1
        ;;
esac
