#!/usr/bin/env bash
# docker/msxproxy.sh — Manage the production msxproxy Docker Compose stack.
#
# Usage:
#   ./docker/msxproxy.sh init                              # Create starter /etc/msxproxy configs & docker/.env
#   ./docker/msxproxy.sh check                             # Verify host configs, keytab, offline tests & openresty -t
#   ./docker/msxproxy.sh up [--activesync-enroll] [--build]# Start stack (core or core + activesync-enroll)
#   ./docker/msxproxy.sh down                              # Stop and remove containers
#   ./docker/msxproxy.sh reload [service...]               # Zero-downtime hot reload (all running or named services)
#   ./docker/msxproxy.sh restart [service...]              # Fast container restart (no image rebuild) for .py edits
#   ./docker/msxproxy.sh update [git-ref] [--build]        # Pull/checkout, test, reload OpenResty & restart Python
#   ./docker/msxproxy.sh status                            # Show container status
#   ./docker/msxproxy.sh logs [service...]                 # Follow container logs
#   ./docker/msxproxy.sh test [args...]                    # Run live smoke test (tests/smoke_test.py)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

# Load defaults from docker/.env (without overriding already-exported env vars)
if [[ -f "${ENV_FILE}" ]]; then
    while IFS='=' read -r k v; do
        [[ -z "$k" || "$k" =~ ^[[:space:]]*# ]] && continue
        k="${k//[[:space:]]/}"
        v="${v%$'\r'}"
        v="${v#\"}" ; v="${v%\"}"
        v="${v#\'}" ; v="${v%\'}"
        if [[ -z "${!k+x}" ]]; then
            export "${k}=${v}"
        fi
    done < "${ENV_FILE}"
fi

ETC_DIR="${MSXPROXY_ETC_DIR:-/etc/msxproxy}"
KRB5_CONF_PATH="${KRB5_CONF:-/etc/krb5.conf}"
COMPOSE=(docker compose -f "${SCRIPT_DIR}/docker-compose.yml")

if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m' C_BOLD=$'\033[1m' C_DIM=$'\033[2m'
    C_RED=$'\033[1;31m' C_GREEN=$'\033[1;32m' C_YELLOW=$'\033[1;33m' C_CYAN=$'\033[1;36m'
else
    C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_CYAN=""
fi

log()  { printf '%s[msxproxy-docker]%s %s\n' "${C_CYAN}" "${C_RESET}" "$*"; }
ok()   { printf '%s[msxproxy-docker] ✓%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
warn() { printf '%s[msxproxy-docker] WARNING:%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
die()  { printf '%s[msxproxy-docker] ERROR:%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; exit 1; }

service_is_running() {
    local svc="$1"
    local cid
    cid="$("${COMPOSE[@]}" --profile activesync-enroll ps -q --status running "${svc}" 2>/dev/null || true)"
    [[ -n "${cid}" ]]
}

install_template() {
    local src="$1" dst="$2" mode="${3:-0640}"
    if [[ ! -f "${dst}" ]]; then
        cp "${src}" "${dst}"
        chmod "${mode}" "${dst}"
        ok "Created ${dst} from $(basename "${src}")"
    else
        log "${C_DIM}Keeping existing ${dst}${C_RESET}"
    fi
}

cmd_init() {
    mkdir -p "${ETC_DIR}/ssl" "${ETC_DIR}/ca"
    install_template "${REPO_DIR}/deploy/etc/config.lua.example"             "${ETC_DIR}/config.lua"             0640
    install_template "${REPO_DIR}/deploy/etc/s4u2api.toml.example"           "${ETC_DIR}/s4u2api.toml"           0640
    install_template "${REPO_DIR}/deploy/etc/mailproxy.toml.example"         "${ETC_DIR}/mailproxy.toml"         0640
    install_template "${REPO_DIR}/deploy/etc/activesync-enroll.toml.example" "${ETC_DIR}/activesync-enroll.toml" 0600
    install_template "${REPO_DIR}/deploy/etc/smoke_test.toml.example"        "${ETC_DIR}/smoke_test.toml"        0600
    install_template "${SCRIPT_DIR}/.env.example"                            "${ENV_FILE}"                        0644

    cat <<EOF

${C_GREEN}${C_BOLD}[msxproxy-docker] Initialization complete!${C_RESET}
Next steps:
  1. Edit configs in ${C_CYAN}${ETC_DIR}/${C_RESET} (config.lua, s4u2api.toml, mailproxy.toml, and optionally activesync-enroll.toml)
  2. Place TLS certificates in ${C_CYAN}${ETC_DIR}/ssl/${C_RESET} and Kerberos keytab at ${C_CYAN}${ETC_DIR}/krb5_keytab${C_RESET}
  3. (Optional) Drop internal Root CA .crt files into ${C_CYAN}${ETC_DIR}/ca/${C_RESET}
  4. Verify with: ${C_CYAN}./docker/msxproxy.sh check${C_RESET}
  5. Start core stack: ${C_CYAN}./docker/msxproxy.sh up --build${C_RESET}
     Or with activesync-enroll: ${C_CYAN}./docker/msxproxy.sh up --activesync-enroll --build${C_RESET}
EOF
}

cmd_check() {
    log "Checking host configs in ${ETC_DIR}..."
    for f in config.lua s4u2api.toml mailproxy.toml; do
        [[ -f "${ETC_DIR}/${f}" ]] || die "Missing ${ETC_DIR}/${f} (run ./docker/msxproxy.sh init)"
        if grep -q "CHANGE_ME" "${ETC_DIR}/${f}" 2>/dev/null; then
            warn "${ETC_DIR}/${f} still contains CHANGE_ME placeholders!"
        fi
    done

    if [[ -f "${ETC_DIR}/activesync-enroll.toml" ]] && grep -q "CHANGE_ME" "${ETC_DIR}/activesync-enroll.toml" 2>/dev/null; then
        warn "${ETC_DIR}/activesync-enroll.toml still contains CHANGE_ME placeholders (ignore if activesync-enroll is disabled)."
    fi

    [[ -f "${ETC_DIR}/krb5_keytab" ]] || warn "Missing ${ETC_DIR}/krb5_keytab"
    [[ -f "${KRB5_CONF_PATH}" ]] || warn "Missing ${KRB5_CONF_PATH}"

    log "Validating docker-compose.yml..."
    "${COMPOSE[@]}" --profile activesync-enroll config --quiet

    if python3 -m pytest --version >/dev/null 2>&1; then
        log "Running offline test suite..."
        (cd "${REPO_DIR}" && python3 -m pytest -q)
    else
        warn "pytest not installed on host; skipping offline unit tests."
    fi

    if service_is_running openresty; then
        log "Validating OpenResty configuration inside running container..."
        "${COMPOSE[@]}" exec -T openresty /usr/local/openresty/bin/openresty -c /etc/msxproxy-openresty/nginx.conf -t
    fi

    ok "All checks passed."
}

cmd_up() {
    local extra_compose=()
    local extra_up=()
    for arg in "$@"; do
        case "$arg" in
            --activesync-enroll) extra_compose+=(--profile activesync-enroll) ;;
            --build)             extra_up+=(--build) ;;
            *)                   die "Unknown option for up: $arg" ;;
        esac
    done
    log "Starting msxproxy Docker stack..."
    "${COMPOSE[@]}" "${extra_compose[@]}" up -d "${extra_up[@]}"
    ok "Stack started."
    "${COMPOSE[@]}" --profile activesync-enroll ps
}

cmd_down() {
    log "Stopping and removing msxproxy containers..."
    "${COMPOSE[@]}" --profile activesync-enroll down -t 5 --remove-orphans
    ok "Stack stopped."
}

reload_one() {
    local svc="$1"
    case "${svc}" in
        openresty)
            service_is_running openresty || die "Container 'openresty' is not running."
            log "Validating OpenResty config (openresty -t)..."
            "${COMPOSE[@]}" exec -T openresty /usr/local/openresty/bin/openresty -c /etc/msxproxy-openresty/nginx.conf -t
            log "Hot-reloading openresty (nginx configs, Lua code, config.lua, TLS certs)..."
            "${COMPOSE[@]}" exec -T openresty /usr/local/openresty/bin/openresty -c /etc/msxproxy-openresty/nginx.conf -s reload
            ok "Reloaded openresty."
            ;;
        mailproxy)
            service_is_running mailproxy || die "Container 'mailproxy' is not running."
            log "Hot-reloading mailproxy (SIGHUP: config, TLS certs, JWKS, backends)..."
            "${COMPOSE[@]}" kill -s HUP mailproxy
            ok "Reloaded mailproxy."
            ;;
        s4u2api)
            service_is_running s4u2api || die "Container 's4u2api' is not running."
            log "Hot-reloading s4u2api (SIGHUP: config, valid_spns, JWKS, keytab)..."
            "${COMPOSE[@]}" kill -s HUP s4u2api
            ok "Reloaded s4u2api."
            ;;
        activesync-enroll)
            service_is_running activesync-enroll || die "Container 'activesync-enroll' is not running."
            log "Hot-reloading activesync-enroll (SIGHUP: config, templates, secrets)..."
            "${COMPOSE[@]}" --profile activesync-enroll kill -s HUP activesync-enroll
            ok "Reloaded activesync-enroll."
            ;;
        *)
            die "Unknown reloadable service '${svc}'. Valid services: openresty, mailproxy, s4u2api, activesync-enroll"
            ;;
    esac
}

cmd_reload() {
    if (( $# > 0 )); then
        for svc in "$@"; do
            reload_one "${svc}"
        done
        return 0
    fi

    local reloaded=0
    for svc in openresty mailproxy s4u2api activesync-enroll; do
        if service_is_running "${svc}"; then
            reload_one "${svc}"
            reloaded=1
        fi
    done

    if [[ "${reloaded}" -eq 0 ]]; then
        warn "No running msxproxy containers found to reload."
    fi
}

cmd_restart() {
    if (( $# > 0 )); then
        log "Restarting service(s): $* (picking up bind-mounted code without rebuild)..."
        "${COMPOSE[@]}" --profile activesync-enroll restart "$@"
    else
        log "Restarting running services..."
        local svcs=()
        for svc in s4u2api mailproxy openresty activesync-enroll; do
            if service_is_running "${svc}"; then
                svcs+=("${svc}")
            fi
        done
        if (( ${#svcs[@]} == 0 )); then
            warn "No running msxproxy containers found to restart."
            return 0
        fi
        "${COMPOSE[@]}" --profile activesync-enroll restart "${svcs[@]}"
    fi
    ok "Restart complete."
    "${COMPOSE[@]}" --profile activesync-enroll ps "$@"
}

cmd_update() {
    local target_ref=""
    local do_build=0
    for arg in "$@"; do
        case "$arg" in
            --build) do_build=1 ;;
            -*)      die "Unknown option for update: $arg" ;;
            *)       target_ref="$arg" ;;
        esac
    done

    cd "${REPO_DIR}"
    if [[ -n "${target_ref}" ]]; then
        log "Fetching and checking out '${target_ref}'..."
        git fetch --tags origin
        git checkout "${target_ref}"
    else
        log "Pulling latest commits (fast-forward only)..."
        git pull --ff-only
    fi

    if python3 -m pytest --version >/dev/null 2>&1; then
        log "Running offline test suite..."
        python3 -m pytest -q
    fi

    if [[ "${do_build}" -eq 1 ]]; then
        local profile_args=()
        if service_is_running activesync-enroll; then
            profile_args=(--profile activesync-enroll)
        fi
        log "Rebuilding images and recreating containers..."
        "${COMPOSE[@]}" "${profile_args[@]}" up -d --build
    else
        if service_is_running openresty; then
            reload_one openresty
        fi
        local py_svcs=()
        for svc in s4u2api mailproxy activesync-enroll; do
            if service_is_running "${svc}"; then
                py_svcs+=("${svc}")
            fi
        done
        if (( ${#py_svcs[@]} > 0 )); then
            log "Restarting Python container(s) to load updated repo code: ${py_svcs[*]}..."
            "${COMPOSE[@]}" --profile activesync-enroll restart "${py_svcs[@]}"
        fi
    fi

    ok "Update complete ($(git rev-parse --short HEAD))."
    "${COMPOSE[@]}" --profile activesync-enroll ps
}

cmd_status() {
    "${COMPOSE[@]}" --profile activesync-enroll ps
}

cmd_logs() {
    "${COMPOSE[@]}" --profile activesync-enroll logs -f --tail=100 "$@"
}

cmd_test() {
    log "Running live smoke test (tests/smoke_test.py)..."
    python3 "${REPO_DIR}/tests/smoke_test.py" "$@"
}

case "${1:-}" in
    init)    shift; cmd_init "$@" ;;
    check)   shift; cmd_check "$@" ;;
    up)      shift; cmd_up "$@" ;;
    down)    shift; cmd_down "$@" ;;
    reload)  shift; cmd_reload "$@" ;;
    restart) shift; cmd_restart "$@" ;;
    update)  shift; cmd_update "$@" ;;
    status)  shift; cmd_status "$@" ;;
    logs)    shift; cmd_logs "$@" ;;
    test)    shift; cmd_test "$@" ;;
    *)
        echo "Usage: $0 {init|check|up [--activesync-enroll] [--build]|down|reload [service...]|restart [service...]|update [git-ref] [--build]|status|logs [service...]|test [args...]}" >&2
        exit 1
        ;;
esac
