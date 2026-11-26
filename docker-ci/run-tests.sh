#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "${SCRIPT_DIR}/docker-compose.yml")
LOG_SERVICES=(keycloak openresty s4u2api activesync-enroll mailproxy mock-exchange)

KEYCLOAK_MAIL_PASSWORDS_DIR="${KEYCLOAK_MAIL_PASSWORDS_DIR:-${SCRIPT_DIR}/../../keycloak-mail-passwords}"
KEYCLOAK_MAIL_PASSWORDS_JAR="${KEYCLOAK_MAIL_PASSWORDS_JAR:-${KEYCLOAK_MAIL_PASSWORDS_DIR}/target/keycloak-mail-passwords-1.0.0.jar}"
export KEYCLOAK_MAIL_PASSWORDS_JAR

KEEP_UP=0
NO_BUILD=0
VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        --keep-up)   KEEP_UP=1 ;;
        --no-build)  NO_BUILD=1 ;;
        -v|--verbose) VERBOSE=1 ;;
        --stop)
            echo "[msxproxy-docker-ci] Stopping and removing containers..."
            "${COMPOSE[@]}" down -t 2 -v --remove-orphans
            exit 0
            ;;
        -h|--help)
            echo "Usage: $0 [--keep-up] [-v|--verbose] [--no-build] [--stop]"
            echo "  --keep-up     Keep containers running after tests pass; press Ctrl+C to stop & remove them"
            echo "  -v, --verbose Stream live container logs (with --keep-up) or print logs after tests"
            echo "  --no-build    Skip docker compose build"
            echo "  --stop        Stop and remove any running test containers and volumes"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg" >&2
            exit 2
            ;;
    esac
done

ensure_keycloak_provider_jar() {
    if [ -f "${KEYCLOAK_MAIL_PASSWORDS_JAR}" ]; then
        return 0
    fi
    if [ ! -d "${KEYCLOAK_MAIL_PASSWORDS_DIR}" ]; then
        echo "[msxproxy-docker-ci] ERROR: Provider JAR not found at ${KEYCLOAK_MAIL_PASSWORDS_JAR}" >&2
        echo "[msxproxy-docker-ci]        and source directory ${KEYCLOAK_MAIL_PASSWORDS_DIR} does not exist." >&2
        echo "[msxproxy-docker-ci]        Set KEYCLOAK_MAIL_PASSWORDS_DIR or KEYCLOAK_MAIL_PASSWORDS_JAR." >&2
        exit 1
    fi

    echo "[msxproxy-docker-ci] Provider JAR missing — building keycloak-mail-passwords..."
    if command -v mvn >/dev/null 2>&1; then
        (cd "${KEYCLOAK_MAIL_PASSWORDS_DIR}" && mvn -q package -DskipTests)
    else
        docker run --rm \
            -u "$(id -u):$(id -g)" \
            -v "${KEYCLOAK_MAIL_PASSWORDS_DIR}:/src" \
            -w /src \
            maven:3.9-eclipse-temurin-21 \
            mvn -q -Duser.home=/tmp package -DskipTests
    fi

    if [ ! -f "${KEYCLOAK_MAIL_PASSWORDS_JAR}" ]; then
        echo "[msxproxy-docker-ci] ERROR: Build completed but JAR still not found at ${KEYCLOAK_MAIL_PASSWORDS_JAR}" >&2
        exit 1
    fi
}

TESTS_PASSED=0
STOPPED_BY_USER=0
WAIT_PID=""

cleanup() {
    rc=$?
    trap - EXIT INT TERM
    if [ -n "$WAIT_PID" ]; then
        kill "$WAIT_PID" 2>/dev/null || true
    fi
    if [ "$TESTS_PASSED" -eq 0 ] && [ "$STOPPED_BY_USER" -eq 0 ] && [ "$rc" -ne 0 ]; then
        echo ""
        echo "=== Tests failed (exit $rc) — recent container logs ==="
        "${COMPOSE[@]}" logs --tail=40 "${LOG_SERVICES[@]}" || true
    fi
    echo ""
    echo "[msxproxy-docker-ci] Stopping and removing containers..."
    "${COMPOSE[@]}" down -t 2 -v --remove-orphans >/dev/null 2>&1 || true
    if [ "$STOPPED_BY_USER" -eq 1 ]; then
        exit 0
    fi
    exit "$rc"
}

on_interrupt() {
    STOPPED_BY_USER=1
    exit 0
}

trap cleanup EXIT
trap on_interrupt INT TERM

ensure_keycloak_provider_jar

if [ "$NO_BUILD" -eq 0 ]; then
    echo "[msxproxy-docker-ci] Building images..."
    "${COMPOSE[@]}" build
fi

echo "[msxproxy-docker-ci] Starting stack and waiting for healthchecks..."
"${COMPOSE[@]}" up -d --wait

echo ""
echo "[msxproxy-docker-ci] Running live smoke_test.py..."
"${COMPOSE[@]}" run --rm test-runner python3 tests/smoke_test.py --config /etc/msxproxy/smoke_test.toml

echo ""
echo "[msxproxy-docker-ci] Running pytest integration_test.py..."
"${COMPOSE[@]}" run --rm test-runner python3 -m pytest -v tests/integration_test.py

TESTS_PASSED=1
echo ""
echo "[msxproxy-docker-ci] All Docker integration tests passed!"

if [ "$KEEP_UP" -eq 1 ]; then
    echo ""
    echo "Stack running (--keep-up):"
    echo "  Webmail (OpenResty): https://webmail.localhost:18443/owa/ (testuser / TestRegularPass123!)"
    echo "  Keycloak Admin:      https://keycloak.localhost:18444/admin/  (admin / admin)"
    echo "  Keycloak Account:    https://keycloak.localhost:18444/realms/TestRealm/account/"
    echo "  Mailproxy:           mailproxy.localhost:10143 / 10993 / 10587 / 10465"
    echo ""
    if [ "$VERBOSE" -eq 1 ]; then
        echo "Streaming container logs — press Ctrl+C to stop and remove all containers..."
        "${COMPOSE[@]}" logs -f --tail=50 "${LOG_SERVICES[@]}" &
        WAIT_PID=$!
        wait "$WAIT_PID" || true
    else
        echo "Press Ctrl+C to stop and remove all containers (pass -v to stream logs)..."
        tail -f /dev/null &
        WAIT_PID=$!
        wait "$WAIT_PID" || true
    fi
elif [ "$VERBOSE" -eq 1 ]; then
    echo ""
    echo "=== Container logs (-v) ==="
    "${COMPOSE[@]}" logs --tail=50 "${LOG_SERVICES[@]}" || true
fi
