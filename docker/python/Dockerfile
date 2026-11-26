FROM python:3.12-slim

ARG INSTALL_TEST_DEPS=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git libkrb5-dev krb5-user libwbxml2-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python runtime dependencies shared across s4u2api, mailproxy, and activesync-enroll.
# Application code is NEVER copied into this image — it is bind-mounted from the repo at runtime.
RUN pip install --no-cache-dir \
        uvloop \
        gssapi \
        "pyjwt[crypto]" \
        httpx \
        redis \
        filelock \
        cryptography \
        fastapi \
        uvicorn \
    && if [ "${INSTALL_TEST_DEPS}" = "1" ]; then \
        pip install --no-cache-dir pytest; \
    fi

# Build python-wbxml against system libwbxml2-dev (auto-discover wbxml.h include dir)
RUN set -eu; \
    WBXML_INC="$(dirname "$(dpkg -L libwbxml2-dev | grep '/wbxml\.h$' | head -n1)")"; \
    C_INCLUDE_PATH="${WBXML_INC}" pip install --no-cache-dir git+https://github.com/BotoX/python-wbxml.git

COPY docker/python/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /opt/msxproxy
ENTRYPOINT ["/entrypoint.sh"]
