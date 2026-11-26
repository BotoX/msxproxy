import logging
import signal

from fastapi import FastAPI

from .config import get_config, reload_config
from .routes import router

logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("activesync_enroll").setLevel(logging.INFO)
logger = logging.getLogger("activesync_enroll")

app = FastAPI(title="activesync-enroll", docs_url=None, redoc_url=None, openapi_url=None)
app.include_router(router)


def _handle_sighup(signum, frame) -> None:
    try:
        reload_config()
        logger.info("SIGHUP received: hot-reloaded activesync-enroll configuration.")
    except Exception as e:
        logger.error("SIGHUP hot reload failed: %s (keeping previous configuration)", e)


def main() -> None:
    import uvicorn

    cfg = get_config()
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _handle_sighup)
    uvicorn.run(
        "activesync_enroll.main:app",
        host=cfg.server.host,
        port=cfg.server.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
