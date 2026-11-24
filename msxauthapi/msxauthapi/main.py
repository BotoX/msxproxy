from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI

from . import auth
from .routes import router


logging.basicConfig(
    level=logging.WARNING,
    format="[%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)

logging.getLogger("msxauthapi").setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await auth.oidc.aclose()


app = FastAPI(lifespan=lifespan)
app.include_router(router)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("msxauthapi.main:app", host="127.0.0.1", port=8000, reload=True)
