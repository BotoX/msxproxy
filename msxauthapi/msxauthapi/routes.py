import time
import base64
import json
import logging

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Security,
    Request,
    Response,
    status,
)
from fastapi.responses import PlainTextResponse
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from typing import Annotated

from wbxml import xml_to_wbxml, wbxml_to_xml

from . import auth
from .utils import json_b64_header
from .activesync import (
    OnHTTPOptions,
    OnProvision,
    OnSettings,
    OnFolderSync,
    OnGetItemEstimate,
    OnSync,
    OnMoveItems,
    OnWrongPolicy,
)
from .config import API_SECRET

logger = logging.getLogger(__name__)

api_secret_header = APIKeyHeader(name="X-API-Secret", auto_error=False)
basic_header = HTTPBasic()


async def validate_api_secret(api_key: str = Security(api_secret_header)):
    if api_key != API_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid API Secret",
            headers={"X-API-Result": json_b64_header({"error": "Invalid API Secret"})},
        )


router = APIRouter(dependencies=[Depends(validate_api_secret)])


def _impersonate(jwt: str, claims: dict[str, any]) -> Response:
    impersonate = {
        "upn": claims.get("user_principal"),
        "jwt": jwt,
        "aud": claims["aud"],
        "exp": claims["exp"],
    }

    return Response(
        "", headers={"X-API-Result": json_b64_header({"impersonate": impersonate})}
    )


def _abort(status_code: int, msg: str, ttl: int):
    abort = {
        "code": status_code,
        "msg": msg,
        "exp": time.time() + ttl
    }

    headers = {
        "X-API-Result": json_b64_header({"abort": abort}),
    }

    raise HTTPException(
        status_code=status_code,
        detail=msg,
        headers=headers
    )

async def authenticate_or_die(
    username: str, password: str, user_ip: str, scope: str = "openid", **kwargs
) -> dict[str, any]:
    try:
        json, claims = await auth.password(username, password, user_ip, scope, **kwargs)
        access_token = json["access_token"]
    except auth.UnauthorizedError as e:
        _abort(
            status.HTTP_401_UNAUTHORIZED,
            "Unauthorized: Incorrect username or password.",
            60
        )
    except auth.BadRequestError as e:
        _abort(
            status.HTTP_400_BAD_REQUEST,
            str(e),
            15
        )
    except auth.ForbiddenError as e:
        _abort(
            status.HTTP_403_FORBIDDEN,
            str(e),
            60
        )
    except auth.OIDCError as e:
        _abort(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            str(e),
            15
        )

    try:
        claims["user_principal"] = auth.claims2principal(claims)
    except ValueError as e:
        _abort(
            status.HTTP_403_FORBIDDEN,
            str(e),
            15
        )

    return access_token, claims


#@router.api_route("/Microsoft-Server-ActiveSync", methods=["GET", "POST", "OPTIONS"])
async def ActiveSync_API(
    request: Request,
    credentials: Annotated[HTTPBasicCredentials, Depends(basic_header)],
):
    is_trustedNetwork = (
        request.headers.get("X-Trusted-Network", "false").lower() == "true"
    )

    cmd = request.query_params.get("Cmd", "").lower()
    deviceId = request.query_params.get("DeviceId", "")
    deviceType = request.query_params.get("DeviceType", "")
    policy_key = request.headers.get("X-MS-PolicyKey", "")
    protocol_version = request.headers.get("MS-ASProtocolVersion", "")
    ua = request.headers.get("User-Agent", "")
    ip = request.client.host

    jwt, claims = await authenticate_or_die(
        credentials.username,
        credentials.password,
        ip,
        "openid profile email",
        DeviceId=deviceId,
        DeviceType=deviceType
    )

    acr = claims.get("acr") or ""
    if is_trustedNetwork or acr == "mail-password" or acr == "deviceId":
        return _impersonate(jwt, claims)

    if request.method == "OPTIONS":
        headers = OnHTTPOptions()
        headers.update({"X-API-Result": json_b64_header({"return": True})})
        return Response("", media_type="application/vnd.ms-sync.wbxml", headers=headers)

    xml = ""
    if request.method == "POST":
        content_type = request.headers.get("Content-Type", None)
        if content_type == "application/vnd.ms-sync.wbxml":
            wbxml = await request.body()
            if wbxml:
                try:
                    xml = wbxml_to_xml(wbxml)
                    logger.debug("Request XML: %s", xml)
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Malformed WBXML\n{e}",
                        headers={"X-API-Result": json_b64_header({"return": True})},
                    )

    if cmd == "provision":
        res = OnProvision(xml)
    elif cmd == "settings":
        res = OnSettings()
    elif policy_key and policy_key != "1337":
        res = OnWrongPolicy(cmd)
    elif cmd == "foldersync":
        res = OnFolderSync(xml)
    elif cmd == "getitemestimate":
        res = OnGetItemEstimate(xml)
    elif cmd == "sync":
        subject = claims["preferred_username"]
        email = claims["email"]
        name = claims["name"]
        res = OnSync(
            xml,
            subject, email, name,
            deviceId, deviceType,
            protocol_version, ip, ua
        )
    elif cmd == "moveitems":
        res = OnMoveItems()
    else:
        return PlainTextResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content=f"Command '{cmd}' not implemented.",
            headers={"X-API-Result": json_b64_header({"return": True})},
        )

    logger.debug("Response XML: %s", res)

    wbxml_bytes = xml_to_wbxml(res)
    return Response(
        content=wbxml_bytes,
        media_type="application/vnd.ms-sync.wbxml",
        headers={"X-API-Result": json_b64_header({"return": True})},
    )


@router.api_route(
    "/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)
async def catch_all_handler(
    request: Request,
    path_name: str,
    credentials: Annotated[HTTPBasicCredentials, Depends(basic_header)],
):
    ip = request.client.host
    is_trustedNetwork = (
        request.headers.get("X-Trusted-Network", "false").lower() == "true"
    )

    jwt, claims = await authenticate_or_die(
        credentials.username,
        credentials.password,
        ip,
        "openid"
    )

    acr = claims.get("acr")
    if not is_trustedNetwork and acr != "mail-password":
        _abort(
            status.HTTP_403_FORBIDDEN,
            "Insufficient authentication: use special mail password",
            60
        )

    return _impersonate(jwt, claims)
