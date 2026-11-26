from __future__ import annotations

import base64
import hmac
import json
import logging
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from wbxml import wbxml_to_xml, xml_to_wbxml

from .activesync import (
    OnFolderSync,
    OnGetItemEstimate,
    OnHTTPOptions,
    OnMoveItems,
    OnProvision,
    OnSettings,
    OnSync,
    OnWrongPolicy,
)
from .config import Config, get_config
from .enroll import generate_enroll_mail

logger = logging.getLogger(__name__)

WBXML_MEDIA_TYPE = "application/vnd.ms-sync.wbxml"
PREVIEW_HEADERS = {
    "X-ActiveSync-Enroll": "preview",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}


@dataclass(frozen=True)
class EnrollUser:
    subject: str
    email: str = ""
    name: str = ""


def verify_preview_secret(provided: str | None, config: Config | None = None) -> None:
    """Guard the HTML preview endpoint with a constant-time shared secret."""
    cfg = config or get_config()
    expected = cfg.server.preview_secret
    if not expected or expected == "CHANGE_ME":
        raise HTTPException(
            status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
            detail="Preview endpoint is disabled",
        )
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid preview secret",
        )


def decode_enroll_user(header_value: str | None) -> EnrollUser:
    """Decode the Base64-encoded UTF-8 JSON user payload forwarded by OpenResty."""
    if not header_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Enroll-User header",
        )
    try:
        raw = base64.b64decode(header_value, validate=True)
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed X-Enroll-User header",
        )

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed X-Enroll-User payload",
        )

    subject = data.get("subject")
    if not isinstance(subject, str) or not subject.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing subject in X-Enroll-User header",
        )

    email = data.get("email") if isinstance(data.get("email"), str) else ""
    name = data.get("name") if isinstance(data.get("name"), str) else ""
    return EnrollUser(subject=subject.strip(), email=email, name=name)


def dispatch_activesync_command(
    cmd: str,
    xml: str,
    policy_key: str,
    user: EnrollUser,
    device_id: str,
    device_type: str,
    protocol_version: str,
    ip: str,
    ua: str,
    config: Config | None = None,
) -> str | None:
    """Return the ActiveSync XML response for the given command, or None if unsupported."""
    cmd_l = cmd.lower()
    if cmd_l == "provision":
        return OnProvision(xml)
    if cmd_l == "settings":
        return OnSettings()
    if policy_key and policy_key != "1337":
        return OnWrongPolicy(cmd_l)
    if cmd_l == "foldersync":
        return OnFolderSync(xml)
    if cmd_l == "getitemestimate":
        return OnGetItemEstimate(xml)
    if cmd_l == "sync":
        return OnSync(
            xml=xml,
            subject=user.subject,
            email=user.email,
            name=user.name,
            device_id=device_id,
            device_type=device_type,
            protocol_version=protocol_version,
            ip=ip,
            ua=ua,
            config=config,
        )
    if cmd_l == "moveitems":
        return OnMoveItems()
    return None


def _get_query_param_ci(query_params, name: str) -> str:
    val = query_params.get(name)
    if val is not None:
        return val
    target = name.lower()
    for k, v in query_params.items():
        if k.lower() == target:
            return v
    return ""


router = APIRouter()


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/preview")
async def preview_template(request: Request) -> HTMLResponse:
    """Localhost browser preview of the rendered HTML enrollment email template."""
    cfg = get_config()
    secret = _get_query_param_ci(request.query_params, "secret") or _get_query_param_ci(
        request.query_params, "preview_secret"
    )
    verify_preview_secret(secret, cfg)

    subject = _get_query_param_ci(request.query_params, "subject") or "testuser"
    email = _get_query_param_ci(request.query_params, "email") or f"{subject}@example.org"
    name = _get_query_param_ci(request.query_params, "name") or subject
    device_id = _get_query_param_ci(request.query_params, "DeviceId") or "PREVIEW12345"
    device_type = _get_query_param_ci(request.query_params, "DeviceType") or "iPhone"
    protocol_version = request.headers.get("MS-ASProtocolVersion", "16.1")
    ua = request.headers.get("User-Agent", "")
    ip = request.headers.get("X-Real-IP") or (request.client.host if request.client else "")

    _, html_body = generate_enroll_mail(
        subject=subject,
        email=email,
        name=name,
        device_id=device_id,
        device_type=device_type,
        protocol_version=protocol_version,
        ip=ip,
        ua=ua,
        config=cfg,
    )
    return HTMLResponse(content=html_body, headers=PREVIEW_HEADERS)


@router.api_route("/Microsoft-Server-ActiveSync", methods=["GET", "OPTIONS", "POST"])
@router.api_route("/microsoft-server-activesync", methods=["GET", "OPTIONS", "POST"])
async def activesync_enroll_endpoint(request: Request) -> Response:
    cfg = get_config()
    user = decode_enroll_user(request.headers.get("X-Enroll-User"))

    device_id = _get_query_param_ci(request.query_params, "DeviceId")
    device_type = _get_query_param_ci(request.query_params, "DeviceType")
    protocol_version = request.headers.get("MS-ASProtocolVersion", "")
    ua = request.headers.get("User-Agent", "")
    ip = request.headers.get("X-Real-IP") or (request.client.host if request.client else "")

    if request.method == "GET":
        secret = _get_query_param_ci(request.query_params, "preview_secret") or _get_query_param_ci(
            request.query_params, "secret"
        )
        verify_preview_secret(secret, cfg)
        _, html_body = generate_enroll_mail(
            subject=user.subject,
            email=user.email,
            name=user.name,
            device_id=device_id or "PREVIEW12345",
            device_type=device_type or "BrowserPreview",
            protocol_version=protocol_version or "16.1",
            ip=ip,
            ua=ua,
            config=cfg,
        )
        return HTMLResponse(content=html_body, headers=PREVIEW_HEADERS)

    if request.method == "OPTIONS":
        headers = OnHTTPOptions()
        headers["X-ActiveSync-Enroll"] = "true"
        return Response(
            content=b"",
            media_type=WBXML_MEDIA_TYPE,
            headers=headers,
        )

    cmd = _get_query_param_ci(request.query_params, "Cmd").lower()
    policy_key = request.headers.get("X-MS-PolicyKey", "")

    xml = ""
    content_type = (request.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if content_type == WBXML_MEDIA_TYPE:
        wbxml = await request.body()
        if len(wbxml) > cfg.server.max_body_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Request body too large",
            )
        if wbxml:
            try:
                xml = wbxml_to_xml(wbxml)
                logger.debug("Request XML: %s", xml)
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Malformed WBXML: {exc}",
                )

    res_xml = dispatch_activesync_command(
        cmd=cmd,
        xml=xml,
        policy_key=policy_key,
        user=user,
        device_id=device_id,
        device_type=device_type,
        protocol_version=protocol_version,
        ip=ip,
        ua=ua,
        config=cfg,
    )
    if res_xml is None:
        return PlainTextResponse(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            content=f"Command '{cmd}' not implemented.",
            headers={"X-ActiveSync-Enroll": "true"},
        )

    logger.debug("Response XML: %s", res_xml)
    wbxml_bytes = xml_to_wbxml(res_xml)
    return Response(
        content=wbxml_bytes,
        media_type=WBXML_MEDIA_TYPE,
        headers={"X-ActiveSync-Enroll": "true"},
    )
