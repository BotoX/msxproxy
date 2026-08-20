import json
import logging
import httpx
import jwt
from jwt.exceptions import PyJWTError

from .config import (
    OIDC_WELL_KNOWN_URL,
    OIDC_AUDIENCE,
    AUTH_CLIENT_ID,
    AUTH_CLIENT_SECRET
)

logger = logging.getLogger(__name__)

class OIDCError(Exception):
    """Base exception for OIDC issues (500)"""
    pass

class BadRequestError(OIDCError):
    """400 - Invalid request parameters"""
    pass

class UnauthorizedError(OIDCError):
    """401 - Invalid credentials or expired session"""
    pass

class ForbiddenError(OIDCError):
    """403 - User lacks required affiliation/roles"""
    pass

class KeycloakOIDCClient:
    def __init__(
        self,
        well_known_url: str,
        audience: str,
        client_id: str,
        client_secret: str | None = None,
        timeout: float = 5.0
    ) -> None:
        self.well_known_url = well_known_url
        self.audience = audience
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout

        self._config: dict[str, any] = {}
        self._jwk_set: jwt.PyJWKSet | None = None

        self._setup()

    def _setup(self) -> None:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(self.well_known_url)
            resp.raise_for_status()
            self._config = resp.json()

            jwks_uri = self._config["jwks_uri"]
            resp = client.get(jwks_uri)
            resp.raise_for_status()
            self._jwk_set = jwt.PyJWKSet.from_dict(resp.json())

    @property
    def authorization_endpoint(self) -> str:
        return self._config["authorization_endpoint"]

    @property
    def token_endpoint(self) -> str:
        return self._config["token_endpoint"]

    @property
    def issuer(self) -> str:
        return self._config["issuer"]

    def verify(self, token: str) -> dict[str, any]:
        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            if not kid:
                raise ValueError("No 'kid' found in token header")
        except PyJWTError as e:
            raise ValueError(f"Invalid token format: {e}")

        try:
            jwk = self._jwk_set[kid]
        except KeyError:
            raise ValueError(f"Key ID {kid} not found in JWKS")

        try:
            claims = jwt.decode(
                token,
                key=jwk.key,
                algorithms=["RS256"],
                options={"verify_aud": True},
                audience=self.audience,
                issuer=self.issuer
            )
            return claims
        except PyJWTError as e:
            logger.error(f"Token verification failed: {e}")
            raise ValueError(f"Token verification failed: {e}")

    async def password_grant(
        self,
        username: str,
        password: str,
        user_ip: str,
        scope: str = "openid",
        **kwargs
    ) -> dict[str, any]:
        data = kwargs
        data.update({
            "grant_type": "password",
            "client_id": self.client_id,
            "username": username,
            "password": password,
            "scope": scope
        })
        if self.client_secret is not None:
            data["client_secret"] = self.client_secret

        headers = {
            "X-Forwarded-For": user_ip
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(self.token_endpoint, data=data, headers=headers)
            resp.raise_for_status()

            # Check if CrowdSec served an HTML CAPTCHA / Challenge page
            content_type = resp.headers.get("content-type", "")
            if "text/html" in content_type and "<title>CrowdSec Captcha</title>" in resp.text:
                logger.warning(
                    "CrowdSec CAPTCHA triggered for client IP '%s' (user '%s')",
                    user_ip,
                    username
                )
                raise ForbiddenError("Authentication blocked by security policy (CrowdSec CAPTCHA)")

            try:
                return resp.json()
            except (json.JSONDecodeError, ValueError) as e:
                logger.error(
                    "Keycloak returned non-JSON response (status %s): %s",
                    resp.status_code,
                    resp.text[:500]  # Log up to 500 chars of body
                )
                raise OIDCError("Keycloak returned an invalid or empty response")


def claims2principal(claims: dict[str, any]) -> str:
    principal = claims.get('krb5_principal')
    if not principal:
        raise ValueError('missing attribute: krb5_principal')
    return principal


async def password(
    username: str,
    password: str,
    user_ip: str,
    scope: str = "openid",
    **kwargs
) -> dict[str, any]:
    try:
        json = await oidc.password_grant(username, password, user_ip, scope, **kwargs)

    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code

        try:
            err_data = e.response.json()
            error_code = err_data.get("error", "unknown_error")
            error_desc = err_data.get("error_description", e.response.text)
        except Exception:
            error_code = "raw_error"
            error_desc = e.response.text[:200]

        # Check if CrowdSec served a HTML Ban page
        content_type = e.response.headers.get("content-type", "")
        if "text/html" in content_type and "<title>CrowdSec Ban</title>" in e.response.text:
            logger.warning(
                "CrowdSec BAN triggered for client IP '%s' (user '%s')",
                user_ip,
                username
            )
            raise ForbiddenError("Authentication blocked by security policy (CrowdSec BAN)")

        # OAuth 2.0 RFC 6749: Keycloak returns 400 with "invalid_grant" on wrong password/username
        if error_code == "invalid_grant" or status_code == 401:
            logger.info(
                "Keycloak invalid credentials for user '%s': %s - %s",
                username, error_code, error_desc
            )
            raise UnauthorizedError("Invalid username or password")

        elif status_code == 400:
            logger.warning(
                "Keycloak 400 for user '%s': %s - %s",
                username, error_code, error_desc
            )
            raise BadRequestError(f"Invalid authentication request: {error_desc}")
        elif status_code == 403:
            logger.warning(
                "Keycloak 403 for user '%s': %s - %s",
                username, error_code, error_desc
            )
            raise ForbiddenError("User access is disabled in Keycloak")
        else:
            logger.error(
                "Keycloak returned status %s for user '%s': %s - %s",
                status_code, username, error_code, error_desc
            )
            raise OIDCError(f"Provider error: {status_code}")

    except httpx.HTTPError as e:
        logger.error("Keycloak connection failed for user '%s': %s", username, e)
        raise OIDCError("Authentication service temporarily unavailable")

    access_token = json.get("access_token")
    if not access_token:
        logger.warning("Keycloak returned no access_token for user '%s'", username)
        raise UnauthorizedError("Authentication failed: No token received")

    try:
        claims = oidc.verify(access_token)
    except (ValueError, PyJWTError) as e:
        logger.warning("Keycloak token verification failed for '%s': %s", username, e)
        raise UnauthorizedError("Invalid or expired token")

    return json, claims


oidc = KeycloakOIDCClient(
    well_known_url=OIDC_WELL_KNOWN_URL,
    audience=OIDC_AUDIENCE,
    client_id=AUTH_CLIENT_ID,
    client_secret=AUTH_CLIENT_SECRET
)
