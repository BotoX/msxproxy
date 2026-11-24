import logging
import httpx
import jwt
import ipaddress
from jwt.exceptions import PyJWTError

from . import config as mp_config
from .config import (
    OIDC_WELL_KNOWN_URL,
    OIDC_AUDIENCE,
    AUTH_CLIENT_ID,
    AUTH_CLIENT_SECRET,
    TRUSTED_NETWORKS
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

class TrustedNetworkError(OIDCError):
    """Password is not valid in this network"""
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
        self._http_client: httpx.AsyncClient | None = None

        self._setup()

    def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=self.timeout)
        return self._http_client

    async def aclose(self) -> None:
        if self._http_client is not None and not self._http_client.is_closed:
            await self._http_client.aclose()
            self._http_client = None

    def _setup(self) -> None:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(self.well_known_url)
            resp.raise_for_status()
            self._config = resp.json()

            jwks_uri = self._config["jwks_uri"]
            resp = client.get(jwks_uri)
            resp.raise_for_status()
            self._jwk_set = jwt.PyJWKSet.from_dict(resp.json())

    def reload_from_config(self) -> None:
        """Reload OIDC settings from mailproxy.config and refresh discovery + JWKS."""
        new_url = mp_config.OIDC_WELL_KNOWN_URL
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(new_url)
            resp.raise_for_status()
            new_cfg = resp.json()

            resp = client.get(new_cfg["jwks_uri"])
            resp.raise_for_status()
            new_jwks = jwt.PyJWKSet.from_dict(resp.json())

        self.well_known_url = new_url
        self.audience = mp_config.OIDC_AUDIENCE
        self.client_id = mp_config.AUTH_CLIENT_ID
        self.client_secret = mp_config.AUTH_CLIENT_SECRET
        self._config = new_cfg
        self._jwk_set = new_jwks

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

        client = self._get_http_client()
        resp = await client.post(self.token_endpoint, data=data, headers=headers)
        resp.raise_for_status()
        return resp.json()


def trusted_network(ip_address: str):
    ip = ipaddress.ip_address(ip_address)
    for network in TRUSTED_NETWORKS:
        if ip in network:
            return True
    return False


def claims2principal(claims: dict[str, any], ip_address: str) -> str:
    acr = claims.get("acr") or ""
    azp = claims.get("azp") or ""
    if azp.endswith("_DirectGrant") and acr != "mail-password" and not trusted_network(ip_address):
        raise TrustedNetworkError()

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
        if status_code == 401:
            logger.debug("Keycloak: Invalid credentials for user '%s'", username)
            raise UnauthorizedError("Invalid username or password")
        elif status_code == 400:
            logger.warning("Keycloak: Bad request: %s", e)
            raise BadRequestError("Invalid authentication request")
        elif status_code == 403:
            logger.warning("Keycloak: Access forbidden for user '%s'", username)
            raise ForbiddenError("User access is disabled in Keycloak")
        else:
            logger.error("Keycloak returned unexpected status %s: %s", status_code, e.response.text)
            raise OIDCError(f"Provider error: {status_code}")

    except httpx.HTTPError as e:
        logger.error("Keycloak connection failed for user '%s': %s", username, e)
        raise OIDCError("Authentication service temporarily unavailable")

    id_token = json.get("id_token")
    if not id_token:
        logger.warning("Keycloak returned no id_token for user '%s'", username)
        raise UnauthorizedError("Authentication failed: No token received")

    try:
        claims = oidc.verify(id_token)
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
