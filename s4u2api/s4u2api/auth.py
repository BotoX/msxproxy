import logging
import httpx
import jwt
from jwt.exceptions import PyJWTError

from .config import OIDC_WELL_KNOWN_URL, OIDC_AUDIENCE

logger = logging.getLogger(__name__)


class KeycloakOIDCClient:
    def __init__(
        self,
        well_known_url: str,
        audience: str,
        timeout: float = 5.0
    ) -> None:
        self.well_known_url = well_known_url
        self.audience = audience
        self.timeout = timeout

        self._config: dict[str, any] = {}
        self._jwk_set: jwt.PyJWKSet | None = None

        self._setup()

    def _setup(self) -> None:
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.get(self.well_known_url)
            resp.raise_for_status()
            self._config = resp.json()

            jwks_uri = self._config['jwks_uri']
            resp = client.get(jwks_uri)
            resp.raise_for_status()
            self._jwk_set = jwt.PyJWKSet.from_dict(resp.json())

    @property
    def issuer(self) -> str:
        return self._config['issuer']

    def verify(self, token: str) -> dict[str, any]:
        try:
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get('kid')
            if not kid:
                raise ValueError('No "kid" found in token header')
        except PyJWTError as e:
            raise ValueError(f'Invalid token format: {e}')

        try:
            jwk = self._jwk_set[kid]
        except KeyError:
            raise ValueError(f'Key ID {kid} not found in JWKS')

        try:
            claims = jwt.decode(
                token,
                key=jwk.key,
                algorithms=['RS256'],
                options={'verify_aud': True},
                audience=self.audience,
                issuer=self.issuer
            )
            return claims
        except PyJWTError as e:
            logger.error(f'Token verification failed: {e}')
            raise ValueError(f'Token verification failed: {e}')


def claims2principal(claims: dict[str, any]) -> str:
    principal = claims.get('krb5_principal')
    if not principal:
        raise ValueError('missing attribute: krb5_principal')
    return principal


oidc = KeycloakOIDCClient(
    well_known_url=OIDC_WELL_KNOWN_URL,
    audience=OIDC_AUDIENCE
)
