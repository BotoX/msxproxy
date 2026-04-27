import os

API_SECRET = "***"

OIDC_WELL_KNOWN_URL = "https://login.uni-graz.at/auth/realms/UniGraz/.well-known/openid-configuration"
OIDC_AUDIENCE = "https_webmail.uni-graz.at"
AUTH_CLIENT_ID = "https_webmail.uni-graz.at_DirectGrant"
AUTH_CLIENT_SECRET = "***"

ENROLL_JWT_ISSUER = "https://webmail.uni-graz.at"
ENROLL_JWT_SECRET = "***"
ENROLL_JWT_AUD = "deviceid-enroll-authenticator"
ENROLL_JWT_ALG = "HS256"

ENROLL_CLIENT_ID = "https_webmail.uni-graz.at_Enroll"
ENROLL_REDIRECT_URI = "https://webmail.uni-graz.at/ActiveSync_Enroll_Complete"
