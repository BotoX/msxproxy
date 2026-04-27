import time
import secrets

from jose import jwt
from jose.exceptions import JWTError
from urllib.parse import urlencode

from .auth import oidc
from .config import (
    ENROLL_JWT_ISSUER,
    ENROLL_JWT_SECRET,
    ENROLL_JWT_AUD,
    ENROLL_JWT_ALG,
    ENROLL_CLIENT_ID,
    ENROLL_REDIRECT_URI
)

def generate_enroll_token(
    subject: str,
    deviceId: str,
    deviceType: str,
    expires_in: int
) -> str:
    now = int(time.time())
    payload: dict[str, any] = {
        "iss": ENROLL_JWT_ISSUER,
        "aud": ENROLL_JWT_AUD,
        "iat": now,
        "exp": now + expires_in,
        "sub": subject,
        "jti": secrets.token_urlsafe(16),
        "DeviceId": deviceId,
        "DeviceType": deviceType
    }
    return jwt.encode(payload, ENROLL_JWT_SECRET, algorithm=ENROLL_JWT_ALG)


def verify_enroll_token(token: str) -> dict[str, any]:
    try:
        claims = jwt.decode(
            token,
            ENROLL_JWT_SECRET,
            algorithms=[ENROLL_JWT_ALG],
            issuer=ENROLL_JWT_ISSUER
        )
        return claims
    except JWTError as e:
        raise ValueError(f"Invalid enroll token: {e}")


def keycloak_enroll_link(
    subject: str,
    deviceId: str,
    deviceType: str,
    expires_in: int
) -> str:
    token = generate_enroll_token(
        subject=subject,
        deviceId=deviceId,
        deviceType=deviceType,
        expires_in=expires_in
    )

    auth_url = oidc.authorization_endpoint
    client_id = ENROLL_CLIENT_ID
    redirect_uri = ENROLL_REDIRECT_URI

    query = {
        "client_id": client_id,
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": redirect_uri,
        "enroll_token": token
    }
    return f"{auth_url}?{urlencode(query)}"


def generate_enroll_mail(username, name, deviceId, deviceType, protocol_version, ip, ua):
    mfa_link = keycloak_enroll_link(
        username,
        deviceId,
        deviceType,
        3600
    )

    timestamp = time.strftime("%d.%m.%Y %H:%M:%S", time.localtime())

    # Plain text version (Bilingual)
    plain = f"""Sehr geehrte*r {name},

ein Anmeldeversuch ohne MFA von einer neuen Geräte-ID wurde erkannt.
Um den Zugriff auf Ihre E-Mails zu ermöglichen, muss dieses Gerät einmalig verifiziert werden.

Details:
- Zeitstempel: {timestamp}
- Gerätetyp: {deviceType}
- Geräte-ID: {deviceId}

Klicken Sie auf den folgenden Link, um über uniLOGIN fortzufahren:
{mfa_link}

Der Link ist ab dem Zeitstempel eine Stunde lang gültig.
Aktualisieren Sie Ihre E-Mails, um einen neuen Link zu erhalten.

-------------------------------English Version-------------------------------

Dear {name},

A login attempt without MFA from a new device ID was detected.
To enable email access, this device must be verified once.

Details:
- Timestamp: {timestamp}
- Device Type: {deviceType}
- Device ID: {deviceId}

Visit the following link to continue via uniLOGIN:
{mfa_link}

The link is valid for one hour from the timestamp.
Refresh your emails to get a new link.


Support & Hilfe | Support & Help:

ASK - Digitaler Assistent: ask.uni-graz.at (24/7 Support)
Telefon: +43 316 380 - 2240 (Mo-Fr: 08:00 - 16:00)
E-Mail: servicedesk@uni-graz.at
Infopoint: Universitätsstrasse 15, RESOWI-Zentrum, Bauteil GE


Informationsmanagement – uniIT | Information Management – uniIT
Universität Graz | University of Graz
https://it.uni-graz.at

---
MS-ASProtocolVersion: {protocol_version}
User-Agent: {ua}
IP Address: {ip}
"""

    # HTML version (Bilingual + Corporate Design)
    html = f"""<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; color: #000000; line-height: 1.6; margin: 0; background-color: #f4f4f4">
<div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 16px; border-top: 10px solid #ffd500; border-bottom: 10px solid #ffd500">
    <h2 style="color: #000000; margin-top: 0">Exchange ActiveSync Multi-Faktor-Authentifizierung</h2>
    <p>Sehr geehrte*r {name},</p>
    <p>ein Anmeldeversuch ohne MFA von einer neuen Geräte-ID wurde erkannt.<br>
    Um den Zugriff auf Ihre E-Mails zu ermöglichen, muss dieses Gerät einmalig verifiziert werden.</p>

    <table border="0" cellpadding="5" cellspacing="0" width="100%" role="presentation" style="background-color: #f9f9f9; margin-bottom: 20px; border-left: 4px solid #ffd500; table-layout: fixed">
        <tr><td style="width: 100px; vertical-align: top"><strong>Zeitstempel:</strong></td><td>{timestamp}</td></tr>
        <tr><td style="vertical-align: top"><strong>Gerätetyp:</strong></td><td style="word-break: break-all">{deviceType}</td></tr>
        <tr><td style="vertical-align: top"><strong>Geräte-ID:</strong></td><td style="word-break: break-all">{deviceId}</td></tr>
    </table>

    <p>Klicken Sie auf den folgenden Button, um über <b>uniLOGIN</b> fortzufahren:</p>

    <div style="text-align: center; margin: 30px 0">
        <a href="{mfa_link}" target="_blank" style="background-color: #ffd500; padding: 14px 25px; color: #000000; text-decoration: none; font-weight: bold; font-size: 16px; display: inline-block; border-radius: 4px">
            ActiveSync Geräte-ID verifizieren
        </a>
    </div>

    <p style="font-size: 13px; color: #666666"><em>Der Button führt zu <b>login.uni-graz.at</b> und ist ab dem Zeitstempel eine Stunde lang gültig.<br>
    Aktualisieren Sie Ihre E-Mails, um einen neuen Link zu erhalten.</em>
    </p>

    <hr style="border: 0; border-top: 1px solid #eeeeee; margin: 40px 0">

    <h2 style="color: #000000; margin-top: 0">Exchange ActiveSync Multi-Factor Authentication</h2>
    <p>Dear {name},</p>
    <p>A login attempt without MFA from a new device ID was detected.<br>
    To enable email access, this device must be verified once.</p>

    <table border="0" cellpadding="5" cellspacing="0" width="100%" role="presentation" style="background-color: #f9f9f9; margin-bottom: 20px; border-left: 4px solid #ffd500; table-layout: fixed">
        <tr><td style="width: 100px; vertical-align: top"><strong>Timestamp:</strong></td><td>{timestamp}</td></tr>
        <tr><td style="vertical-align: top"><strong>Device Type:</strong></td><td style="word-break: break-all">{deviceType}</td></tr>
        <tr><td style="vertical-align: top"><strong>Device ID:</strong></td><td style="word-break: break-all">{deviceId}</td></tr>
    </table>

    <p>Click the following button to continue via <b>uniLOGIN</b>:</p>

    <div style="text-align: center; margin: 30px 0">
        <a href="{mfa_link}" target="_blank" style="background-color: #ffd500; padding: 14px 25px; color: #000000; text-decoration: none; font-weight: bold; font-size: 16px; display: inline-block; border-radius: 4px">
            Verify ActiveSync Device ID
        </a>
    </div>

    <p style="font-size: 13px; color: #666666"><em>The button leads to <b>login.uni-graz.at</b> and is valid for one hour from the timestamp.<br>
    Refresh your emails to get a new link.</em>
    </p>

    <div style="margin-top: 40px; padding-top: 20px; font-size: 12px; color: #666666; border-top: 1px solid #eeeeee">
        <strong style="color: #000000">Support & Hilfe | <span style="color: #666666">Support & Help:</span></strong><br>
        <p style="margin: 5px 0">
            <strong style="color: #000000">ASK - Digitaler Assistent:</strong> <a href="https://ask.uni-graz.at" style="color: #004b91; text-decoration: none">ask.uni-graz.at</a> (24/7 Support)<br>
            <strong style="color: #000000">Telefon:</strong> <a href="tel:+433163802240" style="color: #004b91; text-decoration: none">+43 316 380 - 2240</a> (Mo-Fr: 08:00 - 16:00)<br>
            <strong style="color: #000000">E-Mail:</strong> <a href="mailto:servicedesk@uni-graz.at" style="color: #004b91; text-decoration: none">servicedesk@uni-graz.at</a><br>
            <strong style="color: #000000">Infopoint:</strong> <a href="https://maps.app.goo.gl/mjwqmdz8ZheScn3fA" style="color: #004b91; text-decoration: none">Universitätsstrasse 15, RESOWI-Zentrum, Bauteil GE</a>
        </p>
    </div>

    <div style="margin-top: 20px; padding-top: 20px; border-radius: 4px; border-top: 1px solid #e3e3e3">
        <p style="margin: 0 0 10px 0; font-size: 11px; color: #666666; line-height: 1.4">
            Falls der Button nicht funktioniert, kopieren Sie diesen Link in Ihren Browser:<br>
            If the button doesn't work, copy and paste this link into your browser:
        </p>
        <div style="font-size: 11px; line-height: 1.4; word-break: break-all">
            <a href="{mfa_link}" style="color: #004b91; text-decoration: underline">{mfa_link}</a>
        </div>
    </div>

    <div style="margin-top: 20px; padding-top: 20px; font-size: 12px; text-align: center; color: #000000; border-top: 1px solid #eeeeee">
        Informationsmanagement – uniIT | <span style="color: #666666">Information Management – uniIT</span><br>
        Universität Graz | <span style="color: #666666">University of Graz</span><br>
        <a href="https://it.uni-graz.at" style="color: #004b91; text-decoration: none">it.uni-graz.at</a>
    </div>
</div>
</body>
<div style="margin-top: 5px; font-size: 9px; text-align: left; color: #000000">
    <strong>MS-ASProtocolVersion:</strong> {protocol_version}<br>
    <strong>User-Agent:</strong> {ua}<br>
    <strong>IP Address:</strong> {ip}
</div>
</html>"""

    return plain, html
