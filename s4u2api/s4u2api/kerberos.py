# kerberos.py

import asyncio
import os
import re
import gssapi
import krb5
import hashlib
import time
import traceback
import unicodedata
from functools import partial
from filelock import AsyncUnixFileLock
from contextlib import closing

from .config import (
    KRB5_CLIENT_KTNAME,
    KRB5_PRINCIPAL,
    KRB5_CCACHE_DIR
)


_filename_ascii_strip_re = re.compile(r"[^A-Za-z0-9_.-]")
def secure_filename(filename: str) -> str:
    filename = unicodedata.normalize("NFKD", filename)
    filename = filename.encode("ascii", "ignore").decode("ascii")
    for sep in os.sep, os.path.altsep:
        if sep:
            filename = filename.replace(sep, " ")
    filename = str(_filename_ascii_strip_re.sub("", "_".join(filename.split()))).strip("._")
    return filename


class KerberosProxy:
    def __init__(self, keytab: str, proxy_principal: str, ccache_dir: str, min_lifetime=300):
        self.keytab = keytab
        self.proxy_principal = gssapi.Name(proxy_principal, gssapi.NameType.kerberos_principal)
        self.ccache_dir = ccache_dir
        self.min_lifetime = min_lifetime

        os.makedirs(self.ccache_dir, exist_ok=True, mode=0o700)
        self.proxy_creds = None
        self.krb5_ctx = krb5.init_context()

    async def get_proxy_creds(self) -> gssapi.Credentials:
        # Loaded, not expired and valid for > 5 minutes
        if self.proxy_creds:
            try:
                if self.proxy_creds.lifetime > self.min_lifetime:
                    return self.proxy_creds
            except (gssapi.exceptions.GSSError, gssapi.raw.exceptions.ExpiredCredentialsError):
                pass

        # Load from disk and check if not expired and valid for > 5 minutes
        ccache_path = f'{self.ccache_dir}/_primary'
        async with AsyncUnixFileLock(ccache_path + '.lock'):
            try:
                creds = gssapi.Credentials(
                    name=self.proxy_principal,
                    usage='initiate',
                    store={
                        'client_keytab': self.keytab,
                        'ccache': f'FILE:{ccache_path}'
                    }
                )
                if creds.lifetime > self.min_lifetime:
                    self.proxy_creds = creds
                    return self.proxy_creds
            except (gssapi.exceptions.GSSError, gssapi.raw.exceptions.ExpiredCredentialsError):
                pass

            # Remove in case it exists (valid < 5 minutes)
            if os.path.exists(ccache_path):
                os.remove(ccache_path)

            # Get fresh credentials from the KDC and store to ccache
            loop = asyncio.get_running_loop()
            self.proxy_creds = await loop.run_in_executor(None,
                partial(gssapi.Credentials,
                    name=self.proxy_principal,
                    usage='initiate',
                    store={
                        'client_keytab': self.keytab,
                        'ccache': f'FILE:{ccache_path}'
                    }
                )
            )
            return self.proxy_creds

    def _krb5_get_creds(self, ccache_path: str, spn: str):
        if not os.path.exists(ccache_path):
            return None, None
        try:
            valid = None
            krb5_ccache = krb5.cc_resolve(self.krb5_ctx, f'FILE:{ccache_path}'.encode())
            # would leak file handles on break without wrapping the iterator in closing()
            with closing(iter(krb5_ccache)) as ticket_stream:
                for krb5_cred in ticket_stream:
                    server_name = krb5_cred.server.name.decode()
                    if server_name == spn:
                        valid = krb5_cred.times.endtime > (time.time() + self.min_lifetime)
                        break
            rcreds = gssapi.raw.creds.Creds()
            gssapi.raw.ext_krb5.krb5_import_cred(rcreds, cache=krb5_ccache.addr)
            gss_creds = gssapi.Credentials(base=rcreds)
            return gss_creds, valid
        except Exception as e:
            traceback.print_exc()
            return None, None

    def _upn_ccache_path(self, upn: str) -> str:
        upnhash = hashlib.md5(upn.encode()).hexdigest()[:8]
        user, domain = upn.split('@')
        domain = domain.split('.', maxsplit=1)[0]
        safe_id = secure_filename(f'{domain}_{user}_{upnhash}')
        return f'{self.ccache_dir}/{safe_id}'

    async def create_context(self, upn: str, spn: str) -> tuple[gssapi.SecurityContext, str]:
        target_name = gssapi.Name(spn, gssapi.NameType.kerberos_principal)
        user_name = gssapi.Name(upn, gssapi.NameType.kerberos_principal)
        ccache_path = self._upn_ccache_path(upn)

        def init_context(creds):
            ctx = gssapi.SecurityContext(
                name=target_name,
                creds=creds,
                usage='initiate'
            )
            token = ctx.step()
            return ctx, token

        creds, creds_valid = self._krb5_get_creds(ccache_path, spn)
        if creds and creds_valid:
            return init_context(creds)

        # Not found in cache (or expired/expiring) -> acquire lock
        async with AsyncUnixFileLock(ccache_path + '.lock'):
            # Double check after acquiring lock
            creds, creds_valid = self._krb5_get_creds(ccache_path, spn)
            if creds and creds_valid:
                return init_context(creds)

            # Check if we're just missing this SPN or need to impersonate again
            loop = asyncio.get_running_loop()
            try:
                if not creds:
                    creds = gssapi.Credentials(
                        name=user_name,
                        usage='initiate',
                        store={'ccache': f'FILE:{ccache_path}'}
                    )
                if creds.lifetime < self.min_lifetime:
                    raise gssapi.raw.exceptions.ExpiredCredentialsError(0, 0)
            except (gssapi.exceptions.GSSError, gssapi.raw.exceptions.ExpiredCredentialsError):
                # Get fresh impersonated credentials from the KDC
                proxy_creds = await self.get_proxy_creds()
                creds = await loop.run_in_executor(None,
                    partial(proxy_creds.impersonate,
                        user_name
                    )
                )

            # Get fresh service ticket from the KDC
            ctx, token = await loop.run_in_executor(None,
                partial(init_context,
                    creds
                )
            )

            creds.store(
                usage='initiate',
                store={'ccache': f'FILE:{ccache_path}'},
                overwrite=True
            )
            return ctx, token


kerb_proxy = KerberosProxy(
    KRB5_CLIENT_KTNAME,
    KRB5_PRINCIPAL,
    KRB5_CCACHE_DIR
)
