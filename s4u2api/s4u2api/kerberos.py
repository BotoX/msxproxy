# kerberos.py

import asyncio
import os
import re
import tempfile
import gssapi
import hashlib
import time
import traceback
import unicodedata
from functools import partial
from filelock import AsyncUnixFileLock
from contextlib import suppress

from .ccache import get_ticket_endtime
from . import config
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

    def reload_from_config(self) -> None:
        """Re-read Kerberos settings from s4u2api.config and clear cached proxy credentials."""
        new_keytab = config.KRB5_CLIENT_KTNAME
        new_principal = gssapi.Name(config.KRB5_PRINCIPAL, gssapi.NameType.kerberos_principal)
        new_ccache_dir = config.KRB5_CCACHE_DIR
        os.makedirs(new_ccache_dir, exist_ok=True, mode=0o700)
        self.keytab = new_keytab
        self.proxy_principal = new_principal
        self.ccache_dir = new_ccache_dir
        self.proxy_creds = None

    def prune_ccaches(self, max_age_seconds: int = 86400) -> int:
        """Remove stale per-user ccache and lock files older than max_age_seconds."""
        if not os.path.isdir(self.ccache_dir):
            return 0
        cutoff = time.time() - max_age_seconds
        removed = 0
        with os.scandir(self.ccache_dir) as entries:
            for entry in entries:
                if not entry.is_file(follow_symlinks=False):
                    continue
                if entry.name in ("_primary", "_primary.lock"):
                    continue
                with suppress(OSError):
                    if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                        os.unlink(entry.path)
                        removed += 1
        return removed

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

    def _krb5_get_creds(self, ccache_path: str, user_name: gssapi.Name, spn: str):
        try:
            endtime = get_ticket_endtime(ccache_path, spn)
        except Exception:
            traceback.print_exc()
            return None, None

        if endtime is None:
            return None, None

        if endtime <= (time.time() + self.min_lifetime):
            return None, False

        try:
            gss_creds = gssapi.Credentials(
                name=user_name,
                usage='initiate',
                store={'ccache': f'FILE:{ccache_path}'}
            )
            return gss_creds, True
        except (gssapi.exceptions.GSSError, gssapi.raw.exceptions.ExpiredCredentialsError):
            return None, False

    def _upn_ccache_path(self, upn: str) -> str:
        user, sep, domain = upn.partition('@')
        if not sep or '@' in domain:
            raise ValueError(f'Invalid UPN: {upn!r}')
        upnhash = hashlib.md5(upn.encode()).hexdigest()[:8]
        domain = domain.split('.', maxsplit=1)[0]
        safe_id = secure_filename(f'{domain}_{user}_{upnhash}')
        return f'{self.ccache_dir}/{safe_id}'

    def _store_ccache_atomic(self, creds: gssapi.Credentials, ccache_path: str) -> None:
        """
        Write credentials to a 0600 temp file in ccache_dir and atomically replace
        ccache_path so lock-free readers never observe a truncated/half-written file.
        """
        prefix = f'.{os.path.basename(ccache_path)}.'
        with tempfile.NamedTemporaryFile(
            dir=self.ccache_dir, prefix=prefix, suffix='.tmp', delete=False
        ) as tmp:
            tmp_path = tmp.name

        try:
            creds.store(
                usage='initiate',
                store={'ccache': f'FILE:{tmp_path}'},
                overwrite=True
            )
            os.replace(tmp_path, ccache_path)
        except BaseException:
            with suppress(OSError):
                os.unlink(tmp_path)
            raise

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

        # Fast path (lock-free): _store_ccache_atomic guarantees readers only ever
        # see a complete inode, and valid cached tickets require no KDC network I/O.
        creds, creds_valid = self._krb5_get_creds(ccache_path, user_name, spn)
        if creds and creds_valid:
            return init_context(creds)

        # Not found in cache (or expired/expiring) -> acquire lock
        async with AsyncUnixFileLock(ccache_path + '.lock'):
            # Double check after acquiring lock
            creds, creds_valid = self._krb5_get_creds(ccache_path, user_name, spn)
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
            ctx, token = await loop.run_in_executor(None, init_context, creds)

            self._store_ccache_atomic(creds, ccache_path)
            return ctx, token


kerb_proxy = KerberosProxy(
    KRB5_CLIENT_KTNAME,
    KRB5_PRINCIPAL,
    KRB5_CCACHE_DIR
)
