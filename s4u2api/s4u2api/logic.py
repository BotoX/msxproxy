import asyncio
import hashlib
import hmac
import gssapi
import time
import logging
import base64
import traceback
from functools import partial
import redis.asyncio as redis

from . import kerberos
from . import auth
from .config import (
    VALID_SPNS,
    VALKEY_SOCK,
    CACHE_SECRET
)

logger = logging.getLogger(__name__)


# Create a single connection pool per worker process
valkey_client = redis.Redis(
    unix_socket_path=VALKEY_SOCK,
    decode_responses=True,
    retry_on_timeout=True,
    health_check_interval=30
)


async def setup():
    await valkey_client.flushdb()


def sign_cache_value(principal: str, jwt_hash: str) -> str:
    """Signs the principal bound to a specific hash to prevent cross-key poisoning."""
    msg = f'{principal}:{jwt_hash}'.encode()
    sig = hmac.new(CACHE_SECRET, msg, hashlib.sha256).hexdigest()
    return f'{principal}::{sig}'


def verify_cache_value(stored_val: str, jwt_hash: str) -> str:
    """Verifies the HMAC signature. Raises ValueError if tampered."""
    try:
        principal, sig = stored_val.split('::')
        expected_msg = f'{principal}:{jwt_hash}'.encode()
        expected_sig = hmac.new(CACHE_SECRET, expected_msg, hashlib.sha256).hexdigest()

        if hmac.compare_digest(sig, expected_sig):
            return principal
    except ValueError:
        pass

    logger.critical('REDIS CACHE POISONING DETECTED for hash %s!', jwt_hash)
    raise ValueError('Cache signature invalid!')


async def get_principal_cached(jwt_str: str, oidc_client: auth.KeycloakOIDCClient) -> str:
    jwt_hash = hashlib.sha256(jwt_str.encode()).hexdigest()

    cache_key = f'jwt:{jwt_hash}'
    lock_key = f'lock:{jwt_hash}'
    channel_key = f'pub:{jwt_hash}'

    while True:
        # Fast Path: JWT Hash in Redis Cache
        cached_val = await valkey_client.get(cache_key)
        if cached_val:
            return verify_cache_value(cached_val, jwt_hash)

        # Leader Selection: JWT Hash not in Redis Cache -> first worker calculates and stores it
        # Other potential workers wait for the result

        # NX = Set if Not eXists. EX = Expire in 1s (Failsafe if worker crashes)
        acquired = await valkey_client.set(lock_key, '1', nx=True, ex=1)

        if acquired:
            try:
                # Leader Logic: Verify JWT
                try:
                    loop = asyncio.get_running_loop()
                    claims = await loop.run_in_executor(None,
                        partial(oidc_client.verify,
                            token=jwt_str
                        )
                    )
                    principal = auth.claims2principal(claims)

                    exp = int(claims.get('exp', time.time() + 300))
                    ttl = max(1, exp - int(time.time()))
                except Exception as e:
                    logger.warning(f'JWT Verification failed for {jwt_hash}: {e}\n{jwt_str}')
                    traceback.print_exc()
                    principal = f'ERROR: {e}'
                    ttl = 60

                # Sign the data
                signed_val = sign_cache_value(principal, jwt_hash)

                # Use a pipeline to ensure the Save and Publish happen atomically
                async with valkey_client.pipeline(transaction=True) as pipe:
                    pipe.set(cache_key, signed_val, ex=ttl)
                    pipe.publish(channel_key, 'READY')
                    await pipe.execute()

                return principal

            finally:
                await valkey_client.delete(lock_key)

        else:
            # Follower Logic: Subscribe and wait/fetch result
            async with valkey_client.pubsub() as pubsub:
                await pubsub.subscribe(channel_key)

                # Did the leader finish between our first GET and our SUBSCRIBE?
                cached_val = await valkey_client.get(cache_key)
                if cached_val:
                    await pubsub.unsubscribe(channel_key)
                    return verify_cache_value(cached_val, jwt_hash)

                # Wait 1s for the READY signal. If it never comes (leader crashed),
                # wait_for raises TimeoutError, the loop repeats, and we try to be leader.
                try:
                    async def wait_for_ready():
                        async for message in pubsub.listen():
                            if message['type'] == 'message' and message['data'] == 'READY':
                                return True

                    await asyncio.wait_for(wait_for_ready(), timeout=1.0)
                except (asyncio.TimeoutError, Exception):
                    logger.debug('Follower timed out or lost connection, retrying...')
                    continue
                finally:
                    await pubsub.unsubscribe(channel_key)


async def client_message(msg: dict[str, any], ctx: gssapi.SecurityContext|None, peername: str) -> dict[str, any]:
    want_ctx: bool = msg.get('ctx', False)
    step: str = msg.get('step', None)

    if step:
        if not ctx:
            return ValueError('No context established!')
        step = base64.b64decode(step)
        token = ctx.step(step)
    else:
        spn: str = msg['spn']
        upn: str = msg['upn']
        jwt: str = msg['jwt']

        fullspn = VALID_SPNS.get(spn)
        if not fullspn:
            raise ValueError('Invalid spn')

        principal = await get_principal_cached(jwt, auth.oidc)
        if principal.startswith('ERROR:'):
            raise ValueError(principal)

        if upn != principal:
            raise ValueError(f'upn missmatch: "{upn}" != "{principal}"')

        logger.info(f'[{peername}] Impersonating {upn} for {spn}')
        ctx, token = await kerberos.kerb_proxy.create_context(principal, fullspn)

    res = {
        'token': base64.b64encode(token).decode() if token else None,
        'complete': ctx.complete
    }

    if want_ctx:
        if ctx.complete:
            res['ctx'] = ctx.export()
            return res, None
        else:
            return res, ctx

    return res, None
