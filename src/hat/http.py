from __future__ import annotations

import datetime
import inspect
import mimetypes
import pprint
from contextlib import AbstractAsyncContextManager
from typing import Any
from typing import Mapping

from aiohttp import ClientResponse
from aiohttp import ClientResponseError
from aiohttp import ClientSession


# Ref: https://adamj.eu/tech/2021/12/29/python-type-hints-optional-imports/
try:
    from aiohttp_client_cache import CacheBackend
    from aiohttp_client_cache import CachedSession

    CACHING_ENABLED = True
except ImportError:
    CACHING_ENABLED = False

from . import auth as _auth
from . import errors
from . import urls
from . import utils
from .model import HatRecord
from .model import M


NEVER_CACHE = 0
SESSION_DEFAULTS = {
    "headers": {"Content-Type": mimetypes.types_map[".json"]},
    "allowed_codes": [200] + list(errors.possible_codes),
    "allowed_methods": ["GET", "POST"],
    "expire_after": datetime.timedelta(minutes=10),
    "urls_expire_after": {
        urls.domain_owner_token("*"): NEVER_CACHE,
        urls.domain_app_token("*", "*"): NEVER_CACHE,
    },
}


class Cacheable:
    __slots__ = ()

    def clear_cache(self) -> None:
        pass


class AsyncCacheable(Cacheable):
    async def clear_cache(self) -> None:
        pass


class Closeable:
    __slots__ = ()

    def close(self) -> None:
        pass


class AsyncCloseable(Closeable):
    __slots__ = ()

    async def close(self) -> None:
        pass


class ResponseHandler:
    @staticmethod
    async def on_success(response: ClientResponse, **kwargs) -> str | list[M] | None:
        url = str(response.url)
        if urls.is_pk_endpoint(url):
            return await response.text()
        elif urls.is_token_endpoint(url):
            return utils.loads(await response.read())[_auth.TOKEN_KEY]
        elif response.method.lower() == "delete":
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(await response.read(), kwargs["mtypes"])
        else:
            headers = pprint.pformat(response.headers, indent=2)
            raise ValueError(f"Unable to process response for URL {url}\n{headers}")

    @staticmethod
    async def on_error(error: ClientResponseError, **kwargs) -> None:
        url = str(error.request_info.url)
        status = error.status
        content = utils.loads(error.message)
        if urls.is_auth_endpoint(url):
            raise errors.find_error("auth", status, content)
        elif urls.is_api_endpoint(url):
            method = error.request_info.method.lower()
            raise errors.find_error(method, status, content)
        else:
            raise error


class HttpClient(AsyncCacheable, AsyncCloseable, AbstractAsyncContextManager):
    __slots__ = "_session", "_handler", "_auth"

    def __init__(
        self,
        session: ClientSession | None = None,
        auth: _auth.HttpAuth | None = None,
        **kwargs,
    ) -> None:
        self._session = session or self._new_session(**kwargs)
        self._handler = ResponseHandler()
        self._auth = auth or _auth.HttpAuth()

    @staticmethod
    def _new_session(**kwargs) -> ClientSession:
        kwargs = SESSION_DEFAULTS | kwargs
        if CACHING_ENABLED:
            cache = kwargs.pop("cache", None) or CacheBackend(**kwargs)
            session = CachedSession(cache=cache, **kwargs)
        else:
            params = inspect.signature(ClientSession.__init__).parameters
            kwargs = {k: v for k, v in kwargs.items() if k in params}
            session = ClientSession(**kwargs)
        return session

    async def request(
        self,
        method: str,
        url: str,
        *,
        auth: _auth.HttpAuth | None = None,
        headers: Mapping[str, str] | None = None,
        data: Any = None,
        params: Mapping[str, str] | None = None,
        **kwargs,
    ) -> Any:
        auth = auth or self._auth
        auth_headers = await auth.headers()
        headers = headers | auth_headers if headers else auth_headers
        async with self._session.request(
            method, url, headers=headers, data=data, params=params
        ) as response:
            try:
                response.raise_for_status()
            except ClientResponseError as error:
                result = await self._handler.on_error(error, **kwargs)
            else:
                await auth.on_response(response)
                result = await self._handler.on_success(response, **kwargs)
            return result

    async def close(self) -> None:
        return await self._session.close()

    async def clear_cache(self) -> None:
        if CACHING_ENABLED and isinstance(self._session, CachedSession):
            return await self._session.cache.clear()

    async def __aenter__(self) -> HttpClient:
        await self._session.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)
