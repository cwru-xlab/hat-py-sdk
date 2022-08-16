from __future__ import annotations

import datetime
import mimetypes
import pprint
from contextlib import AbstractAsyncContextManager
from typing import Any
from typing import Mapping

from aiohttp import ClientResponse
from aiohttp import ClientResponseError
from aiohttp import ClientSession
from aiohttp_client_cache import CacheBackend
from aiohttp_client_cache import CachedSession

from . import auth as _auth
from . import errors
from . import urls
from . import utils
from .base import AsyncCachable
from .base import BaseHttpClient
from .base import BaseResponseHandler
from .base import HttpAuth
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


class AsyncResponseHandler(BaseResponseHandler):
    async def on_success(
        self, response: ClientResponse, **kwargs
    ) -> str | list[M] | None:
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

    async def on_error(self, error: ClientResponseError, **kwargs) -> None:
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


class AsyncHttpClient(BaseHttpClient, AsyncCachable, AbstractAsyncContextManager):
    __slots__ = "_session", "_handler", "_auth"

    def __init__(
        self,
        session: ClientSession | None = None,
        handler: AsyncResponseHandler | None = None,
        auth: HttpAuth | None = None,
        **kwargs,
    ) -> None:
        super().__init__()
        self._session = session or self._new_session(**kwargs)
        self._handler = handler or AsyncResponseHandler()
        self._auth = auth or HttpAuth()

    @staticmethod
    def _new_session(**kwargs) -> ClientSession:
        kwargs = SESSION_DEFAULTS | kwargs
        cache = kwargs.pop("cache", None) or CacheBackend(**kwargs)
        return CachedSession(cache=cache, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        auth: HttpAuth | None = None,
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
            await auth.on_response(response)
            try:
                response.raise_for_status()
            except ClientResponseError as error:
                result = await self._handler.on_error(error, **kwargs)
            else:
                result = await self._handler.on_success(response, **kwargs)
            return result

    async def close(self) -> None:
        return await self._session.close()

    async def clear_cache(self) -> None:
        if isinstance(self._session, CachedSession):
            return await self._session.cache.clear()

    async def __aenter__(self) -> AsyncHttpClient:
        await self._session.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)
