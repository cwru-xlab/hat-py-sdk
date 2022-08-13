from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Any, Mapping, Optional

from aiohttp import ClientResponse, ClientResponseError, ClientSession
from aiohttp_client_cache import CachedSession

from . import sessions, tokens, urls, utils
from .base import AsyncCachable, HttpAuth, BaseHttpClient, BaseResponseHandler
from .model import HatRecord, M


class AsyncHttpClient(BaseHttpClient, AsyncCachable, AbstractAsyncContextManager):
    __slots__ = "session", "handler", "auth"

    def __init__(
            self,
            session: Optional[ClientSession] = None,
            handler: Optional[AsyncResponseHandler] = None,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> None:
        super().__init__()
        self.session = session or self._new_session(**kwargs)
        self.handler = handler or AsyncResponseHandler()
        self.auth = auth or HttpAuth()

    @staticmethod
    def _new_session(**kwargs) -> ClientSession:
        return CachedSession(**sessions.DEFAULTS | kwargs)

    async def request(
            self,
            method: str,
            url: str,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> Any:
        auth = auth or self.auth
        kwargs = self._prepare_request(auth, kwargs)
        try:
            response = await self.session.request(method, url, **kwargs)
            auth.on_response(response)
            response.raise_for_status()
        except ClientResponseError as error:
            result = await self.handler.on_error(error, **kwargs)
        else:
            result = await self.handler.on_success(response, **kwargs)
            response.close()
        return result

    def _prepare_request(
            self, auth: HttpAuth, kwargs: dict[str, Any]) -> dict[str, Any]:
        kwargs.update({"headers": auth.headers})
        kwargs["raise_for_status"] = False
        return utils.match_signature(self.session.request, **kwargs)

    async def close(self) -> None:
        return await self.session.close()

    async def clear_cache(self) -> None:
        if isinstance(self.session, CachedSession):
            return await self.session.cache.clear()

    async def __aenter__(self) -> AsyncHttpClient:
        async with self.session:
            return self

    async def __aexit__(self, *args) -> None:
        return await self.session.__aexit__(*args)


class AsyncResponseHandler(BaseResponseHandler):

    async def on_success(
            self, response: ClientResponse, **kwargs) -> str | list[M] | None:
        if urls.is_pk_endpoint(url := str(response.url)):
            return await response.text()
        elif urls.is_token_endpoint(url):
            return utils.loads(await response.read())[tokens.TOKEN_KEY]
        elif response.method.lower() == "delete":
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(await response.read(), kwargs["mtypes"])
        else:
            return super().on_success(response, **kwargs)

    async def on_error(self, error: ClientResponseError, **kwargs) -> None:
        return super().on_error(error, **kwargs)

    def status(self, error: ClientResponseError) -> int:
        return error.status

    def url(self, error: ClientResponseError) -> str:
        return str(error.request_info.url)

    def method(self, error: ClientResponseError) -> str:
        return error.request_info.method.lower()

    def content(self, error: ClientResponseError) -> Mapping[str, str]:
        return utils.loads(error.message)
