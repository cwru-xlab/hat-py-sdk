from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from typing import Any, Mapping, Optional

from aiohttp import ClientResponse, ClientResponseError, ClientSession
from orjson import orjson

from . import tokens, urls
from .base import HttpAuth, HttpClient, ResponseHandler
from .model import HatRecord, M


class AsyncHttpClient(HttpClient, AbstractAsyncContextManager):
    __slots__ = "handler", "auth", "_session"

    def __init__(
            self,
            session: ClientSession,
            handler: Optional[AsyncResponseHandler] = None,
            auth: Optional[HttpAuth] = None
    ) -> None:
        super().__init__()
        self.handler = handler or AsyncResponseHandler()
        self.auth = auth or HttpAuth()
        self._session = session

    async def request(
            self,
            method: str,
            url: str,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> Any:
        auth = auth or self.auth
        kwargs.update({"headers": auth.headers})
        kwargs["raise_for_status"] = False
        try:
            response = await self._session.request(method, url, **kwargs)
            auth.on_response(response)
            response.raise_for_status()
        except ClientResponseError as error:
            result = await self.handler.on_error(error, **kwargs)
        else:
            result = await self.handler.on_success(response, **kwargs)
            response.close()
        return result

    async def close(self) -> None:
        return await self._session.close()

    async def __aenter__(self) -> AsyncHttpClient:
        async with self._session:
            return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)


class AsyncResponseHandler(ResponseHandler):

    async def on_success(
            self, response: ClientResponse, **kwargs) -> str | list[M] | None:
        if urls.is_pk_endpoint(url := str(response.url)):
            return await response.text()
        elif urls.is_token_endpoint(url):
            return orjson.loads(await response.read())[tokens.TOKEN_KEY]
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
        return orjson.loads(error.message)
