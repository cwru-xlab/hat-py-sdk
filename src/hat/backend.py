from __future__ import annotations

from contextlib import AbstractAsyncContextManager, AbstractContextManager
from typing import Any, Optional

from aiohttp import ClientResponse, ClientResponseError, ClientSession
from requests import HTTPError, Response, Session

from base import Handler, HttpClient


class SyncHandler(Handler):

    def on_success(self, response: Response, **kwargs) -> Any:
        return response

    def on_error(self, error: HTTPError, **kwargs) -> Any:
        raise error


class AsyncHandler(Handler):

    async def on_success(self, response: ClientResponse, **kwargs) -> Any:
        return response

    async def on_error(self, error: ClientResponseError, **kwargs) -> Any:
        raise error


class SyncHttpClient(HttpClient, AbstractContextManager):
    __slots__ = "handler", "_session"

    def __init__(self, session: Session, handler: Optional[SyncHandler] = None):
        super().__init__()
        self.handler = handler or SyncHandler()
        self._session = session

    def request(self, method: str, url: str, **kwargs) -> Any:
        response = self._session.request(method=method, url=url, **kwargs)
        try:
            response.raise_for_status()
        except HTTPError as error:
            result = self.handler.on_error(error, **kwargs)
        else:
            result = self.handler.on_success(response, **kwargs)
        finally:
            response.close()
        return result

    def __enter__(self) -> SyncHttpClient:
        with self._session:
            return self

    def __exit__(self, *args) -> None:
        return self._session.__exit__(*args)


class AsyncHttpClient(HttpClient, AbstractAsyncContextManager):
    __slots__ = "handler", "_session"

    def __init__(
            self,
            session: ClientSession,
            handler: Optional[AsyncHandler] = None):
        super().__init__()
        self.handler = handler or AsyncHandler()
        self._session = session

    async def request(self, method: str, url: str, **kwargs):
        kwargs["raise_for_status"] = True
        try:
            response = await self._session.request(method, url, **kwargs)
        except ClientResponseError as error:
            result = await self.handler.on_error(error, **kwargs)
        else:
            result = await self.handler.on_success(response, **kwargs)
            response.close()  # raise_for_status() closes the response.
        return result

    async def __aenter__(self) -> AsyncHttpClient:
        async with self._session:
            return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)
