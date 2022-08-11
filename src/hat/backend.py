from __future__ import annotations

import abc
import asyncio
from contextlib import AbstractAsyncContextManager, AbstractContextManager
from typing import Optional

import aiohttp
from aiohttp import ClientResponse, ClientResponseError, ClientSession
from requests import HTTPError, Response, Session


class Handler:
    __slots__ = ()

    def on_success(self, response: Response):
        return response

    def on_error(self, error: HTTPError):
        raise error


class AsyncHandler(Handler):
    __slots__ = ()

    async def on_success(self, response: ClientResponse):
        return response

    async def on_error(self, error: ClientResponseError):
        raise error


class HttpClient(abc.ABC):

    def request(self, method: str, url: str, **kwargs):
        pass


class SyncHttpClient(HttpClient, AbstractContextManager):
    __slots__ = "handler", "_session"

    def __init__(self, session: Session, handler: Optional[Handler] = None):
        super().__init__()
        self.handler = self._check_handler(handler) or Handler()
        self._session = session

    @staticmethod
    def _check_handler(handler: Handler) -> Handler:
        methods = (handler.on_success, handler.on_error)
        if any(map(asyncio.iscoroutinefunction, methods)):
            raise TypeError("'handler' must not have any async methods")
        return handler

    def request(self, method: str, url: str, **kwargs):
        response = self._session.request(method=method, url=url, **kwargs)
        try:
            response.raise_for_status()
        except HTTPError as error:
            result = self.handler.on_error(error)
        else:
            result = self.handler.on_success(response)
        finally:
            response.close()
        return result

    def __enter__(self) -> SyncHttpClient:
        with self._session:
            return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return self._session.__exit__(exc_type, exc_val, exc_tb)


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
        except aiohttp.ClientResponseError as error:
            result = await self.handler.on_error(error)
        else:
            result = await self.handler.on_success(response)
            response.close()  # raise_for_status() closes the response.
        return result

    async def __aenter__(self) -> AsyncHttpClient:
        async with self._session:
            return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        return await self._session.__aexit__(exc_type, exc_val, exc_tb)
