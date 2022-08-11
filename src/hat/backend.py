from __future__ import annotations

import abc
from contextlib import AbstractAsyncContextManager, AbstractContextManager
from typing import Any, Optional

from aiohttp import ClientResponse, ClientResponseError, ClientSession
from requests import HTTPError, Response, Session


class Handler(abc.ABC):
    __slots__ = ()

    @abc.abstractmethod
    def on_success(self, response: Any) -> Any:
        pass

    @abc.abstractmethod
    def on_error(self, error: BaseException) -> Any:
        pass


class SyncHandler(Handler):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__()

    def on_success(self, response: Response, **kwargs) -> Any:
        return response

    def on_error(self, error: HTTPError, **kwargs) -> Any:
        raise error


class AsyncHandler(Handler):
    __slots__ = ()

    def __init__(self) -> None:
        super().__init__()

    async def on_success(self, response: ClientResponse, **kwargs) -> Any:
        return response

    async def on_error(self, error: ClientResponseError, **kwargs) -> Any:
        raise error


class HttpClient(abc.ABC):
    __slots__ = ()

    def __init__(self):
        super().__init__()

    @abc.abstractmethod
    def request(self, method: str, url: str, **kwargs):
        pass


class SyncHttpClient(HttpClient, AbstractContextManager):
    __slots__ = "handler", "_session"

    def __init__(self, session: Session, handler: Optional[SyncHandler] = None):
        super().__init__()
        self.handler = self._check_handler(handler) or SyncHandler()
        self._session = session

    @staticmethod
    def _check_handler(handler: SyncHandler) -> SyncHandler:
        if not isinstance(handler, SyncHandler):
            raise TypeError("'handler' must be a SyncHandler")
        return handler

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
        self.handler = self._check_handler(handler) or AsyncHandler()
        self._session = session

    @staticmethod
    def _check_handler(handler: AsyncHandler) -> AsyncHandler:
        if not isinstance(handler, AsyncHandler):
            raise TypeError("'handler' must be an AsyncHandler")
        return handler

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
