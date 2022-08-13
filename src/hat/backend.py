from __future__ import annotations

from contextlib import AbstractAsyncContextManager, AbstractContextManager
from typing import Any, Optional

from aiohttp import ClientResponse, ClientResponseError, ClientSession
from requests import HTTPError, Response, Session

from base import AuthHandler, HttpClient, ResponseHandler


class SyncResponseHandler(ResponseHandler):

    def on_success(self, response: Response, **kwargs) -> Any:
        return response

    def on_error(self, error: HTTPError, **kwargs) -> Any:
        raise error


class AsyncResponseHandler(ResponseHandler):

    async def on_success(self, response: ClientResponse, **kwargs) -> Any:
        return response

    async def on_error(self, error: ClientResponseError, **kwargs) -> Any:
        raise error


class SyncHttpClient(HttpClient, AbstractContextManager):
    __slots__ = "response_handler", "auth_handler", "_session"

    def __init__(
            self,
            session: Session,
            response_handler: Optional[SyncResponseHandler] = None,
            auth_handler: Optional[AuthHandler] = None
    ) -> None:
        super().__init__()
        self.response_handler = response_handler or SyncResponseHandler()
        self.auth_handler = auth_handler or AuthHandler()
        self._session = session

    def request(
            self,
            method: str,
            url: str,
            auth: Optional[AuthHandler] = None,
            **kwargs
    ) -> Any:
        auth = auth or self.auth_handler
        kwargs.update({"headers": auth.headers()})
        response = self._session.request(method=method, url=url, **kwargs)
        try:
            response.raise_for_status()
        except HTTPError as error:
            result = self.response_handler.on_error(error, **kwargs)
        else:
            result = self.response_handler.on_success(response, **kwargs)
        finally:
            auth.on_response(response)
            response.close()
        return result

    def __enter__(self) -> SyncHttpClient:
        with self._session:
            return self

    def __exit__(self, *args) -> None:
        return self._session.__exit__(*args)


class AsyncHttpClient(HttpClient, AbstractAsyncContextManager):
    __slots__ = "response_handler", "auth_handler", "_session"

    def __init__(
            self,
            session: ClientSession,
            response_handler: Optional[AsyncResponseHandler] = None,
            auth_handler: Optional[AuthHandler] = None
    ) -> None:
        super().__init__()
        self.response_handler = response_handler or AsyncResponseHandler()
        self.auth_handler = auth_handler or AuthHandler()
        self._session = session

    async def request(
            self,
            method: str,
            url: str,
            auth: Optional[AuthHandler] = None,
            **kwargs
    ) -> Any:
        auth = auth or self.auth_handler
        kwargs.update({"headers": auth.headers()})
        kwargs["raise_for_status"] = False
        try:
            response = await self._session.request(method, url, **kwargs)
            auth.on_response(response)
            response.raise_for_status()
        except ClientResponseError as error:
            result = await self.response_handler.on_error(error, **kwargs)
        else:
            result = await self.response_handler.on_success(response, **kwargs)
            response.close()
        return result

    async def __aenter__(self) -> AsyncHttpClient:
        async with self._session:
            return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)
