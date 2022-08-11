from __future__ import annotations

import abc
from typing import Any

import orjson
from aiohttp import ClientResponse, ClientResponseError
from requests import HTTPError, Response

from . import errors, urls
from .backend import AsyncHandler, Handler, SyncHandler
from .model import HatRecord, M

error_maps: dict[str, errors.ErrorMapping] = {
    "auth": errors.auth_errors,
    "get": errors.get_errors,
    "post": errors.post_errors,
    "put": errors.put_errors,
    "delete": errors.delete_errors
}


def pk_endpoint(url: str) -> bool:
    return urls.PK_PATTERN.match(url)


def auth_endpoint(url: str) -> bool:
    return pk_endpoint(url) or token_endpoint(url)


def token_endpoint(url: str) -> bool:
    return (urls.OWNER_TOKEN_PATTERN.match(url)
            or urls.APP_TOKEN_PATTERN.match(url))


def api_endpoint(url: str) -> bool:
    return urls.DATA_PATTERN.match(url) or urls.ENDPOINT_PATTERN.match(url)


class HatHandler(Handler):

    def __init__(self):
        super().__init__()

    def on_error(self, error, **kwargs) -> None:
        status, content = self.status(error), self.content(error)
        if auth_endpoint(url := self.url(error)):
            raise error_maps["auth"].get(status, content)
        elif api_endpoint(url):
            method = self.method(error)
            raise error_maps[method].get(status, content)
        else:
            raise error

    @abc.abstractmethod
    def status(self, error) -> int:
        pass

    @abc.abstractmethod
    def url(self, error) -> str:
        pass

    @abc.abstractmethod
    def method(self, error) -> str:
        pass

    @abc.abstractmethod
    def content(self, error) -> dict[str, Any]:
        pass


class SyncHatHandler(SyncHandler, HatHandler):

    def __init__(self) -> None:
        super().__init__()

    def on_success(self, response: Response, **kwargs) -> str | list[M]:
        if pk_endpoint(url := response.url):
            return response.text
        elif token_endpoint(url):
            return orjson.loads(response.content)["accessToken"]
        elif api_endpoint(url):
            return HatRecord.parse(response.content, kwargs["mtypes"])
        else:
            raise ValueError("Unknown endpoint")

    def status(self, error: HTTPError) -> int:
        return error.response.status_code

    def url(self, error: HTTPError) -> str:
        return error.response.url

    def method(self, error: HTTPError) -> str:
        return error.request.method.lower()

    def content(self, error: HTTPError) -> dict[str, Any]:
        return orjson.loads(error.response.content)


class AsyncHatHandler(AsyncHandler, HatHandler):

    def __init__(self) -> None:
        super().__init__()

    async def on_success(
            self, response: ClientResponse, **kwargs) -> str | list[M]:
        if pk_endpoint(url := str(response.url)):
            return await response.text()
        elif token_endpoint(url):
            return orjson.loads(await response.read())["accessToken"]
        elif api_endpoint(url):
            return HatRecord.parse(await response.read(), kwargs["mtypes"])
        else:
            raise ValueError("Unknown endpoint")

    async def on_error(self, error: ClientResponseError, **kwargs) -> Any:
        return super().on_error(error, **kwargs)

    def status(self, error: ClientResponseError) -> int:
        return error.status

    def url(self, error: ClientResponseError) -> str:
        return str(error.request_info.url)

    def method(self, error: ClientResponseError) -> str:
        return error.request_info.method.lower()

    def content(self, error: ClientResponseError) -> dict[str, Any]:
        return orjson.loads(error.message)
