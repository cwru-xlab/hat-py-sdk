from __future__ import annotations

import abc
import re
from typing import Any

import orjson
from aiohttp import ClientResponse, ClientResponseError
from requests import HTTPError, Response

from . import errors, tokens, urls
from .backend import AsyncResponseHandler, SyncResponseHandler
from .base import ResponseHandler
from .model import HatRecord, M


def pk_endpoint(url: str) -> bool:
    return matched(url, urls.PK_PATTERN)


def auth_endpoint(url: str) -> bool:
    return pk_endpoint(url) or token_endpoint(url)


def token_endpoint(url: str) -> bool:
    return matched(url, urls.OWNER_TOKEN_PATTERN, urls.APP_TOKEN_PATTERN)


def api_endpoint(url: str) -> bool:
    return matched(url, urls.DATA_PATTERN, urls.ENDPOINT_PATTERN)


def matched(url: str, *patterns: re.Pattern) -> bool:
    return any(p.match(url) is not None for p in patterns)


class HatResponseHandler(ResponseHandler):

    def on_success(self, response: Any, **kwargs) -> Any:
        raise ValueError(f"Unable to process response: {response.content}")

    def on_error(self, error, **kwargs) -> None:
        status, content = self.status(error), self.content(error)
        if auth_endpoint(url := self.url(error)):
            raise errors.find_error("auth", status, content)
        elif api_endpoint(url):
            method = self.method(error)
            raise errors.find_error(method, status, content)
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


class SyncHatResponseHandler(SyncResponseHandler, HatResponseHandler):

    def on_success(self, response: Response, **kwargs) -> str | list[M] | None:
        if pk_endpoint(url := response.url):
            return response.text
        elif token_endpoint(url):
            return orjson.loads(response.content)[tokens.TOKEN_KEY]
        elif response.request.method.lower() == "delete":
            return None
        elif api_endpoint(url):
            return HatRecord.parse(response.content, kwargs["mtypes"])
        else:
            return super(HatResponseHandler, self).on_success(response)

    def status(self, error: HTTPError) -> int:
        return error.response.status_code

    def url(self, error: HTTPError) -> str:
        return error.response.url

    def method(self, error: HTTPError) -> str:
        return error.request.method.lower()

    def content(self, error: HTTPError) -> dict[str, Any]:
        return orjson.loads(error.response.content)


class AsyncHatResponseHandler(AsyncResponseHandler, HatResponseHandler):

    async def on_success(
            self, response: ClientResponse, **kwargs) -> str | list[M] | None:
        if pk_endpoint(url := str(response.url)):
            return await response.text()
        elif token_endpoint(url):
            return orjson.loads(await response.read())[tokens.TOKEN_KEY]
        elif response.method.lower() == "delete":
            return None
        elif api_endpoint(url):
            return HatRecord.parse(await response.read(), kwargs["mtypes"])
        else:
            return super(HatResponseHandler, self).on_success(response)

    async def on_error(self, error: ClientResponseError, **kwargs) -> Any:
        return super(HatResponseHandler, self).on_error(error, **kwargs)

    def status(self, error: ClientResponseError) -> int:
        return error.status

    def url(self, error: ClientResponseError) -> str:
        return str(error.request_info.url)

    def method(self, error: ClientResponseError) -> str:
        return error.request_info.method.lower()

    def content(self, error: ClientResponseError) -> dict[str, Any]:
        return orjson.loads(error.message)
