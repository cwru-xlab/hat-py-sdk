from __future__ import annotations

import abc
from typing import Any, Mapping, Optional, Protocol

from keyring.credentials import Credential

from . import Token, errors, urls, utils


class SupportsHeaders(Protocol):
    headers: Mapping[str, str]


class SupportsContent(Protocol):
    content: Any


class ResponseHandler(abc.ABC):

    def on_success(self, response: SupportsContent, **kwargs) -> Any:
        raise ValueError(f"Unable to process response: {response.content}")

    def on_error(self, error: BaseException, **kwargs) -> None:
        status, content = self.status(error), self.content(error)
        if urls.is_auth_endpoint(url := self.url(error)):
            raise errors.find_error("auth", status, content)
        elif urls.is_api_endpoint(url):
            method = self.method(error)
            raise errors.find_error(method, status, content)
        else:
            raise error

    @abc.abstractmethod
    def status(self, error: BaseException) -> int:
        pass

    @abc.abstractmethod
    def url(self, error: BaseException) -> str:
        pass

    @abc.abstractmethod
    def method(self, error: BaseException) -> str:
        pass

    @abc.abstractmethod
    def content(self, error: BaseException) -> Mapping[str, str]:
        pass


class AuthHandler:
    __slots__ = ()

    def headers(self) -> Mapping[str, str]:
        return {}

    def on_response(self, response: Any) -> None:
        pass


class TokenAuthHandler(AuthHandler):
    __slots__ = "_token"

    def __init__(self, token: Token):
        self._token = token

    def headers(self) -> Mapping[str, str]:
        return {utils.TOKEN_HEADER: self._token.value}

    def on_response(self, response: SupportsHeaders) -> None:
        if utils.TOKEN_HEADER in response.headers:
            self._token.value = response.headers[utils.TOKEN_HEADER]


class CredentialAuthHandler(AuthHandler):
    __slots__ = "_credential",

    def __init__(self, credential: Credential):
        self._credential = credential

    def headers(self) -> Mapping[str, str]:
        return {
            "Accept": utils.JSON_MIMETYPE,
            "username": self._credential.username,
            "password": self._credential.password}


class HttpClient(abc.ABC):

    @abc.abstractmethod
    def request(
            self,
            method: str,
            url: str,
            auth: Optional[AuthHandler] = None,
            **kwargs
    ) -> Any:
        pass

    @abc.abstractmethod
    def close(self) -> None:
        pass
