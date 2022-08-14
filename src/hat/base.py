from __future__ import annotations

import abc
import pprint
from typing import Any, Mapping, Optional, Protocol

from . import errors, urls


class UrlAndHeaders(Protocol):
    headers: Any
    url: Any


class BaseResponseHandler(abc.ABC):

    def on_success(self, response: UrlAndHeaders, **kwargs) -> Any:
        url = str(response.url)
        headers = pprint.pformat(response.headers, indent=2)
        raise ValueError(f"Unable to process response for URL {url}\n{headers}")

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


class HttpAuth:
    __slots__ = ()

    @property
    def headers(self) -> Mapping[str, str]:
        return {}

    def on_response(self, response: Any) -> None:
        pass


class BaseHttpClient(abc.ABC):

    @abc.abstractmethod
    def request(
            self,
            method: str,
            url: str,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> Any:
        pass

    @abc.abstractmethod
    def close(self) -> None:
        pass


class Cachable(abc.ABC):

    @abc.abstractmethod
    def clear_cache(self) -> None:
        pass


class AsyncCachable(Cachable, abc.ABC):

    @abc.abstractmethod
    async def clear_cache(self) -> None:
        pass
