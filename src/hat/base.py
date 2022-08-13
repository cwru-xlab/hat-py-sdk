from __future__ import annotations

import abc
from typing import Any, Optional


class ResponseHandler(abc.ABC):

    @abc.abstractmethod
    def on_success(self, response: Any, **kwargs) -> Any:
        pass

    @abc.abstractmethod
    def on_error(self, error: BaseException, **kwargs) -> Any:
        pass


class AuthHandler:
    __slots__ = ()

    def headers(self) -> dict[str, str]:
        pass

    def on_response(self, response) -> None:
        pass


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
