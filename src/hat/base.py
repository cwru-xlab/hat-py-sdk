from __future__ import annotations

import abc
from typing import Any


class Handler(abc.ABC):

    @abc.abstractmethod
    def on_success(self, response: Any, **kwargs) -> Any:
        pass

    @abc.abstractmethod
    def on_error(self, error: BaseException, **kwargs) -> Any:
        pass


class HttpClient(abc.ABC):

    @abc.abstractmethod
    def request(self, method: str, url: str, **kwargs) -> Any:
        pass
