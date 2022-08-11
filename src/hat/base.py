from __future__ import annotations

import abc
from typing import Any


class Handler(abc.ABC):
    __slots__ = ()

    @abc.abstractmethod
    def on_success(self, response: Any) -> Any:
        pass

    @abc.abstractmethod
    def on_error(self, error: BaseException) -> Any:
        pass


class HttpClient(abc.ABC):
    __slots__ = ()

    def __init__(self):
        super().__init__()

    @abc.abstractmethod
    def request(self, method: str, url: str, **kwargs):
        pass
