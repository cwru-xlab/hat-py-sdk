from __future__ import annotations

import abc
import functools
import re
from typing import (Any, Callable, Collection, Iterable, Iterator, Optional,
                    Type, Union)

from .model import GetOpts, HatModel, M

Models = Union[M, Iterator[M], Collection[M]]
StringLike = Union[str, HatModel]
IStringLike = Iterable[StringLike]


def requires_namespace(method: Callable) -> Callable:
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if self.namespace is None:
            raise ValueError("'namespace' is required to access endpoint data")
        return method(self, *args, **kwargs)

    return wrapper


def ensure_iterable(method: Callable) -> Callable:
    @functools.wraps(method)
    def wrapper(self, iterable, *args, **kwargs):
        # pydantic.BaseModel is an Iterable, so we need to check subclasses.
        if not isinstance(iterable, (Iterator, Collection)):
            iterable = [iterable]
        return method(self, iterable, *args, **kwargs)

    return wrapper


class BaseResponseHandler:
    __slots__ = ()

    def on_success(self, response: Any, **kwargs) -> Any:
        return response

    def on_error(self, error: BaseException, **kwargs) -> None:
        raise error


class HttpAuth:
    __slots__ = ()

    def headers(self) -> dict[str, str]:
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


class AsyncCachable(abc.ABC):

    @abc.abstractmethod
    async def clear_cache(self) -> None:
        pass


class BaseHatClient(abc.ABC):
    __slots__ = "_namespace", "_pattern"

    def __init__(self, namespace: Optional[str] = None):
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")

    @abc.abstractmethod
    @requires_namespace
    def get(
            self,
            endpoint: StringLike,
            mtype: Type[M] = HatModel,
            options: Optional[GetOpts] = None
    ) -> list[M]:
        pass

    @abc.abstractmethod
    @ensure_iterable
    @requires_namespace
    def post(self, models: Models) -> list[M]:
        pass

    @abc.abstractmethod
    @ensure_iterable
    def put(self, models: Models) -> list[M]:
        pass

    @abc.abstractmethod
    @ensure_iterable
    def delete(self, record_ids: StringLike | IStringLike) -> None:
        pass

    @property
    def namespace(self) -> Optional[str]:
        return self._namespace
