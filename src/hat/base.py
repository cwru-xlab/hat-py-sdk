from __future__ import annotations

import abc
import re
from typing import Any
from typing import Collection
from typing import Iterable
from typing import Iterator
from typing import Mapping
from typing import Union

from .model import GetOpts
from .model import HatModel
from .model import M


Models = Union[M, Iterator[M], Collection[M]]
StringLike = Union[str, HatModel]
IStringLike = Iterable[StringLike]


class BaseResponseHandler:
    __slots__ = ()

    def on_success(self, response: Any, **kwargs) -> Any:
        return response

    def on_error(self, error: BaseException, **kwargs) -> None:
        raise error


class HttpAuth:
    __slots__ = ()

    async def headers(self) -> dict[str, str]:
        return {}

    async def on_response(self, response: Any) -> None:
        pass


class BaseHttpClient(abc.ABC):
    @abc.abstractmethod
    def request(
        self,
        method: str,
        url: str,
        auth: HttpAuth | None = None,
        headers: Mapping[str, str] | None = None,
        data: Any = None,
        params: Mapping[str, str] | None = None,
        **kwargs,
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

    def __init__(self, namespace: str | None = None):
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")

    @abc.abstractmethod
    def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M]:
        pass

    @abc.abstractmethod
    def post(self, models: Models) -> list[M]:
        pass

    @abc.abstractmethod
    def put(self, models: Models) -> list[M]:
        pass

    @abc.abstractmethod
    def delete(self, record_ids: StringLike | IStringLike) -> None:
        pass

    @property
    def namespace(self) -> str | None:
        return self._namespace
