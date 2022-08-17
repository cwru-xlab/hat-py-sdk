from __future__ import annotations

import abc
import asyncio
import functools
import itertools
import re
from contextlib import AbstractAsyncContextManager
from contextlib import AbstractContextManager
from typing import Callable
from typing import Collection
from typing import Iterable
from typing import Iterator
from typing import Union

from asgiref import sync

from . import urls
from . import utils
from .auth import ApiToken
from .auth import TokenAuth
from .http import HttpClient
from .model import GetOpts
from .model import HatModel
from .model import HatRecord
from .model import M


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


def require_endpoint(strings: IStringLike) -> Iterator[StringLike]:
    for s in strings:
        if hasattr(s, "endpoint") and s.endpoint is None:
            raise ValueError("'endpoint' is required")
        yield s


def require_record_id(strings: IStringLike) -> Iterator[StringLike]:
    for s in strings:
        if hasattr(s, "record_id") and s.record_id is None:
            raise ValueError("'record_id' is required")
        yield s


def group_by_endpoint(models: Iterable[M]) -> Iterable[tuple[str, list[M]]]:
    by_endpoint = functools.partial(lambda r: r.endpoint)
    groups = itertools.groupby(sorted(models, key=by_endpoint), by_endpoint)
    return ((endpoint, list(models)) for endpoint, models in groups)


class BaseHatClient(abc.ABC):
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
    @abc.abstractmethod
    def token(self) -> ApiToken:
        pass

    @property
    @abc.abstractmethod
    def namespace(self) -> str | None:
        pass

    def __repr__(self) -> str:
        return utils.to_str(self, token=self.token, namespace=self.namespace)


class AsyncHatClient(BaseHatClient, AbstractAsyncContextManager):
    __slots__ = "_client", "_auth", "_token", "_namespace", "_pattern"

    def __init__(
        self,
        client: HttpClient,
        token: ApiToken,
        namespace: str | None = None,
    ) -> None:
        self._client = client
        self._token = token
        self._auth = TokenAuth(token)
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")

    @requires_namespace
    async def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M]:
        if options:
            options = options.json()
        endpoint = self._prepare_get(endpoint)
        return await self._endpoint_request(
            "GET", endpoint, data=options, mtypes=[mtype]
        )

    @ensure_iterable
    @requires_namespace
    async def post(self, models: Models) -> list[M]:
        posted = await asyncio.gather(
            *(
                self._endpoint_request("POST", endpoint, data=data, mtypes=mtypes)
                for endpoint, data, mtypes in self._prepare_post(models)
            )
        )
        return list(itertools.chain.from_iterable(posted))

    @ensure_iterable
    async def put(self, models: Models) -> list[M]:
        data, mtypes = self._prepare_put(models)
        return await self._data_request("PUT", data=data, mtypes=mtypes)

    @ensure_iterable
    async def delete(self, record_ids: StringLike | IStringLike) -> None:
        params = self._prepare_delete(record_ids)
        return await self._data_request("DELETE", params=params)

    async def _endpoint_request(self, method: str, endpoint: str, **kwargs) -> list[M]:
        url = urls.domain_endpoint(
            await self._token.domain(), self._namespace, endpoint
        )
        return await self._request(method, url, **kwargs)

    async def _data_request(self, method: str, **kwargs) -> list[M] | None:
        url = urls.domain_data(await self._token.domain())
        return await self._request(method, url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> list[M] | None:
        return await self._client.request(method, url, auth=self._auth, **kwargs)

    @staticmethod
    def _prepare_get(string: StringLike) -> str:
        string = next(require_endpoint([string]))
        return string if isinstance(string, str) else string.endpoint

    def _prepare_post(self, models: Iterable[M]) -> Iterable[tuple]:
        formatted = []
        for m in require_endpoint(models):
            # The namespace is added when constructing the endpoint URL, so it should
            # not be a part of the endpoint here.
            if self._pattern.match(m.endpoint):
                m.endpoint = self._pattern.split(m.endpoint)[-1]
            formatted.append(m)
        for endpoint, models in group_by_endpoint(formatted):
            records = HatRecord.to_json(models, data_only=True)
            yield endpoint, records, map(type, models)

    def _prepare_put(self, models: Iterable[M]) -> tuple[str, Iterable[type]]:
        formatted = []
        for m in require_endpoint(models):
            # The endpoint should include the namespace. BaseHatModels created from
            # responses will include the namespace. This is just a convenience if
            # wanting to create them manually.
            if self._pattern.match(m.endpoint) is None:
                m.endpoint = f"{self._namespace}/{m.endpoint}"
            formatted.append(m)
        return HatRecord.to_json(formatted), map(type, models)

    @staticmethod
    def _prepare_delete(record_ids: IStringLike) -> dict[str, list[str]]:
        record_ids = [
            r if isinstance(r, str) else r.record_id
            for r in require_record_id(record_ids)
        ]
        return {"records": record_ids}

    @property
    def token(self) -> ApiToken:
        return self._token

    @property
    def namespace(self) -> str | None:
        return self._namespace

    def to_sync(self) -> HatClient:
        return HatClient(self)

    async def __aenter__(self) -> AsyncHatClient:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._client.__aexit__(*args)


class HatClient(BaseHatClient, AbstractContextManager):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncHatClient):
        self._wrapped = wrapped

    def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M]:
        return sync.async_to_sync(self._wrapped.get)(endpoint, mtype, options)

    def post(self, models: Models) -> list[M]:
        return sync.async_to_sync(self._wrapped.post)(models)

    def put(self, models: Models) -> list[M]:
        return sync.async_to_sync(self._wrapped.put)(models)

    def delete(self, record_ids: StringLike | IStringLike) -> None:
        return sync.async_to_sync(self._wrapped.delete)(record_ids)

    def to_async(self) -> AsyncHatClient:
        return self._wrapped

    @property
    def token(self) -> ApiToken:
        return self._wrapped.token

    @property
    def namespace(self) -> str | None:
        return self._wrapped.namespace

    def __enter__(self) -> HatClient:
        sync.async_to_sync(self._wrapped.__aenter__)()
        return self

    def __exit__(self, *args) -> None:
        return sync.async_to_sync(self._wrapped.__aexit__)(*args)
