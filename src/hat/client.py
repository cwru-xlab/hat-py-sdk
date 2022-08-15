from __future__ import annotations

import asyncio
import datetime
import functools
import itertools
import mimetypes
import pprint
from contextlib import AbstractAsyncContextManager
from typing import Any, Generator, Iterable, Iterator, Optional, Type

from aiohttp import ClientResponse, ClientResponseError, ClientSession
from aiohttp_client_cache import CacheBackend, CachedSession
from asgiref import sync

from . import AsyncApiToken, AsyncTokenAuth, auth as _auth, errors, urls, utils
from .base import (AsyncCachable, BaseHatClient, BaseHttpClient,
                   BaseResponseHandler, HttpAuth, IStringLike, Models,
                   StringLike)
from .model import GetOpts, HatModel, HatRecord, M

MTypes = Iterable[Type[M]]

NEVER_CACHE = 0
SESSION_DEFAULTS = {
    "headers": {"Content-Type": mimetypes.types_map[".json"]},
    "stream": True,
    "allowed_codes": [200] + list(errors.possible_codes),
    "allowed_methods": ["GET", "POST"],
    "stale_if_error": True,
    "expire_after": datetime.timedelta(minutes=10),
    "urls_expire_after": {
        urls.domain_owner_token("*"): NEVER_CACHE,
        urls.domain_app_token("*", "*"): NEVER_CACHE}}


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


def types(models: Iterable[M]) -> MTypes:
    return (type(m) for m in models)


class AsyncResponseHandler(BaseResponseHandler):

    async def on_success(
            self, response: ClientResponse, **kwargs) -> str | list[M] | None:
        if urls.is_pk_endpoint(url := str(response.url)):
            return await response.text()
        elif urls.is_token_endpoint(url):
            return utils.loads(await response.read())[_auth.TOKEN_KEY]
        elif response.method.lower() == "delete":
            await response.read()
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(await response.read(), kwargs["mtypes"])
        else:
            headers = pprint.pformat(response.headers, indent=2)
            raise ValueError(
                f"Unable to process response for URL {url}\n{headers}")

    async def on_error(self, error: ClientResponseError, **kwargs) -> None:
        status, content = error.status, utils.loads(error.message)
        if urls.is_auth_endpoint(url := str(error.request_info.url)):
            raise errors.find_error("auth", status, content)
        elif urls.is_api_endpoint(url):
            method = error.request_info.method.lower()
            raise errors.find_error(method, status, content)
        else:
            raise error


class AsyncHttpClient(BaseHttpClient, AsyncCachable,
                      AbstractAsyncContextManager):
    __slots__ = "_session", "_handler", "_auth"

    def __init__(
            self,
            session: Optional[ClientSession] = None,
            handler: Optional[AsyncResponseHandler] = None,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> None:
        super().__init__()
        self._session = session or self._new_session(**kwargs)
        self._handler = handler or AsyncResponseHandler()
        self._auth = auth or HttpAuth()

    @staticmethod
    def _new_session(**kwargs) -> ClientSession:
        kwargs = SESSION_DEFAULTS | kwargs
        return CachedSession(cache=CacheBackend(**kwargs), **kwargs)

    async def request(
            self,
            method: str,
            url: str,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> Any:
        auth = auth or self._auth
        kwargs = self._prepare_request(auth, **kwargs)
        try:
            response = await self._session.request(method, url, **kwargs)
            auth.on_response(response)
            response.raise_for_status()
        except ClientResponseError as error:
            result = await self._handler.on_error(error, **kwargs)
        else:
            result = await self._handler.on_success(response, **kwargs)
            response.close()
        return result

    def _prepare_request(self, auth: HttpAuth, **kwargs: Any) -> dict[str, Any]:
        kwargs.update({"headers": auth.headers})
        kwargs["raise_for_status"] = False
        return utils.match_signature(self._session.request, **kwargs)

    async def close(self) -> None:
        return await self._session.close()

    async def clear_cache(self) -> None:
        if isinstance(self._session, CachedSession):
            return await self._session.cache.clear()

    async def __aenter__(self) -> AsyncHttpClient:
        async with self._session:
            return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)


class AsyncHatClient(BaseHatClient):
    __slots__ = "client", "_auth", "_token"

    def __init__(
            self,
            client: AsyncHttpClient,
            token: AsyncApiToken,
            namespace: Optional[str] = None
    ) -> None:
        super().__init__(namespace)
        self.client = client
        self._token = token
        self._auth = AsyncTokenAuth(token)

    async def get(
            self,
            endpoint: StringLike,
            mtype: Type[M] = HatModel,
            options: Optional[GetOpts] = None
    ) -> list[M]:
        endpoint = self._prepare_get(endpoint)
        return await self._endpoint_request(
            "GET", endpoint, data=options, mtypes=[mtype])

    async def post(self, models: Models) -> list[M]:
        posted = await asyncio.gather(*(
            self._endpoint_request("POST", endpoint, data=models, mtypes=mtypes)
            for endpoint, models, mtypes in self._prepare_post(models)))
        return list(itertools.chain(posted))

    async def put(self, models: Models) -> list[M]:
        put = self._prepare_put(models)
        return await self._data_request("PUT", data=put, mytpes=types(models))

    async def delete(self, record_ids: StringLike | IStringLike) -> None:
        delete = self._prepare_delete(record_ids)
        return await self._data_request("DELETE", params=delete)

    async def _endpoint_request(
            self, method: str, endpoint: str, **kwargs) -> list[M]:
        url = urls.domain_endpoint(
            await self._token.domain(), self._namespace, endpoint)
        return await self._request(method, url, **kwargs)

    async def _data_request(self, method: str, **kwargs) -> list[M] | None:
        url = urls.domain_data(await self._token.domain())
        return await self._request(method, url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> list[M] | None:
        return await self.client.request(method, url, self._auth, **kwargs)

    @staticmethod
    def _prepare_get(string: StringLike) -> str:
        string = next(require_endpoint([string]))
        return string if isinstance(string, str) else string.endpoint

    def _prepare_post(self, models: Iterable[M]) -> Generator[tuple]:
        formatted = []
        for m in require_endpoint(models):
            # The namespace is added when constructing the endpoint URL,
            # so it should not be a part of the endpoint here.
            if self._pattern.match(m.endpoint):
                m.endpoint = self._pattern.split(m.endpoint)[-1]
            formatted.append(m)
        for endpoint, models in group_by_endpoint(formatted):
            records = HatRecord.to_json(models, data_only=True)
            yield endpoint, records, types(models)

    def _prepare_put(self, models: Iterable[M]) -> str:
        formatted = []
        for m in require_endpoint(models):
            # The endpoint should include the namespace. HatRecords created
            # from responses will include the namespace. This is just a
            # convenience if wanting to create HatRecords manually.
            if self._pattern.match(m.endpoint) is None:
                m.endpoint = f"{self._namespace}/{m.endpoint}"
            formatted.append(m)
        return HatRecord.to_json(formatted)

    @staticmethod
    def _prepare_delete(record_ids: IStringLike) -> dict[str, list[str]]:
        record_ids = [
            r if isinstance(r, str) else r.record_id
            for r in require_record_id(record_ids)]
        return {"records": record_ids}

    @property
    def token(self) -> AsyncApiToken:
        return self._token

    def to_sync(self) -> HatClient:
        return HatClient(self)

    def __repr__(self) -> str:
        return utils.to_str(self, token=self._token, namespace=self._namespace)


class HatClient(BaseHatClient):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncHatClient):
        super().__init__(wrapped._namespace)
        self._wrapped = wrapped

    def get(
            self,
            endpoint: StringLike,
            mtype: Type[M] = HatModel,
            options: Optional[GetOpts] = None
    ) -> list[M]:
        return sync.async_to_sync(self._wrapped)(endpoint, mtype, options)

    def post(self, models: Models) -> list[M]:
        return sync.async_to_sync(self._wrapped)(models)

    def put(self, models: Models) -> list[M]:
        return sync.async_to_sync(self._wrapped)(models)

    def delete(self, record_ids: StringLike | IStringLike) -> None:
        return sync.async_to_sync(self._wrapped)(record_ids)

    def to_async(self) -> AsyncHatClient:
        return self._wrapped

    def __repr__(self) -> str:
        return utils.to_str(
            self, token=self._wrapped.token, namespace=self._namespace)
