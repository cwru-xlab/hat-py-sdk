from __future__ import annotations

import asyncio
from contextlib import AbstractAsyncContextManager
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import ClassVar
from typing import Iterable
from typing import Mapping
from typing import cast

from . import errors
from . import urls
from . import utils
from .auth import TOKEN_KEY
from .auth import ApiToken
from .auth import AsyncTokenAuth
from .base import ASYNC_CACHING_ENABLED
from .base import ASYNC_ENABLED
from .base import ASYNC_IMPORT_ERROR_MSG
from .base import A
from .base import AsyncCacheable
from .base import AsyncCloseable
from .base import AsyncHttpAuth
from .base import BaseActiveHatModel
from .base import BaseHatClient
from .base import BaseHttpClient
from .base import BaseResponse
from .base import BaseResponseError
from .base import BaseResponseHandler
from .base import IStringLike
from .base import Models
from .base import StringLike
from .base import ensure_iterable
from .base import requires_namespace
from .model import GetOpts
from .model import HatModel
from .model import HatRecord
from .model import M


if ASYNC_ENABLED:
    from .base import AsyncClientResponse
    from .base import AsyncClientResponseError
    from .base import AsyncClientSession
else:
    raise ImportError(ASYNC_IMPORT_ERROR_MSG)

if ASYNC_CACHING_ENABLED:
    from .base import AsyncCachedSession


class AsyncResponse(BaseResponse):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncClientResponse) -> None:
        self._wrapped = wrapped

    @property
    def method(self) -> str:
        return self._wrapped.method.lower()

    @property
    def headers(self) -> dict[str, str]:
        return dict(self._wrapped.headers)

    @property
    def url(self) -> str:
        return str(self._wrapped.url)

    @property
    async def raw(self) -> bytes:
        return await self._wrapped.read()

    @property
    async def text(self) -> str:
        return await self._wrapped.text()

    def raise_for_status(self) -> None:
        return self._wrapped.raise_for_status()


class AsyncResponseError(BaseResponseError):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncClientResponseError) -> None:
        super().__init__(wrapped)
        self._wrapped = wrapped

    @property
    def method(self) -> str:
        return self._wrapped.request_info.method.lower()

    @property
    def url(self) -> str:
        return str(self._wrapped.request_info.url)

    @property
    def content(self) -> dict[str, str]:
        return utils.loads(self._wrapped.message)

    @property
    def status(self) -> int:
        return self._wrapped.status


class AsyncResponseHandler(BaseResponseHandler):
    @staticmethod
    async def on_success(response: AsyncResponse, **kwargs) -> str | list[M] | None:
        url = response.url
        if urls.is_pk_endpoint(url):
            return await response.text
        elif urls.is_token_endpoint(url):
            return utils.loads(await response.text)[TOKEN_KEY]
        elif response.method == "delete":
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(await response.raw, kwargs["mtypes"])
        else:
            return super()._success_handling_failed(response)

    @staticmethod
    async def on_error(error: AsyncResponseError, **kwargs) -> None:
        super().on_error(error, **kwargs)


class AsyncHttpClient(
    BaseHttpClient, AsyncCacheable, AsyncCloseable, AbstractAsyncContextManager
):
    def __init__(
        self,
        session: AsyncClientSession | None = None,
        auth: AsyncHttpAuth | None = None,
        **kwargs,
    ) -> None:
        super().__init__(session, auth, **kwargs)

    def _new_handler(self) -> AsyncResponseHandler:
        return AsyncResponseHandler()

    def _new_auth(self) -> AsyncHttpAuth:
        return AsyncHttpAuth()

    async def request(
        self,
        method: str,
        url: str,
        *,
        auth: AsyncHttpAuth | None = None,
        headers: Mapping[str, str] | None = None,
        data: Any = None,
        params: Mapping[str, str] | None = None,
        **kwargs,
    ) -> Any:
        auth = auth or self._auth
        auth_headers = await auth.headers()
        headers = headers | auth_headers if headers else auth_headers
        async with self._session.request(
            method, url, headers=headers, data=data, params=params
        ) as response:
            response = AsyncResponse(response)
            try:
                response.raise_for_status()
            except AsyncClientResponseError as error:
                error = AsyncResponseError(error)
                result = await self._handler.on_error(error, **kwargs)
            else:
                await auth.on_response(response)
                result = await self._handler.on_success(response, **kwargs)
            return result

    async def close(self) -> None:
        return await self._session.close()

    async def clear_cache(self) -> None:
        if ASYNC_CACHING_ENABLED and isinstance(self._session, AsyncCachedSession):
            return await self._session.close()

    @property
    def _is_async(self) -> bool:
        return True

    async def __aenter__(self) -> AsyncHttpClient:
        await self._session.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)


class AsyncHatClient(
    BaseHatClient, AsyncCacheable, AsyncCloseable, AbstractAsyncContextManager
):
    def __init__(
        self,
        http_client: AsyncHttpClient,
        token: ApiToken,
        namespace: str | None = None,
    ) -> None:
        super().__init__(http_client, token, namespace)

    def _new_token_auth(self, token: ApiToken) -> AsyncHttpAuth:
        return AsyncTokenAuth(token)

    @requires_namespace
    async def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M]:
        return await super().get(endpoint, mtype, options)

    @ensure_iterable
    @requires_namespace
    async def post(self, models: Models) -> list[M]:
        return await super().post(models)

    @staticmethod
    async def _gather_posted(posted: Iterable) -> list[M]:
        return super()._gather_posted(await asyncio.gather(*posted))

    @ensure_iterable
    async def put(self, models: Models) -> list[M]:
        return await super().put(models)

    @ensure_iterable
    async def delete(self, record_ids: StringLike | IStringLike) -> None:
        return await super().delete(record_ids)

    async def _endpoint_request(self, method: str, endpoint: str, **kwargs) -> list[M]:
        url = urls.domain_endpoint(await self._token.domain, self._namespace, endpoint)
        return await self._request(method, url, **kwargs)

    async def _data_request(self, method: str, **kwargs) -> list[M] | None:
        url = urls.domain_data(await self._token.domain)
        return await self._request(method, url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> list[M] | None:
        return await self._client.request(method, url, auth=self._auth, **kwargs)

    async def clear_cache(self) -> None:
        return await self._client.clear_cache()

    async def close(self) -> None:
        return await self._client.close()

    async def __aenter__(self) -> AsyncHatClient:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._client.__aexit__(*args)

    @property
    def _client(self) -> AsyncHttpClient:
        return cast(AsyncHttpClient, self._http)


class AsyncActiveHatModel(BaseActiveHatModel):
    client: ClassVar[AsyncHatClient]

    async def save(self, endpoint: str | None = None) -> A:
        return await super().save(endpoint)

    async def _save(self, try_first: Callable, has_id: bool) -> A | Awaitable[A] | None:
        try:
            saved = await try_first(self)
        except errors.PutError as error:
            if has_id:
                saved = await self._client().post(self)
            else:
                raise error
        return saved[0]

    async def delete(self) -> None:
        return await super().delete()

    @classmethod
    async def delete_all(cls, record_ids: StringLike | IStringLike) -> None:
        return await super().delete_all(record_ids)

    @classmethod
    async def get(cls, endpoint: StringLike, options: GetOpts | None = None) -> list[A]:
        return await super().get(endpoint, options)

    @classmethod
    def _client(cls) -> AsyncHatClient:
        return cls.client


def set_async_client(client: AsyncHatClient) -> None:
    AsyncActiveHatModel.client = client
