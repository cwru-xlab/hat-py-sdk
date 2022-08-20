from __future__ import annotations

import abc
import asyncio
import mimetypes
from contextlib import AbstractAsyncContextManager
from typing import Any
from typing import Callable
from typing import ClassVar
from typing import Iterable
from typing import Mapping
from typing import TypeVar
from typing import cast

from keyring.credentials import Credential

from . import _urls
from . import _utils
from . import errors
from ._base import ASYNC_CACHING_ENABLED
from ._base import ASYNC_ENABLED
from ._base import ASYNC_IMPORT_ERROR_MSG
from ._base import TOKEN_HEADER
from ._base import TOKEN_KEY
from ._base import AsyncCacheable
from ._base import AsyncCloseable
from ._base import AsyncHttpAuth
from ._base import BaseActiveHatModel
from ._base import BaseApiToken
from ._base import BaseHatClient
from ._base import BaseHttpClient
from ._base import BaseResponse
from ._base import BaseResponseError
from ._base import BaseResponseHandler
from ._base import HttpAuth
from ._base import IStringLike
from ._base import Models
from ._base import StringLike
from .model import GetOpts
from .model import HatModel
from .model import JwtAppToken
from .model import JwtOwnerToken
from .model import JwtToken
from .model import M
from .model import _HatRecord


if ASYNC_ENABLED:
    from ._base import AsyncClientResponse
    from ._base import AsyncClientResponseError
    from ._base import AsyncClientSession
else:
    raise ImportError(ASYNC_IMPORT_ERROR_MSG)

if ASYNC_CACHING_ENABLED:
    from ._base import AsyncCachedSession


class AsyncResponse(BaseResponse):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncClientResponse) -> None:
        self._wrapped = wrapped

    def method(self) -> str:
        return self._wrapped.method.lower()

    def headers(self) -> dict[str, str]:
        return dict(self._wrapped.headers)

    def url(self) -> str:
        return str(self._wrapped.url)

    async def raw(self) -> bytes:
        return await self._wrapped.read()

    async def text(self) -> str:
        return await self._wrapped.text()

    def raise_for_status(self) -> None:
        return self._wrapped.raise_for_status()


class AsyncResponseError(BaseResponseError):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncClientResponseError) -> None:
        super().__init__(wrapped)
        self._wrapped = wrapped

    def method(self) -> str:
        return self._wrapped.request_info.method.lower()

    def url(self) -> str:
        return str(self._wrapped.request_info.url)

    def content(self) -> str:
        status = self.status()
        kind = "Client" if 400 <= status < 500 else "Server"
        return f"{status} {kind} Error: {self.url}"

    def status(self) -> int:
        return self._wrapped.status


class AsyncResponseHandler(BaseResponseHandler):
    async def on_success(
        self, response: AsyncResponse, **kwargs
    ) -> str | list[M] | None:
        url = response.url()
        if _urls.is_pk_endpoint(url):
            return await response.text()
        elif _urls.is_token_endpoint(url):
            return _utils.loads(await response.text())[TOKEN_KEY]
        elif response.method() == "delete":
            return None
        elif _urls.is_api_endpoint(url):
            return _HatRecord.parse(await response.raw(), kwargs["mtypes"])
        else:
            return super()._success_handling_failed(response)

    async def on_error(self, error: AsyncResponseError, **kwargs) -> None:
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
        headers = headers | await auth.headers() if headers else await auth.headers()
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
            return await self._session.cache.clear()

    def _is_async(self) -> bool:
        return True

    async def __aenter__(self) -> AsyncHttpClient:
        await self._session.__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._session.__aexit__(*args)


class AsyncApiToken(BaseApiToken, abc.ABC):
    def __init__(
        self, http_client: BaseHttpClient, auth: HttpAuth, jwt_type: type[JwtToken]
    ) -> None:
        super().__init__(http_client, auth, jwt_type)

    async def pk(self) -> str:
        if self._pk is None:
            url = _urls.domain_pk(await self.domain())
            self._pk = await self._get(url)
        return self._pk

    async def value(self) -> str:
        if self._value is None or self.expired():
            token = await self._get(await self.url())
            await self.set_value(token)
        return self._value

    async def set_value(self, value: str) -> None:
        if self._value != value:
            self._value = value
            self._decoded = await self.decode(verify=True)
            self._expires = self._compute_expiration()

    async def domain(self) -> str:
        if self._domain is None:
            token = await self.decode(verify=False)
            self._domain = _urls.with_scheme(token.iss)
        return self._domain

    async def decode(self, *, verify: bool = True) -> JwtToken:
        value = await self.value()
        pk = await self.pk() if verify else None
        return self._jwt_type.decode(value, pk=pk, verify=verify)

    @abc.abstractmethod
    async def url(self) -> str:
        pass

    async def _get(self, url: str) -> str:
        return await self._http.request("get", url, auth=self._auth)


class AsyncCredentialOwnerToken(AsyncApiToken):
    __slots__ = "_url"

    def __init__(self, http_client: AsyncHttpClient, credential: Credential) -> None:
        super().__init__(http_client, AsyncCredentialAuth(credential), JwtOwnerToken)
        self._url = _urls.username_owner_token(credential.username)

    async def url(self) -> str:
        return self._url


class AsyncAppToken(AsyncApiToken):
    __slots__ = "_owner_token", "_app_id", "_url"

    def __init__(
        self,
        client: AsyncHttpClient,
        owner_token: AsyncCredentialOwnerToken,
        app_id: str,
    ) -> None:
        super().__init__(client, AsyncTokenAuth(owner_token), JwtAppToken)
        self._owner_token = owner_token
        self._app_id = app_id
        self._url: str | None = None

    async def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return await self._owner_token.domain()

    async def url(self) -> str:
        if self._url is None:
            self._url = _urls.domain_app_token(await self.domain(), self._app_id)
        return self._url


class AsyncWebOwnerToken(AsyncApiToken, abc.ABC):  # TODO
    pass


class AsyncTokenAuth(AsyncHttpAuth):
    __slots__ = "_token"

    def __init__(self, token: AsyncApiToken):
        self._token = token

    async def headers(self) -> dict[str, str]:
        return {TOKEN_HEADER: await self._token.value()}

    async def on_response(self, response: AsyncResponse) -> None:
        headers = response.headers()
        if TOKEN_HEADER in headers:
            await self._token.set_value(headers[TOKEN_HEADER])


class AsyncCredentialAuth(AsyncHttpAuth):
    __slots__ = "_credential"

    def __init__(self, credential: Credential):
        self._credential = credential

    async def headers(self) -> dict[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password,
        }


class AsyncHatClient(
    BaseHatClient, AsyncCacheable, AsyncCloseable, AbstractAsyncContextManager
):
    def __init__(
        self,
        http_client: AsyncHttpClient,
        token: AsyncApiToken,
        namespace: str | None = None,
    ) -> None:
        super().__init__(http_client, token, namespace)

    def _new_token_auth(self, token: AsyncApiToken) -> AsyncHttpAuth:
        return AsyncTokenAuth(token)

    async def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M]:
        return await super().get(endpoint, mtype, options)

    async def post(self, models: Models) -> list[M]:
        return await super().post(models)

    async def _gather_posted(self, posted: Iterable) -> list[M]:
        return super()._gather_posted(await asyncio.gather(*posted))

    async def put(self, models: Models) -> list[M]:
        return await super().put(models)

    async def delete(self, record_ids: StringLike | IStringLike) -> None:
        return await super().delete(record_ids)

    async def _endpoint_request(self, method: str, endpoint: str, **kwargs) -> list[M]:
        url = _urls.domain_endpoint(
            await self.token().domain(), self._namespace, endpoint
        )
        return await self._request(method, url, **kwargs)

    async def _data_request(self, method: str, **kwargs) -> list[M] | None:
        url = _urls.domain_data(await self.token().domain())
        return await self._request(method, url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> list[M] | None:
        return await self._client().request(method, url, auth=self._auth, **kwargs)

    async def clear_cache(self) -> None:
        return await self._client().clear_cache()

    async def close(self) -> None:
        return await self._client().close()

    async def __aenter__(self) -> AsyncHatClient:
        await self._client().__aenter__()
        return self

    async def __aexit__(self, *args) -> None:
        return await self._client().__aexit__(*args)

    def token(self) -> AsyncApiToken:
        return cast(AsyncApiToken, super().token())

    def _client(self) -> AsyncHttpClient:
        return cast(AsyncHttpClient, self._http)


class AsyncActiveHatModel(BaseActiveHatModel):
    client: ClassVar[AsyncHatClient]

    async def save(self, endpoint: str | None = None) -> A:
        return await super().save(endpoint)

    async def _save(self, try_first: Callable, has_id: bool) -> A:
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


A = TypeVar("A", bound=AsyncActiveHatModel)


def set_async_client(client: AsyncHatClient) -> None:
    AsyncActiveHatModel.client = client
