from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any
from typing import Callable
from typing import ClassVar
from typing import cast

from . import urls
from . import utils
from .auth import TOKEN_KEY
from .auth import ApiToken
from .base import SYNC_CACHING_ENABLED
from .base import SYNC_ENABLED
from .base import SYNC_IMPORT_ERROR_MSG
from .base import A
from .base import BaseActiveHatModel
from .base import BaseHatClient
from .base import BaseHttpClient
from .base import BaseResponse
from .base import BaseResponseError
from .base import BaseResponseHandler
from .base import Cacheable
from .base import Closeable
from .base import HttpAuth
from .base import IStringLike
from .base import Models
from .base import StringLike
from .base import TokenAuth
from .base import requires_namespace
from .model import GetOpts
from .model import HatModel
from .model import HatRecord
from .model import M


if SYNC_ENABLED:
    from .base import ClientResponse
    from .base import ClientResponseError
    from .base import ClientSession
else:
    raise ImportError(SYNC_IMPORT_ERROR_MSG)

if SYNC_CACHING_ENABLED:
    from .base import CachedSession


class Response(BaseResponse):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: ClientResponse) -> None:
        self._wrapped = wrapped

    @property
    def method(self) -> str:
        return self._wrapped.request.method.lower()

    @property
    def headers(self) -> dict[str, str]:
        return dict(self._wrapped.headers)

    @property
    def url(self) -> str:
        return self._wrapped.url

    @property
    def raw(self) -> bytes:
        return self._wrapped.content

    @property
    def text(self) -> str:
        return self._wrapped.text

    def raise_for_status(self) -> None:
        return self._wrapped.raise_for_status()


class ResponseError(BaseResponseError):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: ClientResponseError) -> None:
        super().__init__(wrapped)
        self._wrapped = wrapped.response

    @property
    def method(self) -> str:
        return self._wrapped.request.method.lower()

    @property
    def url(self) -> str:
        return self._wrapped.url

    @property
    def content(self) -> dict[str, str]:
        return utils.loads(self._wrapped.content)

    @property
    def status(self) -> int:
        return self._wrapped.status_code


class ResponseHandler(BaseResponseHandler):
    @staticmethod
    def on_success(response: Response, **kwargs) -> str | list[M] | None:
        url = response.url
        if urls.is_pk_endpoint(url):
            return response.text
        elif urls.is_token_endpoint(url):
            return utils.loads(response.text)[TOKEN_KEY]
        elif response.method == "delete":
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(response.raw, kwargs["mtypes"])
        else:
            return super()._success_handling_failed(response)


class HttpClient(BaseHttpClient, Cacheable, Closeable, AbstractContextManager):
    def __init__(
        self,
        session: ClientSession | None = None,
        auth: HttpAuth | None = None,
        **kwargs,
    ) -> None:
        super().__init__(session, auth, **kwargs)

    def _new_handler(self) -> ResponseHandler:
        return ResponseHandler()

    def _new_auth(self) -> HttpAuth:
        return HttpAuth()

    def request(
        self,
        method: str,
        url: str,
        *,
        auth: HttpAuth | None = None,
        headers: dict[str, str] | None = None,
        data: Any = None,
        params: dict[str, str] | None = None,
        **kwargs,
    ) -> Any:
        pass

    def close(self) -> None:
        return self._session.close()

    def clear_cache(self) -> None:
        if SYNC_CACHING_ENABLED and isinstance(self._session, CachedSession):
            return self._session.close()

    @property
    def _is_async(self) -> bool:
        return False

    def __enter__(self) -> HttpClient:
        self._session.__enter__()
        return self

    def __exit__(self, *args) -> None:
        return self._session.__exit__(*args)


class HatClient(BaseHatClient, Cacheable, Closeable, AbstractContextManager):
    def __init__(
        self,
        http_client: HttpClient,
        token: ApiToken,
        namespace: str | None = None,
    ) -> None:
        super().__init__(http_client, token, namespace)

    def _new_token_auth(self, token: ApiToken) -> HttpAuth:
        return TokenAuth(token)

    @requires_namespace
    def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M]:
        return super().get(endpoint, mtype, options)

    def post(self, models: Models) -> list[M]:
        return super().post(models)

    def put(self, models: Models) -> list[M]:
        return super().put(models)

    def delete(self, record_ids: StringLike | IStringLike) -> None:
        return super().delete(record_ids)

    def clear_cache(self) -> None:
        return self._client.clear_cache()

    def close(self) -> None:
        return self._client.close()

    def __enter__(self) -> HatClient:
        self._client.__enter__()
        return self

    def __exit__(self, *args) -> None:
        return self._client.__exit__(*args)

    @property
    def _client(self) -> HttpClient:
        return cast(HttpClient, self._http)

    def _endpoint_request(self, method: str, endpoint: str, **kwargs) -> list[M]:
        url = urls.domain_endpoint(self._token.domain, self._namespace, endpoint)
        return self._request(method, url, **kwargs)

    def _data_request(self, method: str, **kwargs) -> list[M] | None:
        url = urls.domain_data(self._token.domain)
        return self._request(method, url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> list[M] | None:
        return await self._client.request(method, url, auth=self._auth, **kwargs)


class ActiveHatModel(BaseActiveHatModel):
    client: ClassVar[HatClient]

    def _save(self, try_first: Callable, has_id: bool) -> A | None:
        return super()._save(try_first, has_id)

    @classmethod
    def _client(cls) -> HatClient:
        return cls.client


def set_client(client: HatClient) -> None:
    ActiveHatModel.client = client
