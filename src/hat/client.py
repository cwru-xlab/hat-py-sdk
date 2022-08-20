from __future__ import annotations

import abc
import mimetypes
from contextlib import AbstractContextManager
from json import JSONDecodeError
from typing import Any
from typing import Callable
from typing import ClassVar
from typing import TypeVar
from typing import cast

from keyring.credentials import Credential

from . import urls
from . import utils
from .base import SYNC_CACHING_ENABLED
from .base import SYNC_ENABLED
from .base import SYNC_IMPORT_ERROR_MSG
from .base import TOKEN_HEADER
from .base import TOKEN_KEY
from .base import BaseActiveHatModel
from .base import BaseApiToken
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
from .model import GetOpts
from .model import HatModel
from .model import HatRecord
from .model import JwtAppToken
from .model import JwtOwnerToken
from .model import JwtToken
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

    def method(self) -> str:
        return self._wrapped.request.method.lower()

    def headers(self) -> dict[str, str]:
        return dict(self._wrapped.headers)

    def url(self) -> str:
        return self._wrapped.url

    def raw(self) -> bytes:
        return self._wrapped.content

    def text(self) -> str:
        return self._wrapped.text

    def raise_for_status(self) -> None:
        return self._wrapped.raise_for_status()


class ResponseError(BaseResponseError):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: ClientResponseError) -> None:
        super().__init__(wrapped)
        self._response = wrapped.response

    def method(self) -> str:
        return self._response.request.method.lower()

    def url(self) -> str:
        return self._response.url

    def content(self) -> dict[str, str] | str:
        try:
            return utils.loads(self._response.content)
        except JSONDecodeError:
            return self._response.text

    def status(self) -> int:
        return self._response.status_code


class ResponseHandler(BaseResponseHandler):
    def on_success(self, response: Response, **kwargs) -> str | list[M] | None:
        url = response.url()
        if urls.is_pk_endpoint(url):
            return response.text()
        elif urls.is_token_endpoint(url):
            return utils.loads(response.text())[TOKEN_KEY]
        elif response.method() == "delete":
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(response.raw(), kwargs["mtypes"])
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
        auth = auth or self._auth
        headers = headers | auth.headers() if headers else auth.headers()
        with self._session.request(
            method, url, headers=headers, data=data, params=params
        ) as response:
            response = Response(response)
            try:
                response.raise_for_status()
            except ClientResponseError as error:
                error = ResponseError(error)
                result = self._handler.on_error(error, **kwargs)
            else:
                auth.on_response(response)
                result = self._handler.on_success(response, **kwargs)
            return result

    def close(self) -> None:
        return self._session.close()

    def clear_cache(self) -> None:
        if SYNC_CACHING_ENABLED and isinstance(self._session, CachedSession):
            return self._session.cache.clear()

    def _is_async(self) -> bool:
        return False

    def __enter__(self) -> HttpClient:
        self._session.__enter__()
        return self

    def __exit__(self, *args) -> None:
        return self._session.__exit__(*args)


class ApiToken(BaseApiToken, abc.ABC):
    def __init__(
        self, http_client: HttpClient, auth: HttpAuth, jwt_type: type[JwtToken]
    ) -> None:
        super().__init__(http_client, auth, jwt_type)

    def pk(self) -> str:
        if self._pk is None:
            url = urls.domain_pk(self.domain())
            self._pk = self._get(url)
        return self._pk

    def value(self) -> str:
        if self._value is None or self.expired():
            token = self._get(self.url())
            self.set_value(token)
        return self._value

    def set_value(self, value: str) -> None:
        if self._value != value:
            self._value = value
            self._decoded = self.decode(verify=True)
            self._expires = self._compute_expiration()

    def domain(self) -> str:
        if self._domain is None:
            token = self.decode(verify=False)
            self._domain = urls.with_scheme(token.iss)
        return self._domain

    def decode(self, *, verify: bool = True) -> JwtToken:
        value = self.value()
        pk = self.pk() if verify else None
        return self._jwt_type.decode(value, pk=pk, verify=verify)

    @abc.abstractmethod
    def url(self) -> str:
        pass

    def _get(self, url: str) -> str:
        return self._http.request("get", url, auth=self._auth)


class CredentialOwnerToken(ApiToken):
    __slots__ = "_url"

    def __init__(self, http_client: HttpClient, credential: Credential) -> None:
        super().__init__(http_client, CredentialAuth(credential), JwtOwnerToken)
        self._url = urls.username_owner_token(credential.username)

    def url(self) -> str:
        return self._url


class AppToken(ApiToken):
    __slots__ = "_owner_token", "_app_id", "_url"

    def __init__(
        self,
        client: HttpClient,
        owner_token: CredentialOwnerToken,
        app_id: str,
    ) -> None:
        super().__init__(client, TokenAuth(owner_token), JwtAppToken)
        self._owner_token = owner_token
        self._app_id = app_id
        self._url: str | None = None

    def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return self._owner_token.domain()

    def url(self) -> str:
        if self._url is None:
            self._url = urls.domain_app_token(self.domain(), self._app_id)
        return self._url


class WebOwnerToken(ApiToken, abc.ABC):  # TODO
    pass


class TokenAuth(HttpAuth):
    __slots__ = "_token"

    def __init__(self, token: ApiToken):
        self._token = token

    def headers(self) -> dict[str, str]:
        return {TOKEN_HEADER: self._token.value()}

    def on_response(self, response: Response) -> None:
        headers = response.headers()
        if TOKEN_HEADER in headers:
            return self._token.set_value(headers[TOKEN_HEADER])


class CredentialAuth(HttpAuth):
    __slots__ = "_credential"

    def __init__(self, credential: Credential):
        self._credential = credential

    def headers(self) -> dict[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password,
        }


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
        return self._client().clear_cache()

    def close(self) -> None:
        return self._client().close()

    def __enter__(self) -> HatClient:
        self._client().__enter__()
        return self

    def __exit__(self, *args) -> None:
        return self._client().__exit__(*args)

    def token(self) -> ApiToken:
        return cast(ApiToken, super().token())

    def _client(self) -> HttpClient:
        return cast(HttpClient, self._http)

    def _endpoint_request(self, method: str, endpoint: str, **kwargs) -> list[M]:
        url = urls.domain_endpoint(self._token.domain(), self._namespace, endpoint)
        return self._request(method, url, **kwargs)

    def _data_request(self, method: str, **kwargs) -> list[M] | None:
        url = urls.domain_data(self._token.domain())
        return self._request(method, url, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> list[M] | None:
        return self._client().request(method, url, auth=self._auth, **kwargs)


class ActiveHatModel(BaseActiveHatModel):
    client: ClassVar[HatClient]

    def _save(self, try_first: Callable, has_id: bool) -> S:
        return super()._save(try_first, has_id)

    def save(self, endpoint: str | None = None) -> S:
        return super().save(endpoint)

    def delete(self) -> None:
        return super().delete()

    @classmethod
    def delete_all(cls, record_ids: StringLike | IStringLike) -> None:
        return super().delete_all(record_ids)

    @classmethod
    def get(cls, endpoint: StringLike, options: GetOpts | None = None) -> list[S]:
        return super().get(endpoint, options)

    @classmethod
    def _client(cls) -> HatClient:
        return cls.client


S = TypeVar("S", bound=ActiveHatModel)


def set_client(client: HatClient) -> None:
    ActiveHatModel.client = client
