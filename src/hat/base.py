from __future__ import annotations

import abc
import datetime
import functools
import inspect
import itertools
import mimetypes
import pprint
import re
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import ClassVar
from typing import Collection
from typing import Iterable
from typing import Iterator
from typing import TypeVar
from typing import Union

from . import errors
from . import urls
from . import utils
from .model import GetOpts
from .model import HatModel
from .model import HatRecord
from .model import JwtToken
from .model import M


try:
    from aiohttp import ClientResponse as AsyncClientResponse  # noqa: F401
    from aiohttp import ClientResponseError as AsyncClientResponseError  # noqa: F401
    from aiohttp import ClientSession as AsyncClientSession  # noqa: F401

    ASYNC_ENABLED = True
except ImportError:
    ASYNC_ENABLED = False

try:
    from requests import HTTPError as ClientResponseError  # noqa: F401
    from requests import Response as ClientResponse  # noqa: F401
    from requests import Session as ClientSession  # noqa: F401

    SYNC_ENABLED = True
except ImportError:
    SYNC_ENABLED = False

if not ASYNC_ENABLED and not SYNC_ENABLED:
    raise ImportError(
        "Must install package with at least one option: 'sync' or 'async'"
    )

try:
    from aiohttp_client_cache import CacheBackend as AsyncCacheBackend  # noqa: F401
    from aiohttp_client_cache import CachedSession as AsyncCachedSession  # noqa: F401

    ASYNC_CACHING_ENABLED = True
except ImportError:
    ASYNC_CACHING_ENABLED = False

try:
    from requests_cache import BaseCache as CacheBackend  # noqa: F401
    from requests_cache import CachedSession  # noqa: F401

    SYNC_CACHING_ENABLED = True
except ImportError:
    SYNC_CACHING_ENABLED = False

SYNC_IMPORT_ERROR_MSG = "Must install package with 'sync' option"
ASYNC_IMPORT_ERROR_MSG = "Must install package with 'async' option"

NEVER_CACHE = 0
SESSION_DEFAULTS = {
    "headers": {"Content-Type": mimetypes.types_map[".json"]},
    "allowed_codes": [200] + list(errors.POSSIBLE_CODES),
    "allowed_methods": ["GET", "POST"],
    "expire_after": datetime.timedelta(minutes=10),
    "urls_expire_after": {
        urls.domain_owner_token("*"): NEVER_CACHE,
        urls.domain_app_token("*", "*"): NEVER_CACHE,
    },
    "stream": True,
}
# requests-cache and asyncio-client-cache use slightly different naming.
SESSION_DEFAULTS["allowable_codes"] = SESSION_DEFAULTS["allowed_codes"]
SESSION_DEFAULTS["allowable_methods"] = SESSION_DEFAULTS["allowed_methods"]

TOKEN_KEY = "accessToken"
TOKEN_HEADER = "x-auth-token"

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


class BaseResponse(abc.ABC):
    @abc.abstractmethod
    def method(self) -> str:
        pass

    @abc.abstractmethod
    def headers(self) -> dict[str, str]:
        pass

    @abc.abstractmethod
    def url(self) -> str:
        pass

    @abc.abstractmethod
    def raw(self) -> bytes:
        pass

    @abc.abstractmethod
    def text(self) -> str:
        pass

    @abc.abstractmethod
    def raise_for_status(self) -> None:
        pass


class BaseResponseError(Exception, abc.ABC):
    @abc.abstractmethod
    def method(self) -> str:
        pass

    @abc.abstractmethod
    def url(self) -> str:
        pass

    @abc.abstractmethod
    def content(self) -> Any:
        pass

    @abc.abstractmethod
    def status(self) -> int:
        pass


class BaseResponseHandler(abc.ABC):
    @abc.abstractmethod
    def on_success(self, response: BaseResponse, **kwargs) -> str | list[M] | None:
        pass

    @staticmethod
    def _success_handling_failed(response: BaseResponse) -> None:
        headers = pprint.pformat(response.headers(), indent=2)
        raise ValueError(
            f"Unable to process response for URL {response.url}\n{headers}"
        )

    def on_error(self, error: BaseResponseError, **kwargs) -> None:
        url = error.url()
        if urls.is_auth_endpoint(url):
            wrapper = errors.find_error("auth", error.status(), error.content())
        elif urls.is_api_endpoint(url):
            wrapper = errors.find_error(error.method(), error.status(), error.content())
        else:
            wrapper, error = error, None
        raise wrapper(error)


class Cacheable:
    __slots__ = ()

    def clear_cache(self) -> None:
        pass


class AsyncCacheable(Cacheable):
    __slots__ = ()

    async def clear_cache(self) -> None:
        pass


class Closeable:
    __slots__ = ()

    def close(self) -> None:
        pass


class AsyncCloseable(Closeable):
    async def close(self) -> None:
        pass


class HttpAuth:
    __slots__ = ()

    def headers(self) -> dict[str, str]:
        return {}

    def on_response(self, response: BaseResponse) -> None:
        pass


class AsyncHttpAuth(HttpAuth):
    async def headers(self) -> dict[str, str]:
        return super().headers()

    async def on_response(self, response: BaseResponse) -> None:
        return super().on_response(response)


class BaseHttpClient(abc.ABC):
    __slots__ = "_session", "_handler", "_auth"

    def __init__(
        self,
        session: Any | None = None,
        auth: HttpAuth | None = None,
        **kwargs,
    ) -> None:
        self._session = session or self._new_session(**kwargs)
        self._handler = self._new_handler()
        self._auth = auth or self._new_auth()

    @abc.abstractmethod
    def _new_handler(self) -> BaseResponseHandler:
        pass

    @abc.abstractmethod
    def _new_auth(self) -> HttpAuth:
        pass

    def _new_session(self, **kwargs) -> Any:
        kwargs = SESSION_DEFAULTS | kwargs
        if self._is_async():
            if not ASYNC_ENABLED:
                raise ImportError(ASYNC_IMPORT_ERROR_MSG)
            elif ASYNC_CACHING_ENABLED:
                cache = kwargs.pop("cache", None) or AsyncCacheBackend(**kwargs)
                session = AsyncCachedSession(cache=cache, **kwargs)
            else:
                params = inspect.signature(AsyncClientSession.__init__).parameters
                kwargs = {k: v for k, v in kwargs.items() if k in params}
                session = AsyncClientSession(**kwargs)
        else:
            if not SYNC_ENABLED:
                raise ImportError(SYNC_IMPORT_ERROR_MSG)
            elif SYNC_CACHING_ENABLED:
                cache = kwargs.pop("cache", None) or CacheBackend(**kwargs)
                session = CachedSession(backend=cache, **kwargs)
            else:
                session = ClientSession()
            session.headers = kwargs["headers"]
            session.stream = kwargs["stream"]
        return session

    @abc.abstractmethod
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

    @abc.abstractmethod
    def _is_async(self) -> bool:
        pass


class BaseApiToken(abc.ABC):
    __slots__ = (
        "_http",
        "_auth",
        "_jwt_type",
        "_value",
        "_decoded",
        "_pk",
        "_ttl",
        "_domain",
        "_expires",
    )

    def __init__(
        self, http_client: BaseHttpClient, auth: HttpAuth, jwt_type: type[JwtToken]
    ) -> None:
        self._http = http_client
        self._auth = auth
        self._jwt_type = jwt_type
        self._value: str | None = None
        self._decoded: JwtToken | None = None
        self._pk: str | None = None
        self._ttl = datetime.timedelta(days=3)
        self._domain: str | None = None
        self._expires = datetime.datetime.max

    @abc.abstractmethod
    def pk(self) -> str:
        pass

    @abc.abstractmethod
    def value(self) -> str:
        pass

    @abc.abstractmethod
    def set_value(self, value: str) -> None:
        pass

    @abc.abstractmethod
    def domain(self) -> str:
        pass

    @abc.abstractmethod
    def decode(self, *, verify: bool = True) -> JwtToken:
        pass

    @abc.abstractmethod
    def url(self) -> str:
        pass

    def expired(self) -> bool:
        return self._expires <= datetime.datetime.utcnow()

    def _compute_expiration(self) -> datetime.datetime:
        iat = datetime.datetime.utcfromtimestamp(float(self._decoded.iat))
        exp = datetime.datetime.utcfromtimestamp(float(self._decoded.exp))
        return min(iat + self._ttl, exp)

    def __repr__(self) -> str:
        return utils.to_str(
            self, domain=self._domain, expired=self.expired(), expires=self._expires
        )


class BaseHatClient(abc.ABC):
    __slots__ = "_http", "_auth", "_token", "_namespace", "_pattern"

    def __init__(
        self,
        http_client: BaseHttpClient,
        token: BaseApiToken,
        namespace: str | None = None,
    ) -> None:
        self._http = http_client
        self._token = token
        self._auth = self._new_token_auth(token)
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")

    @abc.abstractmethod
    def _new_token_auth(self, token: BaseApiToken) -> HttpAuth:
        pass

    @requires_namespace
    def get(
        self,
        endpoint: StringLike,
        mtype: type[M] = HatModel,
        options: GetOpts | None = None,
    ) -> list[M] | Awaitable[list[M]]:
        if options:
            options = options.json()
        endpoint = self._prepare_get(endpoint)
        return self._endpoint_request("get", endpoint, data=options, mtypes=[mtype])

    @ensure_iterable
    @requires_namespace
    def post(self, models: Models) -> list[M]:
        return self._gather_posted(
            self._endpoint_request("post", endpoint, data=data, mtypes=mtypes)
            for endpoint, data, mtypes in self._prepare_post(models)
        )

    def _gather_posted(self, posted: Iterable) -> list[M]:
        return list(itertools.chain.from_iterable(posted))

    @ensure_iterable
    def put(self, models: Models) -> list[M] | Awaitable[list[M]]:
        data, mtypes = self._prepare_put(models)
        return self._data_request("put", data=data, mtypes=mtypes)

    @ensure_iterable
    def delete(self, record_ids: StringLike | IStringLike) -> None | Awaitable:
        params = self._prepare_delete(record_ids)
        return self._data_request("delete", params=params)

    def namespace(self) -> str | None:
        return self._namespace

    def token(self) -> BaseApiToken:
        return self._token

    @abc.abstractmethod
    def _data_request(self, method: str, **kwargs) -> list[M] | Awaitable | None:
        pass

    @abc.abstractmethod
    def _endpoint_request(
        self, method: str, endpoint: str, **kwargs
    ) -> list[M] | Awaitable[list[M]]:
        pass

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

    def __repr__(self) -> str:
        return utils.to_str(self, token=self.token(), namespace=self.namespace())


class BaseActiveHatModel(HatModel, abc.ABC):
    client: ClassVar[BaseHatClient]

    def save(self, endpoint: str | None = None) -> B | Awaitable[B]:
        if endpoint is not None:
            self.endpoint = endpoint
        has_id = self.record_id is not None
        try_first = self._client().put if has_id else self._client().post
        return self._save(try_first, has_id)

    def _save(self, try_first: Callable, has_id: bool) -> B | Awaitable[B]:
        try:
            saved = try_first(self)
        except errors.PutError as error:
            if has_id:
                saved = self._client().post(self)
            else:
                raise error
        return saved[0]

    def delete(self) -> None | Awaitable:
        return self._client().delete(self)

    @classmethod
    def delete_all(cls, record_ids: StringLike | IStringLike) -> None | Awaitable:
        return cls._client().delete(record_ids)

    @classmethod
    def get(
        cls, endpoint: StringLike, options: GetOpts | None = None
    ) -> list[B] | Awaitable[list[B]]:
        return cls._client().get(endpoint, cls, options)

    @classmethod
    def _client(cls) -> BaseHatClient:
        return cls.client  # ClassVar interferes with type checking.


B = TypeVar("B", bound=BaseActiveHatModel)
