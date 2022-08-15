from __future__ import annotations

import abc
import pprint
import re
from typing import Any, Generator, Iterable, Mapping, Optional, Protocol, Type

from . import errors, urls, utils
from .model import GetOpts, HatModel, HatRecord, M


class SupportsUrlAndHeaders(Protocol):
    headers: Any
    url: Any


class BaseResponseHandler(abc.ABC):

    def on_success(self, response: SupportsUrlAndHeaders, **kwargs) -> Any:
        url = str(response.url)
        headers = pprint.pformat(response.headers, indent=2)
        raise ValueError(f"Unable to process response for URL {url}\n{headers}")

    def on_error(self, error: BaseException, **kwargs) -> None:
        status, content = self.status(error), self.content(error)
        if urls.is_auth_endpoint(url := self.url(error)):
            raise errors.find_error("auth", status, content)
        elif urls.is_api_endpoint(url):
            method = self.method(error)
            raise errors.find_error(method, status, content)
        else:
            raise error

    @abc.abstractmethod
    def status(self, error: BaseException) -> int:
        pass

    @abc.abstractmethod
    def url(self, error: BaseException) -> str:
        pass

    @abc.abstractmethod
    def method(self, error: BaseException) -> str:
        pass

    @abc.abstractmethod
    def content(self, error: BaseException) -> Mapping[str, str]:
        pass


class HttpAuth:
    __slots__ = ()

    @property
    def headers(self) -> Mapping[str, str]:
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


class Cachable(abc.ABC):

    @abc.abstractmethod
    def clear_cache(self) -> None:
        pass


class AsyncCachable(Cachable, abc.ABC):

    @abc.abstractmethod
    async def clear_cache(self) -> None:
        pass


def group_by_endpoint(models: Iterable[M]) -> Iterable[tuple[str, list[M]]]:
    by_endpoint = functools.partial(lambda r: r.endpoint)
    groups = itertools.groupby(sorted(models, key=by_endpoint), by_endpoint)
    return ((endpoint, list(models)) for endpoint, models in groups)


def get_models(
        res: Response, on_error: utils.OnError, mtypes: MTypes) -> list[M]:
    return utils.handle(
        res, lambda r: HatRecord.parse(r.content, mtypes), on_error)


def types(models: Iterable[M]) -> MTypes:
    return (type(m) for m in models)


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
