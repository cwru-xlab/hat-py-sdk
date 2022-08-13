from __future__ import annotations

import functools
import itertools
import re
from contextlib import AbstractContextManager
from typing import (Any, Callable, Collection, Generator, Iterable, Iterator,
                    Mapping, Optional, Type, Union)

from requests import HTTPError, Response, Session
from requests_cache import CachedSession

from . import errors, sessions, tokens, urls, utils
from .base import Cachable, HttpAuth, BaseHttpClient, BaseResponseHandler
from .model import GetOpts, HatModel, HatRecord, M
from .tokens import Token

StringLike = Union[str, HatModel]
IStringLike = Iterable[StringLike]
MTypes = Iterable[Type[M]]
Models = Union[M, Iterator[M], Collection[M]]


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


class HttpClient(BaseHttpClient, Cachable, AbstractContextManager):
    __slots__ = "session", "handler", "auth"

    def __init__(
            self,
            session: Optional[Session] = None,
            handler: Optional[ResponseHandler] = None,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> None:
        super().__init__()
        self.session = session or self._new_session(**kwargs)
        self.handler = handler or ResponseHandler()
        self.auth = auth or HttpAuth()

    @staticmethod
    def _new_session(**kwargs) -> Session:
        session = CachedSession(**sessions.DEFAULTS | kwargs)
        session.headers = sessions.DEFAULTS["headers"]
        session.stream = True
        return session

    def request(
            self,
            method: str,
            url: str,
            auth: Optional[HttpAuth] = None,
            **kwargs
    ) -> Any:
        auth = auth or self.auth
        kwargs = self._prepare_request(auth, **kwargs)
        response = self.session.request(method, url, **kwargs)
        try:
            response.raise_for_status()
        except HTTPError as error:
            result = self.handler.on_error(error, **kwargs)
        else:
            result = self.handler.on_success(response, **kwargs)
        finally:
            auth.on_response(response)
            response.close()
        return result

    def _prepare_request(self, auth: HttpAuth, kwargs: Any) -> dict[str, Any]:
        kwargs.update({"headers": auth.headers})
        return utils.match_signature(self.session.request, **kwargs)

    def close(self) -> None:
        self.session.close()

    def clear_cache(self) -> None:
        if isinstance(self.session, CachedSession):
            return self.session.cache.clear()

    def __enter__(self) -> HttpClient:
        with self.session:
            return self

    def __exit__(self, *args) -> None:
        return self.session.__exit__(*args)


class ResponseHandler(BaseResponseHandler):

    def on_success(self, response: Response, **kwargs) -> str | list[M] | None:
        if urls.is_pk_endpoint(url := response.url):
            return response.text
        elif urls.is_token_endpoint(url):
            return utils.loads(response.content)[tokens.TOKEN_KEY]
        elif response.request.method.lower() == "delete":
            return None
        elif urls.is_api_endpoint(url):
            return HatRecord.parse(response.content, kwargs["mtypes"])
        else:
            return super().on_success(response)

    def status(self, error: HTTPError) -> int:
        return error.response.status_code

    def url(self, error: HTTPError) -> str:
        return error.response.url

    def method(self, error: HTTPError) -> str:
        return error.request.method.lower()

    def content(self, error: HTTPError) -> Mapping[str, str]:
        return utils.loads(error.response.content)


class HatClient(utils.SessionMixin):
    __slots__ = "_token", "_auth", "_namespace", "_pattern"

    def __init__(
            self,
            token: Token,
            namespace: Optional[str] = None,
            share_session: bool = True,
            **kwargs):
        super().__init__(token._session if share_session else None, **kwargs)
        self._token = token
        self._auth = tokens.TokenAuth(token)
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")

    @property
    def namespace(self) -> Optional[str]:
        return self._namespace

    @property
    def token(self) -> Token:
        return self._token

    @requires_namespace
    def get(
            self,
            endpoint: StringLike,
            mtype: Type[M] = HatModel,
            options: Optional[GetOpts] = None
    ) -> list[M]:
        if options:
            options = options.json()
        endpoint = self._prepare_get(endpoint)
        res = self._endpoint_request("GET", endpoint, data=options)
        return get_models(res, errors.get_error, [mtype])

    @ensure_iterable
    @requires_namespace
    def post(self, models: Models) -> list[M]:
        posted = []
        for endpoint, models, mtypes in self._prepare_post(models):
            res = self._endpoint_request("POST", endpoint, data=models)
            posted.extend(get_models(res, errors.post_error, mtypes))
        return posted

    @ensure_iterable
    def put(self, models: Models) -> list[M]:
        put = self._prepare_put(models)
        res = self._data_request("PUT", data=put)
        return get_models(res, errors.put_error, types(models))

    @ensure_iterable
    def delete(self, record_ids: StringLike | IStringLike) -> None:
        delete = self._prepare_delete(record_ids)
        res = self._data_request("DELETE", params=delete)
        utils.get_json(res, errors.delete_error)

    def _endpoint_request(
            self, method: str, endpoint: str, **kwargs) -> Response:
        url = urls.domain_endpoint(self.token.domain, self.namespace, endpoint)
        return self._request(method, url=url, **kwargs)

    def _data_request(self, method: str, **kwargs) -> Response:
        url = urls.domain_data(self.token.domain)
        return self._request(method, url=url, **kwargs)

    def _request(self, method: str, **kwargs) -> Response:
        return self._session.request(method, auth=self._auth, **kwargs)

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
                m.endpoint = f"{self.namespace}/{m.endpoint}"
            formatted.append(m)
        return HatRecord.to_json(formatted)

    @staticmethod
    def _prepare_delete(record_ids: IStringLike) -> dict[str, list[str]]:
        record_ids = [
            r if isinstance(r, str) else r.record_id
            for r in require_record_id(record_ids)]
        return {"records": record_ids}

    def __repr__(self) -> str:
        return utils.to_str(self, token=self._token, namespace=self._namespace)
