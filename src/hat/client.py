from __future__ import annotations

import functools
import itertools
import re
from typing import (Any, Callable, Generator, Iterable, Optional, Type, Union)

from requests import Response

from . import errors, tokens, urls, utils
from .models import GetOpts, HatModel, HatRecord, M
from .tokens import Token
from .utils import OnError

StringLike = Union[str, HatModel, HatRecord]
IStringLike = Iterable[StringLike]


def group_by_endpoint(models: Iterable[M]) -> Iterable[tuple[str, list[M]]]:
    by_endpoint = functools.partial(lambda r: r.endpoint)
    groups = itertools.groupby(sorted(models, key=by_endpoint), by_endpoint)
    return ((endpoint, list(models)) for endpoint, models in groups)


def get_models(res: Response, on_error: OnError, *mtypes: Type[M]) -> list[M]:
    content = utils.get_json(res, on_error)
    if not isinstance(content, list):
        content = [content]
    # When more records exist than model types, try binding to the last one.
    mtypes, m = iter(mtypes), None
    return [HatRecord(**rec).to_model(m := next(mtypes, m)) for rec in content]


def types(objs: Iterable) -> Iterable[Type]:
    return (type(o) for o in objs)


def require_endpoint(strings: IStringLike) -> Generator[StringLike]:
    for s in strings:
        if hasattr(s, "endpoint") and s.endpoint is None:
            raise ValueError("'endpoint' is required")
        yield s


def require_record_id(strings: IStringLike) -> Generator[StringLike]:
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
            mtype: Type[M],
            endpoint: StringLike,
            options: Optional[GetOpts] = None,
    ) -> list[M]:
        if options:
            options = options.dict()
        endpoint = self._prepare_get(endpoint)
        res = self._endpoint_request("GET", endpoint, json=options)
        return get_models(res, errors.get_error, mtype)

    @requires_namespace
    def post(self, *models: M) -> list[M]:
        posted = []
        for endpoint, models, mtypes in self._prepare_post(models):
            res = self._endpoint_request("POST", endpoint, json=models)
            posted.extend(get_models(res, errors.post_error, *mtypes))
        return posted

    def put(self, *models: M) -> list[M]:
        put = self._prepare_put(models)
        res = self._data_request("PUT", json=put)
        return get_models(res, errors.put_error, *types(models))

    def delete(self, *record_ids: StringLike) -> None:
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
    def _prepare_get(model: StringLike) -> str:
        model = next(require_endpoint([model]))
        return model if isinstance(model, str) else model.endpoint

    def _prepare_post(self, models: Iterable[M]) -> Iterable[tuple]:
        formatted = []
        # Step 1: Ensure endpoints are present and formatted.
        for m in require_endpoint(models):
            # The namespace is added when constructing the endpoint URL,
            # so it should not be a part of the endpoint here.
            if self._pattern.match(m.endpoint):
                m.endpoint = self._pattern.split(m.endpoint)[-1]
            formatted.append(m)
        # Step 2: Group by endpoint and make unique, if necessary.
        for endpoint, models in group_by_endpoint(formatted):
            yield endpoint, [m.to_record().data for m in models], types(models)

    def _prepare_put(self, models: Iterable[M]) -> list[dict[str, Any]]:
        prepared = []
        for m in require_endpoint(models):
            # The endpoint should include the namespace. HatRecords created
            # from responses will include the namespace. This is just a
            # convenience if wanting to create HatRecords manually.
            if self._pattern.match(m.endpoint) is None:
                m.endpoint = f"{self.namespace}/{m.endpoint}"
            prepared.append(m.to_record().dict())
        return prepared

    @staticmethod
    def _prepare_delete(record_ids: IStringLike) -> dict[str, list[str]]:
        record_ids = [
            r if isinstance(r, str) else r.record_id
            for r in require_record_id(record_ids)]
        return {"records": record_ids}

    def __repr__(self) -> str:
        return utils.to_string(
            self, token=self._token, namespace=self._namespace)
