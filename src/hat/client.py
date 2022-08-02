from __future__ import annotations

import functools
import itertools
import re
import uuid
from typing import Callable, Iterable, Sequence

from requests import Response

from . import errors, tokens, urls, utils
from .models import GetOpts, HatRecord
from .tokens import Token
from .utils import OnError

HatRecords = list[HatRecord]
IHatRecords = Iterable[HatRecord]


def group_by_endpoint(
        records: IHatRecords) -> Iterable[tuple[str, IHatRecords]]:
    by_endpoint = functools.partial(lambda r: r.endpoint)
    return itertools.groupby(sorted(records, key=by_endpoint), by_endpoint)


def get_records(response: Response, on_error: OnError) -> HatRecords:
    content = utils.get_json(response, on_error)
    if isinstance(content, Sequence):
        records = [HatRecord(**record) for record in content]
    else:
        records = [HatRecord(**content)]
    return records


def require_endpoint(records: Iterable[str | HatRecord]) -> IHatRecords:
    for record in records:
        if isinstance(record, HatRecord) and record.endpoint is None:
            raise ValueError("'endpoint' is required")
        yield record


def require_record_id(records: Iterable[str | HatRecord]) -> IHatRecords:
    for record in records:
        if isinstance(record, HatRecord) and record.record_id is None:
            raise ValueError("'record_id' is required")
        yield record


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
            namespace: str | None = None,
            share_session: bool = True,
            **kwargs):
        super().__init__(token._session if share_session else None, **kwargs)
        self._token = token
        self._auth = tokens.TokenAuth(token)
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")

    @property
    def namespace(self) -> str | None:
        return self._namespace

    @property
    def token(self) -> Token:
        return self._token

    @requires_namespace
    def get(
            self,
            *endpoints: str | HatRecord,
            options: GetOpts | None = None
    ) -> HatRecords:
        options = None if options is None else options.dict()
        got = []
        for endpoint in self._prepare_get(endpoints):
            response = self._endpoint_request("GET", endpoint, json=options)
            got.extend(get_records(response, errors.get_error))
        return got

    @requires_namespace
    def post(self, *records: HatRecord, unique: bool = False) -> HatRecords:
        posted = []
        for endpoint, records in self._prepare_post(records, unique):
            response = self._endpoint_request("POST", endpoint, json=records)
            posted.extend(get_records(response, errors.post_error))
        return posted

    def put(self, *records: HatRecord) -> HatRecords:
        put = self._prepare_put(records)
        response = self._data_request("PUT", json=put)
        return get_records(response, errors.put_error)

    def delete(self, *records: str | HatRecord) -> None:
        delete = self._prepare_delete(records)
        response = self._data_request("DELETE", params=delete)
        get_records(response, errors.delete_error)

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
    def _prepare_get(records: Iterable[str | HatRecord]) -> list[str]:
        return [
            rec if isinstance(rec, str) else rec.endpoint
            for rec in require_endpoint(records)]

    def _prepare_post(
            self,
            records: IHatRecords,
            unique: bool
    ) -> Iterable[tuple[str, list]]:
        pattern = self._pattern
        formatted = []
        # Step 1: Ensure endpoints are present and formatted.
        for rec in require_endpoint(records):
            # The namespace is added when constructing the endpoint URL,
            # so it should not be a part of the endpoint here.
            if pattern.match(rec.endpoint):
                endpoint = pattern.split(rec.endpoint)[-1]
                rec = HatRecord.copy(rec, update={"endpoint": endpoint})
            formatted.append(rec)
        # Step 2: Group by endpoint and make unique, if necessary.
        for endpoint, records in group_by_endpoint(formatted):
            records = [rec.dict()["data"] for rec in records]
            if unique:
                for rec in records:
                    rec["uuid"] = str(uuid.uuid4())
            yield endpoint, records

    def _prepare_put(self, records: IHatRecords) -> list[dict]:
        ns, pattern = self.namespace, self._pattern
        prepared = []
        for rec in require_endpoint(records):
            # The endpoint should include the namespace. HatRecords created
            # from responses will include the namespace. This is just a
            # convenience if wanting to create HatRecords manually.
            if pattern.match(e := rec.endpoint) is None:
                rec = HatRecord.copy(rec, update={"endpoint": f"{ns}/{e}"})
            prepared.append(rec.dict())
        return prepared

    @staticmethod
    def _prepare_delete(records: Iterable[str | HatRecord]) -> dict[str, list]:
        records = [
            rec if isinstance(rec, str) else rec.record_id
            for rec in require_record_id(records)]
        return {"records": records}

    def __repr__(self) -> str:
        return utils.to_string(
            self, token=self._token, namespace=self._namespace)
