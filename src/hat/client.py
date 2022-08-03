from __future__ import annotations

import functools
import itertools
import re
from typing import Callable, Iterable, Optional, Sequence

import ulid
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


def get_records(res: Response, on_error: OnError) -> HatRecords:
    content = utils.get_json(res, on_error)
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


def _uniquify(*records: HatRecord, only_data: bool) -> dict | list[dict]:
    unique = []
    for rec in (rec.dict() for rec in records):
        if not isinstance(rec["data"], dict):
            rec["data"] = {"data": rec["data"]}
        rec["data"]["ulid"] = str(ulid.new())
        if only_data:
            unique.append(rec["data"])
        else:
            unique.append(rec)
    return unique if len(unique) > 1 else unique[0]


class HatClient(utils.SessionMixin):
    __slots__ = "_uniquify", "_token", "_auth", "_namespace", "_pattern"

    def __init__(
            self,
            token: Token,
            namespace: Optional[str] = None,
            share_session: bool = True,
            uniquify: bool = False,
            **kwargs):
        super().__init__(token._session if share_session else None, **kwargs)
        self._token = token
        self._auth = tokens.TokenAuth(token)
        self._namespace = namespace
        self._pattern = re.compile(rf"^{namespace}/")
        self._uniquify = uniquify

    @property
    def namespace(self) -> Optional[str]:
        return self._namespace

    @property
    def token(self) -> Token:
        return self._token

    @property
    def uniquify(self) -> bool:
        return self._uniquify

    @requires_namespace
    def get(
            self,
            *endpoints: str | HatRecord,
            options: Optional[GetOpts] = None,
    ) -> HatRecords:
        options = None if options is None else options.dict()
        got = []
        for endpoint in self._prepare_get(endpoints):
            res = self._endpoint_request("GET", endpoint, json=options)
            got.extend(get_records(res, errors.get_error))
        got = [
            # Unwrap the nesting from record-data uniquification.
            HatRecord.copy(rec, update={"data": rec.data["data"]})
            if isinstance(rec.data, dict) and "data" in rec.data
            else rec
            for rec in got]
        return got

    @requires_namespace
    def post(
            self,
            *records: HatRecord,
            uniquify: Optional[bool] = None
    ) -> HatRecords:
        uniquify = self._uniquify if uniquify is None else uniquify
        posted = []
        for endpoint, records in self._prepare_post(records, uniquify):
            res = self._endpoint_request("POST", endpoint, json=records)
            posted.extend(get_records(res, errors.post_error))
        return posted

    def put(
            self,
            *records: HatRecord,
            uniquify: Optional[bool] = None
    ) -> HatRecords:
        uniquify = self._uniquify if uniquify is None else uniquify
        put = self._prepare_put(records, uniquify)
        res = self._data_request("PUT", json=put)
        return get_records(res, errors.put_error)

    def delete(self, *records: str | HatRecord) -> None:
        delete = self._prepare_delete(records)
        res = self._data_request("DELETE", params=delete)
        get_records(res, errors.delete_error)

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
            records = _uniquify(*records, only_data=True) if unique else records
            yield endpoint, records

    def _prepare_put(self, records: IHatRecords, unique: bool) -> list[dict]:
        ns, pattern = self.namespace, self._pattern
        prepared = []
        for rec in require_endpoint(records):
            # The endpoint should include the namespace. HatRecords created
            # from responses will include the namespace. This is just a
            # convenience if wanting to create HatRecords manually.
            if pattern.match(e := rec.endpoint) is None:
                rec = HatRecord.copy(rec, update={"endpoint": f"{ns}/{e}"})
            rec = _uniquify(rec, only_data=False) if unique else rec.dict()
            prepared.append(rec)
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
