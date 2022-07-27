from __future__ import annotations

import functools
import itertools
import re
from typing import Callable, Iterable, Sequence

from requests import Response

from . import errors, urls, utils
from .models import GetOpts, HatRecord
from .tokens import Token
from .utils import OnError

HatRecords = list[HatRecord]
IHatRecords = Iterable[HatRecord]


def group_by_endpoint(records: IHatRecords) -> Iterable[tuple[str, HatRecords]]:
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
    __slots__ = "_token", "_namespace", "_pattern"

    def __init__(
            self,
            token: Token,
            namespace: str | None = None,
            share_session: bool = True,
            **kwargs):
        super().__init__(token._session if share_session else None, **kwargs)
        self._token = token
        self._namespace = namespace
        self._pattern = re.compile(f"^{namespace}/")

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
        get = self._prepare_get(endpoints)
        options = None if options is None else options.dict()
        headers = self._auth_header()
        got = []
        for endpoint in get:
            response = self._session.get(
                url=self._endpoint_url(endpoint), headers=headers, json=options)
            got.extend(get_records(response, errors.get_error))
        return got

    @requires_namespace
    def post(self, *records: HatRecord) -> HatRecords:
        post = self._prepare_post(records)
        headers = self._auth_header()
        posted = []
        for endpoint, records in group_by_endpoint(records):
            response = self._session.post(
                url=self._endpoint_url(endpoint), headers=headers, json=post)
            posted.extend(get_records(response, errors.post_error))
        return posted

    def put(self, *records: HatRecord) -> HatRecords:
        put = self._prepare_put(records)
        response = self._session.put(
            url=self._data_url(), headers=self._auth_header(), json=put)
        return get_records(response, errors.put_error)

    def delete(self, *records: str | HatRecord) -> None:
        delete = self._prepare_delete(records)
        response = self._session.delete(
            url=self._data_url(),
            headers=self._auth_header(),
            params={"records": delete})
        get_records(response, errors.delete_error)

    @staticmethod
    def _prepare_get(records: Iterable[str | HatRecord]) -> list[str]:
        return [
            rec if isinstance(rec, str) else rec.endpoint
            for rec in require_endpoint(records)]

    def _prepare_post(self, records: IHatRecords) -> list:
        pattern = self._pattern
        prepared = []
        for rec in require_endpoint(records):
            # The namespace is added when constructing the endpoint URL,
            # so it should not be a part of the endpoint here.
            if pattern.match(rec.endpoint):
                endpoint = pattern.split(rec.endpoint)[-1]
                rec = HatRecord.copy(rec, update={"endpoint": endpoint})
            prepared.append(rec.data)
        return prepared

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
    def _prepare_delete(records: Iterable[str | HatRecord]) -> list[str]:
        return [
            rec if isinstance(rec, str) else rec.record_id
            for rec in require_record_id(records)]

    def _auth_header(self) -> dict[str, str]:
        return utils.token_header(self.token.value)

    def _data_url(self) -> str:
        return urls.domain_data(self.token.domain)

    def _endpoint_url(self, endpoint: str) -> str:
        return urls.domain_endpoint(self.token.domain, self.namespace, endpoint)
