from __future__ import annotations

import functools
import itertools
from typing import Iterable, Sequence

from requests import Response

from utils import OnError
from . import errors, urls, utils
from .models import GetOpts, HatRecord
from .tokens import Token

HatRecords = list[HatRecord]


def _group_by_endpoint(*records: HatRecord) -> Iterable[tuple[str, HatRecords]]:
    by_endpoint = functools.partial(lambda r: r.endpoint)
    return itertools.groupby(sorted(records, key=by_endpoint), by_endpoint)


def _get_records(response: Response, on_error: OnError) -> HatRecords:
    content = utils.get_json(response, on_error)
    if isinstance(content, Sequence):
        records = [HatRecord(**record) for record in content]
    else:
        records = [HatRecord(**content)]
    return records


class HatClient(utils.SessionMixin):
    __slots__ = "token", "namespace"

    def __init__(self, token: Token, namespace: str | None = None):
        super().__init__(token._session)
        token._session.stream = True  # Avoid downloading when an error occurs.
        self.token = token
        self.namespace = namespace

    def get(
            self,
            *endpoints: str | HatRecord,
            options: GetOpts | None = None
    ) -> HatRecords:
        endpoints = [e if isinstance(e, str) else e.endpoint for e in endpoints]
        options = None if options is None else options.dict()
        headers = self._auth_header()
        got = []
        for endpoint in endpoints:
            url = self._endpoint_url(endpoint)
            response = self._session.get(url=url, headers=headers, json=options)
            got.extend(_get_records(response, errors.get_error))
        return got

    def post(self, *records: HatRecord) -> HatRecords:
        posted = []
        headers = self._auth_header()
        for endpoint, records in _group_by_endpoint(*records):
            response = self._session.post(
                url=self._endpoint_url(endpoint),
                headers=headers,
                json=[r.data for r in records])
            posted.extend(_get_records(response, errors.post_error))
        return posted

    def put(self, *records: HatRecord) -> HatRecords:
        put = [r.dict() for r in records]
        response = self._session.put(
            url=self._data_url(), headers=self._auth_header(), json=put)
        return _get_records(response, errors.put_error)

    def delete(self, *records: str | HatRecord) -> None:
        records = [r if isinstance(r, str) else r.record_id for r in records]
        response = self._session.delete(
            url=self._data_url(),
            headers=self._auth_header(),
            params={"records": records})
        _get_records(response, errors.delete_error)

    def _auth_header(self) -> dict[str, str]:
        return utils.token_header(self.token.value)

    def _data_url(self) -> str:
        return urls.domain_data(self.token.domain)

    def _endpoint_url(self, endpoint: str) -> str:
        if self.namespace is None:
            raise ValueError("'namespace' must be set to access endpoint data")
        return urls.domain_endpoint(
            self.token.domain, self.namespace, endpoint)
