from __future__ import annotations

from urllib import parse

import functools
import itertools
import keyring
import requests
from keyring.credentials import Credential
from requests import HTTPError, JSONDecodeError, Response, Session
from typing import Iterable, Sequence, Type, overload

from .exceptions import *
from .models import GetParams, Record

Records = Sequence[Record]


def _group_by_endpoint(*records: Record) -> Iterable[tuple[str, Records]]:
    by_endpoint = functools.partial(lambda r: r.endpoint)
    return itertools.groupby(sorted(records, key=by_endpoint), by_endpoint)


def _get_records(response: Response, exception: Type) -> Records:
    content = _get_content(response, exception)
    if isinstance(content, Sequence):
        records = tuple(Record(**record) for record in content)
    else:
        records = (Record(**content),)
    return records


def _get_content(response: Response, exception: Type) -> dict | list:
    try:
        response.raise_for_status()
        return response.json()
    except (HTTPError, JSONDecodeError) as error:
        raise exception(error)


class HatClient:
    __slots__ = ("_credential", "_auth_token", "_session")

    def __init__(
            self,
            credential: Credential | None = None,
            username: str | None = None,
            session: Session | None = None):
        self._set_credential(credential, username)
        self._session = session or requests.session()
        self._auth_token = None
        self.authenticate()

    def _set_credential(
            self, credential: Credential | None, username: str | None) -> None:
        if credential is None:
            credential = keyring.get_credential("hat-client", username)
            if credential is None:
                raise HatCredentialException(
                    f"Unable to obtain credential for user {username}")
        self._credential = credential

    def close(self):
        self._session.close()

    def authenticate(self) -> None:
        username = self._credential.username
        password = self._credential.password
        response = self._session.get(
            url=f"https://{username}.hubat.net/users/access_token",
            headers={
                "Accept": "application/json",
                "username": username,
                "password": password})
        auth_token = _get_content(response, HatAuthException)["accessToken"]
        self._auth_token = auth_token

    @overload
    def get(self, *endpoints: str, params: GetParams = None) -> Records:
        pass

    @overload
    def get(self, *endpoints: Record, params: GetParams = None) -> Records:
        pass

    def get(
            self,
            *endpoints: str | Record,
            params: GetParams | None = None
    ) -> Records:
        got = []
        if isinstance(endpoints[0], Record):
            endpoints = (r.endpoint for r in endpoints)
        headers = self._auth_header()
        params = None if params is None else params.dict()
        for endpoint in set(endpoints):
            response = self._session.get(
                url=self._format_url(endpoint), headers=headers, json=params)
            got.extend(_get_records(response, HatGetException))
        return tuple(got)

    def post(self, *records: Record) -> Records:
        posted = []
        headers = self._auth_header()
        for endpoint, records in _group_by_endpoint(*records):
            response = self._session.post(
                url=self._format_url(endpoint),
                headers=headers,
                json=[r.data for r in records])
            posted.extend(_get_records(response, HatPostException))
        return tuple(posted)

    def put(self, *records: Record) -> Records:
        response = self._session.put(
            url=self._format_url(),
            headers=self._auth_header(),
            json=[r.dict() for r in records])
        return _get_records(response, HatPutException)

    @overload
    def delete(self, *records: Record) -> None:
        pass

    @overload
    def delete(self, *records: str) -> None:
        pass

    def delete(self, *records: str | Record) -> None:
        if isinstance(records[0], Record):
            records = [r.record_id for r in records]
        response = self._session.delete(
            url=self._format_url(),
            headers=self._auth_header(),
            params={"records": records})
        _get_content(response, HatDeleteException)

    def _format_url(self, endpoint: str | None = None) -> str:
        url = f"https://{self._credential.username}.hubat.net/api/v2.6/data"
        if endpoint is not None:
            url = parse.urljoin(f"{url}/", endpoint)
        return url

    def _auth_header(self) -> dict:
        return {
            "Content-Type": "application/json",
            "x-auth-token": self._auth_token}

    def __repr__(self):
        return f"{self.__class__.__name__}({self._credential.username})"
