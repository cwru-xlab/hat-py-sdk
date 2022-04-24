from __future__ import annotations

import functools
import itertools
from typing import Sequence, Type
from urllib import parse

import keyring
import requests
from keyring.credentials import Credential
from requests import HTTPError, JSONDecodeError, Response

from hat.exceptions import *
from hat.models import Record


class HatClient:
    __slots__ = ("_credential", "_auth_token", "_session")

    def __init__(self, credential: Credential = None, username: str = None):
        self._set_credential(credential, username)
        self._session = requests.session()
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

    def get(self, endpoint: str) -> Sequence[Record]:
        response = self._session.get(
            url=self._endpoint_url(endpoint), headers=self._auth_header())
        return _get_records(response, HatGetException)

    def post(self, *records: Record) -> Sequence[Record]:
        posted = []
        by_dest = functools.partial(lambda record: record.endpoint)
        groups = itertools.groupby(sorted(records, key=by_dest), by_dest)
        for endpoint, records in groups:
            response = self._session.post(
                url=self._endpoint_url(endpoint),
                headers=self._auth_header(),
                json=[record.dict() for record in records])
            posted.extend(_get_records(response, HatPostException))
        return tuple(posted)

    def put(self, *records: Record) -> Sequence[Record]:
        response = self._session.put(
            url=self._base_url(),
            headers=self._auth_header(),
            json=[record.dict() for record in records])
        return _get_records(response, HatPutException)

    def delete(self, *records: Record) -> None:
        response = self._session.delete(
            url=self._base_url(),
            headers=self._auth_header(),
            params={"records": [record.record_id for record in records]})
        _get_content(response, HatDeleteException)

    def _endpoint_url(self, endpoint: str) -> str:
        return parse.urljoin(f"{self._base_url()}/", endpoint)

    def _base_url(self) -> str:
        return f"https://{self._credential.username}.hubat.net/api/v2.6/data"

    def _auth_header(self) -> dict:
        return {
            "Content-Type": "application/json",
            "x-auth-token": self._auth_token}

    def __repr__(self):
        return f"{self.__class__.__name__}({self._credential.username})"


def _get_records(response: Response, exception: Type) -> Sequence[Record]:
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
