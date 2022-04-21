from __future__ import annotations

from typing import Sequence, Type
from urllib import parse

import keyring
import requests
from keyring.credentials import Credential
from requests import HTTPError, JSONDecodeError, Response

from pda_client.exceptions import *
from pda_client.models import PdaRecord


class PdaClient:
    __slots__ = ("_credential", "_auth_token", "_session")

    def __init__(self, credential: Credential = None, username: str = None):
        self._set_credential(credential, username)
        self._session = requests.session()
        self._auth_token = None
        self.authenticate()

    def _set_credential(
            self, credential: Credential | None, username: str | None) -> None:
        if credential is None:
            credential = keyring.get_credential("pda-client", username)
            if credential is None:
                raise PdaCredentialException(
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
        auth_token = _get_content(response, PdaAuthException)["accessToken"]
        self._auth_token = auth_token

    def get(self, endpoint: str) -> Sequence[PdaRecord]:
        response = self._session.get(
            url=self._format_url(endpoint), headers=self._auth_header())
        return _get_records(response, PdaGetException)

    def post(self, *records: PdaRecord) -> Sequence[PdaRecord]:
        posted = []
        for record in records:
            response = self._session.post(
                url=self._format_url(record.endpoint),
                headers=self._auth_header(),
                json=record.data)
            posted.extend(_get_records(response, PdaPostException))
        return tuple(posted)

    def put(self, *records: PdaRecord) -> Sequence[PdaRecord]:
        response = self._session.put(
            url=self._format_url(),
            headers=self._auth_header(),
            json=[record.dict() for record in records])
        return _get_records(response, PdaPutException)

    def _format_url(self, endpoint: str = None) -> str:
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


def _get_records(response: Response, exception: Type) -> Sequence[PdaRecord]:
    content = _get_content(response, exception)
    if isinstance(content, Sequence):
        records = tuple(PdaRecord(**record) for record in content)
    else:
        records = (PdaRecord(**content),)
    return records


def _get_content(response: Response, exception: Type) -> dict | list:
    try:
        response.raise_for_status()
        return response.json()
    except (HTTPError, JSONDecodeError) as error:
        raise exception(error)
