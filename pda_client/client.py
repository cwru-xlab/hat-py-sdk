from __future__ import annotations

from typing import Any, Optional, Sequence, Type
from urllib import parse

import keyring
import requests
from keyring.credentials import Credential
from requests import Response

from pda_client.models import PdaRecord


class PdaException(Exception):
    pass


class PdaCredentialException(PdaException):
    pass


class PdaAuthException(PdaException):
    pass


class PdaPostException(PdaException):
    pass


class PdaPutException(PdaException):
    pass


class PdaGetException(PdaException):
    pass


class PdaClient:
    __slots__ = ("_credential", "_auth_token", "_session")

    def __init__(self, credential: Credential = None, username: str = None):
        if credential is None:
            self._credential = self._get_credential(username)
        else:
            self._credential = credential
        self._auth_token = None
        self._session = requests.session()

    @staticmethod
    def _get_credential(username: Optional[str]) -> Credential:
        credential = keyring.get_credential("pda-client", username)
        if credential is None:
            raise PdaCredentialException(
                f"Unable to obtain PDA client credential for user {username}")
        return credential

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
        auth_token = self._check_json(response, PdaAuthException)["accessToken"]
        self._auth_token = auth_token

    def get(self, endpoint: str) -> Sequence[PdaRecord]:
        self._check_auth()
        response = self._session.get(
            url=self._format_url(endpoint), headers=self._auth_header())
        response = self._check_json(response, PdaGetException)
        return tuple(PdaRecord(**record) for record in response)

    def post(self, data: Any, endpoint: str) -> Sequence[PdaRecord]:
        self._check_auth()
        response = self._session.post(
            url=self._format_url(endpoint),
            headers=self._auth_header(),
            json=data)
        response = self._check_json(response, PdaPostException)
        return tuple(PdaRecord(**record) for record in response)

    def put(self, *records: PdaRecord) -> Sequence[PdaRecord]:
        self._check_auth()
        response = self._session.put(
            url=self._format_url(),
            headers=self._auth_header(),
            json=records)
        response = self._check_json(response, PdaPutException)
        return tuple(PdaRecord(**record) for record in response)

    def _check_auth(self) -> None:
        if self._auth_token is None:
            self.authenticate()

    @staticmethod
    def _check_json(response: Response, exception: Type) -> dict | list:
        if not response.ok:
            raise exception(f"{response.status_code}: {response.reason}")
        return response.json()

    def _format_url(self, endpoint: str = None) -> str:
        username = self._credential.username
        base = f"https://{username}.hubat.net/api/v2.6/data"
        return parse.urljoin(base, endpoint)

    def _auth_header(self) -> dict:
        return {
            "Content-Type": "application/json",
            "x-auth-token": self._auth_token}
