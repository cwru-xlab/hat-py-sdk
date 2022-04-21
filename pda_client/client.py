from __future__ import annotations

import abc
from typing import Any, Sequence, Type
from urllib import parse

import requests
from requests import Response

from pda_client.models import PdaRecord


class PdaException(Exception):
    pass


class PdaAuthException(PdaException):
    pass


class PdaPostException(PdaException):
    pass


class PdaPutException(PdaException):
    pass


class PdaGetException(PdaException):
    pass


class PdaCredentials(abc.ABC):
    __slots__ = ()

    def __init__(self):
        pass

    @abc.abstractmethod
    def username(self) -> str:
        pass

    @abc.abstractmethod
    def password(self) -> str:
        pass


class StaticPdaCredentials(PdaCredentials):
    __slots__ = ("_username", "_password")

    def __init__(self, username: str, password: str):
        super().__init__()
        self._username = username
        self._password = password

    def username(self) -> str:
        return self._username

    def password(self) -> str:
        return self._password


class PdaClient:
    __slots__ = ("credentials", "_auth_token", "_session")

    def __init__(self, credentials: PdaCredentials):
        self.credentials = credentials
        self._auth_token = None
        self._session = requests.session()

    def close(self):
        self._session.close()

    def authenticate(self) -> None:
        username = self.credentials.username()
        password = self.credentials.password()
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
        username = self.credentials.username()
        base = f"https://{username}.hubat.net/api/v2.6/data"
        return parse.urljoin(base, endpoint)

    def _auth_header(self) -> dict:
        return {
            "Content-Type": "application/json",
            "x-auth-token": self._auth_token}
