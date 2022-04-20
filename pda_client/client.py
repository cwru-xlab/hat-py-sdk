from __future__ import annotations

import abc
from typing import Any, Type

import requests

CONTENT_TYPE = "application/json"


class PdaException(Exception):
    pass


class PdaAuthException(PdaException):
    pass


class PdaPostException(PdaException):
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
                "Accept": CONTENT_TYPE,
                "username": username,
                "password": password})
        auth_token = self._check_json(response, PdaAuthException)["accessToken"]
        self._auth_token = auth_token

    def get(self, endpoint: str) -> dict:
        self._check_auth()
        response = self._session.get(
            url=self._format_url(endpoint), headers=self._auth_header())
        return self._check_json(response, PdaGetException)

    def post(self, data: Any, endpoint: str) -> None:
        self._check_auth()
        response = self._session.post(
            url=self._format_url(endpoint),
            headers=self._auth_header(),
            data=data)
        self._check_json(response, PdaPostException)

    def _check_auth(self) -> None:
        if self._auth_token is None:
            self.authenticate()

    @staticmethod
    def _check_json(response: requests.Response, exception: Type) -> dict:
        if not response.ok:
            raise exception(response.reason)
        return response.json()

    def _format_url(self, endpoint: str) -> str:
        username = self.credentials.username()
        return f"https://{username}.hubat.net/api/v2.6/data/{endpoint}"

    def _auth_header(self) -> dict:
        return {"Content-Type": CONTENT_TYPE, "x-auth-token": self._auth_token}
