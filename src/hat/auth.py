import mimetypes
from typing import Protocol

from keyring.credentials import Credential

from base import HttpAuth

TOKEN_HEADER = "x-auth-token"


class SupportsHeaders(Protocol):
    headers: dict[str, str]


class TokenAuth(HttpAuth):
    __slots__ = "_token"

    def __init__(self, token):  # TODO Add type hint
        self._token = token

    @property
    def headers(self) -> dict[str, str]:
        return {TOKEN_HEADER: self._token.value}

    def on_response(self, response: SupportsHeaders) -> None:
        if TOKEN_HEADER in response.headers:
            self._token.value = response.headers[TOKEN_HEADER]


class AsyncTokenAuth(TokenAuth):

    def __init__(self, token):  # TODO Add type hint
        super().__init__(token)

    @property
    async def headers(self) -> dict[str, str]:
        return {TOKEN_HEADER: await self._token.value}


class CredentialAuth(HttpAuth):
    __slots__ = "_credential",

    def __init__(self, credential: Credential):
        self._credential = credential

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password}
