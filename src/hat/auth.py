import mimetypes
from typing import Mapping, Protocol

from keyring.credentials import Credential

from . import Token
from .base import HttpAuth

TOKEN_HEADER = "x-auth-token"


class SupportsHeaders(Protocol):
    headers: Mapping[str, str]


class TokenHttpAuth(HttpAuth):
    __slots__ = "_token"

    def __init__(self, token: Token):
        self._token = token

    @property
    def headers(self) -> Mapping[str, str]:
        return {TOKEN_HEADER: self._token.value}

    def on_response(self, response: SupportsHeaders) -> None:
        if TOKEN_HEADER in response.headers:
            self._token.value = response.headers[TOKEN_HEADER]


class CredentialHttpAuth(HttpAuth):
    __slots__ = "_credential",

    def __init__(self, credential: Credential):
        self._credential = credential

    @property
    def headers(self) -> Mapping[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password}
