from __future__ import annotations

import abc
import asyncio
import datetime
import mimetypes
import re
from typing import Any

import jwt
from aiohttp import ClientResponse
from keyring.credentials import Credential
from pydantic import BaseModel
from pydantic import PositiveInt
from pydantic import StrictStr
from pydantic import constr

from . import errors
from . import urls
from . import utils
from .http import HttpClient
from .model import ApiConfig


JWT_PATTERN = re.compile(r"^(?:[\w-]*\.){2}[\w-]*$")
TOKEN_KEY = "accessToken"
TOKEN_HEADER = "x-auth-token"


class JwtToken(BaseModel):
    exp: PositiveInt
    iat: PositiveInt
    iss: constr(regex=r"^\w+\.hubat\.net$", strict=True)  # noqa: F722

    Config = ApiConfig

    @classmethod
    def decode(
        cls,
        encoded: str,
        *,
        pk: str | None = None,
        verify: bool = False,
        as_token: bool = False,
    ) -> dict | JwtToken:
        if verify and pk is None:
            raise ValueError("'pk' is required if 'verify' is True")
        if JWT_PATTERN.match(encoded) is None:
            raise ValueError(f"'encoded' has improper syntax:\n{encoded}")
        try:
            payload = jwt.decode(
                jwt=encoded,
                key=pk,
                algorithms=["RS256"],
                options={"verify_signature": verify},
            )
        except jwt.InvalidTokenError as error:
            raise errors.AuthError() from error
        return payload if not as_token else JwtToken(**payload)


class JwtOwnerToken(JwtToken):
    access_scope: constr(regex="^owner$", strict=True)  # noqa: F722

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> JwtOwnerToken:
        kwargs["as_token"] = False
        return JwtOwnerToken(**super().decode(encoded, **kwargs))


class JwtAppToken(JwtToken):
    application: StrictStr
    application_version: constr(regex=r"^\d+.\d+.\d+$", strict=True)  # noqa: F722

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> JwtAppToken:
        kwargs["as_token"] = False
        return JwtAppToken(**super().decode(encoded, **kwargs))


class ApiToken(abc.ABC):
    __slots__ = (
        "_client",
        "_auth",
        "_jwt_type",
        "_value",
        "_decoded",
        "_pk",
        "_ttl",
        "_domain",
        "_expires",
    )

    def __init__(
        self, client: HttpClient, auth: HttpAuth, jwt_type: type[JwtToken]
    ) -> None:
        self._client = client
        self._auth = auth
        self._jwt_type = jwt_type
        self._value: str | None = None
        self._decoded: JwtToken | None = None
        self._pk: str | None = None
        self._ttl = datetime.timedelta(days=3)
        self._domain: str | None = None
        self._expires = datetime.datetime.max

    async def pk(self) -> str:
        if self._pk is None:
            url = urls.domain_public_key(await self.domain())
            self._pk = await self._client.request("GET", url, self._auth)
        return self._pk

    async def value(self) -> str:
        if self._value is None or self.expired:
            token = await self._client.request("GET", await self.url(), self._auth)
            await self.set_value(token)
        return self._value

    async def set_value(self, value: str) -> None:
        if self._value != value:
            self._value = value
            self._decoded = await self.decode(verify=True)
            self._expires = self._compute_expiration()

    async def domain(self) -> str:
        if self._domain is None:
            token = await self.decode(verify=False)
            self._domain = urls.with_scheme(token.iss)
        return self._domain

    async def decode(self, *, verify: bool = True) -> JwtToken:
        if verify:
            value, pk = await asyncio.gather(self.value(), self.pk())
        else:
            value, pk = await self.value(), None
        return self._jwt_type.decode(value, pk=pk, verify=verify)

    @abc.abstractmethod
    async def url(self) -> str:
        pass

    @property
    def expired(self) -> bool:
        return self._expires <= datetime.datetime.utcnow()

    def _compute_expiration(self) -> datetime.datetime:
        iat = datetime.datetime.utcfromtimestamp(float(self._decoded.iat))
        exp = datetime.datetime.utcfromtimestamp(float(self._decoded.exp))
        return min(iat + self._ttl, exp)

    def __repr__(self) -> str:
        return utils.to_str(
            self, domain=self._domain, expired=self.expired, expires=self._expires
        )


class CredentialOwnerToken(ApiToken):
    __slots__ = "_url"

    def __init__(self, client: HttpClient, credential: Credential) -> None:
        super().__init__(client, CredentialAuth(credential), JwtOwnerToken)
        self._url = urls.username_owner_token(credential.username)

    def url(self) -> str:
        return self._url


class AppToken(ApiToken):
    __slots__ = "_owner_token", "_app_id", "_url"

    def __init__(
        self,
        client: HttpClient,
        owner_token: CredentialOwnerToken,
        app_id: str,
    ) -> None:
        super().__init__(client, TokenAuth(owner_token), JwtAppToken)
        self._owner_token = owner_token
        self._app_id = app_id
        self._url: str | None = None

    async def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return await self._owner_token.domain()

    async def url(self) -> str:
        if self._url is None:
            self._url = urls.domain_app_token(await self.domain(), self._app_id)
        return self._url


class WebOwnerToken(ApiToken, abc.ABC):  # TODO
    pass


class HttpAuth:
    __slots__ = ()

    async def headers(self) -> dict[str, str]:
        return {}

    async def on_response(self, response: Any) -> None:
        pass


class TokenAuth(HttpAuth):
    __slots__ = "_token"

    def __init__(self, token: ApiToken):
        self._token = token

    async def headers(self) -> dict[str, str]:
        return {TOKEN_HEADER: await self._token.value()}

    async def on_response(self, response: ClientResponse) -> None:
        if TOKEN_HEADER in response.headers:
            await self._token.set_value(response.headers[TOKEN_HEADER])


class CredentialAuth(HttpAuth):
    __slots__ = ("_credential",)

    def __init__(self, credential: Credential):
        self._credential = credential

    async def headers(self) -> dict[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password,
        }
