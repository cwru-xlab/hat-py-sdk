from __future__ import annotations

import abc
import datetime
import mimetypes
import re

import jwt
from aiohttp import ClientResponse
from keyring.credentials import Credential
from pydantic import BaseModel
from pydantic import PositiveInt
from pydantic import StrictStr
from pydantic import constr

from . import AsyncHttpClient
from . import errors
from . import urls
from . import utils
from .base import HttpAuth
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
        "_http",
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
        self, http_client: AsyncHttpClient, auth: HttpAuth, jwt_type: type[JwtToken]
    ) -> None:
        self._http = http_client
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
            domain = await self.domain()
            url = urls.domain_pk(domain)
            self._pk = await self._get(url)
        return self._pk

    async def value(self) -> str:
        if self._value is None or self.expired:
            url = await self.url()
            token = await self._get(url)
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
        value = await self.value()
        pk = await self.pk() if verify else None
        return self._jwt_type.decode(value, pk=pk, verify=verify)

    @abc.abstractmethod
    async def url(self) -> str:
        pass

    @property
    def expired(self) -> bool:
        return self._expires <= datetime.datetime.utcnow()

    async def _get(self, url: str) -> str:
        return await self._http.request("GET", url, auth=self._auth)

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

    def __init__(self, http_client: AsyncHttpClient, credential: Credential) -> None:
        super().__init__(http_client, AsyncCredentialAuth(credential), JwtOwnerToken)
        self._url = urls.username_owner_token(credential.username)

    async def url(self) -> str:
        return self._url


class AppToken(ApiToken):
    __slots__ = "_owner_token", "_app_id", "_url"

    def __init__(
        self,
        client: AsyncHttpClient,
        owner_token: CredentialOwnerToken,
        app_id: str,
    ) -> None:
        super().__init__(client, AsyncTokenAuth(owner_token), JwtAppToken)
        self._owner_token = owner_token
        self._app_id = app_id
        self._url: str | None = None

    async def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return await self._owner_token.domain()

    async def url(self) -> str:
        if self._url is None:
            domain = await self.domain()
            self._url = urls.domain_app_token(domain, self._app_id)
        return self._url


class WebOwnerToken(ApiToken, abc.ABC):  # TODO
    pass


class AsyncTokenAuth(HttpAuth):
    __slots__ = "_token"

    def __init__(self, token: ApiToken):
        self._token = token

    async def headers(self) -> dict[str, str]:
        return {TOKEN_HEADER: await self._token.value()}

    async def on_response(self, response: ClientResponse) -> None:
        if TOKEN_HEADER in response.headers:
            await self._token.set_value(response.headers[TOKEN_HEADER])


class AsyncCredentialAuth(HttpAuth):
    __slots__ = ("_credential",)

    def __init__(self, credential: Credential):
        self._credential = credential

    async def headers(self) -> dict[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password,
        }
