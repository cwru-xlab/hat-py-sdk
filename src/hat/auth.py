from __future__ import annotations

import abc
import asyncio
import datetime
import mimetypes
import re
from typing import Optional, Type

import jwt
from aiohttp import ClientResponse
from asgiref import sync
from keyring.credentials import Credential
from pydantic import BaseModel, PositiveInt, StrictStr, constr

from base import HttpAuth
from . import errors, urls, utils
from .client import AsyncHttpClient
from .model import ApiConfig

JWT_PATTERN = re.compile(r"^(?:[\w-]*\.){2}[\w-]*$")
TOKEN_KEY = "accessToken"
TOKEN_HEADER = "x-auth-token"


class JwtToken(BaseModel):
    exp: PositiveInt
    iat: PositiveInt
    iss: constr(regex=r"^\w+\.hubat\.net$", strict=True)

    Config = ApiConfig

    @classmethod
    def decode(
        cls,
        encoded: str,
        *,
        pk: Optional[str] = None,
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
        except jwt.InvalidTokenError as e:
            raise errors.AuthError(e)
        return payload if not as_token else JwtToken(**payload)


class JwtOwnerToken(JwtToken):
    access_scope: constr(regex="^owner$", strict=True)

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> JwtOwnerToken:
        kwargs["as_token"] = False
        return JwtOwnerToken(**super().decode(encoded, **kwargs))


class JwtAppToken(JwtToken):
    application: StrictStr
    application_version: constr(regex=r"^\d+.\d+.\d+$", strict=True)

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> JwtAppToken:
        kwargs["as_token"] = False
        return JwtAppToken(**super().decode(encoded, **kwargs))


class BaseApiToken(abc.ABC):
    __slots__ = (
        "_auth",
        "_jwt_type",
        "_value",
        "_decoded",
        "_pk",
        "_ttl",
        "_domain",
        "_expires",
    )

    def __init__(self, auth: HttpAuth, jwt_type: Type[JwtToken]) -> None:
        self._auth = auth
        self._jwt_type = jwt_type
        self._value: Optional[str] = None
        self._decoded: Optional[JwtToken] = None
        self._pk: Optional[str] = None
        self._ttl = datetime.timedelta(days=3)
        self._domain: Optional[str] = None
        self._expires = datetime.datetime.max

    @abc.abstractmethod
    def pk(self) -> str:
        pass

    @abc.abstractmethod
    def value(self) -> str:
        pass

    @abc.abstractmethod
    def set_value(self, value: str) -> None:
        pass

    @abc.abstractmethod
    def domain(self) -> str:
        pass

    @abc.abstractmethod
    def url(self) -> str:
        pass

    @abc.abstractmethod
    def decode(self, *, verify: bool = True) -> JwtToken:
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


class AsyncApiToken(BaseApiToken, abc.ABC):
    __slots__ = "_client"

    def __init__(
        self, client: AsyncHttpClient, auth: HttpAuth, jwt_type: Type[JwtToken]
    ) -> None:
        super().__init__(auth, jwt_type)
        self._client = client

    async def pk(self) -> str:
        if self._pk is None:
            url = urls.domain_public_key(await self.domain())
            self._pk = await self._client.request("GET", url, self._auth)
        return self._pk

    async def value(self) -> str:
        if self._value is None or self.expired:
            token = await self._client.request("GET", self.url(), self._auth)
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


class AsyncCredentialOwnerToken(AsyncApiToken):
    __slots__ = "_url"

    def __init__(self, client: AsyncHttpClient, credential: Credential) -> None:
        super().__init__(client, CredentialAuth(credential), JwtOwnerToken)
        self._url = urls.username_owner_token(credential.username)

    def url(self) -> str:
        return self._url


class AsyncAppToken(AsyncApiToken):
    __slots__ = "_owner_token", "_app_id", "_url"

    def __init__(
        self,
        client: AsyncHttpClient,
        owner_token: AsyncCredentialOwnerToken,
        app_id: str,
    ) -> None:
        super().__init__(client, AsyncTokenAuth(owner_token), JwtAppToken)
        self._owner_token = owner_token
        self._app_id = app_id
        self._url: Optional[str] = None

    async def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return await self._owner_token.domain()

    async def url(self) -> str:
        if self._url is None:
            self._url = urls.domain_app_token(await self.domain(), self._app_id)
        return self._url


class ApiToken(BaseApiToken):
    __slots__ = "_wrapped"

    def __init__(self, wrapped: AsyncApiToken) -> None:
        super().__init__(wrapped._auth, wrapped._jwt_type)
        self._wrapped = wrapped

    def pk(self) -> str:
        return sync.async_to_sync(self._wrapped.pk)()

    def value(self) -> str:
        return sync.async_to_sync(self._wrapped.value)()

    def set_value(self, value: str) -> None:
        return sync.async_to_sync(self._wrapped.set_value)(value)

    def domain(self) -> str:
        return sync.async_to_sync(self._wrapped.domain)()

    def url(self) -> str:
        return sync.async_to_sync(self._wrapped.url)()

    def decode(self, *, verify: bool = True) -> JwtToken:
        return sync.async_to_sync(self._wrapped.decode)(verify=verify)


CredentialOwnerToken = ApiToken
AppToken = ApiToken


class AsyncWebOwnerToken(AsyncApiToken, abc.ABC):  # TODO
    pass


class WebOwnerToken(BaseApiToken, abc.ABC):  # TODO
    pass


class AsyncTokenAuth(HttpAuth):
    __slots__ = "_token"

    def __init__(self, token: AsyncApiToken):
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

    def headers(self) -> dict[str, str]:
        return {
            "Accept": mimetypes.types_map[".json"],
            "username": self._credential.username,
            "password": self._credential.password,
        }
