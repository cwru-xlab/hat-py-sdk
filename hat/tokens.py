from __future__ import annotations

import abc
import datetime
import re
from typing import Optional

import jwt
import pydantic
from humps import camel
from keyring.credentials import Credential
from pydantic import PositiveInt, StrictStr, constr

from . import errors, urls, utils

_JWT_PATTERN = re.compile("^(?:[\w-]*\.){2}[\w-]*$")


class JwtToken(pydantic.BaseModel):
    exp: PositiveInt
    iat: PositiveInt
    iss: constr(regex="[a-zA-Z0-9]+.hubat.net", strict=True)

    class Config:
        allow_population_by_field_name = True
        alias_generator = camel.case
        frozen = True

    @classmethod
    def decode(
            cls,
            encoded: str,
            *,
            pk: str | None = None,
            verify_sig: bool = False,
            as_token: bool = False
    ) -> dict | JwtToken:
        if verify_sig and pk is None:
            raise ValueError("'pk' is required if 'verify_sig' is True")
        if _JWT_PATTERN.fullmatch(encoded) is None:
            raise ValueError(f"'encoded' has improper syntax:\n{encoded}")
        try:
            payload = jwt.decode(
                jwt=encoded,
                key=pk,
                algorithms=["RS256"],
                options={"verify_signature": verify_sig})
        except jwt.InvalidTokenError as e:
            raise errors.AuthError(e)
        return payload if not as_token else JwtToken(**payload)


class JwtOwnerToken(JwtToken):
    access_scope: constr(regex="owner", strict=True)

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> JwtOwnerToken:
        kwargs["as_token"] = False
        return JwtOwnerToken(**super().decode(encoded, **kwargs))


class JwtAppToken(JwtToken):
    application: StrictStr
    application_version: constr(regex="[0-9]+.[0-9]+.[0-9]+", strict=True)

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> JwtAppToken:
        kwargs["as_token"] = False
        return JwtAppToken(**super().decode(encoded, **kwargs))


class Token(abc.ABC, utils.SessionMixin):
    __slots__ = "_value", "_decoded", "_pk", "_ttl", "_expires_at"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._value: Optional[str] = None
        self._decoded: Optional[JwtToken] = None
        self._pk: Optional[str] = None
        self._ttl = datetime.timedelta(days=3)
        self._expires_at = datetime.datetime.max

    @property
    def pk(self):
        if self._pk is None:
            url = urls.domain_public_key(self.domain)
            response = self._session.get(url)
            self._pk = utils.get_string(response, errors.auth_error)
        return self._pk

    @property
    def value(self) -> str:
        if self._value is None or self.expired:
            self.refresh()
        return self._value

    @property
    @abc.abstractmethod
    def domain(self) -> str:
        pass

    @abc.abstractmethod
    def refresh(self) -> None:
        pass

    @property
    def expired(self) -> bool:
        return self._expires_at <= datetime.datetime.utcnow()

    def _compute_expiration(self) -> datetime:
        if self._decoded is None:
            self.refresh()
        iat = datetime.datetime.utcfromtimestamp(float(self._decoded.iat))
        exp = datetime.datetime.utcfromtimestamp(float(self._decoded.exp))
        return min(iat + self._ttl, exp)


class OwnerToken(Token, abc.ABC):
    __slots__ = "_domain"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._domain: Optional[str] = None

    @property
    def domain(self) -> str:
        if self._domain is None:
            token = JwtOwnerToken.decode(self.value, verify_sig=False)
            self._domain = urls.with_scheme(token.iss)
        return self._domain


class ApiOwnerToken(OwnerToken):
    __slots__ = "_credential"

    def __init__(self, credential: Credential, **kwargs):
        super().__init__(**kwargs)
        self._credential = credential

    def refresh(self) -> None:
        username = self.credential.username
        response = self._session.get(
            url=urls.username_owner_token(username),
            headers={
                "Accept": utils.JSON_MIMETYPE,
                "username": username,
                "password": self.credential.password})
        self._value = utils.get_json(response, errors.auth_error)["accessToken"]
        self._decoded = JwtOwnerToken.decode(
            self._value, pk=self.pk, verify_sig=True)
        self._expires_at = self._compute_expiration()

    @property
    def credential(self) -> Credential:
        return self._credential


class AppToken(Token):
    __slots__ = "_owner_token", "_appname"

    def __init__(
            self,
            owner_token: OwnerToken,
            appname: str,
            **kwargs):
        super().__init__(**kwargs)
        self._owner_token = owner_token
        self._appname = appname

    @property
    def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return self._owner_token.domain

    def refresh(self) -> None:
        response = self._session.get(
            url=urls.domain_app_token(self.domain, self.appname),
            headers=utils.token_header(self._owner_token.value))
        self._value = utils.get_json(response, errors.auth_error)["accessToken"]
        self._decoded = JwtAppToken.decode(
            self._value, pk=self.pk, verify_sig=True)
        self._expires_at = self._compute_expiration()

    @property
    def appname(self) -> str:
        return self._appname


class WebOwnerToken(OwnerToken):  # TODO

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def refresh(self) -> None:
        pass
