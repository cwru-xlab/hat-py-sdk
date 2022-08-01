from __future__ import annotations

import abc
import datetime
import re
from typing import Optional

import jwt
from keyring.credentials import Credential
from pydantic import PositiveInt, StrictStr, constr
from requests import PreparedRequest, Response, auth

from . import errors, models, urls, utils

JWT_PATTERN = re.compile(r"^(?:[\w-]*\.){2}[\w-]*$")


class JwtToken(models.HatModel):
    exp: PositiveInt
    iat: PositiveInt
    iss: constr(regex=r"^\w+\.hubat\.net$", strict=True)

    @classmethod
    def decode(
            cls,
            encoded: str,
            *,
            pk: str | None = None,
            verify: bool = False,
            as_token: bool = False
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
                options={"verify_signature": verify})
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


class Token(utils.SessionMixin, abc.ABC):
    __slots__ = "_value", "_decoded", "_pk", "_ttl", "_domain", "_expires"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._value: Optional[str] = None
        self._decoded: Optional[JwtToken] = None
        self._pk: Optional[str] = None
        self._ttl = datetime.timedelta(days=3)
        self._domain: Optional[str] = None
        self._expires = datetime.datetime.max

    @property
    def pk(self) -> str:
        if self._pk is None:
            url = urls.domain_public_key(self.domain)
            res = self._session.get(url)
            self._pk = utils.get_string(res, errors.auth_error)
        return self._pk

    @property
    def value(self) -> str:
        if self._value is None or self.expired:
            self.refresh()
        return self._value

    @value.setter
    def value(self, val: str) -> None:
        if self._value != val:
            self._value = val
            self._decoded = self._decode(verify=True)
            self._expires = self._compute_expiration()

    @property
    def domain(self) -> str:
        if self._domain is None:
            token = self._decode(verify=False)
            self._domain = urls.with_scheme(token.iss)
        return self._domain

    @property
    def expired(self) -> bool:
        return self._expires <= datetime.datetime.utcnow()

    @abc.abstractmethod
    def refresh(self) -> None:
        pass

    @abc.abstractmethod
    def _decode(self, *, verify: bool = True) -> JwtToken:
        pass

    def _compute_expiration(self) -> datetime.datetime:
        iat = datetime.datetime.utcfromtimestamp(float(self._decoded.iat))
        exp = datetime.datetime.utcfromtimestamp(float(self._decoded.exp))
        return min(iat + self._ttl, exp)

    def __repr__(self) -> str:
        return utils.to_string(self, domain=self._domain, expires=self._expires)


class OwnerToken(Token, abc.ABC):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _decode(self, *, verify: bool = True) -> JwtToken:
        return JwtOwnerToken.decode(
            self.value, pk=self.pk if verify else None, verify=verify)


class ApiOwnerToken(OwnerToken):
    __slots__ = "_credential"

    def __init__(self, credential: Credential, **kwargs):
        super().__init__(**kwargs)
        self._credential = credential

    def refresh(self) -> None:
        username = self._credential.username
        url = urls.username_owner_token(username)
        res = self._session.get(
            url=utils.never_cache(url, self._session),
            headers={
                "Accept": utils.JSON_MIMETYPE,
                "username": username,
                "password": self._credential.password})
        self.value = utils.get_json(res, errors.auth_error)["accessToken"]


class AppToken(Token):
    __slots__ = "_owner_token", "_auth", "_app_id"

    def __init__(
            self,
            owner_token: OwnerToken,
            app_id: str,
            **kwargs):
        super().__init__(**kwargs)
        self._owner_token = owner_token
        self._auth = TokenAuth(owner_token)
        self._app_id = app_id

    @property
    def domain(self) -> str:
        # Must defer to owner token to avoid infinite recursion.
        return self._owner_token.domain

    def refresh(self) -> None:
        url = urls.domain_app_token(self.domain, self._app_id)
        res = self._session.get(
            url=utils.never_cache(url, self._session), auth=self._auth)
        self.value = utils.get_json(res, errors.auth_error)["accessToken"]

    def _decode(self, *, verify: bool = True) -> JwtToken:
        return JwtAppToken.decode(
            self.value, pk=self.pk if verify else None, verify=verify)


class WebOwnerToken(OwnerToken):  # TODO

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def refresh(self) -> None:
        pass


class TokenAuth(auth.AuthBase):
    __slots__ = "_token"

    def __init__(self, token: Token):
        self._token = token

    def __call__(self, request: PreparedRequest) -> PreparedRequest:
        request.headers[utils.TOKEN_KEY] = self._token.value
        request.hooks["response"].append(self._on_response)
        return request

    def _on_response(self, response: Response, **kwargs) -> Response:
        if utils.TOKEN_KEY in response.headers:
            self._token.value = response.headers[utils.TOKEN_KEY]
        return response

    def __repr__(self) -> str:
        return utils.to_string(self, token=self._token)
