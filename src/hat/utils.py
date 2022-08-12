from __future__ import annotations

import contextlib
import datetime
from typing import Any, Callable, Optional, Type

import requests
import requests_cache
from requests import Response
from requests_cache.backends import base

from . import errors, urls

JSON_MIMETYPE = "application/json"
TOKEN_HEADER = "x-auth-token"

OnSuccess = Callable[[Response], Any]
OnError = Callable[[int, Any], Type[Exception]]


def get_json(res: Response, on_error: OnError) -> dict | list:
    return handle(res, lambda r: r.json(), on_error)


def get_string(res: Response, on_error: OnError) -> str:
    return handle(res, lambda r: r.text, on_error)


def handle(res: Response, on_success: OnSuccess, on_error: OnError) -> Any:
    try:
        res.raise_for_status()
        return on_success(res)
    except IOError as e:
        error = on_error(res.status_code, res.json())
        raise error(e)
    finally:
        res.close()  # Required for efficiency when streaming.


class SessionMixin(contextlib.AbstractContextManager):
    __slots__ = "_session"

    def __init__(self, session: Optional[requests.Session] = None, **kwargs):
        super().__init__()
        self._session = session or self._default_session()

    @staticmethod
    def _default_session() -> requests.Session:
        session = requests_cache.CachedSession(
            backend=base.BaseCache,
            allowable_codes=[200] + list(errors.possible_codes),
            allowable_methods=["GET", "POST"],
            stale_if_error=True,
            expire_after=datetime.timedelta(minutes=10),
            urls_expire_after={
                urls.domain_owner_token("*"): requests_cache.DO_NOT_CACHE,
                urls.domain_app_token("*", "*"): requests_cache.DO_NOT_CACHE})
        session.stream = True
        session.headers["Content-Type"] = JSON_MIMETYPE
        return session

    def __enter__(self):
        with self._session:
            return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.__exit__()

    def clear_cache(self) -> None:
        if isinstance(self._session, requests_cache.CachedSession):
            self._session.cache.clear()

    def close(self) -> None:
        self._session.close()


def to_str(self: Any, **attrs) -> str:
    name = type(self).__name__
    attrs = ", ".join(f"{name}={value}" for name, value in attrs.items())
    return f"{name}({attrs})"
