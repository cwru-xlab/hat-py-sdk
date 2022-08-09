from __future__ import annotations

import contextlib
from typing import Any, Callable, Type

import cachecontrol
import requests
from cachecontrol import heuristics
from requests import Response

JSON_MIMETYPE = "application/json"
TOKEN_KEY = "x-auth-token"

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

    def __init__(
            self,
            session: requests.Session | None = None,
            cache: bool = True,
            stream: bool = True,
            content_type: str | None = JSON_MIMETYPE):
        super().__init__()
        if session is None:
            session = requests.Session()
            session.stream = stream
            if cache:
                session = cachecontrol.CacheControl(
                    session, heuristic=heuristics.OneDayCache())
        if content_type:
            session.headers["Content-Type"] = content_type
        self._session = session

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.__exit__(exc_type, exc_val, exc_tb)

    def close(self):
        self._session.close()


_never_cache_adapter = cachecontrol.CacheControlAdapter()
_never_cache_adapter.cacheable_methods = {}


def never_cache(url: str, session: requests.Session) -> str:
    session.mount(url, _never_cache_adapter)
    return url


def to_str(self: Any, **attrs) -> str:
    name = type(self).__name__
    attrs = ", ".join(f"{name}={value}" for name, value in attrs.items())
    return f"{name}({attrs})"
