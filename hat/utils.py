from __future__ import annotations

import contextlib
from typing import Any, Callable, Type

import cachecontrol
import requests
from cachecontrol import heuristics
from requests import Response

JSON_MIMETYPE = "application/json"

OnSuccess = Callable[[Response], Any]
OnError = Callable[[int, Any], Type[Exception]]


def token_header(token: str) -> dict:
    return {"Content-Type": JSON_MIMETYPE, "x-auth-token": token}


def get_json(response: Response, on_error: OnError) -> dict | list:
    return _handle_response(response, lambda r: r.json(), on_error)


def get_string(response: Response, on_error: OnError) -> str:
    return _handle_response(response, lambda r: r.text, on_error)


def _handle_response(
        response: Response, on_success: OnSuccess, on_error: OnError) -> Any:
    try:
        response.raise_for_status()
        return on_success(response)
    except requests.RequestException as e:
        error = on_error(response.status_code, response.json())
        raise error(e)
    finally:
        response.close()  # Required for efficiency when streaming.


class SessionMixin(contextlib.AbstractContextManager):
    __slots__ = "_session"

    def __init__(self, session: requests.Session | None = None):
        super().__init__()
        self._session = session or self._new_cached_session()

    @staticmethod
    def _new_cached_session() -> requests.Session:
        return cachecontrol.CacheControl(
            requests.Session(), heuristic=heuristics.OneDayCache())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.__exit__(exc_type, exc_val, exc_tb)

    def close(self):
        self._session.close()


_never_cache_adapter = cachecontrol.CacheControlAdapter()
_never_cache_adapter.cacheable_methods = {}


def never_cache(url: str, session: requests.Session) -> str:
    if url not in session.adapters:
        session.mount(url, _never_cache_adapter)
    return url
