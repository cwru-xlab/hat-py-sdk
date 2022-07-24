from __future__ import annotations

import functools
from typing import Any, Callable, Type

import requests
from requests import Response, Session

JSON_MIMETYPE = "application/json"

OnSuccess = Callable[[Response], Any]
OnError = Callable[[int, Any], Type[Exception]]


def token_header(token: str) -> dict:
    return {"Content-Type": JSON_MIMETYPE, "x-auth-token": token}


def get_json(response: Response, on_error: OnError) -> dict | list:
    return _handle_response(response, lambda r: r.json(), on_error)


def get_string(response: Response, on_error: OnError) -> str:
    decode = functools.partial(lambda r: response.content.decode())
    return _handle_response(response, decode, on_error)


def _handle_response(
        response: Response, on_success: OnSuccess, on_error: OnError) -> Any:
    try:
        response.raise_for_status()
        return on_success(response)
    except requests.RequestException as e:
        error = on_error(response.status_code, response.json())
        raise error(e)


class SessionMixin:
    __slots__ = "_session"

    def __init__(self, session: Session | None = None):
        self._session = session or requests.session()

    def close(self):
        self._session.close()
