from __future__ import annotations

import collections
from typing import Any
from typing import Callable
from typing import Generic
from typing import Optional
from typing import Type
from typing import TypeVar


class HatError(Exception):
    pass


class AuthError(HatError):
    pass


class WrongCredentialsError(AuthError):
    pass


class HatNotFoundError(AuthError):
    pass


class GetError(HatError):
    pass


class PostError(HatError):
    pass


class PutError(HatError):
    pass


class MissingPathError(PutError):
    pass


class MalformedBodyError(PutError):
    pass


class DuplicateDataError(PostError, PutError):
    # It is not officially documented, but it appears that updating (PUT) a record
    # to have the same data as another existing record is also not allowed.
    pass


class DeleteError(HatError):
    pass


class RecordNotFoundError(DeleteError):
    pass


class WrongTokenError(GetError, PostError, PutError, DeleteError):
    pass


class LimitedTokenScopeError(GetError, PostError, PutError, DeleteError):
    pass


class UnsupportedMediaTypeError(PostError, PutError):
    pass


_E = TypeVar("_E", bound=Exception)
_Resolver = Callable[[Any], Type[_E]]
_V = tuple[Optional[Type[_E]], Optional[_Resolver]]


class _ErrorMapping(Generic[_E]):
    __slots__ = "_default", "_errors"

    def __init__(self, default: type[_E]):
        self._default = default
        self._errors = self._new_map(default)

    @staticmethod
    def _new_map(default: type[_E]) -> dict[int, _V]:
        return collections.defaultdict(lambda: (default, None))

    def get(self, status: int, content: Any) -> type[_E]:
        error, resolver = self._errors[status]
        return error if resolver is None else resolver(content)

    def put(
        self,
        status: int,
        error: type[_E] | None = None,
        resolver: _Resolver | None = None,
    ) -> None:
        if not (error is None) ^ (resolver is None):
            raise ValueError("Either 'error' or 'resolver' must be specified")
        self._errors[status] = (error, resolver)

    def update(self, mapping: _ErrorMapping) -> None:
        self._errors.update(mapping._errors)

    def default(self) -> type[_E]:
        return self._default


def _resolve_put_400(content: dict[str, str] | str) -> type[PutError]:
    if isinstance(content, dict):
        if isinstance(content["message"], str):
            error = MalformedBodyError
        else:
            error = MissingPathError
    else:
        error = PutError
    return error


POSSIBLE_CODES = (400, 401, 403, 404, 415, 500)

_auth_errors = _ErrorMapping(AuthError)
_auth_errors.put(401, WrongCredentialsError)
_auth_errors.put(404, HatNotFoundError)

_crud_errors = _ErrorMapping(HatError)
_crud_errors.put(401, WrongTokenError)
_crud_errors.put(403, LimitedTokenScopeError)

_get_errors = _ErrorMapping(GetError)
_get_errors.update(_crud_errors)

_post_errors = _ErrorMapping(PostError)
_post_errors.update(_crud_errors)
_post_errors.put(415, UnsupportedMediaTypeError)
_post_errors.put(400, DuplicateDataError)

_put_errors = _ErrorMapping(PutError)
_put_errors.update(_crud_errors)
_put_errors.put(400, resolver=_resolve_put_400)
_put_errors.put(415, UnsupportedMediaTypeError)
_put_errors.put(500, DuplicateDataError)

_delete_errors = _ErrorMapping(DeleteError)
_delete_errors.update(_crud_errors)
_delete_errors.put(400, RecordNotFoundError)

_errors: dict[str, _ErrorMapping] = {
    "auth": _auth_errors,
    "get": _get_errors,
    "post": _post_errors,
    "put": _put_errors,
    "delete": _delete_errors,
}


def find_error(kind: str, status: int, content: Any) -> type[HatError]:
    key = kind.lower().strip()
    if key in _errors:
        return _errors[key].get(status, content)
    else:
        raise ValueError(f"'kind' must be one of {list(_errors.keys())}; got {kind}")
