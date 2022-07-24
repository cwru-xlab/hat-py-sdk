from __future__ import annotations

import collections
from typing import Any, Callable, Generic, Optional, Type, TypeVar


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


class DuplicateDataError(PostError):
    pass


class PutError(HatError):
    pass


class MissingPathError(PutError):
    pass


class MalformedBodyError(PutError):
    pass


class DeleteError(HatError):
    pass


class RecordNotFoundError(DeleteError):
    pass


class WrongTokenError(GetError, PostError, PutError, DeleteError):
    pass


class LimitedTokenScopeError(GetError, PostError, PutError, DeleteError):
    pass


_T = TypeVar("_T", bound=Exception)
_E = Type[_T]
_Resolver = Callable[[Any], _E]
_V = tuple[Optional[_E], Optional[_Resolver]]


class ErrorMapping(Generic[_T]):
    __slots__ = "default", "_errors"

    def __init__(self, default: _E):
        self.default = default
        self._errors = self._new_map(default)

    @staticmethod
    def _new_map(default: _E) -> dict[int, _V]:
        return collections.defaultdict(lambda: (default, None))

    def get(self, status: int, content: Any) -> _E:
        error, resolver = self._errors[status]
        if resolver is not None:
            error = resolver(content)
        return error

    def put(
            self,
            status: int,
            error: _E | None = None,
            resolver: _Resolver | None = None
    ) -> None:
        if error is None and resolver is None:
            raise ValueError("'error' or 'resolver' must be specified")
        if error is not None and resolver is not None:
            raise ValueError("'error' and 'resolver' may not both be specified")
        self._errors[status] = (error, resolver)

    def update(self, mapping: ErrorMapping) -> None:
        self._errors.update(mapping._errors)


def _resolve_put_400(content: dict) -> Type[PutError]:
    if isinstance(content["message"], str):
        error = MalformedBodyError
    else:
        error = MissingPathError
    return error


_auth_errors = ErrorMapping(AuthError)
_auth_errors.put(401, WrongCredentialsError)
_auth_errors.put(404, HatNotFoundError)

_crud_errors = ErrorMapping(GetError)
_crud_errors.put(401, WrongTokenError)
_crud_errors.put(403, LimitedTokenScopeError)

_get_errors = ErrorMapping(GetError)
_get_errors.update(_crud_errors)

_post_errors = ErrorMapping(PostError)
_post_errors.update(_crud_errors)
_post_errors.put(400, DuplicateDataError)

_put_errors = ErrorMapping(PutError)
_put_errors.update(_crud_errors)
_put_errors.put(400, resolver=_resolve_put_400)

_delete_errors = ErrorMapping(DeleteError)
_delete_errors.update(_crud_errors)
_delete_errors.put(400, RecordNotFoundError)


def auth_error(status: int, content: Any) -> Type[AuthError]:
    return _auth_errors.get(status, content)


def get_error(status: int, content: Any) -> Type[GetError]:
    return _get_errors.get(status, content)


def post_error(status: int, content: Any) -> Type[PostError]:
    return _post_errors.get(status, content)


def put_error(status: int, content: Any) -> Type[PutError]:
    return _put_errors.get(status, content)


def delete_error(status: int, content: Any) -> Type[DeleteError]:
    return _delete_errors.get(status, content)
