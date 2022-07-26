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


T = TypeVar("T", bound=Exception)
E = Type[T]
Resolver = Callable[[Any], E]
V = tuple[Optional[E], Optional[Resolver]]


class ErrorMapping(Generic[T]):
    __slots__ = "_default", "_errors"

    def __init__(self, default: E):
        self._default = default
        self._errors = self._new_map(default)

    @staticmethod
    def _new_map(default: E) -> dict[int, V]:
        return collections.defaultdict(lambda: (default, None))

    def get(self, status: int, content: Any) -> E:
        error, resolver = self._errors[status]
        return error if resolver is None else resolver(content)

    def put(
            self,
            status: int,
            error: E | None = None,
            resolver: Resolver | None = None
    ) -> None:
        if not (error is None) ^ (resolver is None):
            raise ValueError("Either 'error' or 'resolver' must be specified")
        self._errors[status] = (error, resolver)

    def update(self, mapping: ErrorMapping) -> None:
        self._errors.update(mapping._errors)

    @property
    def default(self) -> E:
        return self._default


def resolve_put_400(content: dict) -> Type[PutError]:
    if isinstance(content["message"], str):
        error = MalformedBodyError
    else:
        error = MissingPathError
    return error


auth_errors = ErrorMapping(AuthError)
auth_errors.put(401, WrongCredentialsError)
auth_errors.put(404, HatNotFoundError)

crud_errors = ErrorMapping(HatError)
crud_errors.put(401, WrongTokenError)
crud_errors.put(403, LimitedTokenScopeError)

get_errors = ErrorMapping(GetError)
get_errors.update(crud_errors)

post_errors = ErrorMapping(PostError)
post_errors.update(crud_errors)
post_errors.put(400, DuplicateDataError)

put_errors = ErrorMapping(PutError)
put_errors.update(crud_errors)
put_errors.put(400, resolver=resolve_put_400)

delete_errors = ErrorMapping(DeleteError)
delete_errors.update(crud_errors)
delete_errors.put(400, RecordNotFoundError)


def auth_error(status: int, content: Any) -> Type[AuthError]:
    return auth_errors.get(status, content)


def get_error(status: int, content: Any) -> Type[GetError]:
    return get_errors.get(status, content)


def post_error(status: int, content: Any) -> Type[PostError]:
    return post_errors.get(status, content)


def put_error(status: int, content: Any) -> Type[PutError]:
    return put_errors.get(status, content)


def delete_error(status: int, content: Any) -> Type[DeleteError]:
    return delete_errors.get(status, content)
