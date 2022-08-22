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


E = TypeVar("E", bound=Exception)
Resolver = Callable[[Any], Type[E]]
V = tuple[Optional[Type[E]], Optional[Resolver]]


class ErrorMapping(Generic[E]):
    __slots__ = "_default", "_errors"

    def __init__(self, default: type[E]):
        self._default = default
        self._errors = self._new_map(default)

    @staticmethod
    def _new_map(default: type[E]) -> dict[int, V]:
        return collections.defaultdict(lambda: (default, None))

    def get(self, status: int, content: Any) -> type[E]:
        error, resolver = self._errors[status]
        return error if resolver is None else resolver(content)

    def put(
        self,
        status: int,
        error: type[E] | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        if not (error is None) ^ (resolver is None):
            raise ValueError("Either 'error' or 'resolver' must be specified")
        self._errors[status] = (error, resolver)

    def update(self, mapping: ErrorMapping) -> None:
        self._errors.update(mapping._errors)

    def default(self) -> type[E]:
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
post_errors.put(415, UnsupportedMediaTypeError)

put_errors = ErrorMapping(PutError)
put_errors.update(crud_errors)
put_errors.put(400, resolver=_resolve_put_400)
put_errors.put(415, UnsupportedMediaTypeError)
put_errors.put(500, DuplicateDataError)

delete_errors = ErrorMapping(DeleteError)
delete_errors.update(crud_errors)
delete_errors.put(400, RecordNotFoundError)

all_errors: dict[str, ErrorMapping] = {
    "auth": auth_errors,
    "get": get_errors,
    "post": post_errors,
    "put": put_errors,
    "delete": delete_errors,
}


def find_error(kind: str, status: int, content: Any) -> type[HatError]:
    key = kind.lower().strip()
    if key in all_errors:
        return all_errors[key].get(status, content)
    else:
        raise ValueError(f"'kind' must be one of {list(all_errors.keys())}; got {kind}")
