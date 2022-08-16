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


class PutError(HatError):
    pass


class MissingPathError(PutError):
    pass


class MalformedBodyError(PutError):
    pass


# It is not officially documented, but it appears that updating (PUT) a record
# to have the same data as another existing record is also not allowed.
class DuplicateDataError(PostError, PutError):
    pass


class DeleteError(HatError):
    pass


class RecordNotFoundError(DeleteError):
    pass


class WrongTokenError(GetError, PostError, PutError, DeleteError):
    pass


class LimitedTokenScopeError(GetError, PostError, PutError, DeleteError):
    pass


E = TypeVar("E", bound=Exception)
Resolver = Callable[[Any], Type[E]]
V = tuple[Optional[Type[E]], Optional[Resolver]]


class ErrorMapping(Generic[E]):
    __slots__ = "_default", "_errors"

    def __init__(self, default: Type[E]):
        self._default = default
        self._errors = self._new_map(default)

    @staticmethod
    def _new_map(default: Type[E]) -> dict[int, V]:
        return collections.defaultdict(lambda: (default, None))

    def get(self, status: int, content: Any) -> Type[E]:
        error, resolver = self._errors[status]
        return error if resolver is None else resolver(content)

    def put(
        self,
        status: int,
        error: Optional[Type[E]] = None,
        resolver: Optional[Resolver] = None,
    ) -> None:
        if not (error is None) ^ (resolver is None):
            raise ValueError("Either 'error' or 'resolver' must be specified")
        self._errors[status] = (error, resolver)

    def update(self, mapping: ErrorMapping) -> None:
        self._errors.update(mapping._errors)

    @property
    def default(self) -> Type[E]:
        return self._default


def resolve_put_400(content: dict) -> Type[PutError]:
    if isinstance(content["message"], str):
        error = MalformedBodyError
    else:
        error = MissingPathError
    return error


possible_codes = (400, 401, 403, 404, 500)

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
put_errors.put(500, DuplicateDataError)

delete_errors = ErrorMapping(DeleteError)
delete_errors.update(crud_errors)
delete_errors.put(400, RecordNotFoundError)

errors: dict[str, ErrorMapping] = {
    "auth": auth_errors,
    "get": get_errors,
    "post": post_errors,
    "put": put_errors,
    "delete": delete_errors,
}


def find_error(kind: str, status: int, content: Any) -> Type[HatError]:
    key = kind.lower().strip()
    if key in errors:
        return errors[key].get(status, content)
    else:
        raise ValueError(f"'kind' must be one of {list(errors.keys())}; got {kind}")
