from __future__ import annotations

import collections
from typing import Any
from typing import Callable
from typing import Generic
from typing import Optional
from typing import TypeVar


class HatError(Exception):
    pass


class UnsupportedMediaTypeError(HatError):
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


E = TypeVar("E", bound=Exception)
Resolver = Callable[[Any], type[E]]
V = tuple[Optional[type[E]], Optional[Resolver]]


class ErrorMapping(Generic[E]):
    __slots__ = "_default", "_errors"

    def __init__(self, builder: Builder[E]):
        self._default = builder.default
        self._errors = builder.errors

    @classmethod
    def builder(cls, default: type[E]) -> Builder[E]:
        return ErrorMapping.Builder(default)

    def get(self, status: int, content: Any) -> type[E]:
        error, resolver = self._errors[status]
        return error if resolver is None else resolver(content)

    def default(self) -> type[E]:
        return self._default

    class Builder(Generic[E]):
        __slots__ = "default", "errors"

        def __init__(self, default: type[E]):
            self.default = default
            self.errors = self._new_map(default)

        @staticmethod
        def _new_map(default: type[E]) -> dict[int, V]:
            return collections.defaultdict(lambda: (default, None))

        def put(
            self,
            status: int,
            error: type[E] | None = None,
            resolver: Resolver | None = None,
        ) -> ErrorMapping.Builder[E]:
            if not (error is None) ^ (resolver is None):
                raise ValueError("Either 'error' or 'resolver' must be specified")
            self.errors[status] = (error, resolver)
            return self

        def put_all(self, mapping: ErrorMapping[E]) -> ErrorMapping.Builder[E]:
            self.errors.update(mapping._errors)
            return self

        def build(self) -> ErrorMapping[E]:
            return ErrorMapping(self)


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

auth_errors = (
    ErrorMapping.builder(AuthError)
    .put(401, WrongCredentialsError)
    .put(404, HatNotFoundError)
    .build()
)

crud_errors = (
    ErrorMapping.builder(HatError)
    .put(401, WrongTokenError)
    .put(403, LimitedTokenScopeError)
    .put(415, UnsupportedMediaTypeError)
    .build()
)

get_errors = ErrorMapping.builder(GetError).put_all(crud_errors).build()

post_errors = (
    ErrorMapping.builder(PostError)
    .put_all(crud_errors)
    .put(400, DuplicateDataError)
    .build()
)

put_errors = (
    ErrorMapping.builder(PutError)
    .put_all(crud_errors)
    .put(400, resolver=_resolve_put_400)
    .put(500, DuplicateDataError)
    .build()
)

delete_errors = (
    ErrorMapping.builder(DeleteError)
    .put_all(crud_errors)
    .put(400, RecordNotFoundError)
    .build()
)

all_errors: dict[str, ErrorMapping[HatError]] = {
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
