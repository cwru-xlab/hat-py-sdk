from __future__ import annotations

from typing import Any
from typing import AnyStr

from asgiref import sync


synchronize = sync.async_to_sync


def set_synchronizer(synchronizer: sync.AsyncToSync) -> None:
    global synchronize
    synchronize = synchronizer


try:
    import orjson as json

    def dumps(obj: Any, **kwargs) -> str:
        # Ref: https://pydantic-docs.helpmanual.io/usage/exporting_models
        return json.dumps(obj, **kwargs).decode()

except ImportError:
    import json

    def dumps(obj, **kwargs):
        return json.dumps(obj, **kwargs)

finally:

    def loads(obj: AnyStr, **kwargs) -> dict[str, Any]:
        return json.loads(obj, **kwargs)


try:
    import ulid as unique

    def uid() -> str:
        return str(unique.ULID())

except ImportError:
    import uuid as unique

    def uid() -> str:
        return str(unique.uuid4())


def to_str(self: Any, **attrs) -> str:
    name = type(self).__name__
    attrs = ", ".join(f"{name}={value}" for name, value in attrs.items())
    return f"{name}({attrs})"
