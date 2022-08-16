from __future__ import annotations

import inspect
from typing import Any, AnyStr, Callable

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


def match_signature(obj: Callable, **kwargs) -> dict[str, Any]:
    allowed = inspect.signature(obj).parameters
    return {k: v for k, v in kwargs.items() if k in allowed}


def to_str(self: Any, **attrs) -> str:
    name = type(self).__name__
    attrs = ", ".join(f"{name}={value}" for name, value in attrs.items())
    return f"{name}({attrs})"
