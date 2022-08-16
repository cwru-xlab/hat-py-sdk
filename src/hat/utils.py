from __future__ import annotations

import inspect
from typing import Any
from typing import AnyStr
from typing import Callable


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
    parameters = inspect.signature(obj).parameters
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        matched = kwargs
    else:
        matched = {k: v for k, v in kwargs.items() if k in parameters}
    return matched


def to_str(self: Any, **attrs) -> str:
    name = type(self).__name__
    attrs = ", ".join(f"{name}={value}" for name, value in attrs.items())
    return f"{name}({attrs})"
