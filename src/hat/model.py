import re
from abc import ABC
from enum import Enum
from typing import Any
from typing import AnyStr
from typing import Generic
from typing import Iterable
from typing import Optional
from typing import Type
from typing import TypeVar
from typing import Union

import jwt
import pydantic
from humps import camel
from pydantic import BaseConfig
from pydantic import BaseModel
from pydantic import Field
from pydantic import NonNegativeInt
from pydantic import PositiveInt
from pydantic import StrictStr
from pydantic import conint
from pydantic import constr
from pydantic.generics import GenericModel

from . import errors
from . import utils


JWT_PATTERN = re.compile(r"^(?:[\w-]*\.){2}[\w-]*$")


class HatConfig(BaseConfig):
    allow_population_by_field_name = True
    use_enum_values = True
    json_dumps = utils.dumps
    json_loads = utils.loads


class BaseApiModel(BaseModel, ABC):
    class Config(HatConfig):
        alias_generator = camel.case
        allow_mutation = False

    def dict(self, by_alias: bool = True, **kwargs) -> dict[str, Any]:
        return super().dict(by_alias=by_alias, **kwargs)

    def json(self, by_alias: bool = True, **kwargs) -> Optional[str]:
        return super().json(by_alias=by_alias, **kwargs)


class BaseHatModel(BaseModel, ABC):
    endpoint: Optional[StrictStr]
    record_id: Optional[StrictStr]

    Config = HatConfig


class HatModel(BaseHatModel):
    uid: str = Field(default_factory=utils.uid)

    class Config:
        extra = pydantic.Extra.allow
        arbitrary_types_allowed = True


M = TypeVar("M", bound=HatModel)


class HatRecord(BaseApiModel, BaseHatModel, GenericModel, Generic[M]):
    data: dict[str, Any] = {}

    @classmethod
    def parse(cls, records: AnyStr, mtypes: Iterable[Type[M]]) -> list[M]:
        records = cls.__config__.json_loads(records)
        if not isinstance(records, list):
            records = [records]
        # When more records exist than model types, try binding to the last one.
        mtypes, mtype = iter(mtypes), None
        models = []
        for record in records:
            mtype = next(mtypes, mtype)
            models.append(cls._to_model(record, mtype))
        return models

    @classmethod
    def _to_model(cls, record: dict[str, Any], mtype: Type[M]) -> M:
        if isinstance(record["data"], (bytes, str)):
            record["data"] = cls.__config__.json_loads(record["data"])
        record = cls(**record)
        model = mtype.parse_obj(record.data)
        model.record_id = record.record_id
        model.endpoint = record.endpoint
        return model

    @classmethod
    def to_json(cls, models: Iterable[M], data_only: bool = False) -> str:
        records = map(cls._from_model, models)
        if data_only:
            records = [r.data for r in records]
        else:
            records = [r.dict() for r in records]
        return cls.__config__.json_dumps(records)

    @classmethod
    def _from_model(cls, model: M) -> "HatRecord[M]":
        return cls(
            endpoint=model.endpoint,
            record_id=model.record_id,
            data=model.dict(exclude=set(BaseHatModel.__fields__)),
        )


class Ordering(str, Enum):
    ASCENDING = "ascending"
    DESCENDING = "descending"


class GetOpts(BaseApiModel):
    order_by: Optional[constr(min_length=1)]
    ordering: Optional[Ordering]
    skip: Optional[NonNegativeInt]
    take: Optional[conint(ge=0, le=1000)]

    def dict(self, exclude_none: bool = True, **kwargs) -> dict:
        return super().dict(exclude_none=exclude_none, **kwargs)

    def json(self, exclude_none: bool = True, **kwargs) -> Optional[str]:
        return super().json(exclude_none=exclude_none, **kwargs)


class JwtToken(BaseApiModel):
    exp: PositiveInt
    iat: PositiveInt
    iss: constr(regex=r"^\w+\.hubat\.net$", strict=True)  # noqa: F722

    @classmethod
    def decode(
        cls,
        encoded: str,
        *,
        pk: Optional[str] = None,
        verify: bool = False,
        as_token: bool = False,
    ) -> Union[dict, "JwtToken"]:
        if verify and pk is None:
            raise ValueError("'pk' is required if 'verify' is True")
        if JWT_PATTERN.match(encoded) is None:
            raise ValueError(f"'encoded' has improper syntax:\n{encoded}")
        try:
            payload = jwt.decode(
                jwt=encoded,
                key=pk,
                algorithms=["RS256"],
                options={"verify_signature": verify},
            )
        except jwt.InvalidTokenError as error:
            raise errors.AuthError() from error
        return payload if not as_token else JwtToken(**payload)


class JwtOwnerToken(JwtToken):
    access_scope: constr(regex="^owner$", strict=True)  # noqa: F722

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> "JwtOwnerToken":
        kwargs["as_token"] = False
        return JwtOwnerToken(**super().decode(encoded, **kwargs))


class JwtAppToken(JwtToken):
    application: StrictStr
    application_version: constr(regex=r"^\d+.\d+.\d+$", strict=True)  # noqa: F722

    @classmethod
    def decode(cls, encoded: str, **kwargs) -> "JwtAppToken":
        kwargs["as_token"] = False
        return JwtAppToken(**super().decode(encoded, **kwargs))
