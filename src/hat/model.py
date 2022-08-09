from __future__ import annotations

import abc
from enum import Enum
from typing import Any, AnyStr, Generic, Iterable, Optional, Type, TypeVar

import orjson
import pydantic
import ulid
from humps import camel
from pydantic import BaseModel, Field, NonNegativeInt, StrictStr, conint, constr
from pydantic.generics import GenericModel


def orjson_dumps(value: Any, **kwargs) -> str:
    # Ref: https://pydantic-docs.helpmanual.io/usage/exporting_models
    return orjson.dumps(value, **kwargs).decode()


class HatConfig(pydantic.BaseConfig):
    allow_population_by_field_name = True
    use_enum_values = True
    json_dumps = orjson_dumps
    json_loads = orjson.loads


class ApiConfig(HatConfig):
    alias_generator = camel.case
    allow_mutation = False


class BaseHatModel(BaseModel, abc.ABC):
    endpoint: Optional[StrictStr]
    record_id: Optional[StrictStr]

    Config = HatConfig


class BaseApiModel(BaseModel, abc.ABC):
    Config = ApiConfig

    def dict(self, by_alias: bool = True, **kwargs) -> dict[str, Any]:
        return super().dict(by_alias=by_alias, **kwargs)

    def json(self, by_alias: bool = True, **kwargs) -> str | None:
        return super().json(by_alias=by_alias, **kwargs)


class HatModel(BaseHatModel):
    uid: str = Field(default_factory=lambda: str(ulid.ULID()))

    class Config:
        extra = pydantic.Extra.allow
        arbitrary_types_allowed = True


M = TypeVar("M", bound=HatModel)


class HatRecord(BaseApiModel, BaseHatModel, GenericModel, Generic[M]):
    data: dict[str, Any] = {}

    @classmethod
    def from_model(cls, model: M) -> HatRecord[M]:
        return cls(
            endpoint=model.endpoint,
            record_id=model.record_id,
            data=model.dict(exclude=set(BaseHatModel.__fields__)))

    @classmethod
    def parse(cls, records: AnyStr, *mtypes: Type[M]) -> list[M]:
        if not isinstance(records := cls.__config__.json_loads(records), list):
            records = [records]
        # When more records exist than model types, try binding to the last one.
        mtypes, m = iter(mtypes), None
        return [cls._to_model(r, m := next(mtypes, m)) for r in records]

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
        records = map(cls.from_model, models)
        dump = cls.__config__.json_dumps
        if data_only:
            records = [dump(r.data) for r in records]
        else:
            records = [r.json() for r in records]
        return dump(records)


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

    def json(self, exclude_none: bool = True, **kwargs) -> str | None:
        return super().json(exclude_none=exclude_none, **kwargs)
