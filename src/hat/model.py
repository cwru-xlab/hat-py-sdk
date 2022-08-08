from __future__ import annotations

import abc
from enum import Enum
from typing import Any, Generic, Iterable, Optional, Type, TypeVar

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
    def parse_model(cls, response: dict[str, Any], model: Type[M]) -> M:
        if isinstance(response["data"], str):
            try:  # Assume that the data is encoded JSON.
                response["data"] = cls.Config.json_loads(response["data"])
            except ValueError:
                pass  # Allow pydantic to raise a ValidationError.
        return cls(**response).to_model(model)

    def to_model(self, model: Type[M]) -> M:
        model = model.parse_obj(self.data)
        model.record_id = self.record_id
        model.endpoint = self.endpoint
        return model


def records_json(models: Iterable[HatModel], data_only: bool = False) -> str:
    records = map(HatRecord.from_model, models)
    dump = HatRecord.__config__.json_dumps
    if data_only:
        records = dump([dump(r.data) for r in records])
    else:
        records = dump([r.json() for r in records])
    return records


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
