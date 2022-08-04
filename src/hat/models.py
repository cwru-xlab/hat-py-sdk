from __future__ import annotations

import abc
from enum import Enum
from typing import Any, Optional, TypeVar

import pydantic
import ulid
from humps import camel
from pydantic import BaseModel, Field, NonNegativeInt, StrictStr, conint, constr

T = TypeVar("T")


class BaseHatModel(BaseModel, abc.ABC):
    endpoint: Optional[StrictStr]
    record_id: Optional[StrictStr]


class HatModel(BaseHatModel):
    pk: StrictStr = Field(default_factory=lambda: str(ulid.new()))

    class Config:
        extra = pydantic.Extra.allow

    @classmethod
    def from_record(cls, record: HatRecord) -> HatModel:
        return HatModel(
            endpoint=record.endpoint, record_id=record.record_id, **record.data)

    def to_record(self) -> HatRecord:
        return HatRecord.from_model(self)


class HatRecord(BaseHatModel):
    data: dict[str, Any] = {}

    class Config:
        allow_population_by_field_name = True
        use_enum_values = True
        allow_mutation = False
        alias_generator = camel.case

    @classmethod
    def from_model(cls, model: HatModel) -> HatRecord:
        return HatRecord(
            endpoint=model.endpoint,
            record_id=model.record_id,
            data=model.dict(exclude={"endpoint", "record_id"}))

    def to_model(self) -> HatModel:
        return HatModel.from_record(self)

    def dict(self, by_alias: bool = True, **kwargs) -> dict[str, Any]:
        return super().dict(by_alias=by_alias, **kwargs)

    def json(self, by_alias: bool = True, **kwargs) -> str | None:
        return super().json(by_alias=by_alias, **kwargs)


class Ordering(str, Enum):
    ASCENDING = "ascending"
    DESCENDING = "descending"


class GetOpts(HatModel):
    order_by: Optional[constr(min_length=1)]
    ordering: Optional[Ordering]
    skip: Optional[NonNegativeInt]
    take: Optional[conint(ge=0, le=1000)]

    def dict(self, exclude_none: bool = True, **kwargs) -> dict:
        return super().dict(exclude_none=exclude_none, **kwargs)

    def json(self, exclude_none: bool = True, **kwargs) -> str | None:
        return super().json(exclude_none=exclude_none, **kwargs)
