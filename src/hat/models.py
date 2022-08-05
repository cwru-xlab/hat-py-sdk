from __future__ import annotations

import abc
from enum import Enum
from typing import Any, Generic, Optional, Type, TypeVar

import pydantic
import ulid
from humps import camel
from pydantic import BaseModel, Field, NonNegativeInt, StrictStr, conint, constr
from pydantic.generics import GenericModel


class HatConfig(pydantic.BaseConfig):
    allow_population_by_field_name = True
    use_enum_values = True
    allow_mutation = False
    alias_generator = camel.case


class BaseHatModel(BaseModel, abc.ABC):
    endpoint: Optional[StrictStr]
    record_id: Optional[StrictStr]


class HatModel(BaseHatModel):
    uid: StrictStr = Field(default_factory=lambda: str(ulid.new()))

    __reserved_attrs__ = ("uid",)

    class Config:
        extra = pydantic.Extra.allow
        arbitrary_types_allowed = True

    @pydantic.validator("*", always=True, allow_reuse=True)
    def _check_reserved(cls, value: Any) -> Any:
        if any(hasattr(value, a) for a in cls.__reserved_attrs__):
            raise ValueError(f"'{value}' is a reserved attribute name.")
        return value

    @classmethod
    def from_record(cls, record: HatRecord[M]) -> M:
        model = cls.parse_obj(record.data)
        model.record_id = record.record_id
        model.endpoint = record.endpoint
        return model

    def to_record(self) -> HatRecord[M]:
        return HatRecord.from_model(self)


M = TypeVar("M", bound=HatModel)


class HatRecord(BaseHatModel, GenericModel, Generic[M]):
    data: dict[str, Any] = {}

    Config = HatConfig

    @classmethod
    def from_model(cls, model: M) -> HatRecord[M]:
        return cls(
            endpoint=model.endpoint,
            record_id=model.record_id,
            data=model.dict(exclude={"endpoint", "record_id"}))

    def to_model(self, model: Type[M]) -> M:
        return model.from_record(self)

    def dict(self, by_alias: bool = True, **kwargs) -> dict[str, Any]:
        return super().dict(by_alias=by_alias, **kwargs)

    def json(self, by_alias: bool = True, **kwargs) -> str | None:
        return super().json(by_alias=by_alias, **kwargs)


class Ordering(str, Enum):
    ASCENDING = "ascending"
    DESCENDING = "descending"


class GetOpts(BaseModel):
    order_by: Optional[constr(min_length=1)]
    ordering: Optional[Ordering]
    skip: Optional[NonNegativeInt]
    take: Optional[conint(ge=0, le=1000)]

    Config = HatConfig

    def dict(self, exclude_none: bool = True, **kwargs) -> dict:
        return super().dict(exclude_none=exclude_none, **kwargs)

    def json(self, exclude_none: bool = True, **kwargs) -> str | None:
        return super().json(exclude_none=exclude_none, **kwargs)
