from __future__ import annotations

from abc import ABC
from enum import Enum
from typing import Generic, Optional, TypeVar

from humps import camel
from pydantic import BaseModel, Field, NonNegativeInt, StrictStr, conint, constr
from pydantic.generics import GenericModel

_T = TypeVar("_T")


class HatModel(BaseModel, ABC):
    class Config:
        allow_population_by_field_name = True
        use_enum_values = True


class HatRecord(HatModel, GenericModel, Generic[_T]):
    endpoint: Optional[StrictStr]
    record_id: Optional[StrictStr]
    data: Optional[_T] = Field(default_factory=dict)

    class Config:
        alias_generator = camel.case
        allow_mutation = False

    def dict(self, by_alias: bool = True, **kwargs) -> dict:
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

    class Config:
        alias_generator = camel.case

    def dict(self, exclude_none: bool = True, **kwargs) -> dict:
        return super().dict(exclude_none=exclude_none, **kwargs)

    def json(self, exclude_none: bool = True, **kwargs) -> str | None:
        return super().json(exclude_none=exclude_none, **kwargs)
