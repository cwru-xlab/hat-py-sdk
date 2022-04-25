# noinspection PyPackageRequirements
from __future__ import annotations

import enum

import humps
from pydantic import BaseModel, Field, validator


class HatModel(BaseModel):
    class Config:
        alias_generator = humps.camelize
        allow_population_by_field_name = True
        use_enum_values = True

    def dict(self, *args, **kwargs):
        return super().dict(*args, by_alias=True, **kwargs)


class Record(HatModel):
    endpoint: str = None
    record_id: str = None
    data: dict = Field(default_factory=dict)


class Ordering(str, enum.Enum):
    ASCENDING = "ascending"
    DESCENDING = "descending"


# noinspection PyMethodParameters
class GetParams(HatModel):
    order_by: str = None
    ordering: Ordering = None
    skip: int = None
    take: int = None

    @validator("order_by")
    def validate_order_by(cls, value) -> str:
        if value == "":
            raise ValueError("'order_by' must not be the empty string")
        return value

    @validator("skip")
    def validate_skip(cls, value) -> str:
        if value < 0:
            raise ValueError("'skip' must be non-negative")
        return value

    @validator("take")
    def validate_take(cls, value) -> int:
        if value < 0 or value > 1000:
            raise ValueError("'take' must be between 0 and 1000, inclusive")
        return value

    def dict(self, *args, **kwargs):
        return super().dict(exclude_none=True)
