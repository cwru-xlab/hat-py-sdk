# noinspection PyPackageRequirements
import humps
import pydantic


class Record(pydantic.BaseModel):
    endpoint: str = None
    record_id: str = None
    data: dict = pydantic.Field(default_factory=dict)

    class Config:
        alias_generator = humps.camelize

    def dict(self, *args, **kwargs):
        return super().dict(*args, by_alias=True, **kwargs)
