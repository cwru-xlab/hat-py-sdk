import humps
from pydantic import BaseModel


class Record(BaseModel):
    endpoint: str
    data: dict
    record_id: str = None

    class Config:
        alias_generator = humps.camelize

    def dict(self, *args, **kwargs):
        return super().dict(*args, by_alias=True, **kwargs)
