import humps
from pydantic import BaseModel


class PdaRecord(BaseModel):
    endpoint: str
    record_id: str
    data: dict

    class Config:
        alias_generator = humps.camelize
