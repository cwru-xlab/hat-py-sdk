from __future__ import annotations

from typing import ClassVar, Optional

from . import GetOpts, HatRecord, errors, models
from .client import HatClient


class ActiveHatRecord(models.HatRecord):
    client: ClassVar[HatClient]

    def save(self, uniquify: Optional[bool] = None) -> ActiveHatRecord:
        client: HatClient = self.client
        if has_id := self.record_id is not None:
            method = client.put
        else:
            method = client.post
        try:
            saved = method(self, uniquify=uniquify)
        except errors.PutError as e:
            if has_id:
                saved = client.post(self, uniquify=uniquify)
            else:
                raise e
        return self.from_record(saved[0])

    def delete(self) -> None:
        return self.client.delete(self)

    @classmethod
    def get(
            cls,
            *endpoints: str | HatRecord,
            options: Optional[GetOpts] = None
    ) -> list[ActiveHatRecord]:
        records = cls.client.get(*endpoints, options=options)
        return [cls.from_record(rec) for rec in records]

    @classmethod
    def from_record(cls, record: HatRecord) -> ActiveHatRecord:
        return ActiveHatRecord(**record.dict())
