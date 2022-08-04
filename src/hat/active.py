from __future__ import annotations

from typing import ClassVar, Optional, TypeVar

from . import GetOpts, errors, models
from .client import HatClient, StringLike
from .models import M


class ActiveHatModel(models.HatModel):
    client: ClassVar[HatClient]

    def save(self) -> A:
        client: HatClient = self.client
        if has_id := self.record_id is not None:
            method = client.put
        else:
            method = client.post
        try:
            saved = method(self)
        except errors.PutError as e:
            if has_id:
                saved = client.post(self)
            else:
                raise e
        return saved[0]

    def delete(self) -> None:
        return self.client.delete(self)

    @classmethod
    def get(
            cls,
            endpoint: StringLike,
            options: Optional[GetOpts] = None
    ) -> list[A]:
        return cls.client.get(cls, endpoint, options=options)

    @classmethod
    def of(cls, model: M) -> A:
        return cls.parse_obj(model)


A = TypeVar("A", bound=ActiveHatModel)
