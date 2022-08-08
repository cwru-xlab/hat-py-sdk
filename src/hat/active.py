from __future__ import annotations

from typing import ClassVar, Optional, TypeVar

from . import errors, model
from .client import HatClient, StringLike


class ActiveHatModel(model.HatModel):
    client: ClassVar[HatClient]

    def save(self, endpoint: str | None = None) -> A:
        client: HatClient = self.client
        if endpoint is not None:
            self.endpoint = endpoint
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
            options: Optional[model.GetOpts] = None
    ) -> list[A]:
        return cls.client.get(mtype=cls, endpoint=endpoint, options=options)


A = TypeVar("A", bound=ActiveHatModel)
