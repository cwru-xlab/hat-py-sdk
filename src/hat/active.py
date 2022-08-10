from __future__ import annotations

from typing import ClassVar, Iterable, Optional, TypeVar

from . import GetOpts, HatModel, errors
from .client import HatClient, M, StringLike


class ActiveHatModel(HatModel):
    client: ClassVar[HatClient]

    def save(self, endpoint: Optional[str] = None) -> A:
        if endpoint is not None:
            self.endpoint = endpoint
        if has_id := self.record_id is not None:
            method = self._client().put
        else:
            method = self._client().post
        try:
            saved = method(self)
        except errors.PutError as e:
            if has_id:
                saved = self._client().post(self)
            else:
                raise e
        return saved[0]

    def delete(self) -> None:
        return self._client().delete(self)

    @classmethod
    def delete_all(cls, models: M | Iterable[M]) -> None:
        cls._client().delete(models)

    @classmethod
    def get(
            cls,
            endpoint: StringLike,
            options: Optional[GetOpts] = None
    ) -> list[A]:
        return cls._client().get(mtype=cls, endpoint=endpoint, options=options)

    @classmethod
    def _client(cls) -> HatClient:
        # ClassVar interferes with type checking.
        return cls.client


A = TypeVar("A", bound=ActiveHatModel)
