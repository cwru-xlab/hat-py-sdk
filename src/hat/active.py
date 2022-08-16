from __future__ import annotations

from typing import Any, ClassVar, Optional, TypeVar

from asgiref import sync

from . import errors
from .client import AsyncHatClient, Models, StringLike
from .model import GetOpts, HatModel


class AsyncActiveHatModel(HatModel):
    client: ClassVar[AsyncHatClient]

    async def save(self, endpoint: Optional[str] = None) -> A:
        if endpoint is not None:
            self.endpoint = endpoint
        has_id = self.record_id is not None
        if has_id:
            method = self._client().put
        else:
            method = self._client().post
        try:
            saved = await method(self)
        except errors.PutError as e:
            if has_id:
                saved = await self._client().post(self)
            else:
                raise e
        return saved[0]

    async def delete(self) -> None:
        return await self._client().delete(self)

    @classmethod
    async def delete_all(cls, models: Models) -> None:
        await cls._client().delete(models)

    @classmethod
    async def get(
        cls, endpoint: StringLike, options: Optional[GetOpts] = None
    ) -> list[A]:
        return await cls._client().get(endpoint, cls, options)

    @classmethod
    def _client(cls) -> AsyncHatClient:
        # ClassVar interferes with type checking.
        return cls.client


class ActiveHatModel(HatModel):
    client: ClassVar[AsyncHatClient]

    def __init__(self, **data: Any):
        super(ActiveHatModel, self).__init__(**data)
        self._wrapped = AsyncActiveHatModel(**data)

    def save(self, endpoint: Optional[str] = None) -> S:
        return sync.async_to_sync(self._wrapped.save)(endpoint)

    def delete(self) -> None:
        return sync.async_to_sync(self._wrapped.delete)()

    @classmethod
    def delete_all(cls, models: Models) -> None:
        return sync.async_to_sync(cls._client().delete)(models)

    @classmethod
    def get(cls, endpoint: StringLike, options: Optional[GetOpts] = None) -> list[S]:
        return sync.async_to_sync(cls._client().get)(endpoint, cls, options)

    @classmethod
    def _client(cls) -> AsyncHatClient:
        # ClassVar interferes with type checking.
        return cls.client


A = TypeVar("A", bound=AsyncActiveHatModel)
S = TypeVar("S", bound=ActiveHatModel)
