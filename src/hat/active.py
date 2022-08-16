from __future__ import annotations

from typing import Any
from typing import ClassVar
from typing import TypeVar

from asgiref import sync

from . import errors
from .client import AsyncHatClient
from .client import IStringLike
from .client import StringLike
from .model import GetOpts
from .model import HatModel


class AsyncActiveHatModel(HatModel):
    client: ClassVar[AsyncHatClient]

    async def save(self, endpoint: str | None = None) -> A:
        if endpoint is not None:
            self.endpoint = endpoint
        has_id = self.record_id is not None
        if has_id:
            method = self._client().put
        else:
            method = self._client().post
        try:
            saved = await method(self)
        except errors.PutError as error:
            if has_id:
                saved = await self._client().post(self)
            else:
                raise error
        return saved[0]

    async def delete(self) -> None:
        return await self._client().delete(self)

    @classmethod
    async def delete_all(cls, record_ids: StringLike | IStringLike) -> None:
        await cls._client().delete(record_ids)

    @classmethod
    async def get(cls, endpoint: StringLike, options: GetOpts | None = None) -> list[A]:
        return await cls._client().get(endpoint, cls, options)

    @classmethod
    def _client(cls) -> AsyncHatClient:
        # ClassVar interferes with type checking.
        return cls.client


class ActiveHatModel(HatModel):
    client: ClassVar[AsyncHatClient]

    def __init__(self, **data: Any):
        super().__init__(**data)
        self._wrapped = AsyncActiveHatModel(**data)

    def save(self, endpoint: str | None = None) -> S:
        return sync.async_to_sync(self._wrapped.save)(endpoint)

    def delete(self) -> None:
        return sync.async_to_sync(self._wrapped.delete)()

    @classmethod
    def delete_all(cls, record_ids: StringLike | IStringLike) -> None:
        return sync.async_to_sync(cls._client().delete)(record_ids)

    @classmethod
    def get(cls, endpoint: StringLike, options: GetOpts | None = None) -> list[S]:
        return sync.async_to_sync(cls._client().get)(endpoint, cls, options)

    @classmethod
    def _client(cls) -> AsyncHatClient:
        # ClassVar interferes with type checking.
        return cls.client


A = TypeVar("A", bound=AsyncActiveHatModel)
S = TypeVar("S", bound=ActiveHatModel)
