from __future__ import annotations

import abc
from typing import ClassVar
from typing import TypeVar

from . import errors
from . import utils
from .client import AsyncHatClient
from .client import IStringLike
from .client import StringLike
from .model import GetOpts
from .model import HatModel
from .model import M


class BaseActiveHatModel(HatModel, abc.ABC):
    client: ClassVar[AsyncHatClient]

    @abc.abstractmethod
    def save(self, endpoint: str | None = None) -> M:
        pass

    @abc.abstractmethod
    def delete(self) -> None:
        pass

    @classmethod
    @abc.abstractmethod
    def delete_all(cls, record_ids: StringLike | IStringLike) -> None:
        pass

    @classmethod
    @abc.abstractmethod
    def get(cls, endpoint: StringLike, options: GetOpts | None = None) -> list[M]:
        pass


class AsyncActiveHatModel(BaseActiveHatModel):
    async def save(self, endpoint: str | None = None) -> A:
        if endpoint is not None:
            self.endpoint = endpoint
        has_id = self.record_id is not None
        method = self._client().put if has_id else self._client().post
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

    def to_sync(self) -> ActiveHatModel:
        return ActiveHatModel.parse_obj(self)

    @classmethod
    def _client(cls) -> AsyncHatClient:
        return cls.client  # ClassVar interferes with type checking.


class ActiveHatModel(BaseActiveHatModel):
    def save(self, endpoint: str | None = None) -> S:
        return utils.synchronize(AsyncActiveHatModel.save)(self, endpoint)

    def delete(self) -> None:
        return utils.synchronize(AsyncActiveHatModel.delete)(self)

    @classmethod
    def delete_all(cls, record_ids: StringLike | IStringLike) -> None:
        return utils.synchronize(AsyncActiveHatModel.delete_all)(record_ids)

    @classmethod
    def get(cls, endpoint: StringLike, options: GetOpts | None = None) -> list[S]:
        models = utils.synchronize(AsyncActiveHatModel.get)(endpoint, options)
        return [ActiveHatModel.parse_obj(m) for m in models]

    def to_async(self) -> AsyncActiveHatModel:
        return AsyncActiveHatModel.parse_obj(self)


def set_client(client: AsyncHatClient) -> None:
    AsyncActiveHatModel.client = client


A = TypeVar("A", bound=AsyncActiveHatModel)
S = TypeVar("S", bound=ActiveHatModel)
