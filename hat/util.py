from __future__ import annotations

import abc
import hashlib
from typing import Any

from .client import HatClient
from .models import Record


# noinspection PyMethodMayBeStatic
class BaseIndexedHatClient(abc.ABC, HatClient):
    __slots__ = "_endpoint"

    def __init__(self, endpoint: str, **kwargs):
        super().__init__(**kwargs)
        self._endpoint = endpoint

    def write(self, data: Any) -> None:
        index_record = self._get_index_record()
        index = self._get_index(index_record)
        if (key := self._get_key(data)) in index:
            ids = self._get_ids(index, key)
            self._on_put(data, ids)
        else:
            add_to_index = self._on_post(data)
            self._update_index(index_record, add_to_index, key)

    def _get_index_record(self) -> Record:
        if len(index_record := self.get(self._endpoint)) == 0:
            index_record = Record(data={"index": {}}, endpoint=self._endpoint)
        else:
            index_record = index_record[0]
        return index_record

    def _get_key(self, data: Any) -> str:
        return hashlib.sha256(str(data).encode()).hexdigest()

    def _update_index(self, index_record: Record, add: Any, key: str) -> None:
        index = self._get_index(index_record)
        index[key] = add
        if len(index) == 1:
            self.post(index_record)
        else:
            self.put(index_record)

    def _get_index(self, index_record: Record) -> dict:
        return index_record.data["index"]

    def _get_ids(self, index: dict, key: str) -> Any:
        return index.get(key, None)

    @abc.abstractmethod
    def _on_post(self, data: Any) -> Any:
        pass

    @abc.abstractmethod
    def _on_put(self, data: Any, ids: Any) -> None:
        pass
