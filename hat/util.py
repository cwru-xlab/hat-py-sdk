import abc
import hashlib
from typing import Any, final

from .client import HatClient
from .models import Record


# noinspection PyMethodMayBeStatic
class BaseIndexClient(abc.ABC):
    __slots__ = ("_client", "_endpoint")

    def __init__(self, client: HatClient, endpoint: str):
        super().__init__()
        self._client = client
        self._endpoint = endpoint

    @final
    def write(self, data: Any) -> None:
        index_record = self._get_index_record()
        index = self._get_index(index_record)
        if (key := self._get_key(data)) in index:
            ids = self._get_ids(index, key)
            self._on_put(data, ids)
        else:
            add_to_index = self._on_post(data)
            self._update_index(index_record, add_to_index, key)

    @final
    def _get_index_record(self) -> Record:
        if len(index_record := self._client.get(self._endpoint)) == 0:
            index_record = Record(data={"index": {}}, endpoint=self._endpoint)
        else:
            index_record = index_record[0]
        return index_record

    def _get_key(self, data: Any) -> str:
        return hashlib.sha256(str(data).encode()).hexdigest()

    @final
    def _update_index(self, index_record: Record, add: Any, key: str) -> None:
        index = self._get_index(index_record)
        index[key] = add
        if len(index) == 1:
            self._client.post(index_record)
        else:
            self._client.put(index_record)

    @final
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
