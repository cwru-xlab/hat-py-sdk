from abc import ABC
from typing import Optional

from humps import camel
from pydantic import BaseConfig
from pydantic import BaseModel
from pydantic import StrictStr

from hat import utils


class HatConfig(BaseConfig):
    allow_population_by_field_name = True
    use_enum_values = True
    json_dumps = utils.dumps
    json_loads = utils.loads
    underscore_attrs_are_private = True


class ApiConfig(HatConfig):
    alias_generator = camel.case
    allow_mutation = False


class BaseHatModel(BaseModel, ABC):
    endpoint: Optional[StrictStr]
    record_id: Optional[StrictStr]

    Config = HatConfig
