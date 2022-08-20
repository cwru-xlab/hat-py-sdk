# hat-py-sdk

Unofficial Python SDK for the [Dataswift API](https://api.dataswift.io/).

## Features

- Installation flags for minimal dependency overhead:
  - `sync`: synchronous client backed by the requests package
  - `async`: asynchronous client backed by the aiohttp package
  - `sync-cache`: HTTP caching backed by the requests-cache package
  - `async-cache`: HTTP caching backed by the aiohttp-client-cache package
  - `orjson`: fast JSON (de)serialization with the orjson package
  - `ulid`: use ULID identifiers instead of UUIDs
- Authentication with owner tokens (via API or web auth) and application tokens
- Automatic token refreshing and verification
- Supports any keyring credential for API owner token authentication
- All Direct Data API operations:
  - `POST`: groups records by endpoint to minimize request bandwidth
  - `GET`: supports single-endpoint requests and options
  - `PUT`: supports multi-record requests
  - `DELETE`: supports multi-record requests
- Response streaming and caching to minimize latency and bandwidth
- Meaningful exception types
- Lazy token initialization for efficiency
- Session-based requests
- Powerful model validation and parsing for records and API tokens
  with [pydantic](https://github.com/samuelcolvin/pydantic/)
- Encouraged immutability to avoid subtle bugs

## Usage

### Domain modeling

Top-level domain objects should inherit from `HatModel`, which is a special kind
of pydantic `BaseModel`. All other domain objects can be either be
pydantic `BaseModel` instances or any other kind of JSON-serializable object.
A `HatModel` has a record ID and an endpoint that relate to the Dataswift API.
The record ID uniquely identifies the record in the PDA. The endpoint is a path
that describes where in the PDA the record is located. In this way, a PDA is
like an object database (e.g., Amazon S3) where all the objects are accessible
via the endpoint at which they are located. A PDA is also like a document
database in that each record stored at an endpoint can be arbitrary JSON.

**Note:** This SDK assumes that each endpoint contains homogenous data
(i.e., all records have the same JSON schema). The `HatModel` allows for
arbitrary fields, so it is possible to retrieve any JSON from an endpoint, but
fields that represent JSON objects will remain as Python `dict`s.

```python
from pydantic import BaseModel
from hat.model import HatModel


class Nested(BaseModel):
    prop1: int
    prop2: str


class MyModel(HatModel):
    nested: Nested
    prop3: bytes

```

### Creating a client

This SDK provides both synchronous and asynchronous HTTP support and are very
similar. The two noticeable differences in their usage is that asynchronous
class names have a prefix of "Async" and require the async/await syntax when
using the client.

#### Synchronous

```python
from keyring.credentials import SimpleCredential

from hat.client import HttpClient, HatClient, CredentialOwnerToken, AppToken

http_client = HttpClient()
credential = SimpleCredential("username", "password")
token = CredentialOwnerToken(http_client, credential)
token = AppToken(http_client, token, "application-id")
# Application namespace is only required for endpoint-specific requests.
client = HatClient(http_client, token, "namespace")
```

#### Asynchronous

```python
from keyring.credentials import SimpleCredential

from hat.aioclient import (
    AsyncHttpClient, AsyncHatClient, AsyncCredentialOwnerToken, AsyncAppToken
)

http_client = AsyncHttpClient()
credential = SimpleCredential("username", "password")
token = AsyncCredentialOwnerToken(http_client, credential)
token = AsyncAppToken(http_client, token, "application-id")
# Application namespace is only required for endpoint-specific requests.
client = AsyncHatClient(http_client, token, "namespace")
```

### CRUD API

#### Synchronous

```python
from hat.client import HatClient
from hat.model import HatModel, GetOpts, Ordering

client = HatClient(...)

# GET requests accept objects with an endpoint attribute...
models: list[MyModel] = client.get(
    mtype=MyModel,
    endpoint=HatModel(endpoint="endpoint"),
    # GET request options are also validated using pydantic:
    options=GetOpts(order_by="id", ordering=Ordering.ASCENDING, skip=3, take=5))
# ...or just specify the endpoints.
models = client.get(mtype=MyModel, endpoint="endpoint", ...)

# Models are grouped by endpoint for efficient mixed-endpoint POST requests.
models: list[MyModel] = client.post(my_model, ...)

models: list[MyModel] = client.put(my_model, ...)

# Similar to GET requests, DELETE requests can specify an object...
client.delete(HatModel(record_id="record_id"), ...)
# ...or just the record IDs.
client.delete("record_id", ...)
```

#### Asynchronous

```python
from hat.aioclient import AsyncHatClient
from hat.model import HatModel, GetOpts, Ordering

client = AsyncHatClient(...)

# GET requests accept objects with an endpoint attribute...
models: list[MyModel] = await client.get(
    mtype=MyModel,
    endpoint=HatModel(endpoint="endpoint"),
    # GET request options are also validated using pydantic:
    options=GetOpts(order_by="id", ordering=Ordering.ASCENDING, skip=3, take=5))
# ...or just specify the endpoints.
models = await client.get(mtype=MyModel, endpoint="endpoint", ...)

# Models are grouped by endpoint for efficient mixed-endpoint POST requests.
models: list[MyModel] = await client.post(my_model, ...)

models: list[MyModel] = await client.put(my_model, ...)

# Similar to GET requests, DELETE requests can specify an object...
await client.delete(HatModel(record_id="record_id"), ...)
# ...or just the record IDs.
await client.delete("record_id", ...)
```

### Active-record API

This SDK also provides an alternative usage of the CRUD API with the
active-record pattern. It provides a simpler interface and offers a more
object-centric experience. Domain modeling is the same as before, except that
the top-level object must inherit from either `ActiveHatModel` or
`AsyncActiveHatModel`. The Create and Update operations are provided by a
single `save()` operation.

**Note:** By its very nature, this API does not have the advantage of efficient
bulk POST and PUT operations that the standard CRUD API offers. However, because
this API is merely a thin wrapper around the CRUD API, it is easy to switch
between them when most appropriate.

#### Synchronous

```python
from hat import client

# Assign the client as a class attribute.
client.set_client(client.HatClient(...))


# Model your data using the special active-record pydantic model.
class MyModel(client.ActiveHatModel):
    value: int


# Retrieve models from their endpoint with automatic data binding from JSON.
model: MyModel = MyModel.get("endpoint")[0]
# Modify their attributes,...
model.value += 1
# ...easily persist the changes,...
model.save()
# ...or delete the model.
model.delete()

# It is also possible to delete multiple records...
MyModel.delete_all(HatModel(record_id="record_id"), ...)
# ...or just with the record IDs.
MyModel.delete_all("record_id", ...)
```

#### Asynchronous

```python
from hat import aioclient

# Assign the client as a class attribute.
aioclient.set_async_client(aioclient.AsyncHatClient(...))


# Model your data using the special active-record pydantic model.
class MyModel(aioclient.AsyncActiveHatModel):
    value: int


# Retrieve models from their endpoint with automatic data binding from JSON.
model: MyModel = await MyModel.get("endpoint")[0]
# Modify their attributes,...
model.value += 1
# ...easily persist the changes,...
await model.save()
# ...or delete the model.
await model.delete()
# It is also possible to delete multiple records...
await MyModel.delete_all(HatModel(record_id="record_id"), ...)
# ...or just with the record IDs.
await MyModel.delete_all("record_id", ...)
```
