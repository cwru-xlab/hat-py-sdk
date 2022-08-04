# hat-py-sdk

Python [Dataswift HAT SDK](https://api.dataswift.io/).

## Features

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

### Creating a client

```python
from keyring.credentials import SimpleCredential

from hat import HatClient, ApiOwnerToken, AppToken

token = ApiOwnerToken(SimpleCredential("username", "password"))
token = AppToken(token, "application-id")
# Application namespace is only required for endpoint-specific requests
client = HatClient(token, "namespace")
```

### CRUD API

```python
from hat import HatClient, HatModel, GetOpts, Ordering

client = HatClient(...)

# GET request options are also validated using pydantic:
opts = GetOpts(order_by="id", ordering=Ordering.ASCENDING, skip=3, take=5)

# GET requests accept objects with an endpoint attribute...
models: list[MyModel] = client.get(MyModel, HatModel(endpoint="endpoint"), opts)
# ...or just specify the endpoints.
models = client.get(MyModel, "endpoint", ...)

# Models are grouped by endpoint for efficient mixed-endpoint POST requests. 
models: list[MyModel] = client.post(my_model, ...)

models: list[MyModel] = client.put(my_model, ...)

# Similar to GET requests, DELETE requests can specify an object...
client.delete(HatModel(record_id="record_id"), ...)
# ...or just the record IDs.
client.delete("record_id", ...)
```

#### Active-record API

```python
from hat import HatClient, ActiveHatModel

# Assign the client as a class attribute.
ActiveHatModel.client = HatClient(...)


# Model your data with pydantic.
class EndpointModel(ActiveHatModel):
    value: int


# Retrieve models from their endpoint with automatic data binding from JSON.
model: EndpointModel = EndpointModel.get("endpoint")[0]
# Modify their attributes,...
model.value += 1
# ...easily persist the changes,...
model.save()
# ...or delete the model.
model.delete()
```