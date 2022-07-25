# hat-py-sdk

Python [Dataswift HAT SDK](https://api.dataswift.io/).

## Features

- Authentication with owner tokens (via API or web auth) and application tokens
- Automatic token refreshing and verification
- Keyring credentials owner token authentication
- All Direct Data API operations:
  - `POST`: groups records by endpoint to minimize request bandwidth
  - `GET`: supports multiple endpoints and options
  - `PUT`: supports multiple records to multiple endpoints
  - `DELETE`: supports multiple records
- Response streaming and caching to minimize latency and bandwidth
- Meaningful exception types
- Lazy token initialization for efficiency
- Session-based requests
- Powerful model validation for records and API tokens
  with [pydantic](https://github.com/samuelcolvin/pydantic/)
- Supports arbitrary record data, including pydantic models and any
  JSON-compatible data
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
from hat import HatClient, HatRecord

client = HatClient(...)
# GET requests can use a record object...
records = client.get(HatRecord(endpoint="endpoint"), ...)
# ...or just specify the endpoints.
records = client.get("endpoint", ...)

# Records are grouped by endpoint for efficient mixed-endpoint POST requests. 
records = client.post(HatRecord(endpoint="endpoint", data={...}), ...)

records = client.put(HatRecord(endpoint="namespace/endpoint", data={...}), ...)

# Similar to GET requests, DELETE requests can specify a record object...
client.delete(HatRecord(record_id="record_id"), ...)
# ...or just the record IDs.
client.delete("record_id", ...)
```